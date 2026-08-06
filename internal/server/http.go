package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Luclpor/GophKeeper/internal/auth"
	"github.com/Luclpor/GophKeeper/internal/vault"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

const maxRequestBodyBytes = 1 << 20

type contextKey string

const usernameContextKey contextKey = "username"

// Config contains dependencies and security settings for the HTTP API.
type Config struct {
	// Store persists users and encrypted records.
	Store Store
	// PasswordHasher hashes and verifies user passwords.
	PasswordHasher auth.PasswordHasher
	// TokenSecret is the HMAC key used for bearer tokens.
	TokenSecret []byte
	// TokenTTL controls bearer token lifetime.
	TokenTTL time.Duration
}

// App owns the HTTP handlers for one GophKeeper server instance.
type App struct {
	store     Store
	passwords auth.PasswordHasher
	tokens    auth.TokenManager
}

// NewApp constructs an App from Config.
func NewApp(config Config) (*App, error) {
	if config.Store == nil {
		return nil, errors.New("store is required")
	}
	if len(config.TokenSecret) == 0 {
		config.TokenSecret = make([]byte, 32)
		if _, err := rand.Read(config.TokenSecret); err != nil {
			return nil, fmt.Errorf("read token secret: %w", err)
		}
	}

	tokens, err := auth.NewTokenManager(config.TokenSecret, config.TokenTTL)
	if err != nil {
		return nil, err
	}
	if config.PasswordHasher.Rand == nil {
		config.PasswordHasher.Rand = rand.Reader
	}

	return &App{
		store:     config.Store,
		passwords: config.PasswordHasher,
		tokens:    tokens,
	}, nil
}

// NewRouter constructs a ready-to-serve HTTP handler from Config.
func NewRouter(config Config) (http.Handler, error) {
	app, err := NewApp(config)
	if err != nil {
		return nil, err
	}
	return app.Router(), nil
}

// Router returns the chi-based HTTP API router.
func (a *App) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/auth/register", a.handleRegister)
		r.Post("/auth/login", a.handleLogin)

		r.Group(func(r chi.Router) {
			r.Use(a.requireAuth)
			r.Get("/records", a.handleListRecords)
			r.Post("/records/sync", a.handleSyncRecords)
			r.Get("/records/{id}", a.handleGetRecord)
			r.Put("/records/{id}", a.handlePutRecord)
			r.Delete("/records/{id}", a.handleDeleteRecord)
		})
	})

	return r
}

func (a *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	var request AuthRequest
	if !readJSON(w, r, &request) {
		return
	}

	username := strings.TrimSpace(request.Username)
	passwordHash, err := a.passwords.Hash(request.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := a.store.CreateUser(r.Context(), username, passwordHash); err != nil {
		writeError(w, statusForError(err), err)
		return
	}

	token, err := a.tokens.Issue(username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, AuthResponse{Username: username, Token: token})
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var request AuthRequest
	if !readJSON(w, r, &request) {
		return
	}

	username := strings.TrimSpace(request.Username)
	passwordHash, err := a.store.PasswordHash(r.Context(), username)
	if err != nil {
		writeError(w, http.StatusUnauthorized, errors.New("invalid username or password"))
		return
	}
	matches, err := a.passwords.Verify(passwordHash, request.Password)
	if err != nil || !matches {
		writeError(w, http.StatusUnauthorized, errors.New("invalid username or password"))
		return
	}

	token, err := a.tokens.Issue(username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, AuthResponse{Username: username, Token: token})
}

func (a *App) handleListRecords(w http.ResponseWriter, r *http.Request) {
	records, err := a.store.Records(r.Context(), usernameFromContext(r.Context()))
	if err != nil {
		writeError(w, statusForError(err), err)
		return
	}
	writeJSON(w, http.StatusOK, records)
}

func (a *App) handleGetRecord(w http.ResponseWriter, r *http.Request) {
	record, err := a.store.Record(r.Context(), usernameFromContext(r.Context()), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, statusForError(err), err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (a *App) handlePutRecord(w http.ResponseWriter, r *http.Request) {
	var record vault.Record
	if !readJSON(w, r, &record) {
		return
	}
	record.ID = chi.URLParam(r, "id")

	saved, err := a.store.UpsertRecord(r.Context(), usernameFromContext(r.Context()), record)
	if err != nil {
		writeError(w, statusForError(err), err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (a *App) handleDeleteRecord(w http.ResponseWriter, r *http.Request) {
	tombstone, err := a.store.DeleteRecord(r.Context(), usernameFromContext(r.Context()), chi.URLParam(r, "id"), time.Now().UTC())
	if err != nil {
		writeError(w, statusForError(err), err)
		return
	}
	writeJSON(w, http.StatusOK, tombstone)
}

func (a *App) handleSyncRecords(w http.ResponseWriter, r *http.Request) {
	var request SyncRequest
	if !readJSON(w, r, &request) {
		return
	}

	records, err := a.store.SyncRecords(r.Context(), usernameFromContext(r.Context()), request.Records)
	if err != nil {
		writeError(w, statusForError(err), err)
		return
	}
	writeJSON(w, http.StatusOK, SyncResponse{Records: records})
}

func (a *App) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(header, "Bearer ")
		if !ok || strings.TrimSpace(token) == "" {
			writeError(w, http.StatusUnauthorized, errors.New("missing bearer token"))
			return
		}

		username, err := a.tokens.Verify(token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err)
			return
		}

		ctx := context.WithValue(r.Context(), usernameContextKey, username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func usernameFromContext(ctx context.Context) string {
	username, _ := ctx.Value(usernameContextKey).(string)
	return username
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()

	decoder := json.NewDecoder(io.LimitReader(r.Body, maxRequestBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode json: %w", err))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, ErrorResponse{Error: err.Error()})
}

func statusForError(err error) int {
	switch {
	case errors.Is(err, ErrInvalidInput):
		return http.StatusBadRequest
	case errors.Is(err, ErrUserExists):
		return http.StatusConflict
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}
