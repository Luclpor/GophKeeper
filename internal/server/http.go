package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Luclpor/GophKeeper/internal/auth"
	"github.com/Luclpor/GophKeeper/internal/vault"
)

const maxRequestBodyBytes = 1 << 20

type contextKey string

const usernameContextKey contextKey = "username"
const requestIDContextKey contextKey = "request_id"

// App owns the HTTP handlers for one GophKeeper server instance.
type App struct {
	store     Store
	passwords auth.PasswordHasher
	tokens    auth.TokenManager
	logger    *log.Logger
}

type config struct {
	store          Store
	passwordHasher auth.PasswordHasher
	tokenSecret    []byte
	tokenTTL       time.Duration
	logger         *log.Logger
}

// Option configures an App during construction.
type Option func(*config)

// WithStore configures persistent storage for users and encrypted records.
func WithStore(store Store) Option {
	return func(config *config) {
		config.store = store
	}
}

// WithPasswordHasher configures password hashing and verification.
func WithPasswordHasher(passwordHasher auth.PasswordHasher) Option {
	return func(config *config) {
		config.passwordHasher = passwordHasher
	}
}

// WithTokenSecret configures the HMAC key used for bearer tokens.
func WithTokenSecret(secret []byte) Option {
	return func(config *config) {
		config.tokenSecret = append([]byte(nil), secret...)
	}
}

// WithTokenTTL configures bearer token lifetime.
func WithTokenTTL(ttl time.Duration) Option {
	return func(config *config) {
		config.tokenTTL = ttl
	}
}

// WithLogger configures the logger used by HTTP middleware.
func WithLogger(logger *log.Logger) Option {
	return func(config *config) {
		config.logger = logger
	}
}

// NewApp constructs an App from functional options.
func NewApp(options ...Option) (*App, error) {
	config := config{}
	for _, option := range options {
		if option != nil {
			option(&config)
		}
	}

	if config.store == nil {
		return nil, errors.New("store is required")
	}
	if len(config.tokenSecret) == 0 {
		config.tokenSecret = make([]byte, 32)
		if _, err := rand.Read(config.tokenSecret); err != nil {
			return nil, fmt.Errorf("read token secret: %w", err)
		}
	}

	tokens, err := auth.NewTokenManager(config.tokenSecret, config.tokenTTL)
	if err != nil {
		return nil, err
	}
	if config.passwordHasher.Rand == nil {
		config.passwordHasher.Rand = rand.Reader
	}
	if config.logger == nil {
		config.logger = log.New(io.Discard, "", 0)
	}

	return &App{
		store:     config.store,
		passwords: config.passwordHasher,
		tokens:    tokens,
		logger:    config.logger,
	}, nil
}

// NewRouter constructs a ready-to-serve HTTP handler from functional options.
func NewRouter(options ...Option) (http.Handler, error) {
	app, err := NewApp(options...)
	if err != nil {
		return nil, err
	}
	return app.Router(), nil
}

// Router returns the standard-library HTTP API router.
func (a *App) Router() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("POST /api/v1/auth/register", a.handleRegister)
	mux.HandleFunc("POST /api/v1/auth/login", a.handleLogin)
	mux.Handle("GET /api/v1/records", a.requireAuth(http.HandlerFunc(a.handleListRecords)))
	mux.Handle("POST /api/v1/records/sync", a.requireAuth(http.HandlerFunc(a.handleSyncRecords)))
	mux.Handle("GET /api/v1/records/{id}", a.requireAuth(http.HandlerFunc(a.handleGetRecord)))
	mux.Handle("PUT /api/v1/records/{id}", a.requireAuth(http.HandlerFunc(a.handlePutRecord)))
	mux.Handle("DELETE /api/v1/records/{id}", a.requireAuth(http.HandlerFunc(a.handleDeleteRecord)))

	return a.withRequestID(a.withRealIP(a.logRequests(a.recoverRequests(mux))))
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
	record, err := a.store.Record(r.Context(), usernameFromContext(r.Context()), r.PathValue("id"))
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
	record.ID = r.PathValue("id")

	saved, err := a.store.UpsertRecord(r.Context(), usernameFromContext(r.Context()), record)
	if err != nil {
		writeError(w, statusForError(err), err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (a *App) handleDeleteRecord(w http.ResponseWriter, r *http.Request) {
	tombstone, err := a.store.DeleteRecord(r.Context(), usernameFromContext(r.Context()), r.PathValue("id"), time.Now().UTC())
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

func requestIDFromContext(ctx context.Context) string {
	requestID, _ := ctx.Value(requestIDContextKey).(string)
	return requestID
}

func (a *App) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if requestID == "" {
			requestID = newRequestID()
		}
		w.Header().Set("X-Request-ID", requestID)

		ctx := context.WithValue(r.Context(), requestIDContextKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *App) withRealIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
			if realIP, _, ok := strings.Cut(forwardedFor, ","); ok {
				r.RemoteAddr = strings.TrimSpace(realIP)
			} else {
				r.RemoteAddr = strings.TrimSpace(forwardedFor)
			}
		}
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
			r.RemoteAddr = realIP
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) recoverRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				a.logger.Printf("level=error msg=%q panic=%q request_id=%q stack=%q", "http request panic recovered", recovered, requestIDFromContext(r.Context()), debug.Stack())
				writeError(w, http.StatusInternalServerError, errors.New("internal server error"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func newRequestID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
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
