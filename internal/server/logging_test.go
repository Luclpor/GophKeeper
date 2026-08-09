package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Luclpor/GophKeeper/internal/auth"
	"github.com/Luclpor/GophKeeper/internal/server"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestRequestLoggingMiddleware(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	store, err := server.NewFileStore("")
	if err != nil {
		t.Fatalf("NewFileStore returned error: %v", err)
	}
	handler, err := server.NewRouter(
		server.WithStore(store),
		server.WithTokenSecret(bytes.Repeat([]byte{8}, 32)),
		server.WithTokenTTL(time.Hour),
		server.WithLogger(zap.New(core)),
		server.WithPasswordHasher(auth.PasswordHasher{
			Rand:       repeatingReader(1),
			Iterations: 2,
			SaltSize:   16,
			KeySize:    32,
		}),
	)
	if err != nil {
		t.Fatalf("NewRouter returned error: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if logs.Len() != 1 {
		t.Fatalf("logs len = %d, want 1", logs.Len())
	}

	fields := logs.All()[0].ContextMap()
	if fields["method"] != http.MethodGet {
		t.Fatalf("method field = %v, want GET", fields["method"])
	}
	if fields["path"] != "/health" {
		t.Fatalf("path field = %v, want /health", fields["path"])
	}
	if fields["status"] != int64(http.StatusOK) {
		t.Fatalf("status field = %v, want 200", fields["status"])
	}

	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid json: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("health body = %+v", body)
	}
}
