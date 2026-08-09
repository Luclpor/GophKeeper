package server_test

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Luclpor/GophKeeper/internal/auth"
	"github.com/Luclpor/GophKeeper/internal/server"
)

func TestRequestLoggingMiddleware(t *testing.T) {
	var logs bytes.Buffer
	store, err := server.NewFileStore("")
	if err != nil {
		t.Fatalf("NewFileStore returned error: %v", err)
	}
	handler, err := server.NewRouter(
		server.WithStore(store),
		server.WithTokenSecret(bytes.Repeat([]byte{8}, 32)),
		server.WithTokenTTL(time.Hour),
		server.WithLogger(log.New(&logs, "", 0)),
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

	logLine := logs.String()
	if !strings.Contains(logLine, `method=GET`) {
		t.Fatalf("log line = %q, want method field", logLine)
	}
	if !strings.Contains(logLine, `path="/health"`) {
		t.Fatalf("log line = %q, want path field", logLine)
	}
	if !strings.Contains(logLine, `status=200`) {
		t.Fatalf("log line = %q, want status field", logLine)
	}

	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid json: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("health body = %+v", body)
	}
}
