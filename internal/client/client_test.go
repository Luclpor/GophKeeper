package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Luclpor/GophKeeper/internal/vault"
)

func TestClientMethods(t *testing.T) {
	record := vault.Record{
		ID:        "record-1",
		Type:      vault.DataTypeText,
		Payload:   "payload",
		UpdatedAt: time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/register" && r.URL.Path != "/api/v1/auth/login" {
			if r.Header.Get("Authorization") != "Bearer token" {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(apiError{Error: "missing token"})
				return
			}
		}

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/register":
			_ = json.NewEncoder(w).Encode(authResponse{Username: "alice", Token: "token"})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/login":
			_ = json.NewEncoder(w).Encode(authResponse{Username: "alice", Token: "token"})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/records":
			_ = json.NewEncoder(w).Encode([]vault.Record{record})
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/records/record-1":
			_ = json.NewEncoder(w).Encode(record)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/records/record-1":
			_ = json.NewEncoder(w).Encode(record)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/records/record-1":
			record.Deleted = true
			_ = json.NewEncoder(w).Encode(record)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/records/sync":
			_ = json.NewEncoder(w).Encode(syncResponse{Records: []vault.Record{record}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	api, err := New(Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if _, err := api.Register(context.Background(), "alice", "password"); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if api.Token() != "token" {
		t.Fatalf("Token = %q, want token", api.Token())
	}
	api.SetToken("")
	if _, err := api.Login(context.Background(), "alice", "password"); err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if _, err := api.ListRecords(context.Background()); err != nil {
		t.Fatalf("ListRecords returned error: %v", err)
	}
	if _, err := api.PutRecord(context.Background(), record); err != nil {
		t.Fatalf("PutRecord returned error: %v", err)
	}
	if _, err := api.GetRecord(context.Background(), "record-1"); err != nil {
		t.Fatalf("GetRecord returned error: %v", err)
	}
	if _, err := api.DeleteRecord(context.Background(), "record-1"); err != nil {
		t.Fatalf("DeleteRecord returned error: %v", err)
	}
	if _, err := api.SyncRecords(context.Background(), []vault.Record{record}); err != nil {
		t.Fatalf("SyncRecords returned error: %v", err)
	}
}

func TestNewRejectsInvalidBaseURL(t *testing.T) {
	if _, err := New(Config{BaseURL: "localhost:8080"}); err == nil {
		t.Fatal("New returned nil error for invalid base url")
	}
}
