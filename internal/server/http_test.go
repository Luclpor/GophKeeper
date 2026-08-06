package server_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/Luclpor/GophKeeper/internal/auth"
	"github.com/Luclpor/GophKeeper/internal/client"
	"github.com/Luclpor/GophKeeper/internal/server"
	"github.com/Luclpor/GophKeeper/internal/vault"
)

type repeatingReader byte

func (r repeatingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

func TestHTTPAPIIntegration(t *testing.T) {
	store, err := server.NewFileStore("")
	if err != nil {
		t.Fatalf("NewFileStore returned error: %v", err)
	}
	handler, err := server.NewRouter(server.Config{
		Store:       store,
		TokenSecret: bytes.Repeat([]byte{4}, 32),
		TokenTTL:    time.Hour,
		PasswordHasher: auth.PasswordHasher{
			Rand:       repeatingReader(1),
			Iterations: 2,
			SaltSize:   16,
			KeySize:    32,
		},
	})
	if err != nil {
		t.Fatalf("NewRouter returned error: %v", err)
	}
	testServer := newHTTPTestServer(t, handler)

	api, err := client.New(client.Config{BaseURL: testServer.URL, HTTPClient: testServer.Client()})
	if err != nil {
		t.Fatalf("client.New returned error: %v", err)
	}

	if _, err := api.ListRecords(context.Background()); err == nil {
		t.Fatal("ListRecords without token returned nil error")
	}

	token, err := api.Register(context.Background(), "alice", "password")
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if token == "" {
		t.Fatal("Register returned empty token")
	}
	if _, err := api.Register(context.Background(), "alice", "password"); err == nil {
		t.Fatal("duplicate Register returned nil error")
	}
	if _, err := api.Login(context.Background(), "alice", "wrong"); err == nil {
		t.Fatal("Login with wrong password returned nil error")
	}
	if _, err := api.Login(context.Background(), "alice", "password"); err != nil {
		t.Fatalf("Login returned error: %v", err)
	}

	record, err := vault.NewEncryptedRecord("master", "record-1", vault.DataTypeText, vault.SecretData{
		Name:   "note",
		Fields: map[string]string{"text": "hello"},
	}, time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("NewEncryptedRecord returned error: %v", err)
	}
	if _, err := api.PutRecord(context.Background(), record); err != nil {
		t.Fatalf("PutRecord returned error: %v", err)
	}

	records, err := api.ListRecords(context.Background())
	if err != nil {
		t.Fatalf("ListRecords returned error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records len = %d, want 1", len(records))
	}

	got, err := api.GetRecord(context.Background(), "record-1")
	if err != nil {
		t.Fatalf("GetRecord returned error: %v", err)
	}
	if got.ID != "record-1" {
		t.Fatalf("got record id = %q, want record-1", got.ID)
	}

	merged, err := api.SyncRecords(context.Background(), []vault.Record{record})
	if err != nil {
		t.Fatalf("SyncRecords returned error: %v", err)
	}
	if len(merged) != 1 {
		t.Fatalf("merged len = %d, want 1", len(merged))
	}

	tombstone, err := api.DeleteRecord(context.Background(), "record-1")
	if err != nil {
		t.Fatalf("DeleteRecord returned error: %v", err)
	}
	if !tombstone.Deleted {
		t.Fatal("DeleteRecord returned non-deleted record")
	}
	if _, err := api.GetRecord(context.Background(), "record-1"); err == nil {
		t.Fatal("GetRecord after delete returned nil error")
	}
}
