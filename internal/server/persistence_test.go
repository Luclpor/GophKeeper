package server

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Luclpor/GophKeeper/internal/vault"
)

func TestFileStorePersistsData(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "store.json")

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore returned error: %v", err)
	}
	if err := store.CreateUser(ctx, "alice", "hash"); err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
	}
	record := vault.Record{
		ID:        "record-1",
		Type:      vault.DataTypeText,
		Payload:   "payload",
		UpdatedAt: time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC),
	}
	if _, err := store.UpsertRecord(ctx, "alice", record); err != nil {
		t.Fatalf("UpsertRecord returned error: %v", err)
	}

	reloaded, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("reload NewFileStore returned error: %v", err)
	}
	hash, err := reloaded.PasswordHash(ctx, "alice")
	if err != nil {
		t.Fatalf("PasswordHash returned error: %v", err)
	}
	if hash != "hash" {
		t.Fatalf("hash = %q, want hash", hash)
	}
	got, err := reloaded.Record(ctx, "alice", "record-1")
	if err != nil {
		t.Fatalf("Record returned error: %v", err)
	}
	if got.Payload != "payload" {
		t.Fatalf("payload = %q, want payload", got.Payload)
	}
}
