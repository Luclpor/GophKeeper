package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Luclpor/GophKeeper/internal/vault"
)

func TestFileStoreUserAndRecordLifecycle(t *testing.T) {
	ctx := context.Background()
	store, err := NewFileStore("")
	if err != nil {
		t.Fatalf("NewFileStore returned error: %v", err)
	}

	if err := store.CreateUser(ctx, "alice", "hash"); err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
	}
	if err := store.CreateUser(ctx, "alice", "hash"); !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate CreateUser error = %v, want ErrUserExists", err)
	}
	hash, err := store.PasswordHash(ctx, "alice")
	if err != nil {
		t.Fatalf("PasswordHash returned error: %v", err)
	}
	if hash != "hash" {
		t.Fatalf("hash = %q, want hash", hash)
	}

	oldTime := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	newTime := oldTime.Add(time.Hour)
	oldRecord := vault.Record{ID: "record-1", Type: vault.DataTypeText, Payload: "old", UpdatedAt: oldTime}
	newRecord := vault.Record{ID: "record-1", Type: vault.DataTypeText, Payload: "new", UpdatedAt: newTime}

	if _, err := store.UpsertRecord(ctx, "alice", newRecord); err != nil {
		t.Fatalf("UpsertRecord returned error: %v", err)
	}
	saved, err := store.UpsertRecord(ctx, "alice", oldRecord)
	if err != nil {
		t.Fatalf("older UpsertRecord returned error: %v", err)
	}
	if saved.Payload != "new" {
		t.Fatalf("older record won conflict: %+v", saved)
	}

	records, err := store.Records(ctx, "alice")
	if err != nil {
		t.Fatalf("Records returned error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records len = %d, want 1", len(records))
	}

	tombstone, err := store.DeleteRecord(ctx, "alice", "record-1", newTime.Add(time.Hour))
	if err != nil {
		t.Fatalf("DeleteRecord returned error: %v", err)
	}
	if !tombstone.Deleted {
		t.Fatal("DeleteRecord returned a non-deleted tombstone")
	}

	records, err = store.Records(ctx, "alice")
	if err != nil {
		t.Fatalf("Records after delete returned error: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("records after delete len = %d, want 0", len(records))
	}

	merged, err := store.SyncRecords(ctx, "alice", []vault.Record{
		{ID: "record-2", Type: vault.DataTypeText, Payload: "payload", UpdatedAt: newTime},
	})
	if err != nil {
		t.Fatalf("SyncRecords returned error: %v", err)
	}
	if len(merged) != 2 {
		t.Fatalf("merged len = %d, want 2", len(merged))
	}
}
