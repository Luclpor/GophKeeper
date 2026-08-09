package auth

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestTokenManagerIssueAndVerify(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	manager, err := NewTokenManager(bytes.Repeat([]byte{2}, 32), time.Hour)
	if err != nil {
		t.Fatalf("NewTokenManager returned error: %v", err)
	}
	manager = manager.WithClock(func() time.Time { return now })

	token, err := manager.Issue("alice")
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	subject, err := manager.Verify(token)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if subject != "alice" {
		t.Fatalf("subject = %q, want alice", subject)
	}
}

func TestTokenManagerRejectsTamperedAndExpiredTokens(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	manager, err := NewTokenManager(bytes.Repeat([]byte{3}, 32), time.Minute)
	if err != nil {
		t.Fatalf("NewTokenManager returned error: %v", err)
	}
	manager = manager.WithClock(func() time.Time { return now })

	token, err := manager.Issue("alice")
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	if _, err := manager.Verify(token + "x"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("tampered Verify error = %v, want ErrInvalidToken", err)
	}

	expiredManager := manager.WithClock(func() time.Time { return now.Add(2 * time.Minute) })
	if _, err := expiredManager.Verify(token); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("expired Verify error = %v, want ErrExpiredToken", err)
	}
}
