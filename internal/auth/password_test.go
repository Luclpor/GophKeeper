package auth

import (
	"bytes"
	"errors"
	"testing"
)

func TestPasswordHasherHashAndVerify(t *testing.T) {
	hasher := PasswordHasher{
		Rand:       bytes.NewReader(bytes.Repeat([]byte{1}, 16)),
		Iterations: 2,
		SaltSize:   16,
		KeySize:    32,
	}

	hash, err := hasher.Hash("secret")
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}

	matches, err := hasher.Verify(hash, "secret")
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !matches {
		t.Fatal("Verify returned false for the correct password")
	}

	matches, err = hasher.Verify(hash, "wrong")
	if err != nil {
		t.Fatalf("Verify wrong password returned error: %v", err)
	}
	if matches {
		t.Fatal("Verify returned true for the wrong password")
	}
}

func TestPasswordHasherRejectsInvalidHash(t *testing.T) {
	hasher := NewPasswordHasher()
	if _, err := hasher.Verify("invalid", "secret"); !errors.Is(err, ErrInvalidPasswordHash) {
		t.Fatalf("Verify error = %v, want ErrInvalidPasswordHash", err)
	}
}
