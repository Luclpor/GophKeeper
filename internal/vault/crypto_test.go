package vault

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestNewEncryptedRecordRoundTrip(t *testing.T) {
	updatedAt := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	record, err := NewEncryptedRecord("master", "record-1", DataTypeLoginPassword, SecretData{
		Name:     "github",
		Metadata: map[string]string{"site": "github.com"},
		Fields: map[string]string{
			"login":    "alice",
			"password": "secret",
		},
	}, updatedAt)
	if err != nil {
		t.Fatalf("NewEncryptedRecord returned error: %v", err)
	}
	if record.ID != "record-1" || record.Type != DataTypeLoginPassword || record.Payload == "" {
		t.Fatalf("unexpected record: %+v", record)
	}

	secret, err := OpenRecord("master", record)
	if err != nil {
		t.Fatalf("OpenRecord returned error: %v", err)
	}
	if secret.Name != "github" || secret.Fields["login"] != "alice" || secret.Metadata["site"] != "github.com" {
		t.Fatalf("unexpected secret: %+v", secret)
	}
}

func TestOpenRecordRejectsWrongMasterPassword(t *testing.T) {
	record, err := NewEncryptedRecord("master", "record-1", DataTypeText, SecretData{
		Name:   "note",
		Fields: map[string]string{"text": "hello"},
	}, time.Time{})
	if err != nil {
		t.Fatalf("NewEncryptedRecord returned error: %v", err)
	}

	if _, err := OpenRecord("wrong", record); err == nil {
		t.Fatal("OpenRecord returned nil error for the wrong password")
	}
}

func TestSecretDataValidation(t *testing.T) {
	validBinary := SecretData{
		Name:   "file",
		Fields: map[string]string{"content_base64": base64.StdEncoding.EncodeToString([]byte("bytes"))},
	}
	if err := validBinary.Validate(DataTypeBinary); err != nil {
		t.Fatalf("valid binary rejected: %v", err)
	}

	invalidBinary := SecretData{
		Name:   "file",
		Fields: map[string]string{"content_base64": "not-base64"},
	}
	if err := invalidBinary.Validate(DataTypeBinary); err == nil {
		t.Fatal("invalid binary accepted")
	}

	missingLogin := SecretData{Name: "login", Fields: map[string]string{"login": "alice"}}
	if err := missingLogin.Validate(DataTypeLoginPassword); err == nil {
		t.Fatal("login/password secret without password accepted")
	}
}
