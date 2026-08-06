package vault

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DataType identifies the semantic type of an encrypted record.
type DataType string

const (
	// DataTypeLoginPassword stores a login and password pair.
	DataTypeLoginPassword DataType = "login_password"
	// DataTypeText stores arbitrary textual information.
	DataTypeText DataType = "text"
	// DataTypeBinary stores arbitrary binary information as base64 text.
	DataTypeBinary DataType = "binary"
	// DataTypeBankCard stores bank card details.
	DataTypeBankCard DataType = "bank_card"
	// DataTypeOTP stores an optional one-time password secret.
	DataTypeOTP DataType = "otp"
)

// SecretData is the plaintext payload encrypted by the client before a record
// is sent to the server.
type SecretData struct {
	// Name is a user-facing title for the secret.
	Name string `json:"name"`
	// Metadata stores arbitrary user-provided text metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
	// Fields stores type-specific secret fields.
	Fields map[string]string `json:"fields"`
}

// Record is the encrypted representation stored and synchronized by the server.
type Record struct {
	// ID is a stable record identifier shared by all clients.
	ID string `json:"id"`
	// Type identifies the plaintext schema encrypted inside Payload.
	Type DataType `json:"type"`
	// Payload is a base64-encoded AES-GCM envelope.
	Payload string `json:"payload,omitempty"`
	// UpdatedAt is the UTC timestamp used for last-write-wins synchronization.
	UpdatedAt time.Time `json:"updated_at"`
	// Deleted marks a tombstone that should be propagated during sync.
	Deleted bool `json:"deleted,omitempty"`
}

// NewRecordID returns a random hex identifier suitable for a Record.
func NewRecordID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read record id entropy: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// Validate verifies that t is a supported GophKeeper data type.
func (t DataType) Validate() error {
	switch t {
	case DataTypeLoginPassword, DataTypeText, DataTypeBinary, DataTypeBankCard, DataTypeOTP:
		return nil
	default:
		return fmt.Errorf("unsupported data type %q", t)
	}
}

// Validate verifies that d contains the required plaintext fields for t.
func (d SecretData) Validate(t DataType) error {
	if err := t.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(d.Name) == "" {
		return errors.New("secret name must not be empty")
	}
	if d.Fields == nil {
		return errors.New("secret fields must not be empty")
	}

	switch t {
	case DataTypeLoginPassword:
		return requireFields(d.Fields, "login", "password")
	case DataTypeText:
		return requireFields(d.Fields, "text")
	case DataTypeBinary:
		if err := requireFields(d.Fields, "content_base64"); err != nil {
			return err
		}
		if _, err := base64.StdEncoding.DecodeString(d.Fields["content_base64"]); err != nil {
			return fmt.Errorf("binary content_base64 must be valid base64: %w", err)
		}
		return nil
	case DataTypeBankCard:
		return requireFields(d.Fields, "number", "holder", "expires")
	case DataTypeOTP:
		return requireFields(d.Fields, "secret")
	default:
		return nil
	}
}

// Validate verifies the metadata required for server-side storage.
func (r Record) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return errors.New("record id must not be empty")
	}
	if err := r.Type.Validate(); err != nil {
		return err
	}
	if !r.Deleted && strings.TrimSpace(r.Payload) == "" {
		return errors.New("record payload must not be empty")
	}
	return nil
}

func requireFields(fields map[string]string, names ...string) error {
	for _, name := range names {
		if strings.TrimSpace(fields[name]) == "" {
			return fmt.Errorf("field %q must not be empty", name)
		}
	}
	return nil
}
