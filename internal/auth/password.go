package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	passwordHashScheme      = "pbkdf2_sha256"
	defaultHashIterations   = 210_000
	defaultHashSaltSize     = 16
	defaultHashKeySize      = 32
	passwordHashPartCount   = 4
	passwordHashSchemeIndex = 0
)

// ErrInvalidPasswordHash is returned when a stored password hash cannot be
// parsed or uses an unsupported format.
var ErrInvalidPasswordHash = errors.New("invalid password hash")

// PasswordHasher creates and verifies PBKDF2-SHA256 password hashes.
type PasswordHasher struct {
	// Rand supplies salt entropy. Crypto-random bytes are used when Rand is nil.
	Rand io.Reader
	// Iterations controls PBKDF2 work factor. A secure default is used when it is
	// zero or negative.
	Iterations int
	// SaltSize controls salt length in bytes. A secure default is used when it is
	// zero or negative.
	SaltSize int
	// KeySize controls derived key length in bytes. A secure default is used when
	// it is zero or negative.
	KeySize int
}

// NewPasswordHasher returns a PasswordHasher configured with production
// defaults.
func NewPasswordHasher() PasswordHasher {
	return PasswordHasher{
		Rand:       rand.Reader,
		Iterations: defaultHashIterations,
		SaltSize:   defaultHashSaltSize,
		KeySize:    defaultHashKeySize,
	}
}

// Hash derives and formats a password hash suitable for persistent storage.
func (h PasswordHasher) Hash(password string) (string, error) {
	if password == "" {
		return "", errors.New("password must not be empty")
	}

	h = h.withDefaults()
	salt := make([]byte, h.SaltSize)
	if _, err := io.ReadFull(h.Rand, salt); err != nil {
		return "", fmt.Errorf("read password salt: %w", err)
	}

	key, err := pbkdf2.Key(sha256.New, password, salt, h.Iterations, h.KeySize)
	if err != nil {
		return "", fmt.Errorf("derive password hash: %w", err)
	}

	return strings.Join([]string{
		passwordHashScheme,
		strconv.Itoa(h.Iterations),
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	}, "$"), nil
}

// Verify reports whether password matches encodedHash.
func (h PasswordHasher) Verify(encodedHash, password string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != passwordHashPartCount {
		return false, ErrInvalidPasswordHash
	}
	if parts[passwordHashSchemeIndex] != passwordHashScheme {
		return false, fmt.Errorf("%w: unsupported scheme", ErrInvalidPasswordHash)
	}

	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations <= 0 {
		return false, fmt.Errorf("%w: invalid iteration count", ErrInvalidPasswordHash)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) == 0 {
		return false, fmt.Errorf("%w: invalid salt", ErrInvalidPasswordHash)
	}

	expected, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(expected) == 0 {
		return false, fmt.Errorf("%w: invalid key", ErrInvalidPasswordHash)
	}

	got, err := pbkdf2.Key(sha256.New, password, salt, iterations, len(expected))
	if err != nil {
		return false, fmt.Errorf("derive password hash: %w", err)
	}

	return subtle.ConstantTimeCompare(got, expected) == 1, nil
}

func (h PasswordHasher) withDefaults() PasswordHasher {
	if h.Rand == nil {
		h.Rand = rand.Reader
	}
	if h.Iterations <= 0 {
		h.Iterations = defaultHashIterations
	}
	if h.SaltSize <= 0 {
		h.SaltSize = defaultHashSaltSize
	}
	if h.KeySize <= 0 {
		h.KeySize = defaultHashKeySize
	}
	return h
}
