package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const defaultTokenTTL = 24 * time.Hour

// ErrInvalidToken is returned when a bearer token cannot be parsed or its
// signature is invalid.
var ErrInvalidToken = errors.New("invalid token")

// ErrExpiredToken is returned when a bearer token has passed its expiration
// timestamp.
var ErrExpiredToken = errors.New("expired token")

// TokenManager issues and verifies compact HMAC-signed bearer tokens.
type TokenManager struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time
}

type tokenPayload struct {
	Subject   string `json:"sub"`
	ExpiresAt int64  `json:"exp"`
}

// NewTokenManager creates a TokenManager using secret as the HMAC key.
func NewTokenManager(secret []byte, ttl time.Duration) (TokenManager, error) {
	if len(secret) < 16 {
		return TokenManager{}, errors.New("token secret must contain at least 16 bytes")
	}
	if ttl <= 0 {
		ttl = defaultTokenTTL
	}

	copied := make([]byte, len(secret))
	copy(copied, secret)

	return TokenManager{
		secret: copied,
		ttl:    ttl,
		now:    time.Now,
	}, nil
}

// WithClock returns a TokenManager copy that uses clock for token timestamps.
func (m TokenManager) WithClock(clock func() time.Time) TokenManager {
	if clock != nil {
		m.now = clock
	}
	return m
}

// Issue creates a signed token for subject.
func (m TokenManager) Issue(subject string) (string, error) {
	if strings.TrimSpace(subject) == "" {
		return "", errors.New("token subject must not be empty")
	}
	if m.now == nil {
		m.now = time.Now
	}

	payload := tokenPayload{
		Subject:   subject,
		ExpiresAt: m.now().Add(m.ttl).Unix(),
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal token payload: %w", err)
	}

	payloadPart := base64.RawURLEncoding.EncodeToString(rawPayload)
	signature := sign(payloadPart, m.secret)
	return payloadPart + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// Verify validates token and returns its subject.
func (m TokenManager) Verify(token string) (string, error) {
	if m.now == nil {
		m.now = time.Now
	}

	payloadPart, signaturePart, ok := strings.Cut(token, ".")
	if !ok || payloadPart == "" || signaturePart == "" {
		return "", ErrInvalidToken
	}

	signature, err := base64.RawURLEncoding.DecodeString(signaturePart)
	if err != nil {
		return "", fmt.Errorf("%w: malformed signature", ErrInvalidToken)
	}
	if !hmac.Equal(signature, sign(payloadPart, m.secret)) {
		return "", fmt.Errorf("%w: signature mismatch", ErrInvalidToken)
	}

	rawPayload, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return "", fmt.Errorf("%w: malformed payload", ErrInvalidToken)
	}

	var payload tokenPayload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return "", fmt.Errorf("%w: malformed payload json", ErrInvalidToken)
	}
	if strings.TrimSpace(payload.Subject) == "" {
		return "", fmt.Errorf("%w: empty subject", ErrInvalidToken)
	}
	if payload.ExpiresAt <= m.now().Unix() {
		return "", ErrExpiredToken
	}

	return payload.Subject, nil
}

func sign(payloadPart string, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payloadPart))
	return mac.Sum(nil)
}
