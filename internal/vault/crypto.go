package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	envelopeVersion      = 1
	envelopeKDF          = "pbkdf2_sha256"
	envelopeIterations   = 210_000
	envelopeSaltSize     = 16
	envelopeDerivedBytes = 32
)

type cipherEnvelope struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// Seal encrypts plaintext using a key derived from masterPassword.
func Seal(masterPassword string, plaintext SecretData) (string, error) {
	if masterPassword == "" {
		return "", errors.New("master password must not be empty")
	}

	rawPlaintext, err := json.Marshal(plaintext)
	if err != nil {
		return "", fmt.Errorf("marshal plaintext: %w", err)
	}

	salt := make([]byte, envelopeSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("read encryption salt: %w", err)
	}

	key, err := deriveKey(masterPassword, salt, envelopeIterations)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm cipher: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("read encryption nonce: %w", err)
	}

	envelope := cipherEnvelope{
		Version:    envelopeVersion,
		KDF:        envelopeKDF,
		Iterations: envelopeIterations,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, rawPlaintext, nil)),
	}

	rawEnvelope, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("marshal cipher envelope: %w", err)
	}
	return base64.StdEncoding.EncodeToString(rawEnvelope), nil
}

// Open decrypts payload using a key derived from masterPassword.
func Open(masterPassword, payload string) (SecretData, error) {
	if masterPassword == "" {
		return SecretData{}, errors.New("master password must not be empty")
	}

	rawEnvelope, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return SecretData{}, fmt.Errorf("decode cipher envelope: %w", err)
	}

	var envelope cipherEnvelope
	if err := json.Unmarshal(rawEnvelope, &envelope); err != nil {
		return SecretData{}, fmt.Errorf("unmarshal cipher envelope: %w", err)
	}
	if envelope.Version != envelopeVersion {
		return SecretData{}, fmt.Errorf("unsupported envelope version %d", envelope.Version)
	}
	if envelope.KDF != envelopeKDF || envelope.Iterations <= 0 {
		return SecretData{}, errors.New("unsupported key derivation settings")
	}

	salt, err := base64.StdEncoding.DecodeString(envelope.Salt)
	if err != nil {
		return SecretData{}, fmt.Errorf("decode salt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return SecretData{}, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return SecretData{}, fmt.Errorf("decode ciphertext: %w", err)
	}

	key, err := deriveKey(masterPassword, salt, envelope.Iterations)
	if err != nil {
		return SecretData{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return SecretData{}, fmt.Errorf("create aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return SecretData{}, fmt.Errorf("create gcm cipher: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return SecretData{}, errors.New("invalid nonce size")
	}

	rawPlaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return SecretData{}, fmt.Errorf("decrypt payload: %w", err)
	}

	var plaintext SecretData
	if err := json.Unmarshal(rawPlaintext, &plaintext); err != nil {
		return SecretData{}, fmt.Errorf("unmarshal plaintext: %w", err)
	}
	return plaintext, nil
}

// NewEncryptedRecord validates and encrypts data as a Record.
func NewEncryptedRecord(masterPassword, id string, dataType DataType, data SecretData, updatedAt time.Time) (Record, error) {
	if id == "" {
		generatedID, err := NewRecordID()
		if err != nil {
			return Record{}, err
		}
		id = generatedID
	}
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	if err := data.Validate(dataType); err != nil {
		return Record{}, err
	}

	payload, err := Seal(masterPassword, data)
	if err != nil {
		return Record{}, err
	}

	return Record{
		ID:        id,
		Type:      dataType,
		Payload:   payload,
		UpdatedAt: updatedAt.UTC(),
	}, nil
}

// OpenRecord decrypts record payload into SecretData.
func OpenRecord(masterPassword string, record Record) (SecretData, error) {
	if record.Deleted {
		return SecretData{}, errors.New("deleted record has no plaintext payload")
	}
	return Open(masterPassword, record.Payload)
}

func deriveKey(masterPassword string, salt []byte, iterations int) ([]byte, error) {
	key, err := pbkdf2.Key(sha256.New, masterPassword, salt, iterations, envelopeDerivedBytes)
	if err != nil {
		return nil, fmt.Errorf("derive encryption key: %w", err)
	}
	return key, nil
}
