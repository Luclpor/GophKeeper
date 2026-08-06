package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Luclpor/GophKeeper/internal/vault"
)

// ErrInvalidInput is returned when a request cannot be accepted by the store.
var ErrInvalidInput = errors.New("invalid input")

// ErrNotFound is returned when a user or record does not exist.
var ErrNotFound = errors.New("not found")

// ErrUserExists is returned when a username is already registered.
var ErrUserExists = errors.New("user already exists")

// Store describes the persistent operations required by the HTTP API.
type Store interface {
	// CreateUser stores a username and password hash.
	CreateUser(ctx context.Context, username, passwordHash string) error
	// PasswordHash returns the password hash for username.
	PasswordHash(ctx context.Context, username string) (string, error)
	// UpsertRecord stores record when it wins conflict resolution.
	UpsertRecord(ctx context.Context, username string, record vault.Record) (vault.Record, error)
	// Records returns visible records for username.
	Records(ctx context.Context, username string) ([]vault.Record, error)
	// Record returns one visible record for username.
	Record(ctx context.Context, username, id string) (vault.Record, error)
	// DeleteRecord stores a tombstone for one record.
	DeleteRecord(ctx context.Context, username, id string, deletedAt time.Time) (vault.Record, error)
	// SyncRecords merges client records into the user's server state.
	SyncRecords(ctx context.Context, username string, records []vault.Record) ([]vault.Record, error)
}

// User is a registered GophKeeper account.
type User struct {
	// Username is the user's login name.
	Username string `json:"username"`
	// PasswordHash is the PBKDF2-SHA256 password hash.
	PasswordHash string `json:"password_hash"`
	// CreatedAt is the UTC registration timestamp.
	CreatedAt time.Time `json:"created_at"`
}

type fileData struct {
	Users   map[string]User                    `json:"users"`
	Records map[string]map[string]vault.Record `json:"records"`
}

// FileStore persists users and encrypted records in one JSON file.
type FileStore struct {
	path string
	mu   sync.Mutex
	data fileData
}

// NewFileStore loads or creates a FileStore at path. When path is empty, the
// store is kept in memory only.
func NewFileStore(path string) (*FileStore, error) {
	store := &FileStore{path: path}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

// CreateUser stores a new user and its password hash.
func (s *FileStore) CreateUser(_ context.Context, username, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	username = strings.TrimSpace(username)
	if username == "" || passwordHash == "" {
		return fmt.Errorf("%w: username and password hash are required", ErrInvalidInput)
	}
	if _, ok := s.data.Users[username]; ok {
		return ErrUserExists
	}

	s.data.Users[username] = User{
		Username:     username,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now().UTC(),
	}
	s.ensureRecordMap(username)
	return s.saveLocked()
}

// PasswordHash returns the stored password hash for username.
func (s *FileStore) PasswordHash(_ context.Context, username string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.data.Users[username]
	if !ok {
		return "", ErrNotFound
	}
	return user.PasswordHash, nil
}

// UpsertRecord stores record when it is newer than the current server copy.
func (s *FileStore) UpsertRecord(_ context.Context, username string, record vault.Record) (vault.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.data.Users[username]; !ok {
		return vault.Record{}, ErrNotFound
	}
	record = normalizeRecord(record)
	if err := record.Validate(); err != nil {
		return vault.Record{}, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	records := s.ensureRecordMap(username)
	if current, ok := records[record.ID]; ok && current.UpdatedAt.After(record.UpdatedAt) {
		return current, nil
	}
	records[record.ID] = record
	if err := s.saveLocked(); err != nil {
		return vault.Record{}, err
	}
	return record, nil
}

// Records returns non-deleted records owned by username.
func (s *FileStore) Records(_ context.Context, username string) ([]vault.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.data.Users[username]; !ok {
		return nil, ErrNotFound
	}

	var records []vault.Record
	for _, record := range s.ensureRecordMap(username) {
		if !record.Deleted {
			records = append(records, record)
		}
	}
	sortRecords(records)
	return records, nil
}

// Record returns one non-deleted record owned by username.
func (s *FileStore) Record(_ context.Context, username, id string) (vault.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.data.Users[username]; !ok {
		return vault.Record{}, ErrNotFound
	}
	record, ok := s.ensureRecordMap(username)[id]
	if !ok || record.Deleted {
		return vault.Record{}, ErrNotFound
	}
	return record, nil
}

// DeleteRecord stores a tombstone for id and returns it.
func (s *FileStore) DeleteRecord(_ context.Context, username, id string, deletedAt time.Time) (vault.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.data.Users[username]; !ok {
		return vault.Record{}, ErrNotFound
	}
	records := s.ensureRecordMap(username)
	current, ok := records[id]
	if !ok || current.Deleted {
		return vault.Record{}, ErrNotFound
	}
	if deletedAt.IsZero() {
		deletedAt = time.Now().UTC()
	}

	tombstone := vault.Record{
		ID:        current.ID,
		Type:      current.Type,
		UpdatedAt: deletedAt.UTC(),
		Deleted:   true,
	}
	records[id] = tombstone
	if err := s.saveLocked(); err != nil {
		return vault.Record{}, err
	}
	return tombstone, nil
}

// SyncRecords merges client records and returns the full server state,
// including tombstones, so clients can converge.
func (s *FileStore) SyncRecords(_ context.Context, username string, incoming []vault.Record) ([]vault.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.data.Users[username]; !ok {
		return nil, ErrNotFound
	}
	records := s.ensureRecordMap(username)
	for _, record := range incoming {
		record = normalizeRecord(record)
		if err := record.Validate(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
		}
		current, ok := records[record.ID]
		if !ok || record.UpdatedAt.After(current.UpdatedAt) {
			records[record.ID] = record
		}
	}
	if err := s.saveLocked(); err != nil {
		return nil, err
	}

	merged := make([]vault.Record, 0, len(records))
	for _, record := range records {
		merged = append(merged, record)
	}
	sortRecords(merged)
	return merged, nil
}

func (s *FileStore) load() error {
	s.data = fileData{
		Users:   make(map[string]User),
		Records: make(map[string]map[string]vault.Record),
	}
	if s.path == "" {
		return nil
	}

	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read store file: %w", err)
	}
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return fmt.Errorf("unmarshal store file: %w", err)
	}
	if s.data.Users == nil {
		s.data.Users = make(map[string]User)
	}
	if s.data.Records == nil {
		s.data.Records = make(map[string]map[string]vault.Record)
	}
	return nil
}

func (s *FileStore) saveLocked() error {
	if s.path == "" {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("create store directory: %w", err)
	}

	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal store file: %w", err)
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write store file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("replace store file: %w", err)
	}
	return nil
}

func (s *FileStore) ensureRecordMap(username string) map[string]vault.Record {
	if s.data.Records == nil {
		s.data.Records = make(map[string]map[string]vault.Record)
	}
	if s.data.Records[username] == nil {
		s.data.Records[username] = make(map[string]vault.Record)
	}
	return s.data.Records[username]
}

func normalizeRecord(record vault.Record) vault.Record {
	record.ID = strings.TrimSpace(record.ID)
	if record.UpdatedAt.IsZero() {
		record.UpdatedAt = time.Now().UTC()
	} else {
		record.UpdatedAt = record.UpdatedAt.UTC()
	}
	return record
}

func sortRecords(records []vault.Record) {
	sort.Slice(records, func(i, j int) bool {
		return records[i].ID < records[j].ID
	})
}
