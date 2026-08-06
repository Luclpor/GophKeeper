package cli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Luclpor/GophKeeper/internal/client"
	"github.com/Luclpor/GophKeeper/internal/server"
	"github.com/Luclpor/GophKeeper/internal/vault"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Version is the semantic version printed by the version command.
var Version = "dev"

// BuildDate is the build timestamp printed by the version command.
var BuildDate = "unknown"

// Run executes the CLI with args and returns a process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	logger := newCLILogger(stderr)
	defer func() {
		_ = logger.Sync()
	}()

	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "server":
		return runServer(args[1:], stdout, stderr, logger)
	case "version":
		return runVersion(stdout)
	case "register":
		return runRegister(args[1:], stdout, stderr, logger)
	case "login":
		return runLogin(args[1:], stdout, stderr, logger)
	case "add":
		return runAdd(args[1:], stdout, stderr, logger)
	case "list":
		return runList(args[1:], stdout, stderr, logger)
	case "get":
		return runGet(args[1:], stdout, stderr, logger)
	case "delete":
		return runDelete(args[1:], stdout, stderr, logger)
	case "sync":
		return runSync(args[1:], stdout, stderr, logger)
	default:
		logger.Error("unknown command", zap.String("command", args[0]))
		printUsage(stderr)
		return 2
	}
}

func runVersion(stdout io.Writer) int {
	fmt.Fprintf(stdout, "GophKeeper version=%s build_date=%s\n", Version, BuildDate)
	return 0
}

func runServer(args []string, stdout, stderr io.Writer, logger *zap.Logger) int {
	flags := flag.NewFlagSet("server", flag.ContinueOnError)
	flags.SetOutput(stderr)

	addr := flags.String("addr", ":8080", "HTTP listen address")
	dataPath := flags.String("data", "gophkeeper-server.json", "server JSON storage path")
	tokenSecret := flags.String("token-secret", "", "token HMAC secret; generated for the process when empty")
	tokenTTL := flags.Duration("token-ttl", 24*time.Hour, "bearer token ttl")
	tlsCert := flags.String("tls-cert", "", "TLS certificate path")
	tlsKey := flags.String("tls-key", "", "TLS key path")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	store, err := server.NewFileStore(*dataPath)
	if err != nil {
		logger.Error("create server store", zap.Error(err))
		return 1
	}

	secret := []byte(*tokenSecret)
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			logger.Error("generate token secret", zap.Error(err))
			return 1
		}
		logger.Warn("token secret generated for this server process")
	}

	handler, err := server.NewRouter(server.Config{
		Store:       store,
		TokenSecret: secret,
		TokenTTL:    *tokenTTL,
		Logger:      logger,
	})
	if err != nil {
		logger.Error("create server router", zap.Error(err))
		return 1
	}

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	logger.Info("gophkeeper server listening", zap.String("addr", *addr), zap.String("data", *dataPath))
	if *tlsCert != "" || *tlsKey != "" {
		if *tlsCert == "" || *tlsKey == "" {
			logger.Error("invalid tls configuration", zap.String("error", "both --tls-cert and --tls-key are required for TLS"))
			return 2
		}
		err = httpServer.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		err = httpServer.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server stopped with error", zap.Error(err))
		return 1
	}
	return 0
}

func runRegister(args []string, stdout, stderr io.Writer, logger *zap.Logger) int {
	flags := flag.NewFlagSet("register", flag.ContinueOnError)
	flags.SetOutput(stderr)

	serverURL, username, password := commonAuthFlags(flags)
	if err := flags.Parse(args); err != nil {
		return 2
	}

	api, err := newClient(*serverURL, "")
	if err != nil {
		logger.Error("create api client", zap.Error(err))
		return 1
	}
	token, err := api.Register(context.Background(), *username, *password)
	if err != nil {
		logger.Error("register user", zap.Error(err))
		return 1
	}
	return printJSON(stdout, logger, map[string]string{"username": *username, "token": token})
}

func runLogin(args []string, stdout, stderr io.Writer, logger *zap.Logger) int {
	flags := flag.NewFlagSet("login", flag.ContinueOnError)
	flags.SetOutput(stderr)

	serverURL, username, password := commonAuthFlags(flags)
	if err := flags.Parse(args); err != nil {
		return 2
	}

	api, err := newClient(*serverURL, "")
	if err != nil {
		logger.Error("create api client", zap.Error(err))
		return 1
	}
	token, err := api.Login(context.Background(), *username, *password)
	if err != nil {
		logger.Error("login user", zap.Error(err))
		return 1
	}
	return printJSON(stdout, logger, map[string]string{"username": *username, "token": token})
}

func runAdd(args []string, stdout, stderr io.Writer, logger *zap.Logger) int {
	flags := flag.NewFlagSet("add", flag.ContinueOnError)
	flags.SetOutput(stderr)

	serverURL, token := commonClientFlags(flags)
	master := flags.String("master", "", "client-side encryption password")
	id := flags.String("id", "", "record id; generated when empty")
	dataType := flags.String("type", string(vault.DataTypeText), "record type")
	name := flags.String("name", "", "record name")
	fieldsJSON := flags.String("fields-json", "", "secret fields as JSON object")
	metadataJSON := flags.String("metadata-json", "", "metadata as JSON object")
	var fields keyValues
	var metadata keyValues
	flags.Var(&fields, "field", "secret field as key=value; repeatable")
	flags.Var(&metadata, "meta", "metadata as key=value; repeatable")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	fieldMap, err := mergeMaps(*fieldsJSON, map[string]string(fields))
	if err != nil {
		logger.Error("parse secret fields", zap.Error(err))
		return 2
	}
	metadataMap, err := mergeMaps(*metadataJSON, map[string]string(metadata))
	if err != nil {
		logger.Error("parse secret metadata", zap.Error(err))
		return 2
	}

	record, err := vault.NewEncryptedRecord(*master, *id, vault.DataType(*dataType), vault.SecretData{
		Name:     *name,
		Metadata: metadataMap,
		Fields:   fieldMap,
	}, time.Now().UTC())
	if err != nil {
		logger.Error("encrypt record", zap.Error(err))
		return 1
	}

	api, err := newClient(*serverURL, *token)
	if err != nil {
		logger.Error("create api client", zap.Error(err))
		return 1
	}
	saved, err := api.PutRecord(context.Background(), record)
	if err != nil {
		logger.Error("save record", zap.Error(err))
		return 1
	}

	return printJSON(stdout, logger, map[string]string{
		"id":         saved.ID,
		"type":       string(saved.Type),
		"updated_at": saved.UpdatedAt.Format(time.RFC3339),
	})
}

func runList(args []string, stdout, stderr io.Writer, logger *zap.Logger) int {
	flags := flag.NewFlagSet("list", flag.ContinueOnError)
	flags.SetOutput(stderr)

	serverURL, token := commonClientFlags(flags)
	master := flags.String("master", "", "client-side encryption password")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	api, err := newClient(*serverURL, *token)
	if err != nil {
		logger.Error("create api client", zap.Error(err))
		return 1
	}
	records, err := api.ListRecords(context.Background())
	if err != nil {
		logger.Error("list records", zap.Error(err))
		return 1
	}

	output := make([]recordSummary, 0, len(records))
	for _, record := range records {
		secret, err := vault.OpenRecord(*master, record)
		if err != nil {
			logger.Error("decrypt record", zap.String("record_id", record.ID), zap.Error(err))
			return 1
		}
		output = append(output, recordSummary{
			ID:        record.ID,
			Type:      record.Type,
			Name:      secret.Name,
			Metadata:  secret.Metadata,
			UpdatedAt: record.UpdatedAt,
		})
	}
	return printJSON(stdout, logger, output)
}

func runGet(args []string, stdout, stderr io.Writer, logger *zap.Logger) int {
	flags := flag.NewFlagSet("get", flag.ContinueOnError)
	flags.SetOutput(stderr)

	serverURL, token := commonClientFlags(flags)
	master := flags.String("master", "", "client-side encryption password")
	id := flags.String("id", "", "record id")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	api, err := newClient(*serverURL, *token)
	if err != nil {
		logger.Error("create api client", zap.Error(err))
		return 1
	}
	record, err := api.GetRecord(context.Background(), *id)
	if err != nil {
		logger.Error("get record", zap.String("record_id", *id), zap.Error(err))
		return 1
	}
	secret, err := vault.OpenRecord(*master, record)
	if err != nil {
		logger.Error("decrypt record", zap.String("record_id", record.ID), zap.Error(err))
		return 1
	}
	return printJSON(stdout, logger, struct {
		ID        string           `json:"id"`
		Type      vault.DataType   `json:"type"`
		UpdatedAt time.Time        `json:"updated_at"`
		Secret    vault.SecretData `json:"secret"`
	}{
		ID:        record.ID,
		Type:      record.Type,
		UpdatedAt: record.UpdatedAt,
		Secret:    secret,
	})
}

func runDelete(args []string, stdout, stderr io.Writer, logger *zap.Logger) int {
	flags := flag.NewFlagSet("delete", flag.ContinueOnError)
	flags.SetOutput(stderr)

	serverURL, token := commonClientFlags(flags)
	id := flags.String("id", "", "record id")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	api, err := newClient(*serverURL, *token)
	if err != nil {
		logger.Error("create api client", zap.Error(err))
		return 1
	}
	tombstone, err := api.DeleteRecord(context.Background(), *id)
	if err != nil {
		logger.Error("delete record", zap.String("record_id", *id), zap.Error(err))
		return 1
	}
	return printJSON(stdout, logger, tombstone)
}

func runSync(args []string, stdout, stderr io.Writer, logger *zap.Logger) int {
	flags := flag.NewFlagSet("sync", flag.ContinueOnError)
	flags.SetOutput(stderr)

	serverURL, token := commonClientFlags(flags)
	filePath := flags.String("file", "gophkeeper-client.json", "local encrypted record file")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	records, err := readLocalRecords(*filePath)
	if err != nil {
		logger.Error("read local records", zap.String("file", *filePath), zap.Error(err))
		return 1
	}
	api, err := newClient(*serverURL, *token)
	if err != nil {
		logger.Error("create api client", zap.Error(err))
		return 1
	}
	merged, err := api.SyncRecords(context.Background(), records)
	if err != nil {
		logger.Error("sync records", zap.Error(err))
		return 1
	}
	if err := writeLocalRecords(*filePath, merged); err != nil {
		logger.Error("write local records", zap.String("file", *filePath), zap.Error(err))
		return 1
	}
	return printJSON(stdout, logger, map[string]int{"records": len(merged)})
}

type recordSummary struct {
	ID        string            `json:"id"`
	Type      vault.DataType    `json:"type"`
	Name      string            `json:"name"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	UpdatedAt time.Time         `json:"updated_at"`
}

type keyValues map[string]string

func (v *keyValues) String() string {
	if v == nil || *v == nil {
		return ""
	}
	raw, _ := json.Marshal(map[string]string(*v))
	return string(raw)
}

func (v *keyValues) Set(value string) error {
	key, fieldValue, ok := strings.Cut(value, "=")
	if !ok || strings.TrimSpace(key) == "" {
		return fmt.Errorf("expected key=value, got %q", value)
	}
	if *v == nil {
		*v = make(map[string]string)
	}
	(*v)[strings.TrimSpace(key)] = fieldValue
	return nil
}

func commonAuthFlags(flags *flag.FlagSet) (*string, *string, *string) {
	serverURL := flags.String("server", "http://localhost:8080", "GophKeeper server URL")
	username := flags.String("user", "", "username")
	password := flags.String("password", "", "password")
	return serverURL, username, password
}

func commonClientFlags(flags *flag.FlagSet) (*string, *string) {
	serverURL := flags.String("server", "http://localhost:8080", "GophKeeper server URL")
	token := flags.String("token", "", "bearer token")
	return serverURL, token
}

func newClient(serverURL, token string) (*client.Client, error) {
	return client.New(client.Config{
		BaseURL: serverURL,
		Token:   token,
	})
}

func mergeMaps(rawJSON string, values map[string]string) (map[string]string, error) {
	merged := make(map[string]string)
	if strings.TrimSpace(rawJSON) != "" {
		if err := json.Unmarshal([]byte(rawJSON), &merged); err != nil {
			return nil, fmt.Errorf("parse json object: %w", err)
		}
	}
	for key, value := range values {
		merged[key] = value
	}
	return merged, nil
}

func readLocalRecords(path string) ([]vault.Record, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read local records: %w", err)
	}
	if len(raw) == 0 {
		return nil, nil
	}

	var records []vault.Record
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, fmt.Errorf("decode local records: %w", err)
	}
	return records, nil
}

func writeLocalRecords(path string, records []vault.Record) error {
	raw, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("encode local records: %w", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write local records: %w", err)
	}
	return nil
}

func newCLILogger(stderr io.Writer) *zap.Logger {
	if stderr == nil {
		stderr = io.Discard
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(stderr),
		zapcore.InfoLevel,
	)
	return zap.New(core)
}

func printJSON(stdout io.Writer, logger *zap.Logger, value any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		logger.Error("write json output", zap.Error(err))
		return 1
	}
	return 0
}

func printUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: gophkeeper <server|version|register|login|add|list|get|delete|sync> [flags]")
	fmt.Fprintln(stderr, "")
	fmt.Fprintln(stderr, "record fields:")
	fmt.Fprintln(stderr, "  login_password: --field login=alice --field password=secret")
	fmt.Fprintln(stderr, "  text:           --field text=value")
	fmt.Fprintf(stderr, "  binary:         --field content_base64=%s\n", base64.StdEncoding.EncodeToString([]byte("bytes")))
	fmt.Fprintln(stderr, "  bank_card:      --field number=4111111111111111 --field holder=ALICE --field expires=12/30")
	fmt.Fprintln(stderr, "  otp:            --field secret=BASE32SECRET")
}
