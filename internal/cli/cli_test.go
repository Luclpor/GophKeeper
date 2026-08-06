package cli

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Luclpor/GophKeeper/internal/auth"
	"github.com/Luclpor/GophKeeper/internal/server"
	"github.com/Luclpor/GophKeeper/internal/vault"
)

type repeatingReader byte

func (r repeatingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

func TestRunVersionAndUnknownCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "GophKeeper version=") {
		t.Fatalf("version output = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"unknown"}, &stdout, &stderr); code != 2 {
		t.Fatalf("unknown exit code = %d, want 2", code)
	}
}

func TestRunServerRejectsPartialTLSConfig(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"server",
		"--addr", "127.0.0.1:0",
		"--data", filepath.Join(t.TempDir(), "server.json"),
		"--tls-cert", "cert.pem",
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("server exit code = %d, want 2; stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "both --tls-cert and --tls-key") {
		t.Fatalf("server stderr = %q", stderr.String())
	}
}

func TestCLIClientFlow(t *testing.T) {
	apiServer := startCLITestServer(t)

	token := runRegisterForToken(t, apiServer.URL)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"login", "--server", apiServer.URL, "--user", "alice", "--password", "password"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("login exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"token":`) {
		t.Fatalf("login output = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{
		"add",
		"--server", apiServer.URL,
		"--token", token,
		"--master", "master",
		"--id", "record-1",
		"--type", string(vault.DataTypeText),
		"--name", "note",
		"--field", "text=hello",
		"--meta", "owner=alice",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("add exit code = %d, stderr = %q", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"list", "--server", apiServer.URL, "--token", token, "--master", "master"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("list exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"name": "note"`) {
		t.Fatalf("list output = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"get", "--server", apiServer.URL, "--token", token, "--master", "master", "--id", "record-1"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("get exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"text": "hello"`) {
		t.Fatalf("get output = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"delete", "--server", apiServer.URL, "--token", token, "--id", "record-1"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("delete exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"deleted": true`) {
		t.Fatalf("delete output = %q", stdout.String())
	}
}

func TestCLISync(t *testing.T) {
	apiServer := startCLITestServer(t)
	token := runRegisterForToken(t, apiServer.URL)

	record, err := vault.NewEncryptedRecord("master", "record-2", vault.DataTypeText, vault.SecretData{
		Name:   "synced",
		Fields: map[string]string{"text": "value"},
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("NewEncryptedRecord returned error: %v", err)
	}

	filePath := filepath.Join(t.TempDir(), "records.json")
	raw, err := json.Marshal([]vault.Record{record})
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if err := writeLocalRecords(filePath, nil); err != nil {
		t.Fatalf("writeLocalRecords returned error: %v", err)
	}
	if err := os.WriteFile(filePath, raw, 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"sync", "--server", apiServer.URL, "--token", token, "--file", filePath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("sync exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"records": 1`) {
		t.Fatalf("sync output = %q", stdout.String())
	}
}

func startCLITestServer(t *testing.T) *httptest.Server {
	t.Helper()
	store, err := server.NewFileStore("")
	if err != nil {
		t.Fatalf("NewFileStore returned error: %v", err)
	}
	handler, err := server.NewRouter(server.Config{
		Store:       store,
		TokenSecret: bytes.Repeat([]byte{7}, 32),
		TokenTTL:    time.Hour,
		PasswordHasher: auth.PasswordHasher{
			Rand:       repeatingReader(1),
			Iterations: 2,
			SaltSize:   16,
			KeySize:    32,
		},
	})
	if err != nil {
		t.Fatalf("NewRouter returned error: %v", err)
	}
	apiServer := httptest.NewServer(handler)
	t.Cleanup(apiServer.Close)
	return apiServer
}

func runRegisterForToken(t *testing.T, serverURL string) string {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"register", "--server", serverURL, "--user", "alice", "--password", "password"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("register exit code = %d, stderr = %q", code, stderr.String())
	}

	var payload map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal register output: %v", err)
	}
	if payload["token"] == "" {
		t.Fatal("register returned empty token")
	}
	return payload["token"]
}
