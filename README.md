# GophKeeper

GophKeeper is a client-server password vault implemented in Go.

## Features

- User registration and password authentication.
- Bearer-token authorization.
- Client-side AES-GCM encryption of private payloads.
- Encrypted storage for login/password pairs, text, binary data, bank cards, and OTP secrets.
- Metadata on every record.
- Last-write-wins synchronization endpoint for multiple authorized clients.
- Cross-platform CLI entry point for Windows, Linux, and macOS.
- Build metadata through the `version` command.

## Quick Start

Install dependencies and run tests:

```sh
go mod tidy
go test ./...
```

Run the server:

```sh
go run ./cmd/gophkeeper server --addr :8080 --data ./gophkeeper-server.json
```

The server writes structured Zap logs to stderr, including one log entry for
each HTTP request.

Register and save the returned token:

```sh
go run ./cmd/gophkeeper register --server http://localhost:8080 --user alice --password passw0rd
```

Add a login/password secret:

```sh
go run ./cmd/gophkeeper add \
  --server http://localhost:8080 \
  --token "$TOKEN" \
  --master "$MASTER_PASSWORD" \
  --type login_password \
  --name github \
  --field login=alice \
  --field password=secret \
  --meta site=github.com
```

List records:

```sh
go run ./cmd/gophkeeper list --server http://localhost:8080 --token "$TOKEN" --master "$MASTER_PASSWORD"
```

Build a client binary with version metadata:

```sh
go build \
  -ldflags "-X github.com/Luclpor/GophKeeper/internal/cli.Version=1.0.0 -X github.com/Luclpor/GophKeeper/internal/cli.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o gophkeeper ./cmd/gophkeeper
```

Cross-compilation uses standard Go environment variables:

```sh
GOOS=windows GOARCH=amd64 go build -o gophkeeper.exe ./cmd/gophkeeper
GOOS=linux GOARCH=amd64 go build -o gophkeeper-linux ./cmd/gophkeeper
GOOS=darwin GOARCH=arm64 go build -o gophkeeper-darwin ./cmd/gophkeeper
```

## API

The HTTP API is JSON-based and documented in [docs/openapi.yaml](docs/openapi.yaml).
