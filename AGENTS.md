# rspamd-iscan - Agent Instructions

## Project Overview
Go daemon that monitors IMAP mailboxes via IDLE, sends new mail to Rspamd for spam analysis/training, and moves messages to appropriate mailboxes (Inbox/Spam/Backup). Decouples spam filtering from mail delivery.

## Key Commands

```bash
# Build (static binary, CGO disabled)
make build           # or: CGO_ENABLED=0 go build -o rspamd-iscan main.go

# Lint (golangci-lint)
make check           # or: golangci-lint run ./...

# Test (race detector, 60s timeout)
make test            # or: go test -race -timeout=60s ./...

# Run single test
go test -race -timeout=60s -run TestRun ./internal/iscan

# Run with config
rspamd-iscan --cfg-file /etc/rspamd-iscan/config.toml
rspamd-iscan --once --cfg-file config.toml       # process once and exit
rspamd-iscan --dry-run --cfg-file config.toml    # simulate, implies --once
rspamd-iscan --version                           # print version
```

## Architecture & Package Boundaries

| Package | Responsibility |
|---------|----------------|
| `main.go` | Entry point, flags, signal handling, retry loop |
| `internal/config` | TOML config + credentials directory (systemd compatible) |
| `internal/iscan` | Core logic: scan, learn ham/spam, monitor loop |
| `internal/imapclt` | IMAP client (go-imap/v2), IDLE monitoring, move/upload |
| `internal/rspamc` | Rspamd HTTP client (check/spam/learn) |
| `internal/retry` | Retry runner with exponential backoff |
| `internal/neterr` | Retryable error classification |
| `internal/mail` | Header manipulation (add/replace) |
| `internal/log` | slog wrapper, test logger |
| `internal/testutils` | Test fixtures: in-memory IMAP server, mail samples, assertions |

## Testing Conventions

- **Integration-style tests**: Start real in-memory IMAP server (`imapmemserver`)
- Test mail fixtures in `internal/testutils/mail/testdata/`
- Custom `assert` package in `internal/testutils/assert/`
- Test server setup in `internal/testutils/imapserver/server.go`
- Tests connect with retry loop (server startup async)
- `t.Cleanup` used for client shutdown

## Configuration

- Default config path: `/etc/rspamd-iscan/config.toml` (override with `--cfg-file`)
- Credentials directory: `--credentials-directory` or `$CREDENTIALS_DIRECTORY`
- Credential files: `RspamdURL`, `RspamdPassword`, `ImapUser`, `ImapPassword`
- Required mailboxes: `ScanMailbox`, `InboxMailbox`, `SpamMailbox`, `HamMailbox`, `UndetectedMailbox`, `BackupMailbox`
- `SpamThreshold` (float32) determines spam vs ham classification

## Important Flags

| Flag | Effect |
|------|--------|
| `--once` | Process all mailboxes once, exit |
| `--dry-run` | Simulate IMAP modifications, implies `--once` |
| `--credentials-directory` | Load secrets from files (systemd compatible) |
| `--cfg-file` | Config file path (default: `/etc/rspamd-iscan/config.toml`) |

## Development Gotchas

- **Vendored dependencies**: `vendor/` directory checked in; `go build` uses it automatically
- **No CI workflows**: No `.github/workflows/` - run `make check test` locally before push
- **No timestamp in logs**: `configureLogger` strips timestamps (assumes journald/syslog)
- **IMAP monitoring blocks**: While `Monitor()` runs, other IMAP ops block; must call stop function first
- **Retry logic**: `retry.Runner` in main wraps `monitor()` with exponential backoff (3s, 30s, 1m, 3m)
- **Version info**: Set via `-ldflags` at build time (`version`, `commit` vars in main.go)

## Mail Flow

```
New mail arrives in ScanMailbox
       │
       ▼
Sent to Rspamd for scanning (HTTP)
       │
       ├── Score >= SpamThreshold ──▶ Move to SpamMailbox
       │
       └── Score < SpamThreshold ──▶ Move to InboxMailbox
             │
             ▼
    Original moved to BackupMailbox
    (headers added: X-rspamd-iscan-Score, X-rspamd-iscan-Symbol-*)

Periodic (30min): HamMailbox ──learn ham──▶ InboxMailbox
Periodic (30min): UndetectedMailbox ──learn spam──▶ SpamMailbox
```

## Required IMAP Server Setup

- Port 993 → implicit TLS; other ports → STARTTLS (falls back to insecure if `AllowInsecure=true`)
- Mailboxes must pre-exist (created by test server, but not by production code)

## Building with Version Info

```bash
go build -ldflags "-X main.version=v1.2.3 -X main.commit=$(git rev-parse HEAD)" -o rspamd-iscan main.go
```