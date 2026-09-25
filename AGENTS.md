# Agent notes

## Build and verification

- Use the Go 1.26 toolchain: `go.mod` declares `1.26.5`, and CI installs Go `1.26`.
- The default `make` target is the full gate (`build` → `check` → `test`):
  - `make build` runs `CGO_ENABLED=0 go build -o rspamd-iscan main.go`; the root binary is ignored by Git.
  - `make check` runs `golangci-lint run ./...`. CI uses `golangci-lint` v2.12; `.golangci.yml` configures `gofumpt` and `goimports` as formatters.
  - `make test` runs `go test -race -timeout=60s ./...`.
- For a focused test, keep the race and timeout checks, for example: `go test -race -timeout=60s ./internal/iscan -run '^TestRun$'`.
- Dependencies are checked into `vendor/`; dependency changes must keep that tree synchronized with `go.mod` and `go.sum`.
- Releases are driven by `.goreleaser.yaml` (CGO disabled, Linux/amd64, version/commit linker flags); there is no release target in the `Makefile`.

## Runtime shape

- `main.go` is the only executable entrypoint. It parses flags, loads TOML, optionally overlays credential files, and wires the Rspamd and IMAP adapters into `iscan.Client`.
- Runtime config is TOML (default `/etc/rspamd-iscan/config.toml`); timeout settings are expressed in seconds (`RspamdTimeoutSeconds`, `IMAPOperationTimeoutSeconds`, `IMAPIdleTimeoutSeconds`, `ShutdownTimeoutSeconds`) and are documented in `README.md`. `--credentials-directory` defaults to `CREDENTIALS_DIRECTORY` and overlays the four credential fields documented there. `TempDir` must already exist.
- `iscan.Client` owns orchestration. `RunOnce` processes `HamMailbox` (learn ham), then `UndetectedMailbox` (learn spam), then `ScanMailbox` (scan).
- `Monitor` performs an initial `RunOnce`, then uses IMAP IDLE on `ScanMailbox`; its default 30-minute timer repeats scan, ham-learning, and spam-learning passes, while `IMAPIdleTimeoutSeconds` force-restarts a quiet IDLE connection.
- Scanned mail is downloaded to `TempDir`, sent to Rspamd, modified with scan headers, and then the original is moved to `BackupMailbox` before the modified copy is uploaded to `InboxMailbox` or `SpamMailbox` (`score >= SpamThreshold` selects Spam). Preserve that ordering: a failed upload leaves the original in Backup.
- `imapclt` owns IMAP/TLS: port `993` or `imaps` uses implicit TLS; other ports use STARTTLS, with no plaintext fallback in the daemon. `rspamc` wraps `/checkv2`, `/learnham`, and `/learnspam`; `mail` contains the RFC 2822 file/header rewriting logic.
- `--dry-run` implies `--once` and uses `imapclt.DryClient`, so it still connects to and reads the real IMAP server and sends Rspamd requests, but skips mutating IMAP operations.

## Testing gotchas

- IMAP integration tests need no external service: `internal/testutils/imapserver` starts an in-process server on the fixed address `localhost:10143` (credentials `user`/`none`); mail fixtures are under `internal/testutils/mail/testdata/`.
- `internal/imapclt` and `internal/iscan` tests share that fixed port. Do not run those package test processes concurrently; run them separately or use `go test -race -p 1 -timeout=60s ./...` for a reliable full run.
- The retry tests use Go's `testing/synctest`, so keep the Go 1.26 baseline when changing timing tests.
- The README's “tests are missing” status is stale; `Makefile`, CI, and the current `*_test.go` files are the source of truth.
