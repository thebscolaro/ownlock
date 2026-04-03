# Changelog

All notable changes to ownlock will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.6] - 2026-04-03

### Added

- **Security testing**: [SECURITY_TESTING.md](SECURITY_TESTING.md) documents automated checks, OWASP-oriented mapping, and scope vs pen test / red team.
- **CI**: `security` job runs Bandit (`-c pyproject.toml`) and pip-audit; test job installs `ownlock[mcp]`.
- **Tests**: [tests/test_security.py](tests/test_security.py) for path traversal on relative paths, crypto/tampering, invalid `vault()` keys, subprocess discipline (no shell).
- **Smoke tests**: [tests/test_smoke.py](tests/test_smoke.py) — subprocess `python -m ownlock` with isolated `HOME` (global get, project list, `run` env injection, MCP version). Marked `@pytest.mark.smoke`.

### Changed

- **Dependencies**: `cryptography>=46.0.6`, `pygments>=2.20` (supply-chain / audit hygiene).

## [0.1.5] - 2026-04-03

### Added

- **MCP** (optional): `pip install 'ownlock[mcp]'`, then run `ownlock-mcp` (stdio). Tools delegate to the `ownlock` CLI subprocess only—no vault decryption in the MCP process. Exposes `ownlock_run` (wraps `ownlock run`), `ownlock_list_secret_names` (wraps `ownlock list`), and `ownlock_version`. Does not expose `get` or `export`.
- **`python -m ownlock`**: same as the `ownlock` console script.

## [0.1.0] - 2026-02-17

### Added

- **CLI**: `ownlock` — lightweight secrets manager
  - `init` — create global or project vault
  - `set` / `get` / `list` / `delete` — manage secrets
  - `run` — resolve `.env`, inject secrets, redact stdout
  - `export` — print resolved KEY=VALUE pairs
  - `import` — bulk import from plaintext `.env`
  - `scan` — find leaked secrets in files
- **Encryption**: AES-256-GCM, PBKDF2-HMAC-SHA256 (200K iterations)
- **Storage**: SQLite vault at `~/.ownlock/vault.db` (global) or `.ownlock/vault.db` (project)
- **Keyring**: macOS Keychain / GNOME Keyring for passphrase
- **`.env` format**: `vault("key-name")` references with optional `env=` and `project=true`
- **Redaction**: Automatically redact secret values in subprocess stdout/stderr
- **Hardening**:
  - Path validation (env files and scan dir must stay under cwd when relative)
  - Secret name validation (alphanumeric, hyphen, underscore only)
  - Scan limits (max 10K files, depth 20 by default)
  - Clean error messages (no tracebacks for expected errors)
  - Export value quoting for docker format
