# Changelog

All notable changes to ownlock will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.10] - 2026-04-24

### Added

- **`ownlock render`**: materialize config files from `<name>.template.<ext>` templates containing `{{vault("key")}}` references. Intended for apps whose configuration is read as files on disk rather than environment variables (classic ASP.NET `web.config`, `appsettings.*.json`, kubeconfig, etc.). Supports `--dry-run`, `--out`, `--env`, `--force`, and `--raw`. Writes atomically and applies mode `0600` on POSIX; refuses to overwrite a destination not covered by `.gitignore` without `--force`.
- **`ownlock run --render PATH`** (repeatable) / **`--render-cleanup`** / **`--raw`**: render listed templates before launching the command, optionally unlinking them after the child exits. `run --render` intentionally requires **explicit paths** (no auto-discovery) to avoid rendering untrusted templates that happen to live under the cwd.
- **Format-aware escaping**: vault values are escaped for the output file's string-literal syntax, chosen from the destination extension — JSON (`.json` `.jsonc` `.toml` `.yaml` `.yml` `.tf` `.tfvars`), XML (`.xml` `.config` `.xaml` `.csproj` `.resx`), INI / Java properties (`.ini` `.cfg` `.properties`), dotenv (`.env` `.envrc`), POSIX shell single-quote (`.sh` `.bash` `.zsh`), and raw (everything else). A secret containing `"`, `\`, a newline, or XML specials now produces a syntactically valid output file instead of a broken one. Per-reference overrides are available via `{{vault("name", format="json")}}`; `--raw` disables escaping globally.
- **Full gitignore semantics via `git check-ignore`**: when git is on `PATH` and the destination is inside a git repo, ownlock's "refuses to overwrite non-ignored file" check now uses `git check-ignore`, which honors negation (`!pattern`), anchored patterns, nested `.gitignore`, `.git/info/exclude`, and the global excludes file. Falls back to the fnmatch best-effort scan when git is unavailable.
- **Shared vault lookup**: new `VaultLookup` helper in `ownlock.resolver` encapsulates project/global vault selection for the `.env` resolver and the new template renderer; inline `project=true` / `global=true` semantics are identical across both surfaces.

### Security hardening (post-feature red-team pass)

- **`render --out` path validation**: relative destinations outside cwd (`--out ../../elsewhere`) are rejected, matching the validation applied to `--file` / template paths.
- **Template discovery does not follow symlinks**: switched `discover_templates` from `Path.rglob` to `os.walk(..., followlinks=False)`; symlinked files are also skipped. Prevents symlink-based escape from the project tree and rglob cycles.
- **Malformed reference warning**: `render` now warns when `{{vault(...` fragments remain in the rendered output (typically from wrong quote style or missing closing brace), so a typo can't silently ship.
- **Format-aware substitution (see above)**: supersedes the earlier "vault values are inserted verbatim" caveat — a secret can no longer silently break a JSON/XML output file or inject structure unless the user opts into `--raw` / `format="raw"`.
- **Documented `--force` + `--render-cleanup` data-loss edge**: combining the two can unlink a pre-existing file the render overwrote.

### Documentation

- **[README.md](README.md)**: new "Templates (for apps that can't read env vars)" section with the `web.config` + `configSource` walkthrough, a "Format-aware escaping" subsection with the extension-to-format table, and a "What about non-secret per-env config?" subsection pointing users at native mechanisms (ASP.NET transforms, `appsettings.{Environment}.json`, Terraform workspaces, etc.) for values that vary per env but aren't secret.
- **[SECURITY.md](SECURITY.md)**: note on rendered-file hazards, atomic write, 0600 permissions, `git check-ignore`-backed gitignore detection (with fnmatch fallback), symlink-follow protection, format-aware escaping behavior, `--raw` / `format="raw"` caveats, `.ownlock-tmp` leftover behavior.

## [0.1.9] - 2026-04-03

### Added

- **`ownlock doctor`**: prints version, Python, global/project vault paths (existence), whether `OWNLOCK_PASSPHRASE` is set (boolean only), keyring passphrase availability, and whether the MCP extra is importable — no secret values.
- **`ownlock list --json`**: JSON array of `{name, env, created_at, updated_at}` (metadata only).
- **`ownlock export --example`**: emits `KEY=vault("KEY")` lines for keys in the vault (`--global` / `--project` supported); `--format` does not apply. Non-default `--env` emits `vault("KEY", env="...")`.
- **`ownlock scan --max-file-bytes`**: skips files larger than the limit (default 2 MiB) before reading.

### Documentation

- **[SECURITY_TESTING.md](SECURITY_TESTING.md)**: note on pip-audit skipping the editable ownlock package while still auditing dependencies.
- **[README.md](README.md)**: CI/GitHub Actions (env-only vs optional ownlock + `OWNLOCK_PASSPHRASE`), optional pre-commit snippet for `ownlock scan`, command reference updates.

## [0.1.8] - 2026-04-04

### Changed

- **`auto` / `rewrite-env`**: shared env line rewrite logic in `_rewrite_env_lines_to_vault_syntax()` to avoid drift; unit test for the helper.

## [0.1.7] - 2026-04-03

### Changed

- **`scan`**: interactive confirmation prompt only when the scan root is a **filesystem root** (POSIX `/` or Windows drive root) or when `--max-files` is **greater than** the default cap (10_000). Normal project scans no longer prompt every time. Added `_is_dangerous_scan_root()` for cross-platform root detection.

### Fixed

- **Smoke tests (Windows)**: subprocess CLI tests use UTF-8 decoding for Rich table output (already on `main` before this tag).

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
