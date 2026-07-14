# Changelog

All notable changes to ownlock will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026-07-14

### Fixed

- **Windows console** — ASCII-safe markers (`[x]` / `-`) when stdout cannot encode `✗` / `•`; best-effort UTF-8 `stdout` reconfigure on Windows.
- **`.gitignore` migration** — legacy `.ownlock/` / `.ownlock` directory rules are removed and replaced with `.ownlock/*` so `!.ownlock/team.olbundle` works.
- **`shield --verify` heuristic** — plaintext `.env` scan flags secret-shaped keys/values only (no more false positives on `NODE_ENV=development` / `CUSTOM_TOKENIZER`).
- **PowerShell guard hook** — uses explicit process stdin/stdout (async stdout read; stderr not redirected) instead of pipeline enumeration.
- **Cross-OS Claude hooks** — `install` upserts a single ownlock hook entry; `verify` accepts `.sh` or `.ps1` when settings are wired.
- **Cursor shield** — `preToolUse` covers all tools (incl. MCP); path haystack includes `target_directory`.
- **Hermes config merge** — single-quoted YAML paths (Windows-safe); no orphan list items; refreshes stale absolute command paths; path haystack joins all tool fields.

### Added

- **Windows Claude hooks** — `ownlock-shield.ps1` / `ownlock-guard.ps1` wired via `powershell -NoProfile -File` when `os.name == "nt"`.
- **Cursor `hooks.json`** — `beforeReadFile` / `beforeShellExecution` / `preToolUse` with Cursor deny schema.
- **Hermes shield emitter** — project scripts + `~/.hermes/config.yaml` marker merge (snippet when Hermes is not installed).
- **Pi shield emitter** — `.ownlock/pi/ownlock-shield.js` + `.pi/settings.json` `extensions` entry.
- **`share --team` full-export warning** — when no secret names are given, warn that the entire project vault is exported and personal tokens belong in the global vault.
- README **Team sync vs policies** and **agent support matrix**.

## [0.3.0] - 2026-07-14

### Added

- **`ownlock shield`** — one command to harden repos against agent secret-reading: `.cursorignore` / `.claudeignore`, Claude `permissions.deny`, and `PreToolUse` hook; `ownlock shield --verify` self-test.
- **`ownlock guard`** — DLP redaction for agent tool output; `ownlock guard --stdin` for hooks; `ownlock guard --install-hook` for Claude `PostToolUse`.
- **`ownlock status`** — vault, shield, audit, and agent-detection summary (`--json` for scripts).
- **Agent audit attribution** — process-tree detection auto-enables audit logging when an AI agent calls ownlock; `actor` field in audit JSONL.
- **Per-secret policies** — `ownlock set NAME --policy open|session|confirm` with approval gates on `get` and `vault()` resolution.
- **Team encrypted bundle** — `ownlock share --team` writes `.ownlock/team.olbundle`; `ownlock init` offers auto-import.
- **Provider bridges** — `vault("op://...")` and `vault("aws-sm://...")` via local `op` / `aws` CLI.
- **MCP `ownlock_request_access`** — human approval flow for policy-gated secrets.
- **Distribution assets** — `scripts/install.sh`, Homebrew formula (`packaging/homebrew/`), winget manifest stub, `action/action.yml` for CI.
- **Supply-chain hardening** — workflow default read-only permissions, pinned action SHAs, Dependabot, CODEOWNERS, `docs/github-security.md`.

### Changed

- README repositioned around agent-safety narrative and multi-channel install paths.

## [0.2.2] - 2026-07-01

### Added

- **`ownlock --version` / `-V`** — prints package version from metadata.

### Fixed

- Rekey schema hint uses current schema version constant.
- `ownlock run` exits 127 when command not found.
- Scanner single-pass performance improvement.

### Security

- Bundle KDF iteration cap; backup files created mode 0600 from the start.

## [0.2.1] - 2026-06-03

### Fixed

- **`find_project_vault` no longer treats `~/.ownlock/vault.db` as a project vault** when walking up from `$HOME` or a subdirectory.
- **`ownlock scan` uses the project vault by default** (`--global` for the global vault). When no project vault exists or the passphrase does not unlock it, scan still flags legacy backup files instead of failing silently.

### Added

- **Multi-file positional `ownlock import`** — `ownlock import a.env b.env` imports several files in one command.
- **[UPGRADE.md](UPGRADE.md)** — migration guide for 0.1.x → 0.2.x.

### Security

- **Shorter in-process passphrase lifetime** — vault sessions hold the passphrase in wipeable memory; CLI commands zero the session buffer and remove `OWNLOCK_PASSPHRASE` from the process environment when the command finishes.
- **Parameterized SQL throughout `VaultManager`** — regression tests for metacharacters in secret names and envs.

### Changed

- **Documentation trimmed** to outcome-focused security language (no implementation-level escape or redaction detail in user-facing docs).

### Tests

- Vault defensive-path coverage (WAL checkpoint failure, `rekey` rollback, `find_project_vault` edge cases); `vault.py` at 100% line coverage.

## [0.2.0] - 2026-05-28

### Security

- **`OWNLOCK_PASSPHRASE` is no longer inherited by `ownlock run` children**. Pre-0.2.0 a child process spawned by `run` could read the master passphrase from its own environment and decrypt the entire vault by re-spawning `ownlock`. The passphrase (and `OWNLOCK_NEW_PASSPHRASE`) are now stripped from the child env before the resolved secret values are layered on top. Regression test in `tests/test_security.py`.
- **PBKDF2 default raised from 200,000 to 600,000 iterations** (OWASP 2023 guidance for PBKDF2-SHA256). Existing vaults keep working; upgrade with `ownlock rekey --upgrade-kdf`.
- **Versioned ciphertext format**: each stored value carries a small format prefix (v1 legacy, v2 with embedded iteration count) so a vault can hold a mix during a partial migration. `decrypt` auto-detects.
- **Vault metadata**: new `meta` table records `schema_version`, `kdf_algo`, `kdf_iterations`, `created_at`. `ownlock doctor` reads it without needing the passphrase.
- **Encrypted secret names (schema v3)**: secret names are no longer stored in cleartext in `vault.db`. Rows are keyed by an HMAC lookup id; names are AES-GCM ciphertext. Legacy v1/v2 vaults auto-migrate on first open with your passphrase.
- **`.ownlock.bak` files are gone**: backups (env-rewrite and vault snapshots) live under `.ownlock/backups/` with mode `0600`. `.ownlock/` is gitignored by default. `ownlock scan` and `ownlock doctor` flag any leftover legacy `.ownlock.bak` files.
- **Improved stdout/stderr redaction in `ownlock run`** — broader coverage of common leak patterns; very short values are skipped to limit false positives.
- **WAL mode + 5s busy-timeout**: SQLite vaults now open in WAL mode, so two `ownlock` processes (e.g. an agent and a developer in another shell) can read and write the same vault file safely. `rekey`'s vault snapshot also captures the WAL/SHM sidecars so a hard-killed prior writer's pending bytes are restorable.

### Added

- **`ownlock rekey`** — re-encrypt the entire vault under a new passphrase (`--rotate-passphrase`) and/or a new KDF iteration count (`--upgrade-kdf`). Single SQL transaction; the live file is untouched until commit; a 0600 backup is left under `.ownlock/backups/`.
- **`ownlock import` is now the single entry point** for getting secrets into the vault. Auto-detects the file shape and routes accordingly:
  - Plain `KEY=VALUE` → seed flow (with optional `--rewrite` to also rewrite the file in place to use `vault(...)`).
  - Already on `vault(...)` references → vault_refs flow that prompts only for the keys missing from the local vault. Pair with `--values-from JSON` for non-interactive runs.
- **`ownlock init` walks new users through onboarding**: when a `.env` is present in cwd, it offers to import secrets (and rewrite to vault references) on the spot — that's the entire flow for a teammate cloning the repo.
- **`ownlock share` / `ownlock import-share`** — encrypted JSON bundles for handing real secret values to a teammate. Bundle is encrypted with a separate passphrase from the local vault, so the bundle file and the recipient's vault have independent access boundaries.
- **`ownlock set --from-file PATH` / `--editor`** — multi-line / file-based secret entry (PEM keys, JSON service-account files, etc.). `--strip` controls trailing whitespace handling.
- **`ownlock completion {bash,zsh,fish,pwsh,powershell}`** — print a shell completion script.
- **`ownlock install-hook`** — install a pre-commit hook (or append to `.pre-commit-config.yaml`) that runs `ownlock scan` on every commit.
- **`ownlock_doctor` and `ownlock_status` MCP tools** — both delegate to the CLI subprocess; no decryption in the MCP process.
- **`ownlock doctor`** now reports schema version, KDF iterations, secret-iteration histogram, legacy backup files, and `.ownlock-tmp` leftovers.
- **Opt-in audit log**: set `OWNLOCK_AUDIT=1` to write a JSONL line per write op (`init` / `set` / `delete` / `import` / `rekey` / `share` / `import-share`) to `.ownlock/audit.log`. **Names only, never values.**

### Changed

- **Removed `ownlock auto` and `ownlock bootstrap`** (0.1 commands). Use `ownlock import` and `ownlock import --rewrite` instead.
- **`ownlock import` interactive UX**: cyan numbered pickers for env files and keys (restores the old `auto` feel), multi-file discovery picker when several `.env*` files exist, and clearer rewrite output with file links plus backup on its own line.
- **`ownlock doctor`**: no longer crashes when the optional `mcp` package is not installed (`mcp_importable` reports `false` instead).
- **Refactor**: `cli.py` and `vault.py` split into smaller, focused modules — `paths.py`, `envfile.py`, `backups.py`, `scanner.py`, `doctor.py`, `audit.py`. Most commands now compose helpers from these modules instead of inlining the logic.

### Documentation

- **[UPGRADE.md](UPGRADE.md)** — step-by-step guide for 0.1.x → 0.2.0 (command renames, vault/KDF migration, how to exercise interactive `import` pickers).
- **[README.md](README.md)** — new "ownlock + your AI coding assistant" section explaining why `ownlock run` works inside agentic sandboxes (Cursor background agents, Codex, Claude Code) where regular shell exports don't cross the sandbox boundary; new sections for "Get secrets into the vault" (unified `import`), "Onboarding a teammate" (placeholders vs. encrypted-bundle handoff), "Upgrading a vault" (`rekey`), and "Pairs with your CI / cloud secrets manager" (boundary with Harness / Doppler / GH Secrets / etc.). Crypto details moved to SECURITY.md.
- **[SECURITY.md](SECURITY.md)** — now the authoritative source for cryptographic details: AES-256-GCM, PBKDF2-HMAC-SHA256 iteration history (200k → 600k), versioned ciphertext format, vault meta table, `run` passphrase isolation, encrypted-bundle mechanics, WAL mode + concurrency.

### CI

- **Test job split**: fast unit tests (`-m "not smoke"`) run on Linux 3.11 + 3.12, macOS 3.12, Windows 3.12. Subprocess smoke tests run as a separate single-OS job so a flaky smoke test can't block PR feedback.
- **Coverage gate**: ubuntu / Python 3.12 runs `pytest-cov` with `fail_under=84` and uploads an HTML report artifact (`coverage-html`).

## [0.1.11] - 2026-04-27

### Fixed

- **Windows `ownlock run`**: resolve the command’s first argv token with `shutil.which` against the merged `PATH` (PATHEXT), so bare names like `npm` launch the same executable as `npm.cmd` under `subprocess.Popen` (no shell).

## [0.1.10] - 2026-04-24

### Added

- **`ownlock render`**: materialize config files from `<name>.template.<ext>` templates containing `{{vault("key")}}` references. Intended for apps whose configuration is read as files on disk rather than environment variables (classic ASP.NET `web.config`, `appsettings.*.json`, kubeconfig, etc.). Supports `--dry-run`, `--out`, `--env`, `--force`, and `--raw`. Writes atomically and applies mode `0600` on POSIX; refuses to overwrite a destination not covered by `.gitignore` without `--force`.
- **`ownlock run --render PATH`** (repeatable) / **`--render-cleanup`** / **`--raw`**: render listed templates before launching the command, optionally unlinking them after the child exits. `run --render` intentionally requires **explicit paths** (no auto-discovery) to avoid rendering untrusted templates that happen to live under the cwd.
- **Render produces syntactically valid output files** — vault values are inserted so common config formats stay well-formed. Per-reference `format="..."` overrides and `--raw` are available when you handle quoting yourself.
- **Full gitignore semantics via `git check-ignore`**: when git is on `PATH` and the destination is inside a git repo, ownlock's "refuses to overwrite non-ignored file" check now uses `git check-ignore`, which honors negation (`!pattern`), anchored patterns, nested `.gitignore`, `.git/info/exclude`, and the global excludes file. Falls back to the fnmatch best-effort scan when git is unavailable.
- **Shared vault lookup**: new `VaultLookup` helper in `ownlock.resolver` encapsulates project/global vault selection for the `.env` resolver and the new template renderer; inline `project=true` / `global=true` semantics are identical across both surfaces.

### Security hardening (post-feature red-team pass)

- **`render --out` path validation**: relative destinations outside cwd (`--out ../../elsewhere`) are rejected, matching the validation applied to `--file` / template paths.
- **Template discovery does not follow symlinks**: switched `discover_templates` from `Path.rglob` to `os.walk(..., followlinks=False)`; symlinked files are also skipped. Prevents symlink-based escape from the project tree and rglob cycles.
- **Malformed reference warning**: `render` now warns when `{{vault(...` fragments remain in the rendered output (typically from wrong quote style or missing closing brace), so a typo can't silently ship.
- **Render output validity (see above)**: supersedes the earlier "vault values are inserted verbatim" caveat unless the user opts into `--raw` / `format="raw"`.
- **Documented `--force` + `--render-cleanup` data-loss edge**: combining the two can unlink a pre-existing file the render overwrote.

### Documentation

- **[README.md](README.md)**: new "Templates (for apps that can't read env vars)" section with the `web.config` + `configSource` walkthrough, and a "What about non-secret per-env config?" subsection pointing users at native mechanisms (ASP.NET transforms, `appsettings.{Environment}.json`, Terraform workspaces, etc.) for values that vary per env but aren't secret.
- **[SECURITY.md](SECURITY.md)**: note on rendered-file hazards, atomic write, 0600 permissions, `git check-ignore`-backed gitignore detection (with fnmatch fallback), symlink-follow protection, render output validity, `--raw` / `format="raw"` caveats, `.ownlock-tmp` leftover behavior.

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
