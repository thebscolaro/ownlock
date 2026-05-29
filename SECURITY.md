# Security

## Reporting vulnerabilities

If you discover a security vulnerability in ownlock, please report it responsibly:

1. **Do not** open a public GitHub issue.
2. Email the maintainers or open a [private security advisory](https://github.com/thebscolaro/ownlock/security/advisories/new) on GitHub.
3. Include a description of the vulnerability, steps to reproduce, and any suggested fixes.
4. We will respond promptly and work with you to address the issue.

## Security model

- **Encryption**: Secrets are encrypted with AES-256-GCM. Each secret has a fresh random 16-byte salt and 12-byte nonce; ciphertext + 128-bit GCM tag are stored together.
- **Key derivation**: PBKDF2-HMAC-SHA256. New vaults default to **600,000 iterations** (matching OWASP 2023 guidance for PBKDF2-SHA256). Vaults predating ownlock 0.2.0 are at 200,000 iterations and can be upgraded with `ownlock rekey --upgrade-kdf`.
- **Versioned ciphertext**: Each stored value carries a small format prefix (v1 legacy, v2 with embedded iteration count). A vault can hold a mix during a partial migration; ``decrypt`` auto-detects.
- **Vault metadata**: A `meta` table records `schema_version`, `kdf_algo`, `kdf_iterations`, and `created_at`. `ownlock doctor` reports these without needing the passphrase.
- **Passphrase resolution order**: `OWNLOCK_PASSPHRASE` env var → system keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service) → interactive prompt. The env var wins so CI / scripts can override the keyring.
- **Passphrase isolation in `run`**: `OWNLOCK_PASSPHRASE` and `OWNLOCK_NEW_PASSPHRASE` are stripped from the parent environment before launching child processes via `ownlock run`. Resolved secret values still reach the child as regular environment variables, but the master passphrase that unlocks the vault never does.
- **Backups**: `import --rewrite`, `rewrite-env`, and `rekey` write backups under `.ownlock/backups/` with mode `0600` on POSIX. `.ownlock/` is gitignored by default, so backups never leak through git. Older versions wrote `*.ownlock.bak` next to the original file; `ownlock scan` and `ownlock doctor` flag any such legacy files. `rekey`'s vault snapshot also captures the SQLite WAL/SHM sidecars so a hard-killed previous process whose writes are still in the WAL is restorable.
- **Concurrent writes**: The vault is a single SQLite file; ownlock opens it in **WAL mode** with a 5-second busy-timeout, so two processes (e.g. an agent setting a secret while a developer runs `ownlock run` in another shell) can read and write the same vault file without corruption. `ownlock rekey` takes an `IMMEDIATE` write lock for the duration of the re-encryption transaction.
- **Encrypted bundles**: `ownlock share` packages a subset of secrets into a JSON file encrypted with AES-256-GCM under a separate **bundle passphrase**, so a team can hand off secrets without distributing the local-vault passphrase. `ownlock import-share` decrypts the bundle and refuses to overwrite existing keys without explicit `--overwrite`.
- **No network**: ownlock never makes network requests. All data stays local.
- **Path safety**: Relative paths for `.env` files and scan directories are validated to stay within the current directory.
- **Subprocess**: `ownlock run` passes the command as a list to the OS exec APIs. No shell interpretation. Secrets are injected as environment variables.
- **Redaction**: Known secret values are replaced with `[REDACTED:NAME]` in subprocess stdout/stderr.
- **MCP** (optional, `ownlock[mcp]`): The stdio MCP server does not load the vault or decrypt in-process. It delegates to the `ownlock` CLI via subprocess; `get` / `export` are not exposed as MCP tools.

## Security testing

Automated checks (Bandit, pip-audit, targeted pytest) and OWASP-oriented mapping are described in [SECURITY_TESTING.md](SECURITY_TESTING.md).

## Rendered templates

`ownlock render` (and `ownlock run --render`) materializes files from `<name>.template.<ext>` templates containing `{{vault(...)}}` references. These rendered files contain plaintext secret values and must be treated like any other secret file:

- ownlock writes them atomically (`tempfile` + `os.replace`) and sets mode `0600` on POSIX.
- ownlock refuses to overwrite a destination that does not appear in `.gitignore` unless `--force` is passed. The check prefers `git check-ignore` when git is on `PATH` and the destination is inside a git repository — full gitignore semantics (negation, anchored patterns, nested `.gitignore`, `.git/info/exclude`, global ignore) are honored. When git is unavailable, a best-effort fnmatch scan is used as a fallback.
- Stdout redaction in `ownlock run` does not redact content your app writes *from* a rendered file; the file itself is the boundary.
- `--render-cleanup` unlinks rendered files after the child process exits, but cannot protect against reads that occur while the file exists on disk. Combined with `--force`, it can remove a pre-existing file that the render overwrote — only combine those flags when you are certain no user-owned data lives at the destination path.
- `ownlock run --render` requires **explicit template paths**; it never auto-discovers. This prevents a malicious cwd from placing a template + matching `.gitignore` that would cause `run --render` to write your vault values into an attacker-controlled file. The standalone `ownlock render` still does discovery because the command was invoked intentionally — still, prefer passing explicit template paths when running in untrusted directories.
- Template discovery does not follow directory or file symlinks (`os.walk` with `followlinks=False`), which prevents a symlink from pulling files outside the project into the render set.
- Vault values are escaped for the output file's format (JSON/TOML/YAML/HCL, XML, INI/properties, .env, shell), detected from the rendered file's extension. This prevents a secret containing a quote, backslash, newline, or an XML special character from breaking the output file's syntax or injecting structure. Per-reference overrides (`format="..."`) and the `--raw` flag can disable escaping for formats ownlock doesn't recognize — when using `--raw` or `format="raw"`, the verbatim-insertion caveat applies and you are responsible for quoting in the template.
- An interrupted write can leave a `.<name>.<rand>.ownlock-tmp` file next to the destination with plaintext content. Mode `0600` (POSIX) limits exposure. `ownlock scan` will flag such a file if committed.

## Known limitations

- Decrypted secrets exist in process memory while commands run.
- Environment variables are visible to child processes and can appear in process listings.
- The system keyring can be accessed by other applications running as the same user.
- When git is not available on `PATH`, `ownlock render`'s gitignore safety check falls back to a best-effort fnmatch scan that does not implement full gitignore semantics (negation, anchored `**` patterns, `.git/info/exclude`). Installing git enables full semantics via `git check-ignore`.
- KDF iterations are a defense in depth, not a substitute for a strong passphrase. With a low-entropy passphrase, even 600,000 PBKDF2 iterations are recoverable on cloud GPUs in days. Use a 4-word passphrase or longer.
