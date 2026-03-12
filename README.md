# ownlock

Lightweight secrets manager — encrypted local vault, `.env` injection, stdout redaction.

No Docker. No server. No account. Just `pip install ownlock`.

## Quick start

```bash
pip install ownlock

# Create a vault (passphrase saved to system keyring)
ownlock init

# Store secrets
ownlock set anthropic-api-key
> Enter value: ****

# In your .env, use vault() instead of plain values:
# ANTHROPIC_API_KEY=vault("anthropic-api-key")

# Run commands with secrets injected and stdout redacted
ownlock run -- python app.py
```

## .env format

Plain values pass through unchanged. Secrets stay in the vault and are resolved at runtime:

```bash
# Non-sensitive config (stored as plain text)
OLLAMA_BASE_URL=http://localhost:11434
DEFAULT_WORKER_MODEL=anthropic:claude-opus-4-6

# Secrets (resolved from vault at runtime)
ANTHROPIC_API_KEY=vault("anthropic-api-key")
OPENAI_API_KEY=vault("openai-api-key", env="production")
```

## Commands

| Command | Description |
|---|---|
| `ownlock init` | Create a vault (global or `--project` local) |
| `ownlock set KEY` | Store a secret |
| `ownlock set KEY=VALUE` | Store inline |
| `ownlock get KEY` | Print decrypted value |
| `ownlock list` | Show secret names (never values) |
| `ownlock delete KEY` | Remove a secret |
| `ownlock run -- CMD` | Resolve `.env`, inject secrets, redact stdout |
| `ownlock export` | Print resolved `KEY=VALUE` pairs |
| `ownlock import .env` | Bulk import from plaintext `.env` |
| `ownlock scan .` | Scan files for leaked secret values |

Default: project vault when in a project directory (`.ownlock/vault.db` in cwd or a parent); otherwise global vault. Use `--global` to force the global vault. Use `--project` to force the project vault at cwd.

## How it works

- Secrets are encrypted with **AES-256-GCM** and stored in a local SQLite database
- Key derivation: PBKDF2-HMAC-SHA256 with 200,000 iterations
- Vault passphrase stored in your system keyring (macOS Keychain, GNOME Keyring, etc.)
- `ownlock run` resolves `vault()` references, injects env vars into the subprocess, and redacts any secret values that appear in stdout/stderr
- Zero network calls. Everything is local.

## Storage

- **Global vault**: `~/.ownlock/vault.db` — use `--global` to force this
- **Project vault**: `.ownlock/vault.db` — default when in a project directory (cwd or a parent), or use `--project` to force at cwd

## License

MIT
