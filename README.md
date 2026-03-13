# ownlock

Lightweight secrets manager — encrypted local vault, `.env` injection, stdout redaction.

No Docker. No server. No account. Just `pip install ownlock`.

---

## Quick start

```bash
# Install
pip install ownlock

# Create your first vault (project vault at ./.ownlock/; use --global for ~/.ownlock/)
ownlock init

# Store a secret (interactive prompt)
ownlock set anthropic-api-key

# Or inline
ownlock set openai-api-key=sk-xxxx

# Reference secrets in .env — they’re resolved at runtime
echo 'ANTHROPIC_API_KEY=vault("anthropic-api-key")' >> .env

# Run your app: secrets are injected and redacted from stdout
ownlock run -- python app.py
```

---

## Full usage guide

### 1. Initialize a vault

You need a vault before storing secrets. Pick one of two locations:

| Vault type | Command | Location | When to use |
|------------|---------|----------|-------------|
| **Project** | `ownlock init` | `./.ownlock/vault.db` | One vault per project (adds `.ownlock/` to `.gitignore`) |
| **Global** | `ownlock init --global` | `~/.ownlock/vault.db` | Shared across all projects (passphrase in keyring) |

```bash
# Project vault — good for repo-specific secrets (default)
ownlock init

# Global vault — good for personal API keys you reuse
ownlock init --global
```

### 2. Store and retrieve secrets

```bash
# Store (prompts for value)
ownlock set my-secret

# Store inline
ownlock set DATABASE_URL=postgres://localhost/mydb

# Different environments (default, production, staging, etc.)
ownlock set api-key --env production

# Retrieve
ownlock get my-secret

# List all (names only, never values)
ownlock list

# Delete
ownlock delete my-secret
```

### 3. Which vault is used?

| Situation | Vault used |
|-----------|------------|
| You're inside a directory that has `.ownlock/vault.db` (or a parent does) | **Project vault** (closest one found) |
| No project vault found | **Global vault** |
| You pass `--global` | **Global vault** (always) |
| You pass `--project` | **Project vault** at current directory (always) |

Commands that accept `--global` and `--project`: `set`, `get`, `list`, `delete`, `import`, `scan`.

`run` and `export` don’t use these flags — they read vault references from your `.env` file.

### 4. .env format

Plain values go through as-is. Secrets use `vault("name")` and are resolved when you run commands.

**Example `.env`:**

```env
# Plain config (not secret)
OLLAMA_BASE_URL=http://localhost:11434
DEFAULT_MODEL=anthropic:claude-opus

# Secrets from vault
# If a project vault exists, these come from the project vault by default;
# otherwise they come from the global vault.
SUPABASE_URL=vault("supabase-url")
SUPABASE_SERVICE_KEY=vault("supabase-service-key")
ANTHROPIC_API_KEY=vault("anthropic-api-key")
OPENAI_API_KEY=vault("openai-api-key", env="production")
```

To **force the global vault** even when a project vault exists, use `global=true`:

```env
# Always read from global vault
GLOBAL_ONLY_SECRET=vault("global-only-secret", global=true)
```

### 5. Run and export

```bash
# Resolve .env, inject secrets, run command, redact secret values from stdout
ownlock run -- python app.py

# Custom .env path
ownlock run -f .env.local -- python app.py

# Print resolved KEY=VALUE pairs (e.g. for Docker)
ownlock export --format docker
```

### 6. Bulk import and scanning

```bash
# Import from a plaintext .env
ownlock import secrets.env

# Scan for leaked secret values
ownlock scan .
```

### 7. Guided setup (`ownlock auto`)

```bash
# After init, run a guided import + rewrite:
ownlock auto
```

- `ownlock auto` (project-first) discovers common env files (`.env`, `.env.local`, etc.), lets you pick which to import from, and loads valid `KEY=VALUE` pairs into the vault.
- It can then rewrite your env file (by default `.env`) so matching keys use `vault("KEY")` references, making it easy to go from plaintext env to vault-backed env in one flow.
- For non-interactive or CI, use flags like:

```bash
ownlock auto -f .env --yes
ownlock rewrite-env -f .env --yes
```

---

## Command reference

| Command | Description |
|---------|-------------|
| `ownlock init` | Create project vault at `./.ownlock/vault.db` |
| `ownlock init --global` | Create global vault at `~/.ownlock/vault.db` |
| `ownlock set KEY` | Store secret (prompts for value) |
| `ownlock set KEY=VALUE` | Store secret inline |
| `ownlock get KEY` | Print decrypted value |
| `ownlock list` | List secret names (never values) |
| `ownlock delete KEY` | Remove a secret |
| `ownlock run -- CMD` | Resolve `.env`, inject secrets, redact stdout |
| `ownlock export` | Print resolved KEY=VALUE pairs |
| `ownlock import FILE` | Bulk import from plaintext .env |
| `ownlock rewrite-env` | Rewrite an env file to use `vault()` references |
| `ownlock auto` | Guided import + rewrite for env files |
| `ownlock scan DIR` | Scan for leaked secret values |

Add `--global` or `--project` to `set`, `get`, `list`, `delete`, `import`, `scan` to override vault selection.

---

## How it works

- Secrets are encrypted with **AES-256-GCM** before storage
- Key derivation: **PBKDF2-HMAC-SHA256** with 200,000 iterations
- Passphrase stored in your system keyring (macOS Keychain, GNOME Keyring, etc.)
- `ownlock run` resolves `vault()` in `.env`, injects env vars, and redacts secret values from stdout/stderr
- Zero network calls. Everything stays local.

---

## Security

- **Value-level encryption**: Each secret is encrypted separately with AES-256-GCM. The SQLite file stores ciphertext, not plaintext.
- **Passphrase**: Required to decrypt. Without it, the vault is unusable.
- **No RLS**: SQLite does not support row-level security (RLS). RLS is a multi-tenant feature (e.g. PostgreSQL) that restricts which rows a role can see. ownlock is single-user and local; security comes from per-value encryption and file permissions on `vault.db`.
- **File permissions**: Keep `~/.ownlock/` and `.ownlock/` with restrictive permissions. Add `.ownlock/` to `.gitignore` for project vaults (done automatically with `init --project`).

---

## License

MIT
