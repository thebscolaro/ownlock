# ownlock

Lightweight secrets manager — encrypted local vault, `.env` injection, stdout redaction.

No Docker. No cloud account. Just `pip install ownlock`.

---

## Quick start

```bash
pip install ownlock
ownlock init
```

Have a plaintext `.env`? Run `ownlock auto` to import secrets and rewrite the file to use `vault()`.

Otherwise: set a secret, add one line to `.env`, then run your app:

```bash
ownlock set api-key
# Add to .env: MY_APP_KEY=vault("api-key")
ownlock run -- python app.py
```

---

## MCP (Model Context Protocol)

Optional integration for assistants (e.g. Cursor): the MCP server **does not decrypt the vault in its own process**. It spawns the `ownlock` CLI; passphrase and secrets are handled only in that subprocess.

```bash
pip install 'ownlock[mcp]'
```

Run the stdio server (configure your client to launch this command):

```bash
ownlock-mcp
```

Tools:

- **`ownlock_run`** — same as `ownlock run -f <file> -e <vault_env> -- <command...>`; returns exit code and captured stdout/stderr (redaction applies in the child as usual).
- **`ownlock_list_secret_names`** — same as `ownlock list` (names only, never values).
- **`ownlock_version`** — installed package version.

`get` and `export` are intentionally not exposed via MCP.

**Cursor example** (`.cursor/mcp.json` or global MCP settings):

```json
{
  "mcpServers": {
    "ownlock": {
      "command": "ownlock-mcp",
      "args": []
    }
  }
}
```

Use the full path to `ownlock-mcp` if it is not on your `PATH` (e.g. `~/.local/bin/ownlock-mcp` or your venv’s `bin`).

---

## Guided setup (`ownlock auto`)

`ownlock auto` discovers `.env` and common variants (`.env.local`, etc.), lets you choose which file and keys to import, then optionally rewrites the file so matching keys use `vault("...")`. After that you can use `ownlock run -- your-command` without editing `.env` by hand.

```bash
ownlock auto
```

For CI or non-interactive use:

```bash
ownlock auto -f .env --yes
```

---

## Initialize a vault

| Command | Effect |
|---------|--------|
| `ownlock init` | Project vault at `./.ownlock/vault.db`. First run also creates the global vault and stores the passphrase in the keyring. |
| `ownlock init --global` | Global vault only at `~/.ownlock/vault.db` (passphrase in keyring). |

```bash
ownlock init
# or global only:
ownlock init --global
```

---

## Store, list, delete

```bash
ownlock set my-secret
ownlock set api-key=your-value
ownlock set database-url --env production
ownlock list
ownlock get my-secret
ownlock delete my-secret
```

`set` and `import` overwrite any existing value for the same key (and env).

---

## Which vault is used?

| Situation | Vault used |
|-----------|------------|
| Inside a directory with `.ownlock/vault.db` (or a parent) | **Project vault** |
| No project vault found | **Global vault** |
| `--global` | **Global vault** |
| `--project` | **Project vault** at current directory |

Commands that accept `--global` / `--project`: `set`, `get`, `list`, `delete`, `import`, `scan`, and `export --example` (template lines from vault key names only). `run` and plain `export` resolve vault references from your `.env` file.

---

## .env format

Use `vault("name")` for secrets; they are resolved when you run commands.

```env
API_KEY=vault("api-key")
DATABASE_URL=vault("database-url")
SUPABASE_SERVICE_KEY=vault("supabase-service-key", env="production")
```

To force the global vault: `vault("name", global=true)`.

---

## Run and export

```bash
ownlock run -- python app.py
ownlock run -f .env.local -- python app.py
ownlock export --format docker
```

`get` and `export` print secrets to stdout. Use only in trusted environments; prefer `ownlock run` to inject secrets into a process without printing them.

---

## Import, rewrite-env, scan

```bash
ownlock import secrets.env
ownlock rewrite-env -f .env
ownlock scan .
```

---

## Command reference

| Command | Description |
|---------|-------------|
| `ownlock init` | Create project vault (first run also creates global + keyring) |
| `ownlock init --global` | Create global vault only |
| `ownlock set KEY` / `KEY=VALUE` | Store secret |
| `ownlock get KEY` | Print decrypted value |
| `ownlock list` | List secret names (`--json` for machine-readable metadata, no values) |
| `ownlock doctor` | Environment diagnostics (versions, vault paths, no secret values) |
| `ownlock delete KEY` | Remove a secret |
| `ownlock run -- CMD` | Resolve `.env`, inject secrets, redact stdout |
| `ownlock export` | Print resolved KEY=VALUE pairs (`--example` emits `KEY=vault("KEY")` lines from vault names only) |
| `ownlock import FILE` | Bulk import from plaintext .env |
| `ownlock rewrite-env` | Rewrite env file to use `vault()` |
| `ownlock auto` | Guided import + rewrite |
| `ownlock scan DIR` | Scan for leaked secret values (`--max-file-bytes` skips huge files before reading) |

Add `--global` or `--project` to `set`, `get`, `list`, `delete`, `import`, `scan`, and `export --example` to override vault selection.

---

## How it works

- Secrets are encrypted with **AES-256-GCM** before storage.
- Key derivation: **PBKDF2-HMAC-SHA256** (200,000 iterations).
- Passphrase is stored in the system keyring when you use `init` (global or first project init).
- `ownlock run` resolves `vault()` in `.env`, injects env vars, and redacts secret values from stdout/stderr. No network; everything stays local.

---

## CI and GitHub Actions

The vault is a **local SQLite file** (project `.ownlock/vault.db` or global `~/.ownlock/vault.db`). `.ownlock/` is **gitignored by default**, so CI does **not** see the vault on your laptop unless you deliberately ship something into the job.

**Secrets only in CI (no ownlock):** Put API keys and connection strings in your platform’s encrypted secrets (for example GitHub Actions secrets) and pass them into the job as **environment variables**. Tests and builds read `DATABASE_URL`, `API_KEY`, and so on from the environment. Many teams use ownlock **only on developer machines** and rely on plain env vars in CI.

**Optional ownlock in CI:** A clean runner has no vault file until you create one. You can set **`OWNLOCK_PASSPHRASE`** from a secret, `pip install ownlock`, then run `ownlock set` / `ownlock import`, or restore a vault artifact you manage outside git. Runs are usually **ephemeral**; you normally do **not** commit `vault.db`.

### pre-commit (optional)

Example hook to run `ownlock scan` before commits (requires ownlock on `PATH` and a usable passphrase via keyring or `OWNLOCK_PASSPHRASE` in the environment where hooks run):

```yaml
repos:
  - repo: local
    hooks:
      - id: ownlock-scan
        name: ownlock scan
        entry: ownlock scan .
        language: system
        pass_filenames: false
```

---

## Security

- **Encryption**: Each secret is encrypted with AES-256-GCM; the vault stores ciphertext only.
- **Passphrase**: Required to decrypt; keep it safe. Keyring avoids typing it every time.
- **get / export**: Both print secrets to stdout. Use in trusted environments only; prefer `ownlock run` to inject without printing.
- **Overwrite**: `set` and `import` overwrite existing values for the same key (and env); no append.
- **File permissions**: Restrict permissions on `~/.ownlock/` and `.ownlock/`. Project init adds `.ownlock/` to `.gitignore`.
- **Automated checks**: Bandit, pip-audit, security-focused tests, and subprocess smoke tests (`pytest -m smoke`) — see [SECURITY_TESTING.md](SECURITY_TESTING.md). Editable installs may skip CVE lookup for the ownlock package itself; dependencies are still audited.

---

## License

MIT
