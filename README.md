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

## ownlock + your AI coding assistant

A surprising practical reason ownlock has stuck for me: **agentic sandboxes**.

Modern coding assistants (Cursor's background agents, OpenAI Codex, Claude Code, etc.) often run inside locked-down sandboxes that start with a fresh shell. Plain environment variables exported in your interactive shell rarely cross that boundary — the agent spawns its own session and your `export DATABASE_URL=...` is gone.

`ownlock run` works inside those sandboxes because:

- The vault is a file on disk, not a shell session.
- The agent runs `ownlock run -- some-command`, which reads `.env`, talks to the vault on disk, and **injects secrets as env vars into that one child** — exactly the layer your app reads from.
- Stdout redaction means values that *do* sneak through (logs, error messages) come out as `[REDACTED:NAME]`.
- The MCP integration (below) lets the agent run commands without ever seeing the values itself.

Net effect: agents can run real commands against real local secrets — install from a private package registry, hit your dev database, exercise a paid API — without you handing them a long-lived secret in chat or wiring per-secret env vars into every sandbox.

If you give an agent the ability to run shell commands at all, prefer `ownlock run` over exporting secrets in the parent shell.

### MCP (Model Context Protocol)

Optional integration. The MCP server **does not decrypt the vault in its own process**. It spawns the `ownlock` CLI as a subprocess; passphrase and secrets are handled only in that subprocess.

```bash
pip install 'ownlock[mcp]'
```

Configure your client to launch the stdio server:

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

For multi-line secrets (PEM keys, JSON service-account files, etc.):

```bash
ownlock set tls-key --from-file ./service.pem
ownlock set release-notes --editor   # opens $EDITOR on a 0600 temp file
```

`set` and `import` overwrite any existing value for the same key (and env).

---

## Onboarding a teammate

Two flows depending on whether the new dev needs to *receive* secrets or just fill in placeholders.

**Fill in placeholders** — your `.env` is committed with `vault("...")` lines and the new dev runs:

```bash
ownlock bootstrap
```

This scans `.env` (and common variants) for `vault()` references, checks the local vault, and prompts only for the keys that are missing. Idempotent: re-running after a teammate adds a new vault reference asks for that one key.

**Hand off real values** — pack a subset of your vault into an encrypted bundle, share it (Slack, email, anywhere), and let the recipient import it:

```bash
# Sender
ownlock share API_KEY DB_URL -o handoff.olbundle
# (prompts for a separate "bundle passphrase"; tell the teammate over a different channel)

# Recipient
ownlock import-share handoff.olbundle
```

The bundle uses its own passphrase — independent from your local vault — so the bundle file and the recipient's vault can each have different access boundaries. `import-share` refuses to overwrite existing keys without `--overwrite`.

`ownlock install-hook` writes a `pre-commit` hook (or appends to `.pre-commit-config.yaml`) that runs `ownlock scan` on every commit, so a new dev who pastes a value into a file by mistake gets caught locally.

---

## Upgrading a vault

Your existing vault keeps working forever — but ownlock 0.2.0 raised the default PBKDF2 iteration count and added a versioned ciphertext format so future upgrades don't break anything. Two operations:

```bash
ownlock rekey --upgrade-kdf      # re-encrypt at current KDF parameters, keep passphrase
ownlock rekey --rotate-passphrase  # change the vault passphrase
ownlock rekey                    # interactive: asks which (or both)
```

`rekey` is safe to interrupt: it copies the live vault to `.ownlock/backups/vault.db.backup-<timestamp>` (mode 0600) before any change, then re-encrypts inside a single SQL transaction. If anything fails, the live file is unchanged. Successful runs leave the backup in place for you to delete once you're confident the new vault works.

`ownlock doctor` shows the current schema version + KDF iterations and prints a one-line tip when an upgrade is available.

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

## Templates (for apps that can't read env vars)

Some apps — classic ASP.NET (`web.config`), older .NET / Java config, kubeconfig, `appsettings.Development.json`, etc. — read real files on disk and ignore environment variables. Instead of rewriting these apps, keep a template that references the vault and let ownlock materialize the real file on demand.

Name any file `<stem>.template.<ext>` and use `{{vault("name")}}` inside. `ownlock render` produces `<stem>.<ext>` in the same directory.

```xml
<!-- connectionStrings.template.config -->
<connectionStrings>
  <add name="Default"
       connectionString='Server=db;User=sa;Password={{vault("db-password")}};' />
</connectionStrings>
```

```bash
ownlock render                      # render every *.template.* under cwd
ownlock render web.template.config  # single file
ownlock render --dry-run            # preview without writing
ownlock render -e production        # override vault env
```

Rendered outputs are written atomically and (on POSIX) with mode `0600`. ownlock refuses to write a rendered file unless it appears in `.gitignore` — pass `--force` to override. The gitignore check uses `git check-ignore` when git is installed (so negation, anchored patterns, nested `.gitignore`, and `.git/info/exclude` are all honored); it falls back to a best-effort fnmatch scan otherwise.

### Format-aware escaping

Vault values are **escaped for the output file's format** so a password like `p@ss"w\nord` can't break JSON, inject XML structure, or trip up an INI parser. The format is auto-detected from the rendered file's extension:

| Extension(s)                                                | Format  | Escape behavior                                    |
|-------------------------------------------------------------|---------|----------------------------------------------------|
| `.json` `.jsonc` `.toml` `.yaml` `.yml` `.tf` `.tfvars`     | `json`* | JSON string-literal escaping (`"`, `\`, control chars) |
| `.xml` `.config` `.xaml` `.csproj` `.resx`                  | `xml`   | XML entity escaping (`& < > " '`)                  |
| `.ini` `.cfg` `.properties`                                 | `ini`   | Java .properties escaping (`\`, `\n`, `\r`, `\t`)  |
| `.env` `.envrc`                                             | `env`   | Escape for inside `"..."` in a dotenv              |
| `.sh` `.bash` `.zsh`                                        | `shell` | Escape for inside `'...'` in a POSIX shell         |
| anything else                                               | `raw`   | Verbatim (no escaping)                             |

<sup>*TOML, YAML (double-quoted), and HCL all use the same string-literal semantics as JSON, so a single escaper covers them.</sup>

The value is always inserted **inside** your existing quotes — you still write the quote characters in the template, and ownlock produces something safe to live there:

```json
// appsettings.Development.template.json  (template)
{ "ConnectionStrings": { "Default": "{{vault("db-conn")}}" } }
```

```json
// appsettings.Development.json  (rendered; secret was: Server=db;Password=p"w;)
{ "ConnectionStrings": { "Default": "Server=db;Password=p\"w;" } }
```

Per-reference overrides win over auto-detection. Use them when a single file mixes formats (e.g. a shell script that emits JSON) or when you want to opt a single reference out of escaping:

```hcl
terraform = "{{vault("token", format="json")}}"      # force JSON escaping
passthrough = "{{vault("blob", format="raw")}}"     # no escaping for this ref
```

Pass `--raw` to disable auto-escaping entirely and insert values verbatim (the pre-0.1.10 behavior). You probably don't want this unless you're rendering into a format ownlock doesn't understand and you've already handled quoting yourself.

For legacy .NET apps, the least invasive pattern is `configSource` on `web.config`:

```xml
<connectionStrings configSource="connectionStrings.config" />
<appSettings file="appSettings.secrets.config" />
```

No C# changes, no recompile — `ConfigurationManager` keeps reading XML as usual; ownlock just produces the external file.

You can also chain rendering with `run`. For safety, `run --render` takes **explicit template paths** (it does not auto-discover — that prevents rendering untrusted templates that happen to live under the current directory):

```bash
ownlock run --render web.template.config -- dotnet MyApp.dll
ownlock run --render a.template.json --render b.template.yaml -- ./start.sh
ownlock run --render web.template.config --render-cleanup -- ./start.sh   # unlink on exit
```

`{{vault(...)}}` accepts the same options as the `.env` form: `env="production"`, `project=true`, `global=true`.

### What about non-secret per-env config?

ownlock deliberately handles **secrets only**. Values that vary per environment but aren't sensitive — log levels, port numbers, hostnames, feature flags — should keep using your app's native mechanism:

| Stack | Native per-env mechanism |
|-------|--------------------------|
| ASP.NET (classic) | `Web.Debug.config` / `Web.Release.config` transforms |
| ASP.NET Core / .NET | `appsettings.{Environment}.json` + `IConfiguration` |
| Java / Spring | `application-{profile}.properties` |
| Node / Next.js | `.env.development` / `.env.production` |
| Terraform | workspaces + `terraform.tfvars` per env |
| Kubernetes | `ConfigMap` + `kustomize` overlays |

Put non-secrets there, put secrets in ownlock. The two layers compose cleanly: your app reads its environment-specific config normally, and the one or two values that shouldn't be in git come from a template that ownlock renders.

Example: `web.config` stays untouched and relies on standard transforms for `LogLevel`/`AppUrl`; only `connectionStrings` is externalized via `configSource` and rendered by ownlock from a template. One small surface for secrets, zero disruption to the app's existing config story.

---

## Command reference

| Command | Description |
|---------|-------------|
| `ownlock init` | Create project vault (first run also creates global + keyring) |
| `ownlock init --global` | Create global vault only |
| `ownlock set KEY` / `KEY=VALUE` | Store secret. `--from-file PATH`, `--editor` for multi-line values |
| `ownlock get KEY` | Print decrypted value |
| `ownlock list` | List secret names (`--json` for machine-readable metadata, no values) |
| `ownlock doctor` | Environment diagnostics (versions, vault paths, KDF status, `--json`) |
| `ownlock delete KEY` | Remove a secret |
| `ownlock rekey` | Re-encrypt at current KDF (`--upgrade-kdf`) and/or rotate passphrase (`--rotate-passphrase`) |
| `ownlock run -- CMD` | Resolve `.env`, inject secrets, redact stdout |
| `ownlock export` | Print resolved KEY=VALUE pairs (`--example` emits `KEY=vault("KEY")` lines from vault names only) |
| `ownlock import FILE` | Bulk import from plaintext .env |
| `ownlock bootstrap` | Prompt teammates only for vault keys missing from their local vault |
| `ownlock share KEYS -o FILE` | Export an encrypted bundle for a teammate (separate bundle passphrase) |
| `ownlock import-share FILE` | Import an encrypted bundle into the local vault |
| `ownlock rewrite-env` | Rewrite env file to use `vault()` |
| `ownlock auto` | Guided import + rewrite |
| `ownlock scan DIR` | Scan for leaked secret values (`--max-file-bytes` skips huge files before reading) |
| `ownlock render [TEMPLATE]` | Render `*.template.*` files, substituting `{{vault(...)}}` with decrypted values |
| `ownlock install-hook` | Install a pre-commit hook that runs `ownlock scan` |
| `ownlock completion {bash,zsh,fish,pwsh}` | Print a shell completion script |

Add `--global` or `--project` to `set`, `get`, `list`, `delete`, `import`, `scan`, `rekey`, `bootstrap`, `share`, `import-share`, and `export --example` to override vault selection.

---

## How it works

- Secrets are encrypted with **AES-256-GCM** before storage; key derivation uses **PBKDF2-HMAC-SHA256**. Iteration counts and ciphertext format are documented in [SECURITY.md](SECURITY.md).
- The vault is a local SQLite file. No network; everything stays local.
- `ownlock run` resolves `vault()` in `.env`, injects the resolved values into one child process, and redacts those values from the child's stdout/stderr. The master passphrase is **not** passed to the child.

### Passphrase model

There is one passphrase per vault. ownlock looks for it in this order:

1. **`OWNLOCK_PASSPHRASE` env var** — wins if set. CI / scripts / agent sandboxes use this.
2. **System keyring** — macOS Keychain, Windows Credential Manager, Linux Secret Service. Populated by `ownlock init` so you don't type the passphrase on every command.
3. **Interactive prompt** — last resort.

Use `ownlock doctor` to see which source resolved the passphrase right now.

---

## Pairs with your CI / cloud secrets manager

ownlock is a **local-developer** tool. It does not replace your platform's secrets manager — it complements one:

| Layer | Tool | Where the values live |
|-------|------|------------------------|
| Local development | **ownlock** | `~/.ownlock/vault.db` and per-project `.ownlock/vault.db` |
| CI / production | GitHub Actions secrets, Harness, AWS Secrets Manager, Doppler, Vault, Fly.io secrets, etc. | Your platform's encrypted store |

The shared boundary is **the env vars your application reads** (`DATABASE_URL`, `STRIPE_KEY`, …). ownlock injects them locally; CI / your runtime injects them in production. The app code stays the same.

`.ownlock/` is gitignored by default, so the local vault never reaches CI on its own — you opt in if you want it. A typical team setup:

- Each developer has a per-project vault populated via `ownlock bootstrap` after cloning (or `ownlock import-share` for a one-shot handoff).
- CI sets the same env var names directly from the platform's secrets store. ownlock isn't installed on the runner.
- `ownlock scan` runs in pre-commit (`ownlock install-hook`) and in CI to refuse commits containing leaked vault values.

You can use ownlock in CI too — set `OWNLOCK_PASSPHRASE` from a runner secret and import a vault you manage outside git — but most teams find the dual-store model cleaner.

---

## Security

- **Encryption + KDF details, threat model, and the full security posture** live in [SECURITY.md](SECURITY.md).
- **get / export**: Both print secrets to stdout. Use in trusted environments only; prefer `ownlock run` to inject without printing.
- **Overwrite**: `set` and `import` overwrite existing values for the same key (and env); no append.
- **File permissions**: Restrict permissions on `~/.ownlock/` and `.ownlock/`. Project init adds `.ownlock/` to `.gitignore` and writes backups under that directory with mode `0600`.
- **Reporting**: See [SECURITY.md](SECURITY.md#reporting-vulnerabilities).
- **Automated checks**: Bandit, pip-audit, security-focused tests, and subprocess smoke tests (`pytest -m smoke`) — see [SECURITY_TESTING.md](SECURITY_TESTING.md). Editable installs may skip CVE lookup for the ownlock package itself; dependencies are still audited.

---

## License

MIT
