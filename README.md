# ownlock

**The cross-platform local secret broker for humans and AI agents.**

Encrypted local vault, runtime env injection, stdout redaction, and one-command agent hardening — no Docker, no cloud account.

```bash
# Install (pick one)
uv tool install ownlock    # recommended
pipx install ownlock
pip install ownlock
curl -fsSL https://raw.githubusercontent.com/thebscolaro/ownlock/main/scripts/install.sh | bash

# Homebrew (clone once, or use the upcoming tap — see packaging/README.md)
brew install --formula packaging/homebrew/ownlock.rb
```

**Stop your AI agent from reading `.env` files:**

```bash
ownlock init
ownlock shield          # blocks .env / .ownlock reads in Cursor + Claude Code
ownlock guard --install-hook   # redacts secrets from agent tool output
ownlock status          # vault + shield + audit posture at a glance
```

No Docker. No cloud account. Works on macOS, Linux, and Windows.

**Why teams use it**

- **Agent sandboxes** — `ownlock run` injects secrets from disk into the child process; parent-shell `export` does not cross into Cursor/Codex/Claude Code sandboxes.
- **Agent safety** — `ownlock shield` writes ignore files + Claude `PreToolUse` hooks; `ownlock guard` pipes tool output through DLP redaction.
- **Per-secret policies** — `ownlock set KEY --policy confirm|session|open` gates access for high-risk secrets.
- **Team sync** — `ownlock share --team` writes a git-committable `.ownlock/team.olbundle`; teammates hydrate on `ownlock init`.
- **Commit `.env` with `vault("KEY")` references** — teammates clone and fill their local vault; no Slack DMs with secret lists.

---

## Quick start

```bash
pip install ownlock
ownlock init
```

`ownlock init` creates the vault. If you already have a `.env` in the directory, it offers to import secrets from it (and to rewrite the file to use `vault(...)` references) on the spot — that's the entire onboarding.

If you'd rather drive it manually:

```bash
ownlock set api-key
# Add to .env: MY_APP_KEY=vault("api-key")
ownlock run -- python app.py
```

---

## ownlock + your AI coding assistant

A surprising practical reason ownlock has stuck for me: **agentic sandboxes**.

Modern coding assistants (Cursor's background agents, OpenAI Codex, Claude Code, etc.) often run inside locked-down sandboxes that start with a fresh shell. Plain environment variables exported in your interactive shell rarely cross that boundary — the agent spawns its own session and your `export DATABASE_URL=...` is gone. **`export` and parent-shell env vars do not reach the sandbox**; the vault file on disk does.

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
- **`ownlock_status`** — vault summary via subprocess (`doctor` + `list --json`).
- **`ownlock_doctor`** — health check JSON (schema, KDF, passphrase source).
- **`ownlock_request_access`** — approval flow for policy-gated secrets (`confirm` / `session`).
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

## Get secrets into the vault

There's one command — `ownlock import` — that handles every shape of `.env` you might have:

```bash
ownlock import                       # auto-discover .env / .env.local / etc in cwd
ownlock import path/to/.env          # one file
ownlock import test.env .env         # multiple files (0.2+)
ownlock import -f .env -f .env.local # same via -f
ownlock import .env --rewrite        # plaintext: import, then rewrite file to vault(...)
ownlock import .env --values-from values.json  # non-interactive vault-ref fill
```

**Interactive pickers** (cyan numbered lists) show when you're in a TTY, did not pass `--yes`, and either several env files are selected or a single plaintext file has multiple keys. `--yes` skips all prompts. See [UPGRADE.md](UPGRADE.md#trying-import-locally-interactive-pickers) for examples.

**Upgrading from 0.1.x?** See **[UPGRADE.md](UPGRADE.md)** — command renames (`auto`/`bootstrap` → `import`), vault/KDF upgrades, and migration checklist.

`import` looks at the file and routes itself:

| File contents | What `import` does |
|---|---|
| Plain `KEY=VALUE` lines | Adds them to the vault. With `--rewrite`, also rewrites the file in place to `vault("KEY")` references (with a `0600` backup under `.ownlock/backups/`). |
| Already has `vault(...)` references | Prompts only for the keys that aren't in your vault yet — the teammate-onboarding case. Pair with `--values-from JSON` for non-interactive runs. |

`ownlock init` calls into this flow automatically when it sees a `.env` in the directory, so a teammate cloning the project and running `ownlock init` gets walked all the way to a working vault.

---

## Initialize a vault

| Command | Effect |
|---------|--------|
| `ownlock init` | Project vault at `./.ownlock/vault.db`. First run also creates the global vault and stores the passphrase in the keyring. **If a `.env` is in cwd, init offers to import secrets and rewrite the file to `vault(...)` references.** |
| `ownlock init --global` | Global vault only at `~/.ownlock/vault.db` (passphrase in keyring). |

```bash
ownlock init
# or global only:
ownlock init --global
```

**Teammate onboarding:** commit `.env` with lines like `API_KEY=vault("API_KEY")`. After clone, each dev runs `ownlock init` once — ownlock detects the references and prompts only for the keys missing from their local vault.

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
ownlock init        # init detects the existing .env and walks them through
# or, after the vault already exists:
ownlock import      # auto-detects vault() refs and prompts only for missing keys
```

Idempotent: re-running after another teammate adds a new vault reference asks for that one key only.

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

### Team sync vs policies

**Policies are not how you keep personal API tokens out of GitHub.**

| Feature | Purpose |
|---------|---------|
| `share --team` → `.ownlock/team.olbundle` | Encrypted **copy** of project-vault secrets for teammates/CI. Anyone with the **bundle passphrase** can decrypt into their own local vault. |
| `--policy open\|session\|confirm` | Local **read friction** after a secret is already in *your* vault (agents / `get` / `vault()`). |

Recommended model for “shared services only, not personal tokens”:

- Put **shared** credentials in the **project** vault (what `--team` exports).
- Keep **personal** API tokens in the **global** vault (`ownlock set --global`) or never in that project vault.
- Prefer named export: `ownlock share DB_URL STRIPE_KEY --team` instead of bare `share --team` (which dumps **all** project secrets).

```bash
ownlock share DB_URL STRIPE_KEY --team   # preferred
ownlock share --team                     # warns: exports entire project vault
```

### Agent support matrix

| Tool | What ownlock shields today |
|------|----------------------------|
| **Claude Code** | `.claudeignore` + `permissions.deny` + native `PreToolUse` / `PostToolUse` hooks (`.sh` on macOS/Linux; `.ps1` via PowerShell on Windows) |
| **Cursor** | `.cursorignore` + MCP (`ownlock-mcp`); Cursor `hooks.json` not wired yet |
| **Other agents** | Audit attribution when they call the CLI; use `ownlock run` / MCP so values never land in chat |

On Windows, Git Bash/WSL can still run the `.sh` hooks if you install them manually; the native install path is PowerShell.

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

Commands that accept `--global` / `--project`: `set`, `get`, `list`, `delete`, `import`, `scan`, `rekey`, `share`, `import-share`, and `export --example` (template lines from vault key names only). `run` and plain `export` resolve vault references from your `.env` file.

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

## rewrite-env and scan

```bash
ownlock rewrite-env -f .env   # rewrite an env file to use vault(...) without re-importing
ownlock scan .                # compare files against the project vault's secrets
ownlock scan . --global       # compare against ~/.ownlock/vault.db instead
```

`scan` walks the directory for plaintext copies of vault values. It uses the **project vault** (`.ownlock/vault.db` in cwd or a parent) when one exists; it does **not** silently fall back to your global vault — pass `--global` for that. Without a project vault, it still flags legacy `*.ownlock.bak` plaintext backups. Value comparison needs a vault with secrets and the correct passphrase (`OWNLOCK_PASSPHRASE` or keyring).

`rewrite-env` is useful when you've already populated the vault (e.g. via `ownlock set`) and just want to swap an existing `.env` over to references. For a fresh project, `ownlock import .env --rewrite` does both steps in one go.

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

Rendered values are inserted so the output file stays syntactically valid for common config formats. Use `format="..."` on a single `{{vault(...)}}` reference or pass `--raw` when you handle quoting yourself. See `ownlock render --help` for flags.

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
| `ownlock init` | Create project vault (first run also creates global + keyring). Offers to import an existing `.env` if found |
| `ownlock init --global` | Create global vault only |
| `ownlock set KEY` / `KEY=VALUE` | Store secret. `--from-file PATH`, `--editor` for multi-line values |
| `ownlock get KEY` | Print decrypted value |
| `ownlock list` | List secret names (`--json` for machine-readable metadata, no values) |
| `ownlock doctor` | Environment diagnostics (versions, vault paths, KDF status, `--json`) |
| `ownlock delete KEY` | Remove a secret |
| `ownlock rekey` | Re-encrypt at current KDF (`--upgrade-kdf`) and/or rotate passphrase (`--rotate-passphrase`) |
| `ownlock run -- CMD` | Resolve `.env`, inject secrets, redact stdout |
| `ownlock export` | Print resolved KEY=VALUE pairs (`--example` emits `KEY=vault("KEY")` lines from vault names only) |
| `ownlock import [FILE...]` | Get secrets into the vault. Auto-detects plaintext vs. `vault(...)` references. `--rewrite` to also convert the file. `--values-from JSON` for non-interactive vault-ref fill |
| `ownlock share KEYS -o FILE` | Export an encrypted bundle for a teammate (separate bundle passphrase) |
| `ownlock import-share FILE` | Import an encrypted bundle into the local vault |
| `ownlock rewrite-env` | Rewrite an existing env file to use `vault(...)` (without re-importing) |
| `ownlock scan DIR` | Scan for leaked secret values (`--max-file-bytes` skips huge files before reading) |
| `ownlock render [TEMPLATE]` | Render `*.template.*` files, substituting `{{vault(...)}}` with decrypted values |
| `ownlock install-hook` | Install a pre-commit hook that runs `ownlock scan` |
| `ownlock completion {bash,zsh,fish,pwsh}` | Print a shell completion script |

Add `--global` or `--project` to `set`, `get`, `list`, `delete`, `import`, `scan`, `rekey`, `share`, `import-share`, and `export --example` to override vault selection.

---

## How it works

- Secrets are encrypted with **AES-256-GCM** before storage; key derivation uses **PBKDF2-HMAC-SHA256**. Secret **names** are encrypted too (schema v3): the database stores an HMAC lookup id plus encrypted name blobs, so copying `vault.db` without the passphrase does not reveal key names like `API_KEY`. Iteration counts and ciphertext format are documented in [SECURITY.md](SECURITY.md).
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

`.ownlock/*` is gitignored by default (with `!.ownlock/team.olbundle` allowed), so the local vault never reaches CI on its own — you opt in if you want it. A typical team setup:

- Each developer runs `ownlock init` after cloning (or `ownlock import` to fill in `vault(...)` placeholders).
- CI sets the same env var names directly from the platform's secrets store. ownlock isn't installed on the runner.
- `ownlock scan` runs in pre-commit (`ownlock install-hook`) and in CI to refuse commits containing leaked vault values.

You can use ownlock in CI too — set `OWNLOCK_PASSPHRASE` from a runner secret and import a vault you manage outside git — but most teams find the dual-store model cleaner.

### CI integration examples

The pattern is always the same: **inject env vars the way your platform expects**, using the same names your app reads locally via `ownlock run`. ownlock does not need to be on the runner unless you deliberately store a vault there.

**GitHub Actions** — secrets become env vars; no ownlock install required:

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    env:
      DATABASE_URL: ${{ secrets.DATABASE_URL }}
      STRIPE_KEY: ${{ secrets.STRIPE_KEY }}
    steps:
      - uses: actions/checkout@v4
      - run: pytest

  # Optional: block commits that leak vault values into the repo
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install ownlock
      - run: ownlock scan . --yes
        env:
          OWNLOCK_PASSPHRASE: ${{ secrets.OWNLOCK_PASSPHRASE }}
```

The scan job needs `OWNLOCK_PASSPHRASE` only if you want ownlock to decrypt the vault and compare file contents against live secret values. For many teams, a lighter check (grep for `sk_live_`, AWS key patterns, etc.) plus `ownlock install-hook` locally is enough.

**Harness / other CD platforms** — same idea: map platform secrets to env vars in the pipeline stage. Harness doesn't expose secrets for arbitrary local dev pull (by design); that's why ownlock exists on the laptop. In CI, reference `${{ secrets.YOUR_SECRET }}` or the Harness equivalent — the app never knows the difference.

**Running tests with ownlock on the runner** (when you want one vault file managed outside git):

```yaml
- run: |
    echo "${{ secrets.OWNLOCK_VAULT_B64 }}" | base64 -d > .ownlock/vault.db
    chmod 600 .ownlock/vault.db
- run: ownlock run -- pytest
  env:
    OWNLOCK_PASSPHRASE: ${{ secrets.OWNLOCK_PASSPHRASE }}
```

Store the encrypted `vault.db` as a base64 blob in your secrets manager, rotate via `ownlock rekey`, and never commit `.ownlock/`.

**Pre-commit locally + CI scan** — belt and suspenders:

```bash
ownlock install-hook          # local: ownlock scan on every commit
# CI: ownlock scan . --yes    # catches anything that bypassed the hook
```

### What to commit vs keep local

| Commit to git | Keep local only |
|---------------|-----------------|
| `.env` with `vault("KEY")` references | `.ownlock/vault.db` (encrypted secrets) |
| `*.template.*` files with `{{vault("KEY")}}` | Plaintext `.env` backups under `.ownlock/backups/` |
| Application code that reads standard env vars | `OWNLOCK_PASSPHRASE` (use keyring locally, runner secret in CI) |

---

## Security

- **Encryption + KDF details, threat model, and the full security posture** live in [SECURITY.md](SECURITY.md).
- **get / export**: Both print secrets to stdout. Use in trusted environments only; prefer `ownlock run` to inject without printing.
- **Overwrite**: `set` and `import` overwrite existing values for the same key (and env); no append.
- **File permissions**: Restrict permissions on `~/.ownlock/` and `.ownlock/`. Project init adds `.ownlock/*` (and `!.ownlock/team.olbundle`) to `.gitignore` and writes backups under that directory with mode `0600`.
- **Reporting**: See [SECURITY.md](SECURITY.md#reporting-vulnerabilities).
- **Automated checks**: Bandit, pip-audit, security-focused tests, and subprocess smoke tests (`pytest -m smoke`) — see [SECURITY_TESTING.md](SECURITY_TESTING.md). Editable installs may skip CVE lookup for the ownlock package itself; dependencies are still audited.

---

## License

MIT
