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
| `ownlock render [TEMPLATE]` | Render `*.template.*` files, substituting `{{vault(...)}}` with decrypted values |

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
