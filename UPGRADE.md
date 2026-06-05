# Upgrading to ownlock 0.2.0

This guide is for users on **0.1.x** moving to **0.2.0**. Your existing `vault.db` and `.env` files keep working; most changes are additive or auto-migrate on first use.

## Quick checklist

```bash
pip install -U ownlock
ownlock doctor --json    # schema, KDF, vault paths — no secrets printed
```

| Step | When | Command |
|------|------|---------|
| Upgrade package | Always | `pip install -U ownlock` |
| Upgrade KDF (optional, recommended) | `doctor` shows stale KDF | `ownlock rekey --upgrade-kdf --yes` |
| Migrate secret names (automatic) | First vault open after upgrade | Any command that opens the vault with your passphrase |
| Replace removed commands | Scripts still call old names | See [Command changes](#command-changes) |
| Remove legacy backups | `doctor` or `scan` flags `*.ownlock.bak` | Delete or move files; rotate secrets if any were committed |

---

## Command changes (0.1 → 0.2)

| 0.1 | 0.2 | Notes |
|-----|-----|-------|
| `ownlock auto` | `ownlock import --rewrite` | Import plaintext keys, rewrite file to `vault("KEY")` |
| `ownlock auto -f a -f b` | `ownlock import a b --rewrite` or `ownlock import -f a -f b --rewrite` | Multiple files supported |
| `ownlock bootstrap` | `ownlock import` | Same routing when `.env` already has `vault(...)` refs |
| `ownlock bootstrap --values-from v.json` | `ownlock import --values-from v.json` | Non-interactive teammate fill |
| `ownlock scan .` (used global vault from `$HOME`) | `ownlock scan .` uses **project** vault only; `--global` for global | `find_project_vault` no longer treats `~/.ownlock/vault.db` as a project vault |
| (none) | `ownlock rekey` | Rotate passphrase and/or upgrade KDF |
| (none) | `ownlock share` / `ownlock import-share` | Encrypted bundles for handing secrets to a teammate |

**Breaking:** `auto` and `bootstrap` are **removed**. Update shell aliases, Makefile targets, and CI scripts.

---

## Vault upgrades (automatic vs manual)

### Schema v3 — encrypted secret names

On **first open** with your passphrase, ownlock migrates legacy vaults so secret **names** are no longer stored in cleartext. No extra command.

Check after migration:

```bash
ownlock doctor --json   # global_vault.schema_version should be 3
```

### KDF 200k → 600k (optional but recommended)

Old vaults still decrypt at 200k iterations. New secrets use 600k. To re-encrypt everything at the current default:

```bash
ownlock rekey --upgrade-kdf --yes
```

`doctor` prints a tip when `kdf_stale` is true.

### Passphrase rotation

```bash
export OWNLOCK_NEW_PASSPHRASE='your-new-passphrase'
ownlock rekey --rotate-passphrase --yes
```

Or run `ownlock rekey` interactively.

---

## `.env` and backups

- **New backups** live under `.ownlock/backups/` (mode `0600`), not `*.ownlock.bak` next to the file.
- **`import --rewrite`** and **`rewrite-env`** still create backups before rewriting.
- If you have old `.env.ownlock.bak` files, run `ownlock scan` — delete them and rotate any secrets that were ever committed.

---

## Security behavior changes

- **`ownlock run` no longer passes `OWNLOCK_PASSPHRASE` to the child process.** Scripts that spawned `ownlock get` from inside a `run` child need another approach (pass resolved env only).
- **Redaction** in `ownlock run` is improved for common stdout/stderr leak patterns.

See [SECURITY.md](SECURITY.md) for crypto details.

---

## Trying `import` locally (interactive pickers)

The **cyan numbered file picker** appears when:

- You are in a **TTY** (real terminal, not piped CI)
- You did **not** pass `--yes`
- **Two or more** env files are in play

Ways to trigger it:

```bash
# Auto-discover .env, .env.local, etc. in cwd
ownlock import

# Explicit multiple files (0.2+)
ownlock import test.env .env
ownlock import -f test.env -f .env

# Then answer prompts: file index(es), then key index(es) for a single plaintext file
```

**Will not show the picker:**

```bash
ownlock import test.env .env --rewrite --yes   # --yes skips all prompts
ownlock import .env --rewrite --yes              # single file: key picker also skipped
```

**Single-file key picker** (plaintext `.env`, TTY, no `--yes`):

```bash
ownlock import .env    # lists keys in cyan; enter 1,3 or all
```

Install from the repo while developing:

```bash
pip install -e ".[mcp,dev]"
ownlock --help
```

---

## MCP (optional)

```bash
pip install "ownlock[mcp]"
```

`ownlock doctor` reports `mcp_importable: true` when the package is available. MCP is optional; the core CLI does not require it.

---

## Need 0.1.x behavior?

Pin the old release:

```bash
pip install 'ownlock==0.1.11'
```

We recommend moving to 0.2 for security fixes and unified `import`.
