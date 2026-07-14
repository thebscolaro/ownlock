# Install ownlock like any other CLI tool

## Install paths

| Method | Command |
|--------|---------|
| **uv** (recommended) | `uv tool install ownlock` |
| **pipx** | `pipx install ownlock` |
| **pip** | `pip install ownlock` |
| **curl** | `curl -fsSL …/scripts/install.sh \| bash` |
| **Homebrew** (interim tap) | `brew tap thebscolaro/ownlock && brew install ownlock` |
| **winget** | `winget install thebscolaro.ownlock` (after binary release) |

Target: bare `brew install ownlock` via homebrew-core once notability criteria are met.

## CI

Use `ownlock/setup-action` with `OWNLOCK_PASSPHRASE` and `OWNLOCK_BUNDLE_PASSPHRASE` to hydrate vaults from `.ownlock/team.olbundle` in GitHub Actions.

## Standalone binary

`scripts/build_standalone.sh` builds a PyInstaller one-file binary for platforms without Python tooling.
