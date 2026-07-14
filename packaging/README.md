# Packaging & distribution

## Install paths (users)

| Method | Command | Status |
|--------|---------|--------|
| PyPI / uv | `uv tool install ownlock` | Live (`0.2.2`) |
| pipx | `pipx install ownlock` | Live |
| curl installer | `curl -fsSL …/scripts/install.sh \| bash` | Live (uv/pip; binary when release assets exist) |
| Homebrew formula | `brew install --formula ./packaging/homebrew/ownlock.rb` | Works today against PyPI 0.2.2 |
| Homebrew tap | `brew tap thebscolaro/ownlock && brew install ownlock` | Needs you to create `homebrew-ownlock` repo |
| homebrew-core | `brew install ownlock` | Later (notability) |
| winget | `winget install thebscolaro.ownlock` | After binaries + winget-pkgs PR |
| GitHub Action | `uses: thebscolaro/ownlock/action@…` | Composite action in-repo |

## Maintainers

1. **Tag a release** (`vX.Y.Z`) → CI publishes to PyPI (existing `ci.yml` publish job).
2. **Release binaries** workflow builds Linux/macOS/Windows assets and uploads them to the GitHub Release.
3. **Release announce** workflow opens a Dev.to draft from `docs/blog/X.Y.Z-*.md` (needs `DEVTO_API_KEY`).
4. Bump `packaging/homebrew/ownlock.rb` `url` / `sha256` / `version` from PyPI.
5. Run `scripts/fill_winget_sha.sh vX.Y.Z` and PR into `microsoft/winget-pkgs`.

See [docs/maintainers/LAUNCH.md](../docs/maintainers/LAUNCH.md).
