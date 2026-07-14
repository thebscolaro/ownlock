#!/usr/bin/env bash
# Fill winget InstallerSha256 from a GitHub Release asset.
# Usage: scripts/fill_winget_sha.sh v0.2.2
set -euo pipefail
TAG="${1:?tag required, e.g. v0.2.2}"
VER="${TAG#v}"
ASSET="ownlock-windows-x64.exe"
URL="https://github.com/thebscolaro/ownlock/releases/download/${TAG}/${ASSET}"
TMP="$(mktemp)"
curl -fsSL "$URL" -o "$TMP"
if command -v sha256sum >/dev/null 2>&1; then
  SHA="$(sha256sum "$TMP" | awk '{print toupper($1)}')"
else
  SHA="$(shasum -a 256 "$TMP" | awk '{print toupper($1)}')"
fi
rm -f "$TMP"
MANIFEST="packaging/winget/thebscolaro.ownlock.installer.${VER}.yaml"
if [[ ! -f "$MANIFEST" ]]; then
  echo "Missing $MANIFEST" >&2
  exit 1
fi
# Portable sed: replace placeholder or existing 64-hex SHA
python3 - "$MANIFEST" "$SHA" <<'PY'
import re, sys
path, sha = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()
text2, n = re.subn(
    r"(InstallerSha256:\s*)([A-Fa-f0-9]{64}|REPLACE_AFTER_BINARY_RELEASE)",
    rf"\g<1>{sha}",
    text,
    count=1,
)
if n != 1:
    raise SystemExit(f"Could not patch InstallerSha256 in {path}")
open(path, "w", encoding="utf-8").write(text2)
print(f"Updated {path} -> {sha}")
PY
echo "Next: fork microsoft/winget-pkgs and copy packaging/winget/thebscolaro.ownlock*.${VER}.yaml"
