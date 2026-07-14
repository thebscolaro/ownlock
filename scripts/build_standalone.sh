#!/usr/bin/env bash
# Build a one-file ownlock binary with PyInstaller (local smoke-test for the
# Release binaries workflow). Prefer CI for shipping artifacts.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python -m pip install --upgrade "pip>=26"
pip install -e ".[mcp]" "pyinstaller>=6.3"
pyinstaller \
  --noconfirm \
  --clean \
  --onefile \
  --name ownlock \
  --collect-all keyring \
  --collect-all cryptography \
  --hidden-import ownlock.cli \
  --hidden-import ownlock.mcp_server \
  ownlock/__main__.py
echo "Binary: ${ROOT}/dist/ownlock"
