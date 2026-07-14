#!/usr/bin/env bash
# Install ownlock via uv (preferred), pipx/pip, or a GitHub Release binary.
#
#   curl -fsSL https://raw.githubusercontent.com/thebscolaro/ownlock/main/scripts/install.sh | bash
#   OWNLOCK_INSTALL_METHOD=binary curl -fsSL ... | bash
#   OWNLOCK_VERSION=0.2.2 OWNLOCK_INSTALL_METHOD=binary ... | bash
set -euo pipefail

INSTALL_METHOD="${OWNLOCK_INSTALL_METHOD:-auto}"
OWNLOCK_VERSION="${OWNLOCK_VERSION:-}"
REPO="${OWNLOCK_REPO:-thebscolaro/ownlock}"
BIN_DIR="${OWNLOCK_BIN_DIR:-${HOME}/.local/bin}"

install_uv() {
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="${HOME}/.local/bin:${HOME}/.cargo/bin:${PATH}"
}

detect_binary_asset() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m | tr '[:upper:]' '[:lower:]')"
  case "$os" in
    linux*)
      case "$arch" in
        x86_64|amd64) echo "ownlock-linux-x64" ;;
        aarch64|arm64) echo "ownlock-linux-arm64" ;;
        *) return 1 ;;
      esac
      ;;
    darwin*)
      case "$arch" in
        arm64|aarch64) echo "ownlock-macos-arm64" ;;
        x86_64|amd64) echo "ownlock-macos-x64" ;;
        *) return 1 ;;
      esac
      ;;
    mingw*|msys*|cygwin*)
      echo "ownlock-windows-x64.exe"
      ;;
    *) return 1 ;;
  esac
}

verify_sha256() {
  local file="$1"
  local sumfile="$2"
  if command -v sha256sum >/dev/null 2>&1; then
    echo "$(awk '{print $1}' "$sumfile")  $file" | sha256sum -c -
  elif command -v shasum >/dev/null 2>&1; then
    echo "$(awk '{print $1}' "$sumfile")  $file" | shasum -a 256 -c -
  else
    echo "Neither sha256sum nor shasum found; cannot verify binary." >&2
    return 1
  fi
}

install_binary() {
  local tag asset url dest sum_url
  if [ -n "$OWNLOCK_VERSION" ]; then
    tag="v${OWNLOCK_VERSION#v}"
  else
    tag="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])")"
  fi
  asset="$(detect_binary_asset)" || {
    echo "No binary asset mapping for this OS; falling back to pip." >&2
    return 1
  }
  url="https://github.com/${REPO}/releases/download/${tag}/${asset}"
  sum_url="${url}.sha256"
  mkdir -p "$BIN_DIR"
  case "$asset" in
    *.exe) dest="${BIN_DIR}/ownlock.exe" ;;
    *) dest="${BIN_DIR}/ownlock" ;;
  esac
  local tmp dest_tmp sum_tmp
  tmp="$(mktemp -d)"
  dest_tmp="${tmp}/${asset}"
  sum_tmp="${tmp}/${asset}.sha256"
  echo "Downloading ${url}"
  if ! curl -fsSL "$url" -o "$dest_tmp"; then
    echo "Binary not found for ${tag} (${asset}). Build via Release binaries workflow first." >&2
    rm -rf "$tmp"
    return 1
  fi
  if ! curl -fsSL "$sum_url" -o "$sum_tmp"; then
    echo "Checksum file missing for ${asset}; refusing to install without verification." >&2
    rm -rf "$tmp"
    return 1
  fi
  if ! (cd "$tmp" && verify_sha256 "$asset" "${asset}.sha256"); then
    echo "SHA-256 verification failed for ${asset}." >&2
    rm -rf "$tmp"
    return 1
  fi
  mv "$dest_tmp" "$dest"
  chmod +x "$dest" 2>/dev/null || true
  rm -rf "$tmp"
  echo "Installed ${dest} (SHA-256 verified)"
  echo "Ensure ${BIN_DIR} is on your PATH."
}

if [ "$INSTALL_METHOD" = "binary" ]; then
  install_binary
elif command -v uv >/dev/null 2>&1; then
  if [ -n "$OWNLOCK_VERSION" ]; then
    uv tool install "ownlock==${OWNLOCK_VERSION}"
  else
    uv tool install ownlock
  fi
elif [ "$INSTALL_METHOD" = "uv" ]; then
  install_uv
  uv tool install ownlock
elif command -v pipx >/dev/null 2>&1; then
  pipx install ownlock
elif [ "$INSTALL_METHOD" = "auto" ] && install_binary 2>/dev/null; then
  :
else
  python3 -m pip install --user ownlock
fi

echo "Done. Run: ownlock --version"
