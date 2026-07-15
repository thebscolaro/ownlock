#!/usr/bin/env bash
# Run the ownlock test suite inside a disposable Linux container.
# Prefer podman (daemonless); fall back to docker. Containers share the Linux
# kernel only — they cannot reproduce macOS or Windows hook interpreters.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${OWNLOCK_TEST_IMAGE:-python:3.12-slim-bookworm}"
PYTEST_ARGS=${*:-tests/ -q -m "not smoke"}

ENGINE=""
if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
  ENGINE=podman
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  ENGINE=docker
fi

if [ -z "$ENGINE" ]; then
  if command -v podman >/dev/null 2>&1; then
    echo "podman is on PATH but not ready (try: podman machine start)." >&2
  fi
  if command -v docker >/dev/null 2>&1; then
    echo "docker is on PATH but the daemon is not running (start Docker Desktop)." >&2
  fi
  if ! command -v podman >/dev/null 2>&1 && ! command -v docker >/dev/null 2>&1; then
    echo "Neither podman nor docker found on PATH." >&2
  fi
  echo "Install/start one of them, or run pytest on the host." >&2
  exit 1
fi

echo "Using $ENGINE with $IMAGE"
# Mount the repo read-write so editable install + .pyc/caches can write under /src.
# Install jq as a static binary (avoids apt I/O issues in some Desktop VMs).
exec "$ENGINE" run --rm -t \
  -v "$ROOT:/src:Z" \
  -w /src \
  "$IMAGE" \
  bash -lc "
    set -euo pipefail
    if ! command -v jq >/dev/null 2>&1; then
      python - <<'PY'
import pathlib, stat, sys, urllib.request
arch = {\"aarch64\": \"arm64\", \"arm64\": \"arm64\", \"x86_64\": \"amd64\", \"amd64\": \"amd64\"}.get(
    __import__(\"os\").uname().machine
)
if not arch:
    sys.exit(f\"unsupported arch for jq: {__import__('os').uname().machine}\")
url = f\"https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux-{arch}\"
dest = pathlib.Path(\"/usr/local/bin/jq\")
urllib.request.urlretrieve(url, dest)
dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
print(f\"installed jq ({arch}) -> {dest}\")
PY
    fi
    python -m pip install -q --upgrade 'pip>=26'
    pip install -q -e '.[mcp,dev]'
    pip install -q pytest
    pytest $PYTEST_ARGS
  "
