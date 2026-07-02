"""Redact secret values from text streams and subprocesses."""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import threading
import urllib.parse
from typing import IO

# Don't redact values shorter than this — too many false positives. Common
# words and short hex strings ("ok", "true", "abc") would be replaced with
# ``[REDACTED:NAME]`` and make logs unreadable. The threshold is conservative;
# real API keys and connection strings are well above this length.
_MIN_REDACT_LENGTH = 8

# Environment variables that ownlock uses to drive its own decrypt path. These
# must NEVER be inherited by commands launched via ``ownlock run``: the master
# passphrase would let the child re-spawn ownlock and decrypt the entire vault.
# Resolved secret values from .env still flow through (they're added to the
# child env after these are stripped).
_OWNLOCK_INTERNAL_ENV_VARS = frozenset({
    "OWNLOCK_PASSPHRASE",
    "OWNLOCK_NEW_PASSPHRASE",
})


class CommandNotFoundError(Exception):
    """Raised when ``ownlock run`` cannot execute the requested command."""

    def __init__(self, command: str) -> None:
        self.command = command
        super().__init__(command)


def _sanitize_parent_env(parent: dict[str, str]) -> dict[str, str]:
    """Return *parent* env with ownlock-internal variables removed."""
    return {k: v for k, v in parent.items() if k not in _OWNLOCK_INTERNAL_ENV_VARS}


def _resolve_cmd_for_subprocess(cmd: list[str], merged_env: dict[str, str]) -> list[str]:
    """Copy *cmd*; on Windows resolve argv0 via PATH/PATHEXT (e.g. ``npm`` → ``npm.cmd``)."""
    cmd_resolved = list(cmd)
    if sys.platform != "win32" or not cmd_resolved:
        return cmd_resolved
    resolved = shutil.which(cmd_resolved[0], path=merged_env.get("PATH"))
    if resolved:
        cmd_resolved[0] = resolved
    return cmd_resolved


def _value_variants(value: str) -> list[str]:
    """Return common encodings of *value* that should also be redacted.

    A child process can leak a secret in encoded form (a JWT lib base64url-
    encodes credentials, a webhook handler URL-quotes them, a JSON logger
    escapes them). The variants here are common enough that redacting them
    has caught real bugs in CI without too many false positives.

    Variants:
      * raw value
      * base64 (standard, no padding) and base64url (no padding)
      * URL-percent-encoded
      * JSON-escaped (the inner ``"..."`` form, no surrounding quotes)
      * bytes-style ``utf-8`` round-trip (in case a tool emits ``str(bytes)``)

    Empty / sub-threshold variants are dropped. Duplicates collapse so we
    only register each variant once per secret.
    """
    raw_bytes = value.encode("utf-8")
    candidates = {value}

    # base64 (with and without padding) and base64url-no-padding
    try:
        b64 = base64.b64encode(raw_bytes).decode("ascii")
        candidates.add(b64)
        candidates.add(b64.rstrip("="))
        b64u = base64.urlsafe_b64encode(raw_bytes).decode("ascii")
        candidates.add(b64u)
        candidates.add(b64u.rstrip("="))
    except (ValueError, TypeError):
        pass

    # URL-percent-encoded (quote_plus picks up '+' for spaces; quote keeps them)
    try:
        candidates.add(urllib.parse.quote(value, safe=""))
        candidates.add(urllib.parse.quote_plus(value))
    except (UnicodeError, TypeError):
        pass

    # JSON-escaped form (drop the surrounding quotes that json.dumps adds)
    try:
        encoded = json.dumps(value, ensure_ascii=False)
        if len(encoded) >= 2 and encoded[0] == '"' and encoded[-1] == '"':
            candidates.add(encoded[1:-1])
        ascii_encoded = json.dumps(value, ensure_ascii=True)
        if len(ascii_encoded) >= 2 and ascii_encoded[0] == '"' and ascii_encoded[-1] == '"':
            candidates.add(ascii_encoded[1:-1])
    except (TypeError, ValueError):
        pass

    return [v for v in candidates if v and len(v) >= _MIN_REDACT_LENGTH]


class SecretRedactor:
    """Replace known secret values with [REDACTED:name] in text.

    Each registered secret expands to a small set of common encodings
    (base64, URL-percent, JSON-escaped) so logs / response bodies that pass
    a value through one of those transforms still get redacted.
    """

    def __init__(self, secrets: dict[str, str]) -> None:
        # ``seen`` deduplicates variants across multiple secrets so the same
        # text isn't replaced twice with different placeholders. Longer
        # variants register first (sorted later) so they win over shorter
        # ones that happen to be substrings.
        replacements: list[tuple[str, str]] = []
        seen: set[str] = set()
        for name, value in secrets.items():
            if not value or len(value) < _MIN_REDACT_LENGTH:
                continue
            placeholder = f"[REDACTED:{name}]"
            for variant in _value_variants(value):
                if variant in seen:
                    continue
                seen.add(variant)
                replacements.append((variant, placeholder))
        # Replace longest variants first so a JSON-escaped form beats the raw
        # value when both happen to appear (e.g. raw is a substring of the
        # escaped form).
        replacements.sort(key=lambda t: -len(t[0]))
        self._replacements = replacements

    def redact(self, text: str) -> str:
        """Return *text* with all secret values replaced."""
        for value, placeholder in self._replacements:
            text = text.replace(value, placeholder)
        return text

    def _stream_reader(
        self,
        stream: IO[str],
        dest: IO[str],
    ) -> None:
        """Read lines from stream, redact, and write to dest."""
        for line in stream:
            dest.write(self.redact(line))
            dest.flush()

    def run_process(
        self,
        cmd: list[str],
        env: dict[str, str],
        *,
        stdout: IO[str] = sys.stdout,
        stderr: IO[str] = sys.stderr,
    ) -> int:
        """Run *cmd* with *env*, streaming redacted stdout/stderr.

        Uses threading for cross-platform compatibility (select() does not
        work with pipes on Windows). On Windows, the executable is resolved
        with :func:`shutil.which` on ``cmd[0]`` using the merged ``PATH`` so
        bare names like ``npm`` match ``npm.cmd``.
        """
        merged_env = {**_sanitize_parent_env(os.environ), **env}
        cmd_resolved = _resolve_cmd_for_subprocess(cmd, merged_env)

        try:
            proc = subprocess.Popen(
                cmd_resolved,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=merged_env,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            raise CommandNotFoundError(
                cmd_resolved[0] if cmd_resolved else (cmd[0] if cmd else "")
            ) from None

        t1 = threading.Thread(
            target=self._stream_reader,
            args=(proc.stdout, stdout),
            daemon=True,
        )
        t2 = threading.Thread(
            target=self._stream_reader,
            args=(proc.stderr, stderr),
            daemon=True,
        )
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        return proc.wait()
