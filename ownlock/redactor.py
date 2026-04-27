"""Redact secret values from text streams and subprocesses."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
from typing import IO


def _resolve_cmd_for_subprocess(cmd: list[str], merged_env: dict[str, str]) -> list[str]:
    """Copy *cmd*; on Windows resolve argv0 via PATH/PATHEXT (e.g. ``npm`` → ``npm.cmd``)."""
    cmd_resolved = list(cmd)
    if sys.platform != "win32" or not cmd_resolved:
        return cmd_resolved
    resolved = shutil.which(cmd_resolved[0], path=merged_env.get("PATH"))
    if resolved:
        cmd_resolved[0] = resolved
    return cmd_resolved


class SecretRedactor:
    """Replace known secret values with [REDACTED:name] in text."""

    def __init__(self, secrets: dict[str, str]) -> None:
        self._replacements: list[tuple[str, str]] = []
        for name, value in secrets.items():
            if value:
                self._replacements.append((value, f"[REDACTED:{name}]"))
        self._replacements.sort(key=lambda t: -len(t[0]))

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
        merged_env = {**os.environ, **env}
        cmd_resolved = _resolve_cmd_for_subprocess(cmd, merged_env)

        proc = subprocess.Popen(
            cmd_resolved,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=merged_env,
            text=True,
            bufsize=1,
        )

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
