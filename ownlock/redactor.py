"""Redact secret values from text streams and subprocesses."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from typing import IO


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
        work with pipes on Windows).
        """
        merged_env = {**os.environ, **env}

        proc = subprocess.Popen(
            cmd,
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
