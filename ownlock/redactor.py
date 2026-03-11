"""Redact secret values from text streams and subprocesses."""

from __future__ import annotations

import os
import subprocess
import sys
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

    def run_process(
        self,
        cmd: list[str],
        env: dict[str, str],
        *,
        stdout: IO[str] = sys.stdout,
        stderr: IO[str] = sys.stderr,
    ) -> int:
        """Run *cmd* with *env*, streaming redacted stdout/stderr.

        Returns the process exit code.
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

        import selectors

        sel = selectors.DefaultSelector()
        if proc.stdout:
            sel.register(proc.stdout, selectors.EVENT_READ, stdout)
        if proc.stderr:
            sel.register(proc.stderr, selectors.EVENT_READ, stderr)

        open_streams = 2
        while open_streams > 0:
            for key, _ in sel.select(timeout=0.1):
                stream: IO[str] = key.fileobj  # type: ignore[assignment]
                dest: IO[str] = key.data
                line = stream.readline()
                if line:
                    dest.write(self.redact(line))
                    dest.flush()
                else:
                    sel.unregister(stream)
                    open_streams -= 1

        sel.close()
        proc.wait()
        return proc.returncode
