"""Allow `python -m ownlock` (same as the `ownlock` console script)."""

from ownlock.cli import app

if __name__ == "__main__":
    app()
