"""ownlock CLI — lightweight secrets manager."""

from __future__ import annotations

import getpass
import json
import os
import re
from datetime import datetime, UTC
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar

import typer
from rich.console import Console
from rich.table import Table

from ownlock.keyring_util import resolve_passphrase, store_passphrase
from ownlock.vault import VaultManager, GLOBAL_VAULT_PATH, PROJECT_VAULT_DIR, PROJECT_VAULT_DB

F = TypeVar("F", bound=Callable[..., Any])


def _safe_command(fn: F) -> F:
    """Catch known exceptions and print clean messages; no traceback."""

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except ValueError as e:
            if "OWNLOCK" in str(e) or "passphrase" in str(e).lower():
                console.print(
                    "[red]No vault passphrase found. Run 'ownlock init' first or set OWNLOCK_PASSPHRASE.[/red]"
                )
                raise typer.Exit(1)
            raise
        except Exception as e:
            from cryptography.exceptions import InvalidTag

            if isinstance(e, typer.Exit):
                raise  # Preserve intentional exit code (e.g. from run, scan)
            if isinstance(e, InvalidTag):
                console.print("[red]Invalid passphrase.[/red]")
                raise typer.Exit(1)
            if isinstance(e, KeyError) and e.args:
                msg = str(e.args[0]) if e.args else "Secret not found in vault."
                console.print(f"[red]{msg}[/red]")
                raise typer.Exit(1)
            console.print("[red]An error occurred.[/red]")
            raise typer.Exit(1)

    return wrapper  # type: ignore[return-value]


def _format_vault_path(path: Path) -> str:
    """Return a user-safe display path (e.g. ~/.ownlock/vault.db)."""
    try:
        resolved = path.resolve()
        home = Path.home()
        if resolved.is_relative_to(home):
            return "~" + str(resolved)[len(str(home)) :]
    except (OSError, RuntimeError):
        pass
    return str(path)


def _validate_env_file(path: Path) -> Path:
    """Resolve path; if relative, ensure under cwd."""
    resolved = path.resolve()
    if not path.is_absolute():
        try:
            resolved.relative_to(Path.cwd())
        except ValueError:
            console.print("[red]Path must be inside the current directory.[/red]")
            raise typer.Exit(1)
    return resolved


def _validate_scan_dir(path: Path) -> Path:
    """Resolve path; if relative, ensure under cwd."""
    resolved = path.resolve()
    if not path.is_absolute():
        try:
            resolved.relative_to(Path.cwd())
        except ValueError:
            console.print("[red]Directory must be inside the current directory.[/red]")
            raise typer.Exit(1)
    return resolved


SECRET_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def _validate_secret_name(name: str) -> None:
    """Reject names with path-like or invalid characters."""
    if not SECRET_NAME_RE.match(name):
        console.print("[red]Secret name must use only letters, numbers, hyphens, and underscores.[/red]")
        raise typer.Exit(1)


def _is_valid_secret_name(name: str) -> bool:
    """Return True if name is valid (for non-fatal checks like import)."""
    return bool(SECRET_NAME_RE.match(name))


def _is_tty() -> bool:
    """Return True if running in an interactive terminal."""
    try:
        import sys

        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        return False


_LEGACY_BACKUP_SUFFIX = ".ownlock.bak"


def _backup_dir_for(env_file: Path) -> Path:
    """Pick the safe backup directory for *env_file*.

    Backups contain the user's original plaintext .env values, so they go
    under ``.ownlock/backups/`` which is covered by the default ``.ownlock/``
    gitignore entry. Prefers the project vault's ``.ownlock`` directory when
    one exists; otherwise falls back to ``<cwd>/.ownlock/backups``.
    """
    proj_vault = VaultManager.find_project_vault()
    if proj_vault is not None:
        return proj_vault.parent / "backups"
    return Path.cwd() / PROJECT_VAULT_DIR / "backups"


def _write_env_backup(env_file: Path, content: str) -> Path:
    """Write *content* as a timestamped backup under ``.ownlock/backups/``.

    Mode ``0600`` on POSIX. Ensures the parent ``.ownlock/`` directory is in
    ``.gitignore`` before writing so the plaintext is never accidentally
    committed.
    """
    _ensure_gitignore()
    backup_dir = _backup_dir_for(env_file)
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup_path = backup_dir / f"{env_file.name}.{timestamp}.bak"
    backup_path.write_text(content, encoding="utf-8")
    if os.name == "posix":
        try:
            os.chmod(backup_path, 0o600)
        except OSError:
            pass
    return backup_path


def _import_env_file_into_vault(env_file: Path, env: str, vm: VaultManager) -> int:
    """Import KEY=VALUE pairs from env_file into the given vault manager."""
    count = 0
    for line in env_file.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip()
        if key and value and _is_valid_secret_name(key):
            vm.set(key, value, env)
            count += 1
    return count


def _rewrite_env_lines_to_vault_syntax(
    lines: list[str],
    existing: dict[str, str],
    env: str,
) -> tuple[list[str], int]:
    """Rewrite env lines to use ``vault()`` for keys present in *existing*.

    Skips comments, blank lines, invalid key names, lines already using ``vault()``,
    and keys not in *existing*.
    """
    new_lines: list[str] = []
    changed = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            new_lines.append(line)
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        raw_value = value.strip()
        if not _is_valid_secret_name(key):
            new_lines.append(line)
            continue
        if raw_value.startswith("vault(\""):
            new_lines.append(line)
            continue
        if key not in existing:
            new_lines.append(line)
            continue
        if env == "default":
            vault_expr = f'vault(\"{key}\")'
        else:
            vault_expr = f'vault(\"{key}\", env=\"{env}\")'
        new_lines.append(f"{key}={vault_expr}")
        changed += 1
    return new_lines, changed


app = typer.Typer(
    name="ownlock",
    help="Lightweight secrets manager — encrypted vault, env injection, stdout redaction.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def init(
    global_vault: bool = typer.Option(False, "--global", help="Create global vault at ~/.ownlock/ (passphrase in keyring)."),
) -> None:
    """Create a new vault."""
    project_path = Path.cwd() / PROJECT_VAULT_DIR / PROJECT_VAULT_DB

    if global_vault:
        # Global-only: create global vault and keyring
        if GLOBAL_VAULT_PATH.exists():
            console.print(f"[yellow]Vault already exists at {_format_vault_path(GLOBAL_VAULT_PATH)}[/yellow]")
            raise typer.Exit(0)
        passphrase = getpass.getpass("Choose a vault passphrase: ")
        if not passphrase:
            console.print("[red]Passphrase cannot be empty.[/red]")
            raise typer.Exit(1)
        confirm = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirm:
            console.print("[red]Passphrases do not match.[/red]")
            raise typer.Exit(1)
        vm = VaultManager.init_vault(GLOBAL_VAULT_PATH, passphrase)
        vm.close()
        ok, keyring_err = store_passphrase(passphrase)
        if ok:
            console.print("[dim]Passphrase saved to system keyring.[/dim]")
        else:
            detail = f" ({keyring_err})" if keyring_err else ""
            console.print(
                f"[dim]Could not save to keyring{detail}. Use OWNLOCK_PASSPHRASE env var.[/dim]"
            )
        console.print(f"[green]Vault created at {_format_vault_path(GLOBAL_VAULT_PATH)}[/green]")
        return

    # Project vault (keyring-first: ensure global + keyring on first run)
    if project_path.exists():
        console.print(f"[yellow]Vault already exists at {_format_vault_path(project_path)}[/yellow]")
        raise typer.Exit(0)

    if not GLOBAL_VAULT_PATH.exists():
        # First run: create global vault and keyring, then project vault with same passphrase
        passphrase = getpass.getpass("Choose a vault passphrase: ")
        if not passphrase:
            console.print("[red]Passphrase cannot be empty.[/red]")
            raise typer.Exit(1)
        confirm = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirm:
            console.print("[red]Passphrases do not match.[/red]")
            raise typer.Exit(1)
        vm_global = VaultManager.init_vault(GLOBAL_VAULT_PATH, passphrase)
        vm_global.close()
        ok, keyring_err = store_passphrase(passphrase)
        if ok:
            console.print("[dim]Passphrase saved to system keyring.[/dim]")
        else:
            detail = f" ({keyring_err})" if keyring_err else ""
            console.print(
                f"[dim]Could not save to keyring{detail}. Use OWNLOCK_PASSPHRASE env var.[/dim]"
            )
        vm_proj = VaultManager.init_vault(project_path, passphrase)
        vm_proj.close()
        _ensure_gitignore()
        console.print(
            f"[green]Vault created at {_format_vault_path(project_path)}[/green] "
            f"[dim](passphrase in keyring; global vault at {_format_vault_path(GLOBAL_VAULT_PATH)} also created)[/dim]"
        )
        return

    # Global exists: create only project vault using keyring passphrase
    passphrase = resolve_passphrase()
    vm = VaultManager.init_vault(project_path, passphrase)
    vm.close()
    _ensure_gitignore()
    console.print(f"[green]Vault created at {_format_vault_path(project_path)}[/green]")


def _read_value_from_editor(name: str) -> str:
    """Open ``$EDITOR`` on a temp file and return its contents.

    The temp file is created with mode 0600 on POSIX and unlinked after read,
    even if the editor is killed mid-edit.
    """
    import shlex
    import subprocess
    import tempfile

    editor = os.environ.get("OWNLOCK_EDITOR") or os.environ.get("VISUAL") or os.environ.get("EDITOR")
    if not editor:
        if os.name == "nt":
            editor = "notepad"
        else:
            editor = "vi"

    fd, tmp_name = tempfile.mkstemp(prefix=f"ownlock-{name}-", suffix=".secret")
    try:
        os.close(fd)
        if os.name == "posix":
            try:
                os.chmod(tmp_name, 0o600)
            except OSError:
                pass

        # shlex.split lets users put flags in $EDITOR (e.g. "code --wait").
        argv = shlex.split(editor) + [tmp_name]
        subprocess.run(argv, check=True)  # noqa: S603 (argv list, no shell)

        return Path(tmp_name).read_text(encoding="utf-8")
    finally:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass


@app.command("set")
@_safe_command
def set_secret(
    key_value: str = typer.Argument(..., help="Secret name, or NAME=VALUE for inline."),
    env: str = typer.Option("default", "--env", "-e", help="Environment (default, production, etc.)."),
    global_vault: bool = typer.Option(False, "--global", help="Use global vault."),
    project: bool = typer.Option(False, "--project", help="Use project vault at cwd."),
    from_file: Optional[Path] = typer.Option(
        None,
        "--from-file",
        help="Read the secret value from this file (preserves newlines, "
        "useful for PEM keys / JSON service-account files).",
    ),
    from_editor: bool = typer.Option(
        False,
        "--editor",
        help="Open $EDITOR (or $VISUAL) to type a multi-line secret. "
        "Temp file is mode 0600 and is unlinked when the editor closes.",
    ),
    strip: bool = typer.Option(
        True,
        "--strip/--no-strip",
        help="With --from-file or --editor: strip a single trailing newline from the value.",
    ),
) -> None:
    """Store a secret in the vault.

    Three input modes:

    * ``ownlock set NAME=value`` — inline.
    * ``ownlock set NAME`` — interactive single-line prompt (hidden).
    * ``ownlock set NAME --from-file path`` — read from disk (multi-line ok).
    * ``ownlock set NAME --editor`` — open $EDITOR for multi-line input.
    """
    if "=" in key_value and not (from_file or from_editor):
        name, _, value = key_value.partition("=")
    elif from_file is not None or from_editor:
        # Multi-line modes use the bare key form: `ownlock set NAME --from-file ...`
        name = key_value
        if "=" in key_value:
            console.print(
                "[red]Use either NAME=VALUE or --from-file/--editor, not both.[/red]"
            )
            raise typer.Exit(1)
        if from_file is not None and from_editor:
            console.print("[red]--from-file and --editor are mutually exclusive.[/red]")
            raise typer.Exit(1)
        if from_file is not None:
            file_path = _validate_env_file(from_file)
            if not file_path.exists():
                console.print(f"[red]File not found: {from_file}[/red]")
                raise typer.Exit(1)
            value = file_path.read_text(encoding="utf-8")
        else:
            value = _read_value_from_editor(key_value)
        if strip and value.endswith("\n") and not value.endswith("\n\n"):
            value = value[:-1]
    else:
        name = key_value
        value = getpass.getpass(f"Enter value for '{name}': ")

    if not name or not value:
        console.print("[red]Name and value cannot be empty.[/red]")
        raise typer.Exit(1)
    _validate_secret_name(name)

    passphrase = resolve_passphrase()
    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)

    with VaultManager(vault_path, passphrase) as vm:
        vm.set(name, value, env)

    console.print(f"[green]Secret '{name}' stored (env={env}).[/green]")


@app.command("get")
@_safe_command
def get_secret(
    name: str = typer.Argument(..., help="Secret name."),
    env: str = typer.Option("default", "--env", "-e"),
    global_vault: bool = typer.Option(False, "--global", help="Use global vault."),
    project: bool = typer.Option(False, "--project", help="Use project vault at cwd."),
) -> None:
    """Retrieve and print a decrypted secret."""
    passphrase = resolve_passphrase()
    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)

    with VaultManager(vault_path, passphrase) as vm:
        value = vm.get(name, env)

    if value is None:
        console.print(f"[red]Secret '{name}' not found (env={env}).[/red]")
        raise typer.Exit(1)

    typer.echo(value)


@app.command("list")
@_safe_command
def list_secrets(
    env: Optional[str] = typer.Option(None, "--env", "-e"),
    global_vault: bool = typer.Option(False, "--global", help="Use global vault."),
    project: bool = typer.Option(False, "--project", help="Use project vault at cwd."),
    as_json: bool = typer.Option(False, "--json", help="Print JSON array of name/env/timestamps (no secret values)."),
) -> None:
    """List stored secret names (never values)."""
    passphrase = resolve_passphrase()
    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)

    with VaultManager(vault_path, passphrase) as vm:
        secrets = vm.list_secrets(env)

    if not secrets:
        if as_json:
            typer.echo("[]")
        else:
            console.print("[dim]No secrets stored.[/dim]")
        return

    if as_json:
        payload = [
            {
                "name": s["name"],
                "env": s["env"],
                "created_at": s["created_at"],
                "updated_at": s["updated_at"],
            }
            for s in secrets
        ]
        typer.echo(json.dumps(payload, indent=2))
        return

    table = Table(title="Secrets")
    table.add_column("Name")
    table.add_column("Env")
    table.add_column("Updated")
    for s in secrets:
        table.add_row(s["name"], s["env"], s["updated_at"][:19])
    console.print(table)


def _passphrase_source() -> str:
    """Identify which source would resolve the passphrase right now.

    Mirrors :func:`ownlock.keyring_util.resolve_passphrase`'s precedence
    (env var > keyring > prompt) but does not return the value itself.
    """
    if os.environ.get("OWNLOCK_PASSPHRASE"):
        return "env var"
    try:
        from ownlock.keyring_util import get_passphrase

        if get_passphrase():
            return "keyring"
    except Exception:
        return "keyring (unavailable)"
    return "would prompt"


def _vault_health(vault_path: Path) -> dict[str, Any]:
    """Return a dict describing a vault's existence + meta, no values exposed."""
    from ownlock.crypto import KDF_ITERATIONS_CURRENT

    info: dict[str, Any] = {
        "path": str(vault_path),
        "exists": vault_path.exists(),
    }
    if not info["exists"]:
        return info
    # Open without a passphrase by reading meta directly via SQLite. We avoid
    # decrypting anything; meta rows are plaintext.
    import sqlite3

    try:
        conn = sqlite3.connect(str(vault_path))
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute("SELECT key, value FROM meta")
            meta = {row["key"]: row["value"] for row in cursor.fetchall()}
        except sqlite3.OperationalError:
            meta = {}  # legacy vault without meta table
        try:
            secret_count = conn.execute("SELECT COUNT(*) AS n FROM secrets").fetchone()["n"]
        except sqlite3.OperationalError:
            secret_count = 0
        conn.close()
    except sqlite3.DatabaseError as e:
        info["error"] = str(e)
        return info

    schema_version = int(meta.get("schema_version", "1"))
    kdf_iterations = int(meta.get("kdf_iterations", "200000"))
    info.update(
        {
            "schema_version": schema_version,
            "kdf_algo": meta.get("kdf_algo", "PBKDF2-HMAC-SHA256"),
            "kdf_iterations": kdf_iterations,
            "kdf_stale": kdf_iterations < KDF_ITERATIONS_CURRENT,
            "secret_count": secret_count,
        }
    )
    return info


def _gather_doctor_state() -> dict[str, Any]:
    """Collect everything ``ownlock doctor`` reports, no secret values."""
    import importlib.util
    import sys
    from importlib.metadata import version as pkg_version

    pv = VaultManager.find_project_vault()
    state: dict[str, Any] = {
        "ownlock_version": pkg_version("ownlock"),
        "python_version": sys.version.split()[0],
        "python_executable": sys.executable,
        "global_vault": _vault_health(GLOBAL_VAULT_PATH),
        "project_vault": _vault_health(pv) if pv else {"path": None, "exists": False},
        "ownlock_passphrase_env_set": bool(os.environ.get("OWNLOCK_PASSPHRASE")),
        "passphrase_source": _passphrase_source(),
        "mcp_importable": importlib.util.find_spec("mcp.server.fastmcp") is not None,
    }
    try:
        from ownlock.keyring_util import get_passphrase

        state["keyring_passphrase_stored"] = bool(get_passphrase())
    except Exception as e:
        state["keyring_passphrase_stored"] = None
        state["keyring_error"] = str(e)

    # Stale plaintext leftovers in cwd that ownlock scan would also flag.
    cwd = Path.cwd()
    stale_tmp: list[str] = []
    legacy_baks: list[str] = []
    try:
        for path in cwd.rglob("*"):
            if any(part in {".git", "node_modules", ".venv", ".ownlock"} for part in path.parts):
                continue
            if not path.is_file():
                continue
            if path.name.endswith(_LEGACY_BACKUP_SUFFIX):
                legacy_baks.append(str(path))
            elif path.name.startswith(".") and ".ownlock-tmp" in path.name:
                stale_tmp.append(str(path))
    except OSError:
        pass
    state["legacy_backups_in_cwd"] = legacy_baks
    state["stale_render_tmp_files"] = stale_tmp

    # .gitignore coverage (best-effort: just check the literal substring).
    gitignore = cwd / ".gitignore"
    if gitignore.exists():
        try:
            text = gitignore.read_text(encoding="utf-8", errors="ignore")
            state["gitignore_covers_ownlock"] = ".ownlock" in text
        except OSError:
            state["gitignore_covers_ownlock"] = None
    else:
        state["gitignore_covers_ownlock"] = False

    return state


@app.command("doctor")
def doctor(
    as_json: bool = typer.Option(
        False, "--json", help="Emit machine-readable JSON instead of human-readable output."
    ),
) -> None:
    """Print environment diagnostics (versions, vault paths, no secret values)."""
    from ownlock.crypto import KDF_ITERATIONS_CURRENT

    state = _gather_doctor_state()

    if as_json:
        typer.echo(json.dumps(state, indent=2, default=str))
        return

    console.print(f"[bold]ownlock[/bold] {state['ownlock_version']}")
    console.print(
        f"Python {state['python_version']} — {state['python_executable']}"
    )

    def _fmt_vault(label: str, info: dict[str, Any]) -> None:
        path = info.get("path")
        if path is None:
            console.print(f"{label}: (none found from cwd)")
            return
        if not info.get("exists"):
            console.print(f"{label}: {path} — missing")
            return
        line = f"{label}: {path} — exists"
        if "schema_version" in info:
            line += f", schema v{info['schema_version']}"
            line += f", {info['kdf_algo']} {info['kdf_iterations']:,} iters"
            if info.get("kdf_stale"):
                line += "  [yellow](stale)[/yellow]"
            line += f", {info['secret_count']} secret(s)"
        console.print(line)

    _fmt_vault("Global vault", state["global_vault"])
    _fmt_vault("Project vault", state["project_vault"])

    console.print(
        f"OWNLOCK_PASSPHRASE: {'set' if state['ownlock_passphrase_env_set'] else 'not set'}"
    )
    keyring_state = state.get("keyring_passphrase_stored")
    if keyring_state is None:
        console.print("Keyring passphrase: unavailable (error reading keyring)")
    else:
        console.print(
            f"Keyring passphrase: {'stored' if keyring_state else 'not stored'}"
        )
    console.print(f"Passphrase resolved from: {state['passphrase_source']}")

    if state["legacy_backups_in_cwd"]:
        console.print(
            f"[yellow]Legacy plaintext backups (*.ownlock.bak) found:[/yellow] "
            f"{len(state['legacy_backups_in_cwd'])} — move or delete these "
            f"(run [bold]ownlock scan[/bold] for details)."
        )
    if state["stale_render_tmp_files"]:
        console.print(
            f"[yellow]Stale render temp files (.ownlock-tmp) found:[/yellow] "
            f"{len(state['stale_render_tmp_files'])} — delete these manually."
        )

    if state["gitignore_covers_ownlock"] is False:
        console.print(
            "[yellow].gitignore does not cover .ownlock/ — run "
            "[bold]ownlock init[/bold] in this directory or add the entry "
            "manually.[/yellow]"
        )

    # Suggest rekey when KDF is below current default.
    stale_globally = state["global_vault"].get("kdf_stale")
    stale_project = state["project_vault"].get("kdf_stale")
    if stale_globally or stale_project:
        target_flag = "--global" if stale_globally and not stale_project else "--project"
        console.print(
            f"[dim]Tip: this vault uses KDF iterations below the current "
            f"default ({KDF_ITERATIONS_CURRENT:,}). Run "
            f"[bold]ownlock rekey --upgrade-kdf {target_flag} --yes[/bold] to "
            "upgrade.[/dim]"
        )

    console.print(
        f"MCP package importable: {'yes' if state['mcp_importable'] else 'no'} "
        "(pip install 'ownlock[mcp]')"
    )


def _backup_vault_file(vault_path: Path) -> Path:
    """Copy *vault_path* to ``.ownlock/backups/vault.db.backup-<UTC>`` (mode 0600).

    Used by ``rekey`` so a partial / failed rekey can never corrupt the live
    vault: the live file is untouched until the SQL transaction commits, and
    the backup copy is left in place after success for the user to delete
    once they're confident.
    """
    backup_dir = vault_path.parent / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup_path = backup_dir / f"{vault_path.name}.backup-{timestamp}"
    backup_path.write_bytes(vault_path.read_bytes())
    if os.name == "posix":
        try:
            os.chmod(backup_path, 0o600)
        except OSError:
            pass
    return backup_path


@app.command("rekey")
@_safe_command
def rekey(
    upgrade_kdf: bool = typer.Option(
        False,
        "--upgrade-kdf",
        help="Re-encrypt all secrets at the current default KDF iterations. Keeps the same passphrase.",
    ),
    rotate_passphrase: bool = typer.Option(
        False,
        "--rotate-passphrase",
        help="Rotate the vault passphrase. Reads OWNLOCK_NEW_PASSPHRASE if set, otherwise prompts.",
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompts."),
    no_keyring: bool = typer.Option(
        False,
        "--no-keyring",
        help="With --rotate-passphrase: do not update the system keyring with the new passphrase.",
    ),
    global_vault: bool = typer.Option(False, "--global", help="Use global vault."),
    project: bool = typer.Option(False, "--project", help="Use project vault at cwd."),
) -> None:
    """Re-encrypt vault secrets, optionally with new passphrase or new KDF parameters.

    With no flags in a TTY: interactive flow that asks whether to upgrade KDF
    and/or rotate the passphrase. The vault file is copied to
    ``.ownlock/backups/`` before any change so a failed rekey can never
    corrupt the live vault.
    """
    from ownlock.crypto import KDF_ITERATIONS_CURRENT

    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)
    if not vault_path.exists():
        console.print(f"[red]Vault not found at {_format_vault_path(vault_path)}.[/red]")
        raise typer.Exit(1)

    passphrase = resolve_passphrase()

    with VaultManager(vault_path, passphrase) as vm:
        meta = vm.get_meta()
        schema = vm.schema_version()
        current_iters = vm.kdf_iterations()
        iter_summary = vm.secret_iterations_summary()
        secret_count = sum(iter_summary.values())
        envs = sorted({s["env"] for s in vm.list_secrets()})

    is_kdf_stale = current_iters < KDF_ITERATIONS_CURRENT or any(
        i < KDF_ITERATIONS_CURRENT for i in iter_summary
    )

    # Decide actions: explicit flags win; otherwise interactive prompts.
    do_upgrade_kdf = upgrade_kdf
    do_rotate = rotate_passphrase

    if not (upgrade_kdf or rotate_passphrase):
        if _is_tty() and not yes:
            console.print(f"[bold]Vault[/bold]: {_format_vault_path(vault_path)}")
            console.print(
                f"  schema:        v{schema}"
                + ("" if schema == 2 else "  [yellow](current: v2)[/yellow]")
            )
            console.print(
                f"  kdf:           {meta.get('kdf_algo', 'PBKDF2-HMAC-SHA256')}, "
                f"{current_iters:,} iterations"
                + ("" if not is_kdf_stale else f"  [yellow](current: {KDF_ITERATIONS_CURRENT:,})[/yellow]")
            )
            if iter_summary:
                breakdown = ", ".join(
                    f"{count} at {iters:,}" for iters, count in sorted(iter_summary.items())
                )
                console.print(f"  secrets:       {secret_count} ({breakdown})")
            else:
                console.print("  secrets:       0")
            if envs:
                console.print(f"  environments:  {', '.join(envs)}")

            do_upgrade_kdf = typer.confirm(
                "Upgrade KDF to current parameters?",
                default=is_kdf_stale,
            )
            do_rotate = typer.confirm(
                "Rotate passphrase to a new one?",
                default=False,
            )
        else:
            console.print(
                "[red]Pass --upgrade-kdf and/or --rotate-passphrase, or run interactively.[/red]"
            )
            raise typer.Exit(1)

    if not (do_upgrade_kdf or do_rotate):
        console.print("[dim]Nothing to do.[/dim]")
        return

    new_passphrase = passphrase
    if do_rotate:
        env_pp = os.environ.get("OWNLOCK_NEW_PASSPHRASE")
        if env_pp:
            new_passphrase = env_pp
        else:
            if not _is_tty() and not yes:
                console.print(
                    "[red]Cannot rotate passphrase non-interactively without "
                    "OWNLOCK_NEW_PASSPHRASE.[/red]"
                )
                raise typer.Exit(1)
            new_passphrase = getpass.getpass("New vault passphrase: ")
            if not new_passphrase:
                console.print("[red]Passphrase cannot be empty.[/red]")
                raise typer.Exit(1)
            confirm = getpass.getpass("Confirm new passphrase: ")
            if new_passphrase != confirm:
                console.print("[red]Passphrases do not match.[/red]")
                raise typer.Exit(1)

    target_iters = KDF_ITERATIONS_CURRENT  # always re-encrypt at current default

    # Idempotent fast-path: nothing to do if already at current params and not rotating.
    if (
        not do_rotate
        and current_iters == KDF_ITERATIONS_CURRENT
        and iter_summary == {KDF_ITERATIONS_CURRENT: secret_count}
        and schema == 2
    ):
        console.print(
            f"[dim]Vault is already at schema v2, KDF {KDF_ITERATIONS_CURRENT:,}. "
            "Nothing to upgrade.[/dim]"
        )
        return

    if _is_tty() and not yes:
        action_parts: list[str] = []
        if do_upgrade_kdf and current_iters != KDF_ITERATIONS_CURRENT:
            action_parts.append(
                f"raise KDF iterations to {KDF_ITERATIONS_CURRENT:,}"
            )
        if do_rotate:
            action_parts.append("rotate the passphrase")
        action_str = " and ".join(action_parts) if action_parts else "re-encrypt secrets"
        if not typer.confirm(
            f"Re-encrypt {secret_count} secret(s) to {action_str}?", default=True
        ):
            console.print("[dim]Cancelled.[/dim]")
            raise typer.Exit(1)

    backup_path = _backup_vault_file(vault_path)
    console.print(f"[dim]Backed up vault to {backup_path}.[/dim]")

    try:
        with VaultManager(vault_path, passphrase) as vm:
            count = vm.rekey(new_passphrase, target_iterations=target_iters)
    except Exception as e:
        console.print(
            f"[red]Rekey failed: {e}. Live vault is unchanged. "
            f"Backup at {backup_path}.[/red]"
        )
        raise typer.Exit(1)

    console.print(f"[green]Re-encrypted {count} secret(s).[/green]")

    # Two-phase keyring update: only after the SQL transaction succeeds.
    if do_rotate and not no_keyring:
        ok, err = store_passphrase(new_passphrase)
        if ok:
            console.print("[dim]Updated keyring with new passphrase.[/dim]")
        else:
            detail = f" ({err})" if err else ""
            console.print(
                f"[yellow]Could not update keyring{detail}. "
                "Set OWNLOCK_PASSPHRASE to the new passphrase or update the keyring manually.[/yellow]"
            )

    console.print(
        f"[dim]Backup left at {backup_path}; remove once you've verified the new vault works.[/dim]"
    )


@app.command()
@_safe_command
def delete(
    name: str = typer.Argument(..., help="Secret name."),
    env: str = typer.Option("default", "--env", "-e"),
    global_vault: bool = typer.Option(False, "--global", help="Use global vault."),
    project: bool = typer.Option(False, "--project", help="Use project vault at cwd."),
) -> None:
    """Delete a secret from the vault."""
    passphrase = resolve_passphrase()
    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)

    with VaultManager(vault_path, passphrase) as vm:
        removed = vm.delete(name, env)

    if removed:
        console.print(f"[green]Deleted '{name}' (env={env}).[/green]")
    else:
        console.print(f"[yellow]Secret '{name}' not found (env={env}).[/yellow]")


@app.command()
@_safe_command
def run(
    env_file: Path = typer.Option(Path(".env"), "-f", "--file", help="Path to .env file."),
    env: str = typer.Option("default", "--env", "-e", help="Environment for vault lookups."),
    no_redact: bool = typer.Option(False, "--no-redact-stdout", help="Disable stdout redaction."),
    render_templates: Optional[list[Path]] = typer.Option(
        None,
        "--render",
        help=(
            "Template file to render before running (repeat for multiple). "
            "Auto-discovery is intentionally NOT done here to avoid rendering "
            "untrusted templates in the current directory. Use `ownlock render` "
            "by itself if you want discovery."
        ),
    ),
    render_cleanup: bool = typer.Option(
        False,
        "--render-cleanup",
        help=(
            "With --render: unlink rendered output files after the command exits. "
            "Note: combined with --force, this can remove a pre-existing file you "
            "overwrote."
        ),
    ),
    force_render: bool = typer.Option(
        False,
        "--force",
        help="With --render: skip the gitignore safety check for rendered outputs.",
    ),
    raw_render: bool = typer.Option(
        False,
        "--raw",
        help="With --render: insert values verbatim (disable format-aware escaping).",
    ),
    command: list[str] = typer.Argument(None, help="Command to run."),
) -> None:
    """Resolve .env vault() references, inject secrets, and run a command."""
    if not command:
        console.print("[red]No command specified. Use: ownlock run -- your-command[/red]")
        raise typer.Exit(1)

    from ownlock.resolver import resolve_env_file
    from ownlock.redactor import SecretRedactor

    env_file = _validate_env_file(env_file)
    passphrase = resolve_passphrase()
    resolved, secret_names = resolve_env_file(env_file, passphrase, env=env)

    rendered_outputs: list[Path] = []
    if render_templates:
        rendered_outputs = _render_explicit_templates(
            render_templates,
            passphrase,
            default_env=env,
            force=force_render,
            raw=raw_render,
        )

    if no_redact:
        secrets_for_redaction: dict[str, str] = {}
    else:
        secrets_for_redaction = {k: resolved[k] for k in secret_names if k in resolved}

    redactor = SecretRedactor(secrets_for_redaction)
    try:
        exit_code = redactor.run_process(command, resolved)
    finally:
        if render_cleanup and rendered_outputs:
            for p in rendered_outputs:
                try:
                    p.unlink()
                except OSError:
                    pass
    raise typer.Exit(exit_code)


@app.command("render")
@_safe_command
def render(
    template: Optional[Path] = typer.Argument(
        None,
        help="Template file to render. Omit to discover all *.template.* under cwd.",
    ),
    out: Optional[Path] = typer.Option(
        None,
        "-o",
        "--out",
        help="Destination path (single-template mode only).",
    ),
    env: str = typer.Option("default", "--env", "-e", help="Vault environment for lookups."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print planned actions; write nothing."),
    force: bool = typer.Option(False, "--force", help="Skip gitignore safety check for outputs."),
    raw: bool = typer.Option(
        False,
        "--raw",
        help=(
            "Insert secret values verbatim (no format escaping). By default, "
            "values are escaped for the output file's format (JSON, XML, YAML, "
            "TOML, INI, .env, shell, HCL) based on its extension. Per-reference "
            "format=\"...\" always wins."
        ),
    ),
) -> None:
    """Render *.template.* files, replacing {{vault(...)}} with decrypted values."""
    from ownlock.resolver import VaultLookup
    from ownlock.templates import (
        detect_format,
        discover_templates,
        find_unmatched_vault_refs,
        is_path_gitignored,
        render_text,
        template_output_path,
        write_atomic,
    )

    passphrase = resolve_passphrase()

    if template is not None:
        template = _validate_env_file(template)
        if not template.exists():
            console.print("[red]Template not found.[/red]")
            raise typer.Exit(1)
        if out is not None:
            dst = _validate_env_file(out)
        else:
            try:
                dst = template_output_path(template)
            except ValueError as e:
                console.print(f"[red]{e}[/red]")
                raise typer.Exit(1)
        pairs: list[tuple[Path, Path]] = [(template, dst)]
    else:
        if out is not None:
            console.print("[red]--out is only valid when rendering a single template.[/red]")
            raise typer.Exit(1)
        discovered = discover_templates(Path.cwd())
        if not discovered:
            console.print("[dim]No *.template.* files found under current directory.[/dim]")
            return
        pairs = [(t, template_output_path(t)) for t in discovered]

    if dry_run:
        for src, dst in pairs:
            fmt = "raw" if raw else detect_format(dst)
            console.print(f"  {src} -> {dst} [{fmt}]")
        return

    rendered = 0
    with VaultLookup(passphrase) as lookup:
        for src, dst in pairs:
            text = src.read_text(encoding="utf-8")
            default_format = "raw" if raw else detect_format(dst)
            new_text, refs = render_text(
                text, lookup, default_env=env, default_format=default_format
            )
            if refs == 0:
                console.print(f"[dim]{src}: no vault() references; skipping.[/dim]")
                continue
            if not force and not is_path_gitignored(dst):
                console.print(
                    f"[red]{dst} does not appear to be gitignored. Refusing to write.[/red]"
                )
                console.print(
                    f"[dim]Add '{dst.name}' (or the full path) to .gitignore, "
                    "or re-run with --force.[/dim]"
                )
                raise typer.Exit(1)
            write_atomic(dst, new_text)
            console.print(
                f"[green]Rendered {src} -> {dst} "
                f"({refs} value(s), format={default_format}).[/green]"
            )
            _warn_unmatched(src, new_text, find_unmatched_vault_refs)
            rendered += 1

    if rendered == 0:
        console.print("[dim]Nothing rendered.[/dim]")


def _warn_unmatched(src: Path, rendered_text: str, finder) -> None:
    """Print a yellow warning for any ``{{vault(`` fragments left in *rendered_text*."""
    leftovers = finder(rendered_text)
    if not leftovers:
        return
    console.print(
        f"[yellow]Warning: {src} contains {len(leftovers)} "
        "malformed vault() reference(s) (wrong quotes or missing braces). "
        "These were left as literal text in the rendered output:[/yellow]"
    )
    for line_num, excerpt in leftovers[:3]:
        console.print(f"[yellow]  line {line_num}: {excerpt}[/yellow]")
    if len(leftovers) > 3:
        console.print(f"[yellow]  ... and {len(leftovers) - 3} more[/yellow]")


def _render_explicit_templates(
    templates: list[Path],
    passphrase: str,
    *,
    default_env: str = "default",
    force: bool = False,
    raw: bool = False,
) -> list[Path]:
    """Render each path in *templates*. Returns paths that were written.

    Unlike ``ownlock render`` with no args, this does NOT discover templates.
    Callers (``ownlock run --render``) must list every template explicitly to
    avoid rendering untrusted files that happen to live under the cwd.
    """
    from ownlock.resolver import VaultLookup
    from ownlock.templates import (
        detect_format,
        find_unmatched_vault_refs,
        is_path_gitignored,
        render_text,
        template_output_path,
        write_atomic,
    )

    resolved_pairs: list[tuple[Path, Path]] = []
    for t in templates:
        src = _validate_env_file(t)
        if not src.exists():
            console.print(f"[red]Template not found: {t}[/red]")
            raise typer.Exit(1)
        try:
            dst = template_output_path(src)
        except ValueError as e:
            console.print(f"[red]{e}[/red]")
            raise typer.Exit(1)
        resolved_pairs.append((src, dst))

    written: list[Path] = []
    with VaultLookup(passphrase) as lookup:
        for src, dst in resolved_pairs:
            text = src.read_text(encoding="utf-8")
            default_format = "raw" if raw else detect_format(dst)
            new_text, refs = render_text(
                text, lookup, default_env=default_env, default_format=default_format
            )
            if refs == 0:
                console.print(f"[dim]{src}: no vault() references; skipping.[/dim]")
                continue
            if not force and not is_path_gitignored(dst):
                console.print(
                    f"[red]{dst} does not appear to be gitignored. Refusing to write.[/red]"
                )
                console.print("[dim]Add it to .gitignore or re-run with --force.[/dim]")
                raise typer.Exit(1)
            write_atomic(dst, new_text)
            console.print(
                f"[green]Rendered {src} -> {dst} "
                f"({refs} value(s), format={default_format}).[/green]"
            )
            _warn_unmatched(src, new_text, find_unmatched_vault_refs)
            written.append(dst)
    return written


@app.command("export")
@_safe_command
def export_env(
    env_file: Path = typer.Option(Path(".env"), "-f", "--file"),
    env: str = typer.Option("default", "--env", "-e"),
    fmt: str = typer.Option(
        "env",
        "--format",
        help="Output format: env, docker (ignored with --example; example lines are always env-style vault() references).",
    ),
    example: bool = typer.Option(
        False,
        "--example",
        help="Emit KEY=vault(...) lines for keys in the vault only; does not read .env.",
    ),
    global_vault: bool = typer.Option(False, "--global", help="Use global vault (with --example)."),
    project: bool = typer.Option(False, "--project", help="Use project vault (with --example)."),
) -> None:
    """Print resolved KEY=VALUE pairs to stdout."""
    from ownlock.resolver import resolve_env_file

    if example:
        passphrase = resolve_passphrase()
        vault_path = _resolve_vault_path(global_vault=global_vault, project=project)
        with VaultManager(vault_path, passphrase) as vm:
            rows = vm.list_secrets(env)
        for s in sorted(rows, key=lambda x: x["name"]):
            name = s["name"]
            if env == "default":
                typer.echo(f'{name}=vault("{name}")')
            else:
                typer.echo(f'{name}=vault("{name}", env="{env}")')
        return

    env_file = _validate_env_file(env_file)
    passphrase = resolve_passphrase()
    resolved, _ = resolve_env_file(env_file, passphrase, env=env)

    def _quote_value(v: str) -> str:
        if not any(c in v for c in "= \n\t\"'\\"):
            return v
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'

    for key, value in resolved.items():
        if fmt == "docker":
            typer.echo(f"{key}={_quote_value(value)}")
        else:
            typer.echo(f"{key}={value}")


@app.command("import")
@_safe_command
def import_env(
    env_file: Path = typer.Argument(..., help="Path to plaintext .env to import."),
    env: str = typer.Option("default", "--env", "-e"),
    global_vault: bool = typer.Option(False, "--global", help="Use global vault."),
    project: bool = typer.Option(False, "--project", help="Use project vault at cwd."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Import without interactive key selection."),
) -> None:
    """Bulk import secrets from a plaintext .env file."""
    env_file = _validate_env_file(env_file)
    if not env_file.exists():
        console.print("[red]File not found.[/red]")
        raise typer.Exit(1)

    passphrase = resolve_passphrase()
    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)

    # Interactive key picker in TTY mode (unless --yes)
    if _is_tty() and not yes:
        # Preview keys without writing anything yet
        candidates: list[tuple[str, str]] = []
        for line in env_file.read_text().splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if key and value and _is_valid_secret_name(key):
                candidates.append((key, value))

        if not candidates:
            console.print("[dim]No valid KEY=VALUE entries found to import.[/dim]")
            return

        console.print(f"Found {len(candidates)} key(s) in {env_file}:")
        for idx, (key, _val) in enumerate(candidates, start=1):
            console.print(f"  {idx}. {key}")

        choice = typer.prompt(
            "Enter indexes to import (comma-separated, 'all' for all, blank = cancel)",
            default="all",
        ).strip()
        if not choice:
            console.print("[dim]Import cancelled.[/dim]")
            raise typer.Exit(1)

        selected_indexes: list[int] = []
        if choice.lower() == "all":
            selected_indexes = list(range(1, len(candidates) + 1))
        else:
            for part in choice.split(","):
                part = part.strip()
                if not part:
                    continue
                try:
                    idx = int(part)
                except ValueError:
                    console.print(f"[red]Invalid selection '{part}'.[/red]")
                    raise typer.Exit(1)
                if idx < 1 or idx > len(candidates):
                    console.print(f"[red]Selection {idx} is out of range.[/red]")
                    raise typer.Exit(1)
                selected_indexes.append(idx)

        # Deduplicate while preserving order, map back to keys
        seen: set[int] = set()
        selected_keys: list[str] = []
        for idx in selected_indexes:
            if idx not in seen:
                seen.add(idx)
                key, _ = candidates[idx - 1]
                selected_keys.append(key)

        with VaultManager(vault_path, passphrase) as vm:
            count = 0
            for key, value in candidates:
                if key in selected_keys:
                    vm.set(key, value, env)
                    count += 1
    else:
        # Non-interactive or --yes: import all valid keys
        with VaultManager(vault_path, passphrase) as vm:
            count = _import_env_file_into_vault(env_file, env, vm)

    console.print(f"[green]Imported {count} secrets into vault (env={env}).[/green]")


_COMPLETION_SHELLS = {"bash", "zsh", "fish", "pwsh", "powershell"}


@app.command("completion")
def completion(
    shell: str = typer.Argument(
        ...,
        help="Shell to generate completion for: bash, zsh, fish, pwsh.",
    ),
) -> None:
    """Print a shell completion script.

    Source the output to enable tab-completion of ownlock subcommands and
    options. Examples:

    \b
    Bash:        eval "$(ownlock completion bash)"
    Zsh:         eval "$(ownlock completion zsh)"
    Fish:        ownlock completion fish | source
    PowerShell:  ownlock completion pwsh | Out-String | Invoke-Expression

    cmd.exe is not supported (no installable-completion framework). Windows
    users on cmd retain full ownlock functionality, just without
    autocomplete.
    """
    shell_norm = shell.lower()
    # Accept "powershell" as an alias for "pwsh" since users may type either.
    if shell_norm == "powershell":
        shell_norm = "pwsh"
    if shell_norm not in {"bash", "zsh", "fish", "pwsh"}:
        console.print(
            f"[red]Unsupported shell '{shell}'. "
            "Supported: bash, zsh, fish, pwsh.[/red]"
        )
        raise typer.Exit(1)

    # Click's shell_completion expects "powershell" as its name even though
    # we accept "pwsh" on the command line for ergonomics.
    click_shell = "powershell" if shell_norm == "pwsh" else shell_norm

    from click.shell_completion import get_completion_class
    from typer.main import get_command

    klass = get_completion_class(click_shell)
    if klass is None:
        console.print(f"[red]No completion class available for {shell_norm}.[/red]")
        raise typer.Exit(1)

    cli = get_command(app)
    inst = klass(
        cli=cli,
        ctx_args={},
        prog_name="ownlock",
        complete_var="_OWNLOCK_COMPLETE",
    )
    typer.echo(inst.source())


_GIT_HOOK_TEMPLATE = """#!/usr/bin/env bash
# Installed by `ownlock install-hook`.
# Runs `ownlock scan` to refuse commits containing leaked vault values.
set -e
exec ownlock scan .
"""


_PRE_COMMIT_SNIPPET = """  - repo: local
    hooks:
      - id: ownlock-scan
        name: ownlock scan
        entry: ownlock scan .
        language: system
        pass_filenames: false
"""


@app.command("install-hook")
@_safe_command
def install_hook(
    git_hook: bool = typer.Option(
        False,
        "--git-hook",
        help="Write a raw .git/hooks/pre-commit script (default if no .pre-commit-config.yaml exists).",
    ),
    pre_commit: bool = typer.Option(
        False,
        "--pre-commit",
        help="Append the ownlock-scan snippet to .pre-commit-config.yaml.",
    ),
    force: bool = typer.Option(
        False, "--force", help="Overwrite an existing pre-commit hook."
    ),
) -> None:
    """Install a pre-commit hook that runs ``ownlock scan`` before every commit.

    Auto-detects: if a ``.pre-commit-config.yaml`` exists, appends an
    ``ownlock-scan`` repo block to it; otherwise writes
    ``.git/hooks/pre-commit``. Pass ``--git-hook`` or ``--pre-commit`` to
    force one mode.
    """
    cwd = Path.cwd()
    pre_commit_yaml = cwd / ".pre-commit-config.yaml"
    git_dir = cwd / ".git"

    if pre_commit and git_hook:
        console.print("[red]--pre-commit and --git-hook are mutually exclusive.[/red]")
        raise typer.Exit(1)

    use_pre_commit = pre_commit or (not git_hook and pre_commit_yaml.exists())

    if use_pre_commit:
        if not pre_commit_yaml.exists():
            pre_commit_yaml.write_text("repos:\n", encoding="utf-8")
        text = pre_commit_yaml.read_text(encoding="utf-8")
        if "id: ownlock-scan" in text and not force:
            console.print(
                "[yellow]ownlock-scan hook already present in "
                f"{pre_commit_yaml}; pass --force to add another.[/yellow]"
            )
            return
        if not text.endswith("\n"):
            text += "\n"
        if "repos:" not in text:
            text = "repos:\n" + text
        text += _PRE_COMMIT_SNIPPET
        pre_commit_yaml.write_text(text, encoding="utf-8")
        console.print(
            f"[green]Added ownlock-scan to {pre_commit_yaml}.[/green] "
            "[dim]Run [bold]pre-commit install[/bold] to enable.[/dim]"
        )
        return

    # Raw git hook path.
    if not git_dir.exists():
        console.print(
            "[red]Not in a git repository (no .git/ found in cwd). "
            "Initialize git first or pass --pre-commit if you use the "
            "pre-commit framework.[/red]"
        )
        raise typer.Exit(1)

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"
    if hook_path.exists() and not force:
        console.print(
            f"[yellow]{hook_path} already exists; pass --force to overwrite.[/yellow]"
        )
        return

    hook_path.write_text(_GIT_HOOK_TEMPLATE, encoding="utf-8")
    if os.name == "posix":
        try:
            os.chmod(hook_path, 0o755)
        except OSError:
            pass
    console.print(f"[green]Wrote {hook_path} (runs `ownlock scan .` on every commit).[/green]")


@app.command("share")
@_safe_command
def share(
    secret_names: Optional[list[str]] = typer.Argument(
        None,
        help="Secret names to include. Omit to share every secret.",
    ),
    output: Path = typer.Option(
        ..., "-o", "--output", help="Where to write the encrypted bundle file."
    ),
    env: Optional[str] = typer.Option(
        None,
        "--env",
        "-e",
        help="Restrict the export to one vault environment (default: all).",
    ),
    global_vault: bool = typer.Option(False, "--global", help="Use global vault."),
    project: bool = typer.Option(False, "--project", help="Use project vault at cwd."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation."),
) -> None:
    """Export secrets into an encrypted bundle for a teammate.

    The bundle is protected by its own passphrase, prompted separately from
    the vault passphrase. Send the bundle file and tell the recipient the
    bundle passphrase out of band; they decrypt it locally with
    ``ownlock import-share``.

    Reads ``OWNLOCK_BUNDLE_PASSPHRASE`` if set (for non-interactive use).
    """
    from ownlock.share import export_bundle

    passphrase = resolve_passphrase()
    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)

    with VaultManager(vault_path, passphrase) as vm:
        rows = vm.list_secrets(env)
        decrypted: list[dict[str, str]] = []
        for row in rows:
            if secret_names and row["name"] not in secret_names:
                continue
            value = vm.get(row["name"], row["env"])
            if value is None:
                continue
            decrypted.append(
                {"name": row["name"], "env": row["env"], "value": value}
            )

    if not decrypted:
        if secret_names:
            console.print(
                f"[yellow]No matching secrets found for: {', '.join(secret_names)}[/yellow]"
            )
        else:
            console.print("[dim]Vault is empty; nothing to share.[/dim]")
        raise typer.Exit(1)

    bundle_pp = os.environ.get("OWNLOCK_BUNDLE_PASSPHRASE")
    if bundle_pp is None:
        if not _is_tty():
            console.print(
                "[red]Non-interactive run requires OWNLOCK_BUNDLE_PASSPHRASE.[/red]"
            )
            raise typer.Exit(1)
        bundle_pp = getpass.getpass("Bundle passphrase: ")
        if not bundle_pp:
            console.print("[red]Bundle passphrase cannot be empty.[/red]")
            raise typer.Exit(1)
        confirm = getpass.getpass("Confirm bundle passphrase: ")
        if bundle_pp != confirm:
            console.print("[red]Passphrases do not match.[/red]")
            raise typer.Exit(1)

    if _is_tty() and not yes and not os.environ.get("OWNLOCK_BUNDLE_PASSPHRASE"):
        if not typer.confirm(
            f"Export {len(decrypted)} secret(s) to {output}?", default=True
        ):
            console.print("[dim]Cancelled.[/dim]")
            raise typer.Exit(1)

    bundle_text = export_bundle(decrypted, bundle_pp)
    output.write_text(bundle_text, encoding="utf-8")
    if os.name == "posix":
        try:
            os.chmod(output, 0o600)
        except OSError:
            pass

    console.print(
        f"[green]Wrote {len(decrypted)} secret(s) to {output} "
        "(encrypted, mode 0600 on POSIX).[/green]"
    )


@app.command("import-share")
@_safe_command
def import_share(
    bundle_file: Path = typer.Argument(..., help="Encrypted bundle file to import."),
    global_vault: bool = typer.Option(False, "--global", help="Use global vault."),
    project: bool = typer.Option(False, "--project", help="Use project vault at cwd."),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Overwrite existing secrets without prompting.",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Overwrite existing secrets that conflict with the bundle.",
    ),
) -> None:
    """Import an encrypted bundle (from ``ownlock share``) into the local vault.

    Reads ``OWNLOCK_BUNDLE_PASSPHRASE`` if set, otherwise prompts. Refuses to
    overwrite existing secrets unless ``--overwrite`` is passed (or you
    confirm interactively).
    """
    from ownlock.share import import_bundle

    if not bundle_file.exists():
        console.print(f"[red]Bundle file not found: {bundle_file}[/red]")
        raise typer.Exit(1)

    bundle_pp = os.environ.get("OWNLOCK_BUNDLE_PASSPHRASE")
    if bundle_pp is None:
        if not _is_tty():
            console.print(
                "[red]Non-interactive run requires OWNLOCK_BUNDLE_PASSPHRASE.[/red]"
            )
            raise typer.Exit(1)
        bundle_pp = getpass.getpass("Bundle passphrase: ")
        if not bundle_pp:
            console.print("[red]Bundle passphrase cannot be empty.[/red]")
            raise typer.Exit(1)

    try:
        bundle_text = bundle_file.read_text(encoding="utf-8")
    except OSError as e:
        console.print(f"[red]Could not read bundle: {e}[/red]")
        raise typer.Exit(1)

    try:
        secrets = import_bundle(bundle_text, bundle_pp)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        from cryptography.exceptions import InvalidTag

        if isinstance(e, InvalidTag):
            console.print(
                "[red]Could not decrypt bundle: wrong passphrase or tampered file.[/red]"
            )
            raise typer.Exit(1)
        raise

    if not secrets:
        console.print("[dim]Bundle is empty; nothing to import.[/dim]")
        return

    passphrase = resolve_passphrase()
    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)

    # Detect conflicts before writing anything.
    conflicts: list[tuple[str, str]] = []
    with VaultManager(vault_path, passphrase) as vm:
        for entry in secrets:
            if vm.get(entry["name"], entry["env"]) is not None:
                conflicts.append((entry["name"], entry["env"]))

    if conflicts and not overwrite:
        console.print(
            f"[yellow]{len(conflicts)} secret(s) in the bundle already exist in the vault:[/yellow]"
        )
        for name, env in conflicts[:10]:
            suffix = f" (env={env})" if env != "default" else ""
            console.print(f"  - {name}{suffix}")
        if len(conflicts) > 10:
            console.print(f"  ... and {len(conflicts) - 10} more")
        if _is_tty() and not yes:
            if not typer.confirm("Overwrite them?", default=False):
                console.print(
                    "[dim]Cancelled. Run with --overwrite to overwrite, or "
                    "delete conflicting keys first.[/dim]"
                )
                raise typer.Exit(1)
        else:
            console.print(
                "[red]Refusing to overwrite without --overwrite (or interactive confirm).[/red]"
            )
            raise typer.Exit(1)

    with VaultManager(vault_path, passphrase) as vm:
        for entry in secrets:
            vm.set(entry["name"], entry["value"], entry["env"])

    console.print(
        f"[green]Imported {len(secrets)} secret(s) into "
        f"{_format_vault_path(vault_path)}.[/green]"
    )


@app.command("bootstrap")
@_safe_command
def bootstrap(
    env_files: Optional[list[Path]] = typer.Option(
        None,
        "-f",
        "--file",
        help="Env file(s) to scan for vault() references. Defaults to common .env* files.",
    ),
    env: str = typer.Option("default", "--env", "-e", help="Vault environment for missing keys."),
    global_vault: bool = typer.Option(False, "--global", help="Use global vault."),
    project: bool = typer.Option(False, "--project", help="Use project vault at cwd."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip final confirmation prompt."),
    values_from: Optional[Path] = typer.Option(
        None,
        "--values-from",
        help="JSON file mapping {key: value} for missing secrets (non-interactive).",
    ),
) -> None:
    """Onboard a teammate: prompt only for vault() keys missing from the vault.

    Reads ``.env`` (and common variants) for ``vault("name")`` references,
    compares against what's already in the vault, and asks for the rest. A
    new dev can run this once after cloning to fill in the secrets the
    project expects, without learning what every key is from a teammate over
    Slack.
    """
    from ownlock.resolver import collect_vault_refs

    if env_files:
        candidates = [_validate_env_file(Path(f)) for f in env_files]
    else:
        candidates = [
            _validate_env_file(Path(name))
            for name in (".env", ".env.local", ".env.development", ".env.production")
            if (Path.cwd() / name).exists()
        ]

    candidates = [c for c in candidates if c.exists()]
    if not candidates:
        console.print(
            "[dim]No env files found. Use --file to specify one, or create a .env "
            'file with vault("...") references.[/dim]'
        )
        return

    # Collect every vault() reference; deduplicate by (key, env, vault selection).
    seen: set[tuple[str, str]] = set()
    refs: list[tuple[str, str, Optional[bool], Optional[bool]]] = []
    for path in candidates:
        for ref in collect_vault_refs(path):
            key = ref["key"]
            ref_env = ref["env_arg"] or env
            if (key, ref_env) in seen:
                continue
            seen.add((key, ref_env))
            project_flag = ref.get("project")
            global_flag = ref.get("use_global")
            project_bool = (project_flag == "true") if project_flag else None
            global_bool = (global_flag == "true") if global_flag else None
            refs.append((key, ref_env, project_bool, global_bool))

    if not refs:
        console.print("[dim]No vault() references found in scanned env files.[/dim]")
        return

    passphrase = resolve_passphrase()
    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)

    missing: list[tuple[str, str]] = []
    with VaultManager(vault_path, passphrase) as vm:
        for key, ref_env, _proj, _glob in refs:
            if vm.get(key, ref_env) is None:
                missing.append((key, ref_env))

    if not missing:
        console.print(
            f"[green]All {len(refs)} vault() reference(s) already populated. "
            "Nothing to do.[/green]"
        )
        return

    console.print(
        f"[bold]Missing {len(missing)} secret(s)[/bold] "
        f"(of {len(refs)} reference(s) found):"
    )
    for key, ref_env in missing:
        suffix = f" (env={ref_env})" if ref_env != "default" else ""
        console.print(f"  - {key}{suffix}")

    # Source values: --values-from JSON or interactive prompts.
    supplied: dict[tuple[str, str], str] = {}
    if values_from is not None:
        try:
            payload = json.loads(values_from.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            console.print(f"[red]Could not read --values-from: {e}[/red]")
            raise typer.Exit(1)
        if not isinstance(payload, dict):
            console.print("[red]--values-from must contain a JSON object.[/red]")
            raise typer.Exit(1)
        for key, ref_env in missing:
            if key in payload:
                supplied[(key, ref_env)] = str(payload[key])

    if not supplied:
        if not _is_tty():
            console.print(
                "[red]Non-interactive run with no --values-from. "
                "Pass values via --values-from or run interactively.[/red]"
            )
            raise typer.Exit(1)
        for key, ref_env in missing:
            value = getpass.getpass(f"Enter value for {key} (env={ref_env}): ")
            if value:
                supplied[(key, ref_env)] = value

    if not supplied:
        console.print("[dim]No values provided. Nothing to write.[/dim]")
        return

    if _is_tty() and not yes and not values_from:
        if not typer.confirm(
            f"Save {len(supplied)} new secret(s) to {_format_vault_path(vault_path)}?",
            default=True,
        ):
            console.print("[dim]Cancelled.[/dim]")
            raise typer.Exit(1)

    with VaultManager(vault_path, passphrase) as vm:
        for (key, ref_env), value in supplied.items():
            vm.set(key, value, ref_env)

    console.print(f"[green]Stored {len(supplied)} secret(s).[/green]")
    skipped = len(missing) - len(supplied)
    if skipped:
        console.print(f"[dim]Skipped {skipped} (no value provided).[/dim]")


@app.command("auto")
@_safe_command
def auto(
    files: Optional[list[Path]] = typer.Option(
        None,
        "-f",
        "--file",
        help="Env file(s) to import from.",
    ),
    env: str = typer.Option("default", "--env", "-e", help="Vault environment for import and rewrite."),
    global_vault: bool = typer.Option(False, "--global", help="Use global vault."),
    project: bool = typer.Option(False, "--project", help="Use project vault at cwd."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Run without interactive prompts."),
) -> None:
    """Guided flow: import secrets from env files and rewrite env to use vault()."""
    is_tty = _is_tty()

    # Determine candidate files
    if files:
        candidate_files = [Path(f) for f in files]
    else:
        # Common env file names in current directory
        candidate_files = [Path(".env"), Path(".env.local"), Path(".env.development"), Path(".env.production")]

    valid_files: list[Path] = []
    for f in candidate_files:
        f = _validate_env_file(f)
        if f.exists():
            valid_files.append(f)

    if not valid_files:
        console.print("[dim]No env files found. Use --file to specify one or more files.[/dim]")
        return

    selected_files: list[Path]
    if files:
        # Explicit file list: no further selection
        selected_files = valid_files
    elif is_tty and not yes:
        console.print("Found env files:")
        for idx, f in enumerate(valid_files, start=1):
            console.print(f"  {idx}. {f}")
        choice = typer.prompt(
            "Select file(s) to import from (comma-separated indexes, or blank to cancel)",
            default="",
        ).strip()
        if not choice:
            console.print("[dim]Import cancelled.[/dim]")
            raise typer.Exit(1)
        indexes: list[int] = []
        for part in choice.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                idx = int(part)
            except ValueError:
                console.print(f"[red]Invalid selection '{part}'.[/red]")
                raise typer.Exit(1)
            if idx < 1 or idx > len(valid_files):
                console.print(f"[red]Selection {idx} is out of range.[/red]")
                raise typer.Exit(1)
            indexes.append(idx)
        # Deduplicate while preserving order
        seen: set[int] = set()
        selected_files = []
        for idx in indexes:
            if idx not in seen:
                seen.add(idx)
                selected_files.append(valid_files[idx - 1])
    else:
        # Non-interactive or --yes with no explicit files: use all discovered files
        selected_files = valid_files

    # Preview import counts (TTY, no --yes)
    total_keys = 0
    if is_tty and not yes:
        for f in selected_files:
            count = 0
            for line in f.read_text().splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    continue
                key, _, value = stripped.partition("=")
                key = key.strip()
                value = value.strip()
                if key and value and _is_valid_secret_name(key):
                    count += 1
            total_keys += count
        console.print(
            f"About to import approximately {total_keys} key(s) "
            f"from {len(selected_files)} file(s) into the {'global' if global_vault else 'project'} vault."
        )
        if not typer.confirm("Continue?", default=False):
            console.print("[dim]Import cancelled.[/dim]")
            raise typer.Exit(1)

    passphrase = resolve_passphrase()
    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)

    with VaultManager(vault_path, passphrase) as vm:
        imported_total = 0
        for f in selected_files:
            imported_total += _import_env_file_into_vault(f, env, vm)

    console.print(
        f"[green]Imported {imported_total} secrets into "
        f"{'global' if global_vault else 'project'} vault (env={env}).[/green]"
    )

    # Decide which env file to rewrite: prefer .env if present, otherwise the first selected file
    rewrite_target = None
    for f in selected_files:
        if f.name == ".env":
            rewrite_target = f
            break
    if rewrite_target is None:
        rewrite_target = selected_files[0]

    if is_tty and not yes:
        if not typer.confirm(f"Rewrite {rewrite_target} to use vault() references now?", default=False):
            console.print(
                "[dim]Rewrite step skipped. You can run "
                f"'ownlock rewrite-env -f {rewrite_target}' later.[/dim]"
            )
            return
    elif not yes:
        # Non-interactive without --yes: skip rewrite
        console.print(
            "[dim]Non-interactive session; skipping rewrite. "
            f"Run 'ownlock rewrite-env -f {rewrite_target}' manually.[/dim]"
        )
        return

    # Perform rewrite (shared logic with rewrite-env)
    original_text = rewrite_target.read_text()
    lines = original_text.splitlines()

    with VaultManager(vault_path, passphrase) as vm:
        existing = vm.get_all_decrypted(env)

    new_lines, changed = _rewrite_env_lines_to_vault_syntax(lines, existing, env)

    if changed == 0:
        console.print(
            f"[dim]No changes needed; {rewrite_target} already uses vault() or keys not in vault.[/dim]"
        )
        return

    backup_path = _write_env_backup(rewrite_target, original_text)
    rewrite_target.write_text("\n".join(new_lines) + "\n")
    console.print(
        f"[green]Rewrote {changed} key(s) in {rewrite_target}. Backup saved to {backup_path}.[/green]"
    )


@app.command("rewrite-env")
@_safe_command
def rewrite_env(
    env_file: Path = typer.Option(Path(".env"), "-f", "--file", help="Env file to rewrite."),
    env: str = typer.Option("default", "--env", "-e", help="Vault environment to target."),
    global_vault: bool = typer.Option(False, "--global", help="Use global vault."),
    project: bool = typer.Option(False, "--project", help="Use project vault at cwd."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Rewrite without confirmation."),
) -> None:
    """Rewrite an env file to use vault(\"KEY\") references where possible."""
    env_file = _validate_env_file(env_file)
    if not env_file.exists():
        console.print("[red]Env file not found.[/red]")
        raise typer.Exit(1)

    original_text = env_file.read_text()
    lines = original_text.splitlines()

    passphrase = resolve_passphrase()
    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)

    with VaultManager(vault_path, passphrase) as vm:
        existing = vm.get_all_decrypted(env)

    new_lines, changed = _rewrite_env_lines_to_vault_syntax(lines, existing, env)

    if changed == 0:
        console.print("[dim]No changes needed; env file already uses vault() or keys not in vault.[/dim]")
        return

    if _is_tty() and not yes:
        if not typer.confirm(
            f"Rewrite {env_file} replacing values for {changed} key(s) with vault() references?", default=False
        ):
            console.print("[dim]Rewrite cancelled.[/dim]")
            raise typer.Exit(1)

    backup_path = _write_env_backup(env_file, original_text)
    env_file.write_text("\n".join(new_lines) + "\n")
    console.print(f"[green]Rewrote {changed} key(s) in {env_file}. Backup saved to {backup_path}.[/green]")


MAX_SCAN_FILES = 10_000
MAX_SCAN_DEPTH = 20
MAX_SCAN_FILE_BYTES = 2 * 1024 * 1024  # 2 MiB — skip huge files before read_text


def _is_dangerous_scan_root(directory: Path) -> bool:
    """True when the scan root is a filesystem root (Unix ``/`` or a Windows drive root like ``C:\\``)."""
    try:
        resolved = directory.resolve()
    except (OSError, RuntimeError):
        return False
    # Windows drive roots and POSIX `/` satisfy `path == path.parent`.
    if resolved == resolved.parent:
        return True
    return resolved == Path("/")


@app.command()
@_safe_command
def scan(
    directory: Path = typer.Argument(Path("."), help="Directory to scan for leaked secrets."),
    env: str = typer.Option("default", "--env", "-e"),
    global_vault: bool = typer.Option(False, "--global", help="Use global vault."),
    project: bool = typer.Option(False, "--project", help="Use project vault at cwd."),
    max_files: int = typer.Option(MAX_SCAN_FILES, "--max-files", help="Maximum files to scan."),
    max_depth: int = typer.Option(MAX_SCAN_DEPTH, "--max-depth", help="Maximum directory depth."),
    max_file_bytes: int = typer.Option(
        MAX_SCAN_FILE_BYTES,
        "--max-file-bytes",
        help="Skip files larger than this many bytes (avoids reading huge binaries).",
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Run without interactive confirmation prompts."),
) -> None:
    """Scan files for leaked secret values."""
    directory = _validate_scan_dir(directory)

    if _is_tty() and not yes:
        # Prompt only for dangerous roots or when --max-files exceeds the default cap.
        if _is_dangerous_scan_root(directory) or max_files > MAX_SCAN_FILES:
            if not typer.confirm(
                f"You're about to scan up to {max_files} files under {directory}. Continue?", default=False
            ):
                console.print("[dim]Scan cancelled.[/dim]")
                raise typer.Exit(1)
    passphrase = resolve_passphrase()
    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)

    with VaultManager(vault_path, passphrase) as vm:
        all_secrets = vm.get_all_decrypted(env)

    if not all_secrets:
        console.print("[dim]No secrets in vault to scan for.[/dim]")
        return

    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", ".ownlock", ".env"}
    skip_extensions = {".db", ".sqlite", ".pyc", ".whl", ".tar", ".gz", ".zip", ".png", ".jpg"}
    findings: list[tuple[str, int, str]] = []
    legacy_backups: list[Path] = []
    files_scanned = 0

    for file_path in directory.rglob("*"):
        if files_scanned >= max_files:
            break
        try:
            rel = file_path.relative_to(directory)
            depth = len(rel.parts) - 1 if rel.parts else 0  # dir depth (exclude filename)
        except ValueError:
            depth = 0
        if depth > max_depth:
            continue
        if not file_path.is_file():
            continue
        if any(part in skip_dirs for part in file_path.parts):
            continue
        # Plaintext backup written by older ownlock versions; flag and skip.
        if file_path.name.endswith(_LEGACY_BACKUP_SUFFIX):
            legacy_backups.append(file_path)
            continue
        if file_path.suffix in skip_extensions:
            continue
        try:
            if file_path.stat().st_size > max_file_bytes:
                continue
        except OSError:
            continue
        files_scanned += 1
        try:
            content = file_path.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        for secret_name, secret_value in all_secrets.items():
            if secret_value and secret_value in content:
                for i, line in enumerate(content.splitlines(), 1):
                    if secret_value in line:
                        findings.append((str(file_path), i, secret_name))

    if legacy_backups:
        console.print(
            f"[red bold]Found {len(legacy_backups)} legacy plaintext backup file(s) "
            "(*.ownlock.bak written next to the original .env):[/red bold]"
        )
        for p in legacy_backups:
            console.print(f"  {p}")
        console.print(
            "[dim]Newer ownlock versions write backups under .ownlock/backups/ "
            "(gitignored, mode 0600). Move or delete these files; if any were "
            "committed, treat the values as exposed and rotate them.[/dim]"
        )

    if findings:
        console.print(f"[red bold]Found {len(findings)} leaked secret(s):[/red bold]")
        for path, line_num, secret_name in findings:
            console.print(f"  {path}:{line_num} — contains value of [bold]{secret_name}[/bold]")
        raise typer.Exit(1)
    if legacy_backups:
        # Legacy backups are themselves a finding even if scan didn't match the
        # vault values (the vault may have moved on since the backup was written).
        raise typer.Exit(1)
    console.print("[green]No leaked secrets found.[/green]")


OWNLOCK_GITIGNORE_ENTRY = (
    "\n# ownlock vault (never commit)\n.ownlock/\n"
)


def _ensure_gitignore() -> None:
    """Add .ownlock/ to .gitignore if not already present."""
    gitignore_path = Path.cwd() / ".gitignore"
    if not gitignore_path.exists():
        gitignore_path.write_text(
            "# ownlock vault (never commit)\n.ownlock/\n",
            encoding="utf-8",
        )
        console.print("[dim]Created .gitignore with .ownlock/[/dim]")
        return

    content = gitignore_path.read_text(encoding="utf-8")
    if ".ownlock" in content:
        return

    with gitignore_path.open("a", encoding="utf-8") as f:
        f.write(OWNLOCK_GITIGNORE_ENTRY)
    console.print("[dim]Added .ownlock/ to .gitignore[/dim]")


def _resolve_vault_path(global_vault: bool = False, project: bool = False) -> Path:
    """Pick vault path. Default: project if found, else global. --global forces global."""
    if global_vault:
        return GLOBAL_VAULT_PATH
    if project:
        return Path.cwd() / PROJECT_VAULT_DIR / PROJECT_VAULT_DB
    proj = VaultManager.find_project_vault()
    if proj:
        return proj
    return GLOBAL_VAULT_PATH
