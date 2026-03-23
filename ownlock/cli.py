"""ownlock CLI — lightweight secrets manager."""

from __future__ import annotations

import getpass
import re
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


@app.command("set")
@_safe_command
def set_secret(
    key_value: str = typer.Argument(..., help="Secret name, or NAME=VALUE for inline."),
    env: str = typer.Option("default", "--env", "-e", help="Environment (default, production, etc.)."),
    global_vault: bool = typer.Option(False, "--global", help="Use global vault."),
    project: bool = typer.Option(False, "--project", help="Use project vault at cwd."),
) -> None:
    """Store a secret in the vault."""
    if "=" in key_value:
        name, _, value = key_value.partition("=")
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
) -> None:
    """List stored secret names (never values)."""
    passphrase = resolve_passphrase()
    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)

    with VaultManager(vault_path, passphrase) as vm:
        secrets = vm.list_secrets(env)

    if not secrets:
        console.print("[dim]No secrets stored.[/dim]")
        return

    table = Table(title="Secrets")
    table.add_column("Name")
    table.add_column("Env")
    table.add_column("Updated")
    for s in secrets:
        table.add_row(s["name"], s["env"], s["updated_at"][:19])
    console.print(table)


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

    if no_redact:
        secrets_for_redaction: dict[str, str] = {}
    else:
        secrets_for_redaction = {k: resolved[k] for k in secret_names if k in resolved}

    redactor = SecretRedactor(secrets_for_redaction)
    exit_code = redactor.run_process(command, resolved)
    raise typer.Exit(exit_code)


@app.command("export")
@_safe_command
def export_env(
    env_file: Path = typer.Option(Path(".env"), "-f", "--file"),
    env: str = typer.Option("default", "--env", "-e"),
    fmt: str = typer.Option("env", "--format", help="Output format: env, docker."),
) -> None:
    """Print resolved KEY=VALUE pairs to stdout."""
    from ownlock.resolver import resolve_env_file

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

    # Perform rewrite similar to rewrite-env
    original_text = rewrite_target.read_text()
    lines = original_text.splitlines()

    with VaultManager(vault_path, passphrase) as vm:
        existing = vm.get_all_decrypted(env)

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

    if changed == 0:
        console.print(
            f"[dim]No changes needed; {rewrite_target} already uses vault() or keys not in vault.[/dim]"
        )
        return

    backup_path = rewrite_target.with_suffix(rewrite_target.suffix + ".ownlock.bak")
    backup_path.write_text(original_text)
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
        # Avoid rewriting lines that already use vault()
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

    if changed == 0:
        console.print("[dim]No changes needed; env file already uses vault() or keys not in vault.[/dim]")
        return

    if _is_tty() and not yes:
        if not typer.confirm(
            f"Rewrite {env_file} replacing values for {changed} key(s) with vault() references?", default=False
        ):
            console.print("[dim]Rewrite cancelled.[/dim]")
            raise typer.Exit(1)

    backup_path = env_file.with_suffix(env_file.suffix + ".ownlock.bak")
    backup_path.write_text(original_text)
    env_file.write_text("\n".join(new_lines) + "\n")
    console.print(f"[green]Rewrote {changed} key(s) in {env_file}. Backup saved to {backup_path}.[/green]")


MAX_SCAN_FILES = 10_000
MAX_SCAN_DEPTH = 20


@app.command()
@_safe_command
def scan(
    directory: Path = typer.Argument(Path("."), help="Directory to scan for leaked secrets."),
    env: str = typer.Option("default", "--env", "-e"),
    global_vault: bool = typer.Option(False, "--global", help="Use global vault."),
    project: bool = typer.Option(False, "--project", help="Use project vault at cwd."),
    max_files: int = typer.Option(MAX_SCAN_FILES, "--max-files", help="Maximum files to scan."),
    max_depth: int = typer.Option(MAX_SCAN_DEPTH, "--max-depth", help="Maximum directory depth."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Run without interactive confirmation prompts."),
) -> None:
    """Scan files for leaked secret values."""
    directory = _validate_scan_dir(directory)

    if _is_tty() and not yes:
        # Guard against extremely broad scans (root or very high max_files)
        if directory == Path("/") or max_files >= MAX_SCAN_FILES:
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
        if file_path.suffix in skip_extensions:
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
    if findings:
        console.print(f"[red bold]Found {len(findings)} leaked secret(s):[/red bold]")
        for path, line_num, secret_name in findings:
            console.print(f"  {path}:{line_num} — contains value of [bold]{secret_name}[/bold]")
        raise typer.Exit(1)
    else:
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
