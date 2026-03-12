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

            if isinstance(e, InvalidTag):
                console.print("[red]Invalid passphrase.[/red]")
                raise typer.Exit(1)
            if isinstance(e, KeyError) and e.args:
                msg = str(e.args[0]) if e.args else "Secret not found in vault."
                console.print(f"[red]{msg}[/red]")
                raise typer.Exit(1)
            raise

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


app = typer.Typer(
    name="ownlock",
    help="Lightweight secrets manager — encrypted vault, env injection, stdout redaction.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def init(
    project: bool = typer.Option(False, "--project", help="Create a project-local vault instead of global."),
) -> None:
    """Create a new vault."""
    if project:
        vault_path = Path.cwd() / PROJECT_VAULT_DIR / PROJECT_VAULT_DB
    else:
        vault_path = GLOBAL_VAULT_PATH

    if vault_path.exists():
        console.print(f"[yellow]Vault already exists at {_format_vault_path(vault_path)}[/yellow]")
        raise typer.Exit(0)

    passphrase = getpass.getpass("Choose a vault passphrase: ")
    if not passphrase:
        console.print("[red]Passphrase cannot be empty.[/red]")
        raise typer.Exit(1)
    confirm = getpass.getpass("Confirm passphrase: ")
    if passphrase != confirm:
        console.print("[red]Passphrases do not match.[/red]")
        raise typer.Exit(1)

    vm = VaultManager.init_vault(vault_path, passphrase)
    vm.close()

    if not project:
        if store_passphrase(passphrase):
            console.print("[dim]Passphrase saved to system keyring.[/dim]")
        else:
            console.print("[dim]Could not save to keyring. Use OWNLOCK_PASSPHRASE env var.[/dim]")
    else:
        _ensure_gitignore()

    console.print(f"[green]Vault created at {_format_vault_path(vault_path)}[/green]")


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
) -> None:
    """Bulk import secrets from a plaintext .env file."""
    env_file = _validate_env_file(env_file)
    if not env_file.exists():
        console.print("[red]File not found.[/red]")
        raise typer.Exit(1)

    passphrase = resolve_passphrase()
    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)
    count = 0

    with VaultManager(vault_path, passphrase) as vm:
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

    console.print(f"[green]Imported {count} secrets into vault (env={env}).[/green]")


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
) -> None:
    """Scan files for leaked secret values."""
    directory = _validate_scan_dir(directory)
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
