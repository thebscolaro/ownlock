"""ownlock CLI — lightweight secrets manager."""

from __future__ import annotations

import getpass
import json
import os
from functools import wraps
from pathlib import Path
from typing import Annotated, Any, Callable, Optional, TypeVar

import typer
from rich.console import Console
from rich.table import Table

from ownlock.consoleutil import bullet_mark, configure_stdio, fail_mark

configure_stdio()

# Re-export module-level helpers under the cli namespace so existing tests that
# monkeypatch ``ownlock.cli._is_tty`` / ``ownlock.cli._resolve_vault_path`` /
# ``ownlock.cli._write_env_backup`` keep working without each test learning
# about the new module layout.
from ownlock import audit
from ownlock.backups import (
    LEGACY_BACKUP_SUFFIX as _LEGACY_BACKUP_SUFFIX,
    backup_dir_for as _backup_dir_for,
    backup_vault_file as _backup_vault_file,
    write_env_backup as _write_env_backup_impl,
    write_private_text as _write_private_text,
)
from ownlock.doctor import gather_doctor_state as _gather_doctor_state
from ownlock.envfile import (
    DEFAULT_ENV_FILE_CANDIDATES,
    classify_env_file,
    format_vault_expr,
    import_env_file_into_vault as _import_env_file_into_vault,
    iter_env_kv_pairs,
    rewrite_env_lines_to_vault_syntax as _rewrite_env_lines_to_vault_syntax,
)
from ownlock.keyring_util import (
    passphrase_session,
    prompt_passphrase_session,
    store_passphrase,
)
from ownlock.policy import VALID_POLICIES, check_policy_access, normalize_policy
from ownlock.redactor import CommandNotFoundError
from ownlock.passphrase import PassphraseInput
from ownlock.paths import (
    OWNLOCK_GITIGNORE_ENTRY,
    SECRET_NAME_RE,
    ensure_gitignore as _ensure_gitignore,
    format_vault_path as _format_vault_path,
    is_tty as _is_tty,
    is_valid_secret_name as _is_valid_secret_name,
    resolve_vault_path as _resolve_vault_path,
    resolve_scan_vault_path as _resolve_scan_vault_path,
    validate_env_file as _validate_env_file,
    validate_scan_dir as _validate_scan_dir,
    validate_secret_name as _validate_secret_name,
    vault_exists as _vault_exists,
    vault_path_for_ref as _vault_path_for_ref,
)
from ownlock.scanner import (
    DEFAULT_MAX_DEPTH as MAX_SCAN_DEPTH,
    DEFAULT_MAX_FILE_BYTES as MAX_SCAN_FILE_BYTES,
    DEFAULT_MAX_FILES as MAX_SCAN_FILES,
    is_dangerous_scan_root as _is_dangerous_scan_root,
    scan_directory,
)
from ownlock.vault import (
    VaultManager,
    GLOBAL_VAULT_PATH,
    PROJECT_VAULT_DIR,
    PROJECT_VAULT_DB,
    SCHEMA_VERSION_CURRENT,
)

F = TypeVar("F", bound=Callable[..., Any])

# Interactive import pickers (key list, env file list) — cyan matches prior ``auto`` UX.
_STYLE_PICK_HEADER = "bold cyan"
_STYLE_PICK_ITEM = "cyan"


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
            if isinstance(e, PermissionError):
                console.print(f"[red]{e}[/red]")
                raise typer.Exit(1)
            if isinstance(e, CommandNotFoundError):
                console.print(f"[red]Command not found: {e.command}[/red]")
                raise typer.Exit(127)
            console.print(f"[red]An error occurred: {type(e).__name__}: {e}[/red]")
            raise typer.Exit(1)

    return wrapper  # type: ignore[return-value]


def _file_link(path: Path) -> str:
    """Rich markup for a ``file://`` link (clickable in Cursor, VS Code, iTerm, etc.)."""
    resolved = path.expanduser().resolve()
    return f"[link={resolved.as_uri()}]{resolved}[/link]"


def _print_env_rewrite_result(changed: int, env_file: Path, backup_path: Path) -> None:
    """Human-readable rewrite summary: file link on one line, backup on the next."""
    console.print(f"Rewrote [bold]{changed}[/bold] key(s) in {_file_link(env_file)}")
    console.print(f"[dim]Backup saved to[/dim] {_file_link(backup_path)}")


def _write_env_backup(env_file: Path, content: str) -> Path:
    """Thin wrapper around :func:`ownlock.backups.write_env_backup` that wires
    in this module's gitignore helper. Existing call sites and tests still
    reference ``cli._write_env_backup`` directly so this stays exported even
    though the body has moved to ``ownlock.backups``.
    """
    return _write_env_backup_impl(
        env_file, content, ensure_gitignore_fn=_ensure_gitignore
    )


def _prompt_new_passphrase(label: str = "vault") -> str:
    """Prompt twice for a new passphrase; bail on mismatch or empty input.

    Used by ``init`` (both global and project paths) and ``rekey``. Each
    caller used to inline the same six-line pattern; centralizing it keeps
    the empty/mismatch error wording identical everywhere.
    """
    passphrase = getpass.getpass(f"Choose a {label} passphrase: ")
    if not passphrase:
        console.print("[red]Passphrase cannot be empty.[/red]")
        raise typer.Exit(1)
    confirm = getpass.getpass("Confirm passphrase: ")
    if passphrase != confirm:
        console.print("[red]Passphrases do not match.[/red]")
        raise typer.Exit(1)
    return passphrase


def _save_passphrase_to_keyring(passphrase: str) -> None:
    """Best-effort keyring save with a consistent user-facing message.

    On success: print confirmation. On failure: print a hint pointing at
    ``OWNLOCK_PASSPHRASE`` plus the underlying error so users in CI / locked
    down hosts know which env var to set.
    """
    ok, keyring_err = store_passphrase(passphrase)
    if ok:
        console.print("[dim]Passphrase saved to system keyring.[/dim]")
    else:
        detail = f" ({keyring_err})" if keyring_err else ""
        console.print(
            f"[dim]Could not save to keyring{detail}. Use OWNLOCK_PASSPHRASE env var.[/dim]"
        )


def _resolve_bundle_passphrase(*, confirm: bool) -> str:
    """Resolve the share-bundle passphrase from env or interactive prompt.

    Used by ``share`` (confirm=True) and ``import-share`` (confirm=False).
    The bundle passphrase is intentionally distinct from the vault
    passphrase so users can hand a bundle to someone without revealing
    their main vault passphrase.
    """
    pp = os.environ.get("OWNLOCK_BUNDLE_PASSPHRASE")
    if pp is not None:
        return pp
    if not _is_tty():
        console.print(
            "[red]Non-interactive run requires OWNLOCK_BUNDLE_PASSPHRASE.[/red]"
        )
        raise typer.Exit(1)
    pp = getpass.getpass("Bundle passphrase: ")
    if not pp:
        console.print("[red]Bundle passphrase cannot be empty.[/red]")
        raise typer.Exit(1)
    if confirm:
        check = getpass.getpass("Confirm bundle passphrase: ")
        if pp != check:
            console.print("[red]Passphrases do not match.[/red]")
            raise typer.Exit(1)
    return pp


app = typer.Typer(
    name="ownlock",
    help="Lightweight secrets manager — encrypted vault, env injection, stdout redaction.",
    no_args_is_help=True,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        from ownlock import __version__

        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Lightweight secrets manager — encrypted vault, env injection, stdout redaction."""


def _offer_import_after_init(vault_path: Path, passphrase: PassphraseInput) -> None:
    """Walk a fresh vault owner through populating it from an existing ``.env``.

    Triggers only when:

    * stdin/stdout are TTYs (so we never block a non-interactive caller),
    * cwd contains at least one of :data:`DEFAULT_ENV_FILE_CANDIDATES`.

    Dispatches to the same seed / vault_refs flows as ``ownlock import``,
    which means a teammate cloning a repo whose ``.env`` already uses
    ``vault(...)`` references gets prompted for the missing values, while
    an author with a plaintext ``.env`` gets walked through seeding the
    vault and (optionally) rewriting the file. Either path is the *whole*
    onboarding flow — once it returns, ``init`` is done.
    """
    if not _is_tty():
        return

    discovered = [
        Path.cwd() / name
        for name in DEFAULT_ENV_FILE_CANDIDATES
        if (Path.cwd() / name).exists()
    ]
    if not discovered:
        return

    names = ", ".join(p.name for p in discovered)
    if not typer.confirm(
        f"Found {names} in this directory. Import secrets into the vault now?",
        default=True,
    ):
        console.print(
            "[dim]Skipping import. Run "
            "[bold]ownlock import[/bold] later when ready.[/dim]"
        )
        return

    selected = [_validate_env_file(p) for p in discovered]
    has_vault_refs = any(classify_env_file(f) == "vault_refs" for f in selected)
    if has_vault_refs:
        _import_vault_refs_flow(
            selected, vault_path, passphrase, "default",
            yes=False, values_from=None, is_tty=True,
        )
        return

    rewrite = typer.confirm(
        "After import, rewrite the file to use vault(\"KEY\") references?",
        default=True,
    )
    _import_seed_flow(
        selected, vault_path, passphrase, "default",
        yes=False, rewrite=rewrite, is_tty=True,
    )


def _init_global_vault() -> None:
    """Create the global vault and store its passphrase in the keyring.

    Aborts cleanly if the global vault already exists. Used by ``init
    --global`` and as a step inside the first-run combined ``init``.
    """
    if GLOBAL_VAULT_PATH.exists():
        console.print(
            f"[yellow]Vault already exists at {_format_vault_path(GLOBAL_VAULT_PATH)}[/yellow]"
        )
        raise typer.Exit(0)
    pp_str = _prompt_new_passphrase()
    with prompt_passphrase_session(pp_str) as pp:
        VaultManager.init_vault(GLOBAL_VAULT_PATH, pp).close()
        _save_passphrase_to_keyring(pp_str)
        audit.record("init", vault_path=GLOBAL_VAULT_PATH, extra={"scope": "global"})
        console.print(
            f"[green]Vault created at {_format_vault_path(GLOBAL_VAULT_PATH)}[/green]"
        )


def _init_project_vault(project_path: Path) -> None:
    """Create a project vault, ensuring the global vault + keyring exist first.

    Three branches:

    * Project vault already there → friendly message, exit 0.
    * No global vault yet → prompt for a passphrase, create both the global
      and the project vault with it, store in the keyring.
    * Global already there → reuse its keyring passphrase to create the
      project vault silently (no prompt).

    After a fresh project vault is created we offer the onboarding import
    flow if a ``.env`` is sitting in cwd.
    """
    if project_path.exists():
        console.print(
            f"[yellow]Vault already exists at {_format_vault_path(project_path)}[/yellow]"
        )
        raise typer.Exit(0)

    if not GLOBAL_VAULT_PATH.exists():
        pp_str = _prompt_new_passphrase()
        with prompt_passphrase_session(pp_str) as pp:
            VaultManager.init_vault(GLOBAL_VAULT_PATH, pp).close()
            _save_passphrase_to_keyring(pp_str)
            VaultManager.init_vault(project_path, pp).close()
            _ensure_gitignore()
            audit.record("init", vault_path=GLOBAL_VAULT_PATH, extra={"scope": "global"})
            audit.record("init", vault_path=project_path, extra={"scope": "project"})
            console.print(
                f"[green]Vault created at {_format_vault_path(project_path)}[/green] "
                f"[dim](passphrase in keyring; global vault at "
                f"{_format_vault_path(GLOBAL_VAULT_PATH)} also created)[/dim]"
            )
            _offer_import_after_init(project_path, pp)
            _offer_team_bundle_import(project_path, pp)
    else:
        with passphrase_session() as pp:
            VaultManager.init_vault(project_path, pp).close()
            _ensure_gitignore()
            audit.record("init", vault_path=project_path, extra={"scope": "project"})
            console.print(
                f"[green]Vault created at {_format_vault_path(project_path)}[/green]"
            )
            _offer_import_after_init(project_path, pp)
            _offer_team_bundle_import(project_path, pp)


def _offer_team_bundle_import(vault_path: Path, passphrase: PassphraseInput) -> None:
    """Import secrets from ``.ownlock/team.olbundle`` when present after init."""
    from ownlock.share import find_team_bundle, import_bundle

    bundle_path = find_team_bundle(vault_path)
    if bundle_path is None or not _is_tty():
        return
    if not typer.confirm(
        f"Found team bundle at {bundle_path.name}. Import shared secrets now?",
        default=True,
    ):
        console.print(
            "[dim]Skipping team bundle. Run "
            "[bold]ownlock import-share .ownlock/team.olbundle[/bold] later.[/dim]"
        )
        return
    bundle_pp = _resolve_bundle_passphrase(confirm=True)
    try:
        entries = import_bundle(bundle_path.read_text(encoding="utf-8"), bundle_pp)
    except Exception as e:
        console.print(f"[red]Team bundle import failed: {e}[/red]")
        return
    imported = 0
    with VaultManager(vault_path, passphrase) as vm:
        for entry in entries:
            try:
                pol = _policy_from_bundle_entry(entry)
            except ValueError as e:
                console.print(f"[red]Team bundle import failed: {e}[/red]")
                return
            vm.set(entry["name"], entry["value"], entry["env"], policy=pol)
            imported += 1
    audit.record(
        "import-share",
        vault_path=vault_path,
        extra={"bundle_path": str(bundle_path), "secrets_imported": imported, "team": True},
    )
    console.print(f"[green]Imported {imported} secret(s) from team bundle.[/green]")


def _policy_from_bundle_entry(entry: dict) -> str:
    """Normalize a bundle secret's policy.

    Missing policy → ``open`` (older bundles). Present but invalid → error
    (do not silently downgrade confirm/session to open).
    """
    if "policy" not in entry or entry.get("policy") in (None, ""):
        return normalize_policy(None)
    return normalize_policy(entry.get("policy"), strict=True)


@app.command()
def init(
    global_vault: bool = typer.Option(
        False,
        "--global",
        help="Create global vault at ~/.ownlock/ (passphrase in keyring).",
    ),
    project: bool = typer.Option(
        False,
        "--project",
        help="Create project vault at ./.ownlock/ (default when --global is omitted).",
    ),
) -> None:
    """Create a new vault, then offer to import an existing .env if one is present."""
    if global_vault and project:
        console.print("[red]Use either --global or --project, not both.[/red]")
        raise typer.Exit(1)
    if global_vault:
        _init_global_vault()
        return
    _init_project_vault(Path.cwd() / PROJECT_VAULT_DIR / PROJECT_VAULT_DB)


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
        argv = shlex.split(editor, posix=(os.name != "nt")) + [tmp_name]
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
    policy: str = typer.Option(
        "open",
        "--policy",
        help=(
            "Access policy: open (default), session (unlock ~30 minutes across "
            "CLI invocations), confirm (prompt each time; Enter declines)."
        ),
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
    pol = normalize_policy(policy)
    if policy not in VALID_POLICIES:
        console.print(f"[red]Invalid policy '{policy}'. Use: open, session, confirm.[/red]")
        raise typer.Exit(1)

    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)

    with passphrase_session() as passphrase:
        with VaultManager(vault_path, passphrase) as vm:
            vm.set(name, value, env, policy=pol)

    audit.record("set", vault_path=vault_path, name=name, env=env)
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
    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)

    with passphrase_session() as passphrase:
        with VaultManager(vault_path, passphrase) as vm:
            pol = vm.get_policy(name, env)
            if not check_policy_access(name, env, pol, is_tty=_is_tty()):
                console.print(f"[red]Access denied for secret '{name}' (env={env}).[/red]")
                raise typer.Exit(1)
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
    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)

    with passphrase_session() as passphrase:
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


@app.command("doctor")
def doctor(
    as_json: bool = typer.Option(
        False, "--json", help="Emit machine-readable JSON instead of human-readable output."
    ),
) -> None:
    """Print environment diagnostics (versions, vault paths, no secret values)."""
    from ownlock.doctor import render_doctor_report

    state = _gather_doctor_state()
    if as_json:
        typer.echo(json.dumps(state, indent=2, default=str))
        return
    render_doctor_report(state, console)


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

    with passphrase_session() as passphrase:
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
                    + (
                        ""
                        if schema == SCHEMA_VERSION_CURRENT
                        else f"  [yellow](current: v{SCHEMA_VERSION_CURRENT})[/yellow]"
                    )
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

        new_passphrase: str
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
                new_passphrase = _prompt_new_passphrase("new vault")
        else:
            new_passphrase = bytes(passphrase.material()).decode()

        target_iters = KDF_ITERATIONS_CURRENT  # always re-encrypt at current default

        # Idempotent fast-path: nothing to do if already at current params and not rotating.
        if (
            not do_rotate
            and current_iters == KDF_ITERATIONS_CURRENT
            and iter_summary == {KDF_ITERATIONS_CURRENT: secret_count}
            and schema >= SCHEMA_VERSION_CURRENT
        ):
            console.print(
                f"[dim]Vault is already at schema v{SCHEMA_VERSION_CURRENT}, "
                f"KDF {KDF_ITERATIONS_CURRENT:,}. Nothing to upgrade.[/dim]"
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

        audit.record(
            "rekey",
            vault_path=vault_path,
            extra={
                "secrets_rekeyed": count,
                "rotated_passphrase": do_rotate,
                "target_iterations": target_iters,
            },
        )
        console.print(f"[green]Re-encrypted {count} secret(s).[/green]")

        # Two-phase keyring update: only after the SQL transaction succeeds.
        if do_rotate and not no_keyring:
            ok, err = store_passphrase(new_passphrase)
            if ok:
                console.print("[dim]Updated keyring with new passphrase.[/dim]")
            else:
                detail = f" ({err})" if err else ""
                msg = (
                    "[yellow]Could not update keyring"
                    + detail
                    + ". Set OWNLOCK_PASSPHRASE to the new passphrase or update the keyring manually.[/yellow]"
                )
                console.print(msg)

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
    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)

    with passphrase_session() as passphrase:
        with VaultManager(vault_path, passphrase) as vm:
            removed = vm.delete(name, env)

    if removed:
        audit.record("delete", vault_path=vault_path, name=name, env=env)
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

    with passphrase_session() as passphrase:
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
            # Redact every value ownlock injects — vault-resolved secrets *and*
            # inline .env literals (common during migration before rewrite-env).
            secrets_for_redaction = dict(resolved)

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

    with passphrase_session() as passphrase:
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
                    text,
                    lookup,
                    default_env=env,
                    default_format=default_format,
                    is_tty=_is_tty(),
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
    passphrase: PassphraseInput,
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
                text,
                lookup,
                default_env=default_env,
                default_format=default_format,
                is_tty=_is_tty(),
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
        vault_path = _resolve_vault_path(global_vault=global_vault, project=project)
        with passphrase_session() as passphrase:
            with VaultManager(vault_path, passphrase) as vm:
                rows = vm.list_secrets(env)
        for s in sorted(rows, key=lambda x: x["name"]):
            name = s["name"]
            typer.echo(f"{name}={format_vault_expr(name, env)}")
        return

    env_file = _validate_env_file(env_file)
    with passphrase_session() as passphrase:
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


def _pick_indexes_interactively(
    items: list[Any],
    prompt_text: str,
    *,
    label: Callable[[Any], str],
    cancel_message: str = "Cancelled.",
    prompt_default: str = "all",
) -> list[Any]:
    """Show *items* numbered, prompt for a comma-separated index list, return picks.

    Accepts ``"all"`` when *prompt_default* is ``"all"``. When *prompt_default*
    is empty, blank input cancels (env file picker). De-dupes selections while
    preserving order. Used by ``import`` for file and per-key selection.
    """
    if not items:
        return []
    for idx, item in enumerate(items, start=1):
        console.print(f"  {idx}. [{_STYLE_PICK_ITEM}]{label(item)}[/{_STYLE_PICK_ITEM}]")
    choice = typer.prompt(prompt_text, default=prompt_default).strip()
    if not choice:
        console.print(f"[dim]{cancel_message}[/dim]")
        raise typer.Exit(1)
    if choice.lower() == "all":
        return list(items)
    seen: set[int] = set()
    picked: list[Any] = []
    for part in choice.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            idx = int(part)
        except ValueError:
            console.print(f"[red]Invalid selection '{part}'.[/red]")
            raise typer.Exit(1)
        if idx < 1 or idx > len(items):
            console.print(f"[red]Selection {idx} is out of range.[/red]")
            raise typer.Exit(1)
        if idx not in seen:
            seen.add(idx)
            picked.append(items[idx - 1])
    return picked


def _collect_env_files(
    positional: Optional[list[Path]],
    files: Optional[list[Path]],
) -> list[Path]:
    """Build the file list for ``ownlock import``.

    Resolution order:

    1. Positional argument(s), if given (one or more paths).
    2. ``-f / --file`` (repeatable), if given.
    3. Auto-discover from :data:`DEFAULT_ENV_FILE_CANDIDATES` in cwd.

    Each path is validated and existence-checked; missing positional input
    is a hard error (the user typed an explicit path), but missing files in
    auto-discovery just get filtered out.
    """
    if positional:
        out: list[Path] = []
        for p in positional:
            v = _validate_env_file(Path(p))
            if not v.exists():
                console.print(f"[red]File not found: {p}[/red]")
                raise typer.Exit(1)
            out.append(v)
        return out

    if files:
        out: list[Path] = []
        for f in files:
            v = _validate_env_file(Path(f))
            if not v.exists():
                console.print(f"[red]File not found: {f}[/red]")
                raise typer.Exit(1)
            out.append(v)
        return out

    discovered: list[Path] = []
    for name in DEFAULT_ENV_FILE_CANDIDATES:
        path = Path(name)
        if (Path.cwd() / name).exists():
            discovered.append(_validate_env_file(path))
    return discovered


def _import_seed_flow(
    files: list[Path],
    vault_path: Path,
    passphrase: PassphraseInput,
    env: str,
    *,
    yes: bool,
    rewrite: bool,
    is_tty: bool,
) -> None:
    """Plaintext ``KEY=VALUE`` → vault.

    Single-file interactive runs get a per-key picker. Multi-file or
    non-interactive runs import every valid key. With *rewrite*, the
    primary file (preferring ``.env``) is rewritten to use ``vault(...)``
    references afterwards — that's the old ``auto`` workflow.
    """
    selected_keys_per_file: dict[Path, set[str]] = {}

    if is_tty and not yes and len(files) == 1:
        f = files[0]
        candidates = list(iter_env_kv_pairs(f))
        if not candidates:
            console.print("[dim]No valid KEY=VALUE entries found to import.[/dim]")
            return
        console.print(
            f"[{_STYLE_PICK_HEADER}]Found {len(candidates)} key(s) in[/{_STYLE_PICK_HEADER}] "
            f"{_file_link(f)}:"
        )
        picked = _pick_indexes_interactively(
            candidates,
            "Enter indexes to import (comma-separated, 'all' for all, blank = cancel)",
            label=lambda kv: kv[0],
            cancel_message="Import cancelled.",
        )
        selected_keys_per_file[f] = {k for k, _ in picked}

    count = 0
    with VaultManager(vault_path, passphrase) as vm:
        for f in files:
            if f in selected_keys_per_file:
                allowed = selected_keys_per_file[f]
                for key, value in iter_env_kv_pairs(f):
                    if key in allowed:
                        vm.set(key, value, env)
                        count += 1
            else:
                count += _import_env_file_into_vault(f, env, vm)

    audit.record(
        "import",
        vault_path=vault_path,
        env=env,
        extra={
            "sources": [str(f) for f in files],
            "secrets_imported": count,
            "mode": "seed",
        },
    )
    console.print(
        f"[green]Imported {count} secret(s) into vault[/green] [dim](env={env})[/dim]"
    )

    if not rewrite or count == 0:
        return

    # Pick the rewrite target: prefer literal ".env" if present, else first file.
    rewrite_target = next((f for f in files if f.name == ".env"), files[0])
    original_text = rewrite_target.read_text()
    lines = original_text.splitlines()
    with VaultManager(vault_path, passphrase) as vm:
        existing = vm.get_all_decrypted(env)
    new_lines, changed = _rewrite_env_lines_to_vault_syntax(lines, existing, env)

    if changed == 0:
        console.print(
            f"[dim]No rewrite needed for {rewrite_target}; already on vault().[/dim]"
        )
        return

    backup_path = _write_env_backup(rewrite_target, original_text)
    rewrite_target.write_text("\n".join(new_lines) + "\n")
    _print_env_rewrite_result(changed, rewrite_target, backup_path)


def _import_vault_refs_flow(
    files: list[Path],
    vault_path: Path,
    passphrase: PassphraseInput,
    default_env: str,
    *,
    yes: bool,
    values_from: Optional[Path],
    is_tty: bool,
) -> None:
    """``vault(...)`` refs → prompt only for keys missing from the vault.

    Used when an env file has already been rewritten to vault references
    (the teammate-clone workflow). Idempotent: if every reference resolves,
    the function reports that and exits clean.
    """
    from ownlock.resolver import VaultLookup, collect_vault_refs

    seen: set[tuple[str, str, Optional[str], Optional[str]]] = set()
    refs: list[dict[str, Optional[str]]] = []
    for path in files:
        for ref in collect_vault_refs(path):
            key = ref["key"]
            ref_env = ref["env_arg"] or default_env
            dedupe_key = (key, ref_env, ref.get("project"), ref.get("use_global"))
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            refs.append(ref)

    if not refs:
        console.print("[dim]No vault() references found.[/dim]")
        return

    missing: list[dict[str, Optional[str]]] = []
    with VaultLookup(passphrase) as lookup:
        for ref in refs:
            key = ref["key"]
            ref_env = ref["env_arg"] or default_env
            project_flag = ref.get("project")
            global_flag = ref.get("use_global")
            project_bool = (project_flag == "true") if project_flag else None
            global_bool = (global_flag == "true") if global_flag else None
            try:
                lookup.lookup(
                    key,
                    ref_env,
                    project=project_bool,
                    use_global=global_bool,
                    is_tty=_is_tty(),
                )
            except KeyError:
                missing.append(ref)
            except PermissionError:
                # Secret exists but policy blocked this non-interactive check.
                pass

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
    for ref in missing:
        key = ref["key"]
        ref_env = ref["env_arg"] or default_env
        suffix = f" (env={ref_env})" if ref_env != "default" else ""
        vault_hint = ""
        if ref.get("use_global") == "true":
            vault_hint = " [dim](global vault)[/dim]"
        elif ref.get("project") == "true":
            vault_hint = " [dim](project vault)[/dim]"
        console.print(f"  - {key}{suffix}{vault_hint}")

    supplied: dict[tuple[str, str, Optional[str], Optional[str]], str] = {}
    if values_from is not None:
        try:
            payload = json.loads(values_from.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            console.print(f"[red]Could not read --values-from: {e}[/red]")
            raise typer.Exit(1)
        if not isinstance(payload, dict):
            console.print("[red]--values-from must contain a JSON object.[/red]")
            raise typer.Exit(1)
        for ref in missing:
            key = ref["key"]
            ref_env = ref["env_arg"] or default_env
            if key in payload:
                supplied[(key, ref_env, ref.get("project"), ref.get("use_global"))] = str(
                    payload[key]
                )

    if not supplied:
        if not is_tty:
            console.print(
                "[red]Non-interactive run with no --values-from. "
                "Pass values via --values-from or run interactively.[/red]"
            )
            raise typer.Exit(1)
        for ref in missing:
            key = ref["key"]
            ref_env = ref["env_arg"] or default_env
            value = getpass.getpass(f"Enter value for {key} (env={ref_env}): ")
            if value:
                supplied[(key, ref_env, ref.get("project"), ref.get("use_global"))] = value

    if not supplied:
        console.print("[dim]No values provided. Nothing to write.[/dim]")
        return

    if is_tty and not yes and not values_from:
        if not typer.confirm(
            f"Save {len(supplied)} new secret(s) to the vault?",
            default=True,
        ):
            console.print("[dim]Cancelled.[/dim]")
            raise typer.Exit(1)

    # Group writes by target vault so each file is opened once.
    by_vault: dict[Path, list[tuple[str, str, str]]] = {}
    for (key, ref_env, proj, glob), value in supplied.items():
        target = _vault_path_for_ref(proj, glob)
        by_vault.setdefault(target, []).append((key, ref_env, value))

    for target_path, items in by_vault.items():
        with VaultManager(target_path, passphrase) as vm:
            for key, ref_env, value in items:
                vm.set(key, value, ref_env)

    audit.record(
        "import",
        vault_path=vault_path,
        extra={
            "sources": [str(f) for f in files],
            "secrets_set": len(supplied),
            "names": sorted({k for (k, _, _, _) in supplied}),
            "mode": "vault_refs",
        },
    )
    console.print(f"[green]Stored {len(supplied)} secret(s).[/green]")
    skipped = len(missing) - len(supplied)
    if skipped:
        console.print(f"[dim]Skipped {skipped} (no value provided).[/dim]")


@app.command("import")
@_safe_command
def import_env(
    env_files: Annotated[
        Optional[list[Path]],
        typer.Argument(
            help="Env file(s) to import. Omit to auto-discover .env / .env.local / etc.",
        ),
    ] = None,
    files: Optional[list[Path]] = typer.Option(
        None,
        "-f",
        "--file",
        help="Env file(s). Repeatable. Use instead of the positional argument when "
        "you have multiple files.",
    ),
    env: str = typer.Option("default", "--env", "-e", help="Vault environment to write to."),
    global_vault: bool = typer.Option(False, "--global", help="Use global vault."),
    project: bool = typer.Option(False, "--project", help="Use project vault at cwd."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip interactive prompts."),
    rewrite: bool = typer.Option(
        False,
        "--rewrite",
        help="After a plaintext seed import, rewrite the env file in place to "
        "use vault(\"KEY\") references (with a 0600 backup under .ownlock/backups/).",
    ),
    values_from: Optional[Path] = typer.Option(
        None,
        "--values-from",
        help="JSON object {KEY: VALUE} for non-interactive vault-ref fill "
        "(when the env file already has vault(\"...\") references).",
    ),
) -> None:
    """Get secrets into the vault from a .env file.

    Auto-routes based on what the file looks like:

    * Plain ``KEY=VALUE`` lines  → seed flow (adds them to the vault).
      Pass ``--rewrite`` to also rewrite the file to use ``vault(...)``
      references afterwards.
    * Already contains ``vault(...)`` refs → vault_refs flow (prompts only
      for the keys missing from your vault). Use ``--values-from JSON``
      for non-interactive runs.

    Run with no arguments to auto-discover ``.env`` / ``.env.local`` /
    ``.env.development`` / ``.env.production`` in the current directory.
    """
    selected_files = _collect_env_files(env_files, files)
    if not selected_files:
        console.print(
            "[dim]No env files found. Pass a path, use -f, or create one of "
            f"{', '.join(DEFAULT_ENV_FILE_CANDIDATES)}.[/dim]"
        )
        return

    is_tty = _is_tty()
    if is_tty and not yes and len(selected_files) > 1:
        console.print(f"[{_STYLE_PICK_HEADER}]Found env files:[/{_STYLE_PICK_HEADER}]")
        selected_files = _pick_indexes_interactively(
            selected_files,
            "Select file(s) to import from (comma-separated indexes, 'all' for all, blank = cancel)",
            label=lambda p: _file_link(p),
            cancel_message="Import cancelled.",
            prompt_default="",
        )

    has_vault_refs = any(classify_env_file(f) == "vault_refs" for f in selected_files)

    if has_vault_refs and rewrite:
        # Rewriting a file that already uses vault() is a no-op at best and
        # confusing at worst — flag it loudly rather than silently ignore.
        console.print(
            "[yellow]--rewrite has no effect when the file already uses "
            "vault() references; ignoring.[/yellow]"
        )

    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)

    with passphrase_session() as passphrase:
        if has_vault_refs:
            _import_vault_refs_flow(
                selected_files,
                vault_path,
                passphrase,
                env,
                yes=yes,
                values_from=values_from,
                is_tty=is_tty,
            )
        else:
            _import_seed_flow(
                selected_files,
                vault_path,
                passphrase,
                env,
                yes=yes,
                rewrite=rewrite,
                is_tty=is_tty,
            )


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
            os.chmod(hook_path, 0o755)  # nosec B103 — git hooks must be executable
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
    output: Optional[Path] = typer.Option(
        None, "-o", "--output", help="Where to write the encrypted bundle file (not needed with --team)."
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
    team: bool = typer.Option(
        False,
        "--team",
        help="Write git-committable bundle to .ownlock/team.olbundle (project vault only).",
    ),
) -> None:
    """Export secrets into an encrypted bundle for a teammate.

    The bundle is protected by its own passphrase, prompted separately from
    the vault passphrase. Send the bundle file and tell the recipient the
    bundle passphrase out of band; they decrypt it locally with
    ``ownlock import-share``.

    Reads ``OWNLOCK_BUNDLE_PASSPHRASE`` if set (for non-interactive use).
    """
    from ownlock.share import export_bundle, write_team_bundle

    if team and global_vault:
        console.print("[red]--team requires a project vault (omit --global).[/red]")
        raise typer.Exit(1)
    if team:
        # Never fall back to ~/.ownlock — team bundles belong in the repo.
        vault_path = Path.cwd() / PROJECT_VAULT_DIR / PROJECT_VAULT_DB
        if not _vault_exists(vault_path):
            console.print(
                "[red]--team requires a project vault. Run [bold]ownlock init[/bold] first.[/red]"
            )
            raise typer.Exit(1)
        out_path = vault_path.parent / "team.olbundle"
    else:
        vault_path = _resolve_vault_path(global_vault=global_vault, project=project)
        if output is None:
            console.print("[red]--output is required unless --team is set.[/red]")
            raise typer.Exit(1)
        out_path = output

    with passphrase_session() as passphrase:
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
                    {
                        "name": row["name"],
                        "env": row["env"],
                        "value": value,
                        "policy": row.get("policy", "open"),
                    }
                )

    if not decrypted:
        if secret_names:
            console.print(
                f"[yellow]No matching secrets found for: {', '.join(secret_names)}[/yellow]"
            )
        else:
            console.print("[dim]Vault is empty; nothing to share.[/dim]")
        raise typer.Exit(1)

    if team and not secret_names:
        console.print(
            f"[yellow]Warning: exporting all {len(decrypted)} project secret(s) to "
            f"team.olbundle. Anyone with the bundle passphrase can decrypt them.[/yellow]"
        )
        console.print(
            "[yellow]Keep personal API tokens in the global vault "
            "(`ownlock set --global`) or pass named secrets: "
            "`ownlock share DB_URL STRIPE_KEY --team`.[/yellow]"
        )

    bundle_pp = _resolve_bundle_passphrase(confirm=True)

    if _is_tty() and not yes and not os.environ.get("OWNLOCK_BUNDLE_PASSPHRASE"):
        if not typer.confirm(
            f"Export {len(decrypted)} secret(s) to {out_path}?", default=True
        ):
            console.print("[dim]Cancelled.[/dim]")
            raise typer.Exit(1)

    bundle_text = export_bundle(decrypted, bundle_pp)
    if team:
        out_path = write_team_bundle(vault_path, bundle_text)
    else:
        _write_private_text(output, bundle_text)
        out_path = output

    audit.record(
        "share",
        vault_path=vault_path,
        extra={
            "bundle_path": str(out_path),
            "secrets_exported": len(decrypted),
            "names": sorted({s["name"] for s in decrypted}),
            "team": team,
        },
    )
    console.print(
        f"[green]Wrote {len(decrypted)} secret(s) to {out_path} "
        "(encrypted, mode 0600 on POSIX).[/green]"
    )
    if team:
        console.print(
            "[dim]Commit .ownlock/team.olbundle and share the bundle passphrase "
            "out of band. Teammates get secrets on `ownlock init`.[/dim]"
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

    bundle_pp = _resolve_bundle_passphrase(confirm=False)

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

    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)

    with passphrase_session() as passphrase:
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
                try:
                    pol = _policy_from_bundle_entry(entry)
                except ValueError as e:
                    console.print(f"[red]{e}[/red]")
                    raise typer.Exit(1)
                vm.set(entry["name"], entry["value"], entry["env"], policy=pol)

        audit.record(
            "import-share",
            vault_path=vault_path,
            extra={
                "bundle_path": str(bundle_file),
                "secrets_imported": len(secrets),
                "names": sorted({s["name"] for s in secrets}),
            },
        )
        console.print(
            f"[green]Imported {len(secrets)} secret(s) into "
            f"{_format_vault_path(vault_path)}.[/green]"
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

    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)

    with passphrase_session() as passphrase:
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
        _print_env_rewrite_result(changed, env_file, backup_path)


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
        # Prompt only for filesystem roots or when --max-files exceeds the default cap.
        if _is_dangerous_scan_root(directory) or max_files > MAX_SCAN_FILES:
            if not typer.confirm(
                f"You're about to scan up to {max_files} files under {directory}. Continue?", default=False
            ):
                console.print("[dim]Scan cancelled.[/dim]")
                raise typer.Exit(1)

    vault_path = _resolve_scan_vault_path(global_vault=global_vault, project=project)
    all_secrets: dict[str, str] = {}

    if vault_path is None:
        console.print(
            "[dim]No project vault found; scanning for legacy backup files only. "
            "Use --global to compare files against the global vault.[/dim]"
        )
    elif not _vault_exists(vault_path):
        console.print(
            f"[dim]Vault not found at {_format_vault_path(vault_path)}; "
            "scanning for legacy backup files only.[/dim]"
        )
    else:
        from cryptography.exceptions import InvalidTag

        try:
            with passphrase_session() as passphrase:
                with VaultManager(vault_path, passphrase) as vm:
                    all_secrets = vm.get_all_decrypted(env)
        except InvalidTag:
            console.print(
                f"[red]Passphrase does not unlock vault at "
                f"{_format_vault_path(vault_path)}.[/red]"
            )
            console.print(
                "[dim]Keyring or OWNLOCK_PASSPHRASE may be stale — run "
                "'ownlock init' to update the keyring, or set the correct "
                "OWNLOCK_PASSPHRASE. Continuing with legacy-backup scan only.[/dim]"
            )
        else:
            if not all_secrets:
                console.print(
                    f"[dim]No secrets in vault at {_format_vault_path(vault_path)} "
                    f"(env={env}); value comparison skipped.[/dim]"
                )

    result = scan_directory(
        directory,
        all_secrets,
        max_files=max_files,
        max_depth=max_depth,
        max_file_bytes=max_file_bytes,
    )

    if result.legacy_backups:
        console.print(
            f"[red bold]Found {len(result.legacy_backups)} legacy plaintext backup file(s) "
            "(*.ownlock.bak written next to the original .env):[/red bold]"
        )
        for p in result.legacy_backups:
            console.print(f"  {p}")
        console.print(
            "[dim]Newer ownlock versions write backups under .ownlock/backups/ "
            "(gitignored, mode 0600). Move or delete these files; if any were "
            "committed, treat the values as exposed and rotate them.[/dim]"
        )

    if result.findings:
        console.print(f"[red bold]Found {len(result.findings)} leaked secret(s):[/red bold]")
        for finding in result.findings:
            console.print(
                f"  {finding.path}:{finding.line_number} — contains value of "
                f"[bold]{finding.secret_name}[/bold]"
            )
        raise typer.Exit(1)
    if result.legacy_backups:
        raise typer.Exit(1)
    if all_secrets:
        console.print("[green]No leaked secrets found.[/green]")
    else:
        console.print("[dim]No legacy backup files found.[/dim]")


@app.command()
@_safe_command
def shield(
    directory: Path = typer.Argument(Path("."), help="Project directory to harden."),
    verify: bool = typer.Option(False, "--verify", help="Verify shield installation."),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite hook scripts."),
) -> None:
    """Harden a repo against AI agents reading secrets on disk."""
    from ownlock.shield import install_shield, simulate_agent_env_read, verify_shield

    if verify:
        issues = verify_shield(directory)
        leak = simulate_agent_env_read(directory)
        if leak:
            issues.append(leak)
        if issues:
            for issue in issues:
                console.print(f"[red]{fail_mark()} {issue}[/red]")
            raise typer.Exit(1)
        console.print("[green]Shield verified — agent secret reads blocked.[/green]")
        return

    results = install_shield(directory, force=force)
    tip = bool(results.pop("hermes_tip", False))
    any_changed = False
    for path, changed in results.items():
        if changed:
            any_changed = True
            console.print(f"[green]Updated {path}[/green]")
    if tip:
        console.print(
            "[yellow]Hermes: merge .ownlock/hermes-hooks.snippet.yaml into "
            "~/.hermes/config.yaml (or create ~/.hermes and re-run shield).[/yellow]"
        )
    if not any_changed and not tip:
        console.print("[dim]Shield already up to date.[/dim]")
    else:
        console.print("[dim]Run [bold]ownlock shield --verify[/bold] to self-test.[/dim]")

@app.command()
@_safe_command
def guard(
    stdin: bool = typer.Option(
        False,
        "--stdin",
        help="Read stdin, redact known vault secrets, write stdout (for hooks).",
    ),
    install_hook: bool = typer.Option(
        False,
        "--install-hook",
        help="Install Claude Code PostToolUse hook for output redaction.",
    ),
    directory: Path = typer.Option(
        Path("."),
        "--directory",
        "-C",
        help="Project directory for --install-hook.",
    ),
    env: Optional[str] = typer.Option(
        None,
        "--env",
        "-e",
        help="Vault environment for --stdin (default: all environments).",
    ),
    global_vault: bool = typer.Option(False, "--global", help="Use global vault."),
    project: bool = typer.Option(False, "--project", help="Use project vault at cwd."),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite guard hook script."),
) -> None:
    """Redact secret values from agent tool output (DLP guard)."""
    from ownlock.guard import guard_stdin, install_guard_hook

    if install_hook:
        if install_guard_hook(directory, force=force):
            console.print("[green]Installed PostToolUse guard hook.[/green]")
        else:
            console.print("[dim]Guard hook already up to date.[/dim]")
        return

    if stdin:
        vault_path = _resolve_vault_path(global_vault=global_vault, project=project)
        with passphrase_session() as passphrase:
            with VaultManager(vault_path, passphrase) as vm:
                secrets = vm.get_all_decrypted(env)
        raise typer.Exit(guard_stdin(secrets))

    console.print("[red]Use --stdin or --install-hook.[/red]")
    raise typer.Exit(1)


@app.command()
@_safe_command
def status(
    env: Optional[str] = typer.Option(None, "--env", "-e"),
    global_vault: bool = typer.Option(False, "--global", help="Use global vault."),
    project: bool = typer.Option(False, "--project", help="Use project vault at cwd."),
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable summary."),
) -> None:
    """Show vault, agent-safety, and audit posture for the current project."""
    from ownlock.agent import detect_agent_actor
    from ownlock.shield import verify_shield

    vault_path = _resolve_vault_path(global_vault=global_vault, project=project)
    # Always evaluate shield for the cwd project — never $HOME when using global vault.
    project_dir = Path.cwd()

    agent = detect_agent_actor()
    shield_issues = verify_shield(project_dir)
    audit_on = audit.is_enabled()

    secret_count = 0
    environments: list[str] = []
    if _vault_exists(vault_path):
        with passphrase_session() as passphrase:
            with VaultManager(vault_path, passphrase) as vm:
                rows = vm.list_secrets(env)
                secret_count = len(rows)
                environments = sorted({r["env"] for r in rows})

    payload = {
        "vault_path": str(vault_path),
        "vault_exists": _vault_exists(vault_path),
        "secret_count": secret_count,
        "environments": environments,
        "agent_detected": agent,
        "audit_enabled": audit_on,
        "shield_ok": len(shield_issues) == 0,
        "shield_issues": shield_issues,
    }

    if as_json:
        typer.echo(json.dumps(payload, indent=2))
        return

    console.print(f"[bold]Vault[/bold]: {_format_vault_path(vault_path)}")
    console.print(f"  Secrets: {secret_count}")
    if environments:
        console.print(f"  Environments: {', '.join(environments)}")
    console.print(f"[bold]Agent[/bold]: {agent or 'none detected'}")
    console.print(f"[bold]Audit[/bold]: {'on' if audit_on else 'off'}")
    if shield_issues:
        console.print("[bold yellow]Shield[/bold yellow]: incomplete")
        for issue in shield_issues:
            console.print(f"  [yellow]{bullet_mark()} {issue}[/yellow]")
        console.print("[dim]Run [bold]ownlock shield[/bold] to fix.[/dim]")
    else:
        console.print("[bold green]Shield[/bold green]: ok")


