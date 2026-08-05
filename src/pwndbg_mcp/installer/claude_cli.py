"""Wrappers around the `claude mcp` CLI surface"""

from __future__ import annotations

import logging
import shutil
import subprocess

from pwndbg_mcp.installer.config import validate_server_name
from pwndbg_mcp.installer.json_fallback import remove_permissions
from pwndbg_mcp.installer.json_fallback import sync_permissions
from pwndbg_mcp.installer.outcome import OperationResult
from pwndbg_mcp.installer.outcome import OperationStatus

logger = logging.getLogger(__name__)


def find_claude_cli() -> str | None:
    return shutil.which("claude")


def _message(proc: subprocess.CompletedProcess[str]) -> str:
    return (proc.stderr or proc.stdout or "").strip()


def _not_found(message: str) -> bool:
    lowered = message.lower()
    return any(
        marker in lowered
        for marker in ("not found", "does not exist", "no mcp server", "not registered")
    )


def _already_registered(message: str) -> bool:
    lowered = message.lower()
    return "already exists" in lowered or "already registered" in lowered


def _remove(claude: str, name: str, scope: str) -> OperationResult:
    try:
        proc = subprocess.run(
            [claude, "mcp", "remove", name, "--scope", scope],
            capture_output=True,
            text=True,
        )
    except OSError as error:
        return OperationResult(OperationStatus.ERROR, f"could not run Claude CLI: {error}")
    if proc.returncode == 0:
        return OperationResult(OperationStatus.REMOVED)
    message = _message(proc)
    if _not_found(message):
        return OperationResult(OperationStatus.NOT_FOUND, message)
    return OperationResult(OperationStatus.ERROR, message or "claude mcp remove failed")


def install_via_cli(
    *,
    name: str,
    scope: str,
    command: str,
    server_args: list[str],
    force: bool = False,
    unsafe: bool = False,
) -> OperationResult:
    """Register a stdio server and synchronize scoped Claude permissions"""
    validate_server_name(name)
    claude = find_claude_cli()
    if not claude:
        return OperationResult(OperationStatus.UNAVAILABLE, "Claude CLI was not found")

    removed_existing = False
    if force:
        removed = _remove(claude, name, scope)
        if removed.status not in {OperationStatus.REMOVED, OperationStatus.NOT_FOUND}:
            return removed
        removed_existing = removed.status is OperationStatus.REMOVED
    force_suffix = (
        "; existing registration was removed and could not be restored" if removed_existing else ""
    )

    cmd = [
        claude,
        "mcp",
        "add",
        "--scope",
        scope,
        "--transport",
        "stdio",
        name,
        command,
        "--",
        *server_args,
    ]
    logger.info("running Claude MCP add for server %s", name)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as error:
        return OperationResult(
            OperationStatus.ERROR,
            f"could not run Claude CLI: {error}{force_suffix}",
        )
    if proc.returncode == 0:
        registration = OperationResult(OperationStatus.ADDED)
    else:
        message = _message(proc)
        if _already_registered(message):
            registration = OperationResult(OperationStatus.EXISTS, message)
        else:
            return OperationResult(
                OperationStatus.ERROR,
                f"{message or 'claude mcp add failed'}{force_suffix}",
            )

    try:
        sync_permissions(name, scope, unsafe)
    except (OSError, ValueError) as error:
        if registration.status is OperationStatus.ADDED:
            rollback = _remove(claude, name, scope)
            if rollback.status in {OperationStatus.REMOVED, OperationStatus.NOT_FOUND}:
                return OperationResult(
                    OperationStatus.ERROR,
                    f"Claude permission update failed: {error}; registration rolled back"
                    f"{force_suffix}",
                )
            return OperationResult(
                OperationStatus.ERROR,
                f"Claude permission update failed: {error}; server remains registered and "
                f"rollback failed: {rollback.detail}",
            )
        return OperationResult(
            OperationStatus.ERROR,
            f"server already registered, but Claude permission update failed: {error}",
        )
    return registration


def uninstall_via_cli(name: str, scope: str) -> OperationResult:
    validate_server_name(name)
    claude = find_claude_cli()
    if not claude:
        return OperationResult(OperationStatus.UNAVAILABLE, "Claude CLI was not found")
    result = _remove(claude, name, scope)
    if result.status not in {OperationStatus.REMOVED, OperationStatus.NOT_FOUND}:
        return result
    try:
        remove_permissions(name, scope)
    except (OSError, ValueError) as error:
        return OperationResult(
            OperationStatus.ERROR,
            f"server removal state is {result.status}, but Claude permission cleanup failed: "
            f"{error}; remove its exact "
            "mcp__ rules from permissions.allow and permissions.ask manually",
        )
    return result


def list_via_cli() -> list[str]:
    """Return the server lines from `claude mcp list`"""
    claude = find_claude_cli()
    if not claude:
        return []
    try:
        proc = subprocess.run([claude, "mcp", "list"], capture_output=True, text=True)
    except OSError:
        return []
    if proc.returncode != 0:
        return []
    out: list[str] = []
    for line in proc.stdout.splitlines():
        value = line.strip()
        if not value or value.startswith("#") or "Configured" in value or "Note:" in value:
            continue
        out.append(value)
    return out
