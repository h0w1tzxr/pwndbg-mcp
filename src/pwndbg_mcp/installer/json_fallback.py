"""Claude JSON configuration and permission policy updates"""

from __future__ import annotations

import copy
import errno
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

from pwndbg_mcp.installer.config import validate_server_name
from pwndbg_mcp.installer.outcome import OperationResult
from pwndbg_mcp.installer.outcome import OperationStatus
from pwndbg_mcp.tools._registry import MUTATING_TOOLS
from pwndbg_mcp.tools._registry import SAFE_TOOLS

FileSnapshot = tuple[bytes, int] | None


def _config_path(scope: str) -> Path:
    if scope == "project":
        return Path.cwd() / ".mcp.json"
    if scope == "local":
        raise ValueError(
            "local scope requires the Claude CLI; choose user or project for JSON fallback"
        )
    if scope == "user":
        return Path.home() / ".claude.json"
    raise ValueError(f"unsupported Claude scope: {scope}")


def _settings_path(scope: str) -> Path:
    if scope == "project":
        return Path.cwd() / ".claude" / "settings.json"
    if scope == "local":
        return Path.cwd() / ".claude" / "settings.local.json"
    if scope == "user":
        return Path.home() / ".claude" / "settings.json"
    raise ValueError(f"unsupported Claude scope: {scope}")


def _load(p: Path) -> dict[str, Any]:
    try:
        info = p.lstat()
    except FileNotFoundError:
        return {}
    if stat.S_ISLNK(info.st_mode):
        raise ValueError(f"refusing to read symbolic link: {p}")
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"{p} must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(p, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError(f"{p} must be a regular file")
        stream = os.fdopen(descriptor, encoding="utf-8")
        descriptor = -1
        with stream:
            cfg = json.load(stream)
    except json.JSONDecodeError as e:
        raise ValueError(
            f"could not parse {p}: {e}; fix the JSON or move the file aside, then retry"
        ) from e
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(cfg, dict):
        raise ValueError(f"{p} top level must be a JSON object; fix the JSON and retry")
    servers = cfg.get("mcpServers")
    if servers is not None and not isinstance(servers, dict):
        raise ValueError(f"{p} field mcpServers must be a JSON object; fix the JSON and retry")
    return cfg


def _existing_mode(p: Path) -> int:
    try:
        info = p.lstat()
    except FileNotFoundError:
        return 0o600
    if stat.S_ISLNK(info.st_mode):
        raise OSError(f"refusing to replace symbolic link: {p}")
    if not stat.S_ISREG(info.st_mode):
        raise OSError(f"refusing to replace non-file: {p}")
    return stat.S_IMODE(info.st_mode)


def _atomic_write_bytes(p: Path, data: bytes, mode: int | None = None) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    file_mode = _existing_mode(p) if mode is None else mode
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            dir=p.parent,
            prefix=f".{p.name}.",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            os.fchmod(temporary.fileno(), file_mode)
            temporary.write(data)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, p)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _atomic_write(p: Path, cfg: dict[str, Any]) -> None:
    data = (json.dumps(cfg, indent=2) + "\n").encode()
    _atomic_write_bytes(p, data)


def _snapshot(p: Path) -> FileSnapshot:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(p, flags)
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise OSError(f"refusing to snapshot symbolic link: {p}") from error
        raise OSError(f"could not open configuration snapshot {p}: {error}") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise OSError(f"refusing to snapshot non-regular file: {p}")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        return b"".join(chunks), stat.S_IMODE(info.st_mode)
    finally:
        os.close(descriptor)


def _restore(p: Path, snapshot: FileSnapshot) -> None:
    if snapshot is None:
        p.unlink(missing_ok=True)
        return
    data, mode = snapshot
    _atomic_write_bytes(p, data, mode)


def _write_changes(changes: list[tuple[Path, dict[str, Any]]]) -> str | None:
    try:
        snapshots = {path: _snapshot(path) for path, _ in changes}
    except OSError as error:
        return f"could not prepare configuration update: {error}"

    written: list[Path] = []
    try:
        for path, cfg in changes:
            _atomic_write(path, cfg)
            written.append(path)
    except OSError as error:
        rollback_errors: list[str] = []
        for path in reversed(written):
            try:
                _restore(path, snapshots[path])
            except OSError as rollback_error:
                rollback_errors.append(f"{path}: {rollback_error}")
        if rollback_errors:
            return (
                f"configuration update failed: {error}; partial state remains because rollback "
                f"failed ({'; '.join(rollback_errors)})"
            )
        return f"configuration update failed: {error}; changes rolled back"
    return None


def _permission_rules(name: str, tools: list[str]) -> list[str]:
    validate_server_name(name)
    return [f"mcp__{name}__{tool}" for tool in tools]


def _permission_list(permissions: dict[str, Any], key: str) -> list[str]:
    values = permissions.get(key, [])
    if not isinstance(values, list):
        raise ValueError(f"permissions.{key} must be a JSON array")
    if not all(isinstance(value, str) for value in values):
        raise ValueError(f"permissions.{key} must contain only strings")
    return values


def _updated_permissions(
    cfg: dict[str, Any],
    *,
    name: str,
    unsafe: bool = False,
    remove: bool = False,
) -> dict[str, Any]:
    updated = copy.deepcopy(cfg)
    raw_permissions = updated.get("permissions")
    if raw_permissions is None:
        if remove:
            return updated
        permissions: dict[str, Any] = {}
        updated["permissions"] = permissions
    elif not isinstance(raw_permissions, dict):
        raise ValueError("permissions must be a JSON object")
    else:
        permissions = raw_permissions

    safe = _permission_rules(name, SAFE_TOOLS)
    mutating = _permission_rules(name, MUTATING_TOOLS)
    owned_prefix = f"mcp__{validate_server_name(name)}__"
    allow = [
        rule for rule in _permission_list(permissions, "allow") if not rule.startswith(owned_prefix)
    ]
    ask = [
        rule for rule in _permission_list(permissions, "ask") if not rule.startswith(owned_prefix)
    ]

    if not remove:
        allow.extend(safe + mutating if unsafe else safe)
        if not unsafe:
            ask.extend(mutating)
    if allow or "allow" in permissions or not remove:
        permissions["allow"] = allow
    if ask or "ask" in permissions or not remove:
        permissions["ask"] = ask
    return updated


def sync_permissions(name: str, scope: str, unsafe: bool) -> Path:
    path = _settings_path(scope)
    cfg = _load(path)
    updated = _updated_permissions(cfg, name=name, unsafe=unsafe)
    if updated != cfg:
        _atomic_write(path, updated)
    return path


def remove_permissions(name: str, scope: str) -> Path:
    path = _settings_path(scope)
    cfg = _load(path)
    updated = _updated_permissions(cfg, name=name, remove=True)
    if updated != cfg:
        _atomic_write(path, updated)
    return path


def install_via_json(
    *,
    name: str,
    entry: dict[str, Any],
    scope: str,
    force: bool = False,
    unsafe: bool = False,
) -> OperationResult:
    validate_server_name(name)
    config_path = _config_path(scope)
    settings_path = _settings_path(scope)
    cfg = _load(config_path)
    servers = cfg.setdefault("mcpServers", {})
    settings = _load(settings_path)
    existed = name in servers

    changes: list[tuple[Path, dict[str, Any]]] = []
    if force or not existed:
        updated_cfg = copy.deepcopy(cfg)
        updated_cfg["mcpServers"][name] = entry
        changes.append((config_path, updated_cfg))
    updated_settings = _updated_permissions(settings, name=name, unsafe=unsafe)
    if updated_settings != settings:
        changes.append((settings_path, updated_settings))

    error = _write_changes(changes)
    if error:
        return OperationResult(OperationStatus.ERROR, error)
    status = OperationStatus.EXISTS if existed and not force else OperationStatus.ADDED
    return OperationResult(status, str(config_path))


def uninstall_via_json(name: str, scope: str) -> OperationResult:
    validate_server_name(name)
    config_path = _config_path(scope)
    cfg = _load(config_path)
    servers = cfg.get("mcpServers", {})
    settings_path = _settings_path(scope)
    settings = _load(settings_path)
    found = name in servers
    changes: list[tuple[Path, dict[str, Any]]] = []
    if found:
        updated_cfg = copy.deepcopy(cfg)
        del updated_cfg["mcpServers"][name]
        changes.append((config_path, updated_cfg))
    updated_settings = _updated_permissions(settings, name=name, remove=True)
    if updated_settings != settings:
        changes.append((settings_path, updated_settings))

    error = _write_changes(changes)
    if error:
        return OperationResult(OperationStatus.ERROR, error)
    status = OperationStatus.REMOVED if found else OperationStatus.NOT_FOUND
    return OperationResult(status, str(config_path))
