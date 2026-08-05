"""Integrations with external tools: ROP, ropper, onegadget, leakfind, decomp"""

from __future__ import annotations

import ast
import re
from typing import Annotated
from typing import Any

from pwndbg_mcp.bridge import GdbResponse
from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import InvalidArgument
from pwndbg_mcp.errors import MissingDependency
from pwndbg_mcp.errors import PwndbgError
from pwndbg_mcp.errors import RemoteConnectionError
from pwndbg_mcp.errors import _require_gdb_success
from pwndbg_mcp.errors import require_loaded
from pwndbg_mcp.errors import require_not_running
from pwndbg_mcp.errors import require_stopped
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.types import DecompilerActionResult
from pwndbg_mcp.types import DecompilerStatus
from pwndbg_mcp.util import ANSI_RE
from pwndbg_mcp.util import _safe_gdb_arg
from pwndbg_mcp.util import _truncate_lines
from pwndbg_mcp.util import _validate_bounded_int
from pwndbg_mcp.util import _validate_host
from pwndbg_mcp.util import _validate_limit
from pwndbg_mcp.util import _validate_port
from pwndbg_mcp.util import _validate_readonly_location
from pwndbg_mcp.util import _validate_text_size

_PWNDBG_VERSION_RE = re.compile(r"^Pwndbg:\s+(\S+)", re.MULTILINE)
_SHOW_VALUE_RE = re.compile(r"\bis\s+('(?:[^'\\]|\\.)*'|[0-9]+)\.")
_DECOMPILER_DEPENDENCY_MARKERS = (
    "decomp2dbg is not installed.",
    "Unsupported decomp2dbg version installed.",
    "Ghidra plugin not installed.",
    "Ghidra plugin outdated.",
)
_DECOMPILER_CONNECTION_LOSS_MARKERS = (
    "Disconnecting..",
    "Failed connecting.",
)
_SYNC_NO_CONNECTION = "Failed: Not connected to a decompiler."
_SYNC_PROCESS_NOT_ALIVE = "Can only sync with the debugger while the process is alive."
_SYNC_STARTED = "Syncing symbols..."
_DECOMP_RETRIEVE_FAILURE = "Could not retrieve decompilation."
_DECOMP_ADDRESS_FORBIDDEN = frozenset("'\"\\#;")
_DECOMPILER_RUNTIME_QUERY = (
    "import importlib.metadata as _metadata\n"
    "import pwndbg.commands.decompiler_integration as _di\n"
    "import pwndbg.dintegration as _dintegration\n"
    "try:\n"
    "    _dependency_version = _metadata.version('decomp2dbg')\n"
    "except _metadata.PackageNotFoundError:\n"
    "    _dependency_version = None\n"
    "_connected = _dintegration.manager.is_connected()\n"
    "mcp_emit({\n"
    "    'connected': _connected,\n"
    "    'provider': _dintegration.manager.decompiler_name() if _connected else None,\n"
    "    'dependency_version': _dependency_version,\n"
    "    'dependency_required': _di.d2d_required_version_str,\n"
    "})"
)


def _contains_decompiler_marker(lines: set[str], markers: tuple[str, ...]) -> bool:
    return any(marker.casefold() in line.casefold() for line in lines for marker in markers)


def _format_decompiler_endpoint(host: str, port: int) -> str:
    if host.startswith("[") and host.endswith("]"):
        return f"{host}:{port}"
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _normalized_decompiler_lines(output: str) -> set[str]:
    lines = {ANSI_RE.sub("", line).strip() for line in output.splitlines()}
    lines.discard("")
    return lines


async def _check_decompiler_connection(
    ctrl: Any,
    output: str,
    *,
    action: str,
    require_connected: bool = False,
    connection_loss_line: str | None = None,
    endpoint: str | None = None,
) -> set[str]:
    lines = _normalized_decompiler_lines(output)
    connected = any("Connected to " in line for line in lines)
    dependency_failed = _contains_decompiler_marker(
        lines, _DECOMPILER_DEPENDENCY_MARKERS
    )
    connection_failed = _contains_decompiler_marker(
        lines, _DECOMPILER_CONNECTION_LOSS_MARKERS
    ) or (
        connection_loss_line is not None
        and _contains_decompiler_marker(lines, (connection_loss_line,))
    )

    if dependency_failed:
        ctrl._decompiler_connected = False
        raise MissingDependency(
            f"decompiler {action} failed; pwndbg output:\n{output}\n"
            "install decomp2dbg 3.14.x in pwndbg's Python environment, run the "
            "approved `di install <provider>` command, restart the provider, and retry"
        )
    if connection_failed:
        ctrl._decompiler_connected = False
        if endpoint is None:
            endpoint = await _configured_decompiler_endpoint(ctrl)
        raise RemoteConnectionError(
            f"decompiler {action} failed at {endpoint}; pwndbg output:\n{output}\n"
            "open the provider server on loopback with Ctrl+Shift+D, then call "
            "decompiler_connect to reconnect and retry"
        )
    if require_connected and not connected:
        ctrl._decompiler_connected = False
        raise PwndbgError(
            f"decompiler {action} returned an unrecognized result; pwndbg output:\n"
            f"{output}\ncall mcp_hard_reset if GDB no longer responds"
        )
    return lines


def _show_value(text: str) -> str | int:
    match = _SHOW_VALUE_RE.search(text)
    if not match:
        raise PwndbgError(f"could not parse pwndbg configuration output: {text!r}")
    return ast.literal_eval(match.group(1))


async def _run_decompiler_command(
    ctrl: Any, command: str, timeout: float
) -> GdbResponse:
    response = await ctrl.run_command_and_drain(
        command,
        timeout=timeout,
        drain_timeout=1.0,
    )
    if not response.ok:
        raise PwndbgError(
            f"{command!r} failed: "
            f"{response.error or response.text or 'unknown GDB error'}; "
            "call mcp_hard_reset if GDB no longer responds"
        )
    return response


async def _configured_decompiler_endpoint(ctrl: Any) -> str:
    host_result = await _run_decompiler_command(ctrl, "show decompiler-host", 5.0)
    port_result = await _run_decompiler_command(ctrl, "show decompiler-port", 5.0)
    host = _validate_host(
        str(_show_value(host_result.text)), field="decompiler host"
    )
    port = _validate_port(
        int(_show_value(port_result.text)), field="decompiler port"
    )
    return _format_decompiler_endpoint(host, port)


def _validate_decomp_address(value: str) -> str:
    value = _validate_text_size(value, field="decomp address")
    if (
        not value
        or not value.isprintable()
        or value.startswith("-")
        or any(char.isspace() or char in _DECOMP_ADDRESS_FORBIDDEN for char in value)
    ):
        raise InvalidArgument(
            f"invalid decomp address {value!r}; expected one printable GDB expression token "
            "without quotes, backslashes, comments, command separators, or a leading '-'"
        )
    return _safe_gdb_arg(value, field="decomp address")


def _dependency_checked_text(
    response: GdbResponse,
    *,
    dependency: str,
    markers: tuple[str, ...],
    recovery: str,
    limit: int | None,
) -> str:
    lowered = f"{response.text}\n{response.error or ''}".lower()
    if any(marker.lower() in lowered for marker in markers):
        raise MissingDependency(f"{dependency} is unavailable; {recovery}")
    _require_gdb_success(response, dependency)
    return _truncate_lines(response.text, limit)


@mcp.tool()
@require_not_running
@require_loaded
async def rop(
    grep: Annotated[str | None, "Optional grep filter passed to ROPgadget"] = None,
    limit: Annotated[int | None, "Max output lines. None removes the soft cap; hard cap is 4096"] = 100,
) -> str:
    """Find ROP gadgets via pwndbg's ROPgadget integration (mirrors `rop`)"""
    cmd = "rop --plain"
    if grep is not None:
        grep = _safe_gdb_arg(grep, field="ROPgadget grep filter")
    if grep:
        cmd = f"rop --plain --grep {grep!r}"
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    r = await ctrl.run_command(cmd, timeout=60.0)
    return _dependency_checked_text(
        r,
        dependency="ROPgadget",
        markers=("no module named 'ropgadget'", "ropgadget is unavailable"),
        recovery="install ROPgadget in pwndbg's Python environment",
        limit=limit,
    )


@mcp.tool()
@require_not_running
@require_loaded
async def ropper(
    args: Annotated[str | None, "Raw ropper flags passed after pwndbg's `--` delimiter"] = None,
    limit: Annotated[int | None, "Max output lines. None removes the soft cap; hard cap is 4096"] = 100,
) -> str:
    """Invoke ropper for ROP gadget search (mirrors `ropper`)"""
    cmd = "ropper"
    if args is not None:
        args = _safe_gdb_arg(args, field="ropper arguments")
    if args:
        cmd = f"ropper -- {args}"
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    r = await ctrl.run_command(cmd, timeout=60.0)
    return _dependency_checked_text(
        r,
        dependency="ropper",
        markers=("could not run ropper", "ropper: command not found"),
        recovery="install ropper and ensure its executable is on PATH",
        limit=limit,
    )


@mcp.tool()
@require_not_running
@require_stopped
async def onegadget(
    limit: Annotated[int | None, "Max output lines. None removes the soft cap; hard cap is 4096"] = 100,
) -> str:
    """Run one_gadget against the loaded libc to find one-shot RCE offsets (mirrors `onegadget`)"""
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    r = await ctrl.run_command("onegadget", timeout=30.0)
    return _dependency_checked_text(
        r,
        dependency="one_gadget",
        markers=("could not find one_gadget", "one_gadget: command not found"),
        recovery="install the one_gadget gem and ensure it is on PATH",
        limit=limit,
    )


@mcp.tool()
@require_not_running
@require_stopped
async def leakfind(
    address: Annotated[str, "Start address (typically a stack/heap region)"],
    max_depth: Annotated[int, "Max pointer-chain depth to follow"] = 4,
    limit: Annotated[int | None, "Max output lines. None removes the soft cap; hard cap is 4096"] = 100,
) -> str:
    """Find pointer leak chains rooted at an address (mirrors `leakfind`)"""
    address = _validate_readonly_location(address, field="leakfind address")
    max_depth = _validate_bounded_int(
        max_depth, field="max_depth", minimum=1, maximum=64
    )
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    r = await ctrl.run_command(f"leakfind {address} --max_depth {max_depth}", timeout=60.0)
    _require_gdb_success(r, "find pointer leaks")
    return _truncate_lines(r.text, limit)


@mcp.tool()
@require_stopped
async def decompiler_status() -> DecompilerStatus:
    """Report pwndbg's DI endpoint, live manager, and dependency state"""
    ctrl = await get_controller()
    async with ctrl.mi_transaction():
        version = await _run_decompiler_command(ctrl, "version", 5.0)
        version_match = _PWNDBG_VERSION_RE.search(version.text)
        help_result = await ctrl.run_command_and_drain(
            "help decompiler-integration",
            timeout=5.0,
            drain_timeout=1.0,
        )
        help_text = f"{help_result.text}\n{help_result.error or ''}"
        if "Undefined command" in help_text:
            active = version_match.group(1) if version_match else None
            return {
                "pwndbg_version": active,
                "command_available": False,
                "host": None,
                "port": None,
                "connected": ctrl._decompiler_connected,
                "provider": None,
                "dependency_available": False,
                "dependency_version": None,
                "dependency_required": None,
                "error": (
                    f"pwndbg {active or 'unknown'} lacks decompiler-integration; "
                    "require pwndbg >=2026.02.18"
                ),
            }
        if not help_result.ok:
            raise PwndbgError(
                "'help decompiler-integration' failed: "
                f"{help_result.error or help_result.text or 'unknown GDB error'}; "
                "call mcp_hard_reset if GDB no longer responds"
            )
        host_result = await _run_decompiler_command(ctrl, "show decompiler-host", 5.0)
        port_result = await _run_decompiler_command(ctrl, "show decompiler-port", 5.0)
        runtime = await ctrl.pi_query(_DECOMPILER_RUNTIME_QUERY, timeout=5.0)
        if not isinstance(runtime, dict):
            raise PwndbgError(
                "pwndbg returned invalid decompiler runtime state; call mcp_hard_reset"
            )
        dependency_version = runtime.get("dependency_version")
        dependency_required = runtime.get("dependency_required")
        provider = runtime.get("provider")
        connected = bool(runtime.get("connected"))
        ctrl._decompiler_connected = connected
        return {
            "pwndbg_version": version_match.group(1) if version_match else None,
            "command_available": True,
            "host": str(_show_value(host_result.text)),
            "port": int(_show_value(port_result.text)),
            "connected": connected,
            "provider": str(provider) if provider is not None else None,
            "dependency_available": dependency_version is not None,
            "dependency_version": (
                str(dependency_version) if dependency_version is not None else None
            ),
            "dependency_required": (
                str(dependency_required) if dependency_required is not None else None
            ),
            "error": None,
        }


@mcp.tool()
@require_stopped
async def decompiler_connect(
    host: Annotated[str, "Decompiler plugin host"] = "localhost",
    port: Annotated[int, "Decompiler plugin port"] = 3662,
) -> DecompilerActionResult:
    """Connect pwndbg to a running decompiler plugin server"""
    ctrl = await get_controller()
    host = _validate_host(host, field="decompiler host")
    port = _validate_port(port, field="decompiler port")
    endpoint = _format_decompiler_endpoint(host, port)
    async with ctrl.mi_transaction():
        await _run_decompiler_command(ctrl, f"set decompiler-host {host}", 5.0)
        await _run_decompiler_command(ctrl, f"set decompiler-port {port}", 5.0)
        response = await _run_decompiler_command(ctrl, "di connect", 30.0)
        output = response.text
        await _check_decompiler_connection(
            ctrl,
            output,
            action="connection",
            require_connected=True,
            endpoint=endpoint,
        )
        ctrl._decompiler_connected = True
        return {"output": output, "connected": True}


@mcp.tool()
@require_stopped
async def decompiler_disconnect() -> DecompilerActionResult:
    """Drop the decompiler connection and leave GDB running"""
    ctrl = await get_controller()
    async with ctrl.mi_transaction():
        response = await _run_decompiler_command(ctrl, "di disconnect", 10.0)
        output = response.text
        if "Disconnected from" in output or "Am not connected" in output:
            ctrl._decompiler_connected = False
            return {"output": output, "connected": False}
        await _check_decompiler_connection(ctrl, output, action="disconnect")
        raise PwndbgError(
            f"decompiler disconnect returned an unknown result: {output!r}"
        )


@mcp.tool()
@require_stopped
async def decompiler_sync() -> DecompilerActionResult:
    """Pull decompiler symbols into the running inferior"""
    ctrl = await get_controller()
    async with ctrl.mi_transaction():
        response = await _run_decompiler_command(ctrl, "di sync", 60.0)
        output = response.text
        lines = await _check_decompiler_connection(
            ctrl, output, action="sync", connection_loss_line=_SYNC_NO_CONNECTION
        )
    if _SYNC_PROCESS_NOT_ALIVE in lines or any(
        line.startswith("Failed: ") for line in lines
    ):
        raise PwndbgError(f"decompiler sync failed; pwndbg output:\n{output}")
    if _SYNC_STARTED in lines or any(
        line.startswith(("Connected to ", "Synced ")) for line in lines
    ):
        ctrl._decompiler_connected = True
    return {"output": output, "connected": ctrl._decompiler_connected}


@mcp.tool()
@require_stopped
async def decomp(
    address: Annotated[str | None, "Optional address; default is $pc"] = None,
    lines: Annotated[int, "Number of decompiled lines (1..1000)"] = 14,
) -> str:
    """Show the current pwndbg integration's decompilation at an address"""
    lines = _validate_bounded_int(lines, field="decomp lines", minimum=1, maximum=1000)
    target = _validate_decomp_address("$pc" if address is None else address)
    ctrl = await get_controller()
    async with ctrl.mi_transaction():
        response = await _run_decompiler_command(
            ctrl, f"decomp {target} {lines}", 30.0
        )
        output_lines = await _check_decompiler_connection(
            ctrl, response.text, action="decompilation"
        )
    if _DECOMP_RETRIEVE_FAILURE in output_lines:
        raise PwndbgError(
            f"decompiler decompilation failed; pwndbg output:\n{response.text}"
        )
    if any("Connected to " in line for line in output_lines):
        ctrl._decompiler_connected = True
    return response.text
