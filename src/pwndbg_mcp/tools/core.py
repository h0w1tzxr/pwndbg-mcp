"""Core MCP-only tools"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from pwndbg_mcp.bridge import GdbState
from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import InvalidArgument
from pwndbg_mcp.errors import _require_gdb_success
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.types import AttachResult
from pwndbg_mcp.types import StatusReport
from pwndbg_mcp.util import _quote_gdb_arguments
from pwndbg_mcp.util import _safe_gdb_arg
from pwndbg_mcp.util import _validate_text_size


@mcp.tool()
async def mcp_status() -> StatusReport:
    """Report GDB controller, target, and current decompiler integration state"""
    ctrl = await get_controller()
    async with ctrl.mi_transaction():
        await ctrl.refresh_state()
        s: StatusReport = ctrl.status()  # type: ignore[assignment]
        # `pi <expr>` queues while the inferior runs, so return state only instead of blocking
        if ctrl.state in {GdbState.RUNNING, GdbState.ERROR}:
            return s
        # pi_query already returns a typed diagnosis, keep it for the caller
        info = await ctrl.pi_query(
            "mcp_emit({"
            "'arch': str(pwndbg.aglib.arch.name) if pwndbg.aglib.arch else None,"
            "'pid': pwndbg.aglib.proc.pid() if pwndbg.aglib.proc.alive() else None"
            "})"
        )
        s["arch"] = info.get("arch")
        s["pid"] = info.get("pid")
        s["pwndbg_loaded"] = True
        return s


@mcp.tool()
async def mcp_load_executable(
    executable_path: Annotated[str, "Absolute path to the binary to debug"],
    args: Annotated[list[str] | None, "CLI arguments to set (will use -exec-arguments)"] = None,
) -> str:
    """Load an executable into GDB and set its arguments"""
    executable_path = _validate_text_size(
        executable_path, field="executable path", maximum=4096
    )
    if "\0" in executable_path or not Path(executable_path).is_absolute():
        raise InvalidArgument("executable path must be an absolute NUL-free path")
    if args is not None:
        _quote_gdb_arguments(args)
    ctrl = await get_controller()
    r = await ctrl.load_executable(executable_path, args)
    _require_gdb_success(r, "load executable")
    return r.text or f"loaded {executable_path}"


@mcp.tool()
async def mcp_attach_pid(
    pid_or_name: Annotated[str, "PID (e.g. '1234') or process-name substring"],
) -> AttachResult:
    """Attach through the canonical verified PID-or-name flow"""
    pid_or_name = _safe_gdb_arg(
        _validate_text_size(pid_or_name, field="attach target", maximum=4096),
        field="attach target",
    )
    ctrl = await get_controller()
    return await ctrl.attach(pid_or_name)


@mcp.tool()
async def mcp_hard_reset() -> str:
    """Terminate GDB and respawn for recovery"""
    ctrl = await get_controller()
    r = await ctrl.hard_reset()
    _require_gdb_success(r, "hard reset")
    return f"reset complete; state={ctrl.state}"
