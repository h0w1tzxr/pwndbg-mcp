"""Breakpoint and watchpoint lifecycle"""

from __future__ import annotations

from typing import Annotated

from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import InvalidArgument
from pwndbg_mcp.errors import PwndbgError
from pwndbg_mcp.errors import _require_gdb_success
from pwndbg_mcp.errors import require_loaded
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.types import BreakpointListResult
from pwndbg_mcp.util import _safe_gdb_arg


@mcp.tool()
@require_loaded
async def break_set(
    location: Annotated[
        str,
        "Function, file:line, or *0xADDR (e.g. 'main', 'main.c:42', '*0x401234')",
    ],
    condition: Annotated[str | None, "C-style condition expression"] = None,
    temp: Annotated[bool, "Use `tbreak` (one-shot)"] = False,
) -> str:
    """Set a breakpoint after confirming a target is loaded"""
    ctrl = await get_controller()
    location = _safe_gdb_arg(location, field="breakpoint location")
    if condition is not None:
        condition = _safe_gdb_arg(condition, field="breakpoint condition")
    cmd = "tbreak" if temp else "break"
    conditional = f" if {condition}" if condition else ""
    r = await ctrl.run_command(f"{cmd} {location}{conditional}")
    if r.error or r.result_class != "done":
        raise PwndbgError(
            f"failed to set breakpoint: {r.error or r.text or 'no GDB result'}"
        )
    return r.text or (r.error or "set")


@mcp.tool()
async def break_list() -> BreakpointListResult:
    """List breakpoints with raw GDB text and empty-output metadata"""
    ctrl = await get_controller()
    r = await ctrl.run_command("info breakpoints")
    text = r.text or ""
    return {
        "text": text,
        "gdb_ok": r.ok,
        "gdb_error": r.error,
        "is_empty": not text.strip(),
    }


@mcp.tool()
async def break_delete(
    num: Annotated[int | None, "Breakpoint number; None = delete ALL"] = None,
) -> str:
    """Delete one breakpoint or all breakpoints"""
    ctrl = await get_controller()
    cmd = f"delete {num}" if num is not None else "delete"
    r = await ctrl.run_command(cmd)
    _require_gdb_success(r, "delete breakpoint")
    return r.text or "deleted"


@mcp.tool()
async def break_disable(
    num: Annotated[int, "Breakpoint number"],
) -> str:
    """Disable a breakpoint"""
    ctrl = await get_controller()
    r = await ctrl.run_command(f"disable {num}")
    _require_gdb_success(r, "disable breakpoint")
    return r.text or "disabled"


@mcp.tool()
async def break_enable(
    num: Annotated[int, "Breakpoint number"],
) -> str:
    """Enable a breakpoint"""
    ctrl = await get_controller()
    r = await ctrl.run_command(f"enable {num}")
    _require_gdb_success(r, "enable breakpoint")
    return r.text or "enabled"


@mcp.tool()
async def break_condition(
    num: Annotated[int, "Breakpoint number"],
    condition: Annotated[str | None, "Condition expression; empty = clear"] = None,
) -> str:
    """Set or clear a breakpoint condition"""
    ctrl = await get_controller()
    cond = condition if condition is not None else ""
    cond = _safe_gdb_arg(cond, field="breakpoint condition")
    ctrl = await get_controller()
    r = await ctrl.run_command(f"condition {num} {cond}")
    _require_gdb_success(r, "set breakpoint condition")
    return r.text or "set"


@mcp.tool()
async def watch_set(
    expression: Annotated[
        str, "Memory expression to watch (e.g. 'global_var', '*(int*)0x600d80')"
    ],
    kind: Annotated[str, "Kind: 'watch' (write), 'rwatch' (read), 'awatch' (any)"] = "watch",
) -> str:
    """Set a watchpoint"""
    if kind not in ("watch", "rwatch", "awatch"):
        raise InvalidArgument(
            f"watch_set kind must be 'watch', 'rwatch', or 'awatch' (got {kind!r})"
        )
    expression = _safe_gdb_arg(expression, field="watch expression")
    ctrl = await get_controller()
    r = await ctrl.run_command(f"{kind} {expression}")
    _require_gdb_success(r, "set watchpoint")
    return r.text or "set"
