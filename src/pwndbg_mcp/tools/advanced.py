"""Escape hatches: execute_command, pi_eval, set_param

These are powerful - they let clients run any GDB CLI command or Python snippet inside the
debugger session. They remain approval-gated by the default Claude policy
"""

from __future__ import annotations

from typing import Annotated

from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import _require_gdb_success
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.util import _safe_gdb_arg
from pwndbg_mcp.util import _validate_text_size
from pwndbg_mcp.util import _validate_timeout


@mcp.tool()
async def execute_command(
    command: Annotated[
        str, "Any GDB CLI or pwndbg command (e.g. 'b main', 'info reg', 'set $rax = 0')"
    ],
    timeout: Annotated[float, "Seconds to wait for completion"] = 10.0,
) -> str:
    """Run an arbitrary GDB/pwndbg command and return its captured output

    Use sparingly - prefer the dedicated tools (vmmap, telescope, heap, ...) which return
    structured data. This is a fallback for commands that don't yet have a wrapper
    """
    command = _validate_text_size(command, field="command")
    timeout = _validate_timeout(timeout, field="timeout")
    ctrl = await get_controller()
    r = await ctrl.run_command(command, timeout=timeout)
    drain_after_result = getattr(ctrl, "drain_after_result", None)
    if drain_after_result is not None:
        r = await drain_after_result(r, timeout=1.0)
    _require_gdb_success(r, "execute_command")
    return r.text


@mcp.tool()
async def pi_eval(
    code: Annotated[str, "Python source to execute inside GDB (`pi` interpreter)"],
    timeout: Annotated[float, "Seconds to wait for completion"] = 30.0,
) -> str:
    """Run arbitrary Python inside GDB's `pi` interpreter

    The pwndbg, pwndbg.aglib, JSON modules are pre-imported. To return data, `print()` it
    """
    code = _validate_text_size(code, field="code")
    timeout = _validate_timeout(timeout, field="timeout")
    ctrl = await get_controller()
    r = await ctrl.run_python(code, timeout=timeout)
    _require_gdb_success(r, "pi_eval")
    return r.text


@mcp.tool()
async def set_param(
    name: Annotated[str, "GDB/pwndbg parameter name"],
    value: Annotated[str, "New value"],
) -> str:
    """Update a GDB/pwndbg parameter via `set <name> <value>`"""
    name = _safe_gdb_arg(name, field="parameter name")
    value = _safe_gdb_arg(value, field="parameter value")
    ctrl = await get_controller()
    r = await ctrl.run_command(f"set {name} {value}")
    _require_gdb_success(r, "set parameter")
    return r.text or "set"
