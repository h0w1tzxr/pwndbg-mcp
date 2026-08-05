"""Execution flow: step, next, ni, si, continue, finish, up, down, kill"""

from __future__ import annotations

from typing import Annotated

from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import _require_gdb_success
from pwndbg_mcp.errors import require_stopped
from pwndbg_mcp.errors import require_stopped_or_interrupt
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.util import _validate_bounded_int


@mcp.tool()
@require_stopped
async def step(
    count: Annotated[int, "Number of source lines to step (steps INTO calls)"] = 1,
) -> str:
    """Step into source-line granularity (mirrors GDB `step`)"""
    count = _validate_bounded_int(count, field="count", minimum=1, maximum=4096)
    ctrl = await get_controller()
    r = await ctrl.run_command(f"step {count}", timeout=30.0)
    _require_gdb_success(r, "step")
    return r.text


@mcp.tool()
@require_stopped
async def next(  # noqa: A001
    count: Annotated[int, "Source lines to step OVER calls"] = 1,
) -> str:
    """Step over source-line granularity (mirrors GDB `next`)"""
    count = _validate_bounded_int(count, field="count", minimum=1, maximum=4096)
    ctrl = await get_controller()
    r = await ctrl.run_command(f"next {count}", timeout=30.0)
    _require_gdb_success(r, "next")
    return r.text


@mcp.tool()
@require_stopped
async def ni(
    count: Annotated[int, "Instructions to step over"] = 1,
) -> str:
    """Step over one or more instructions (mirrors GDB `ni`)"""
    count = _validate_bounded_int(count, field="count", minimum=1, maximum=4096)
    ctrl = await get_controller()
    r = await ctrl.run_command(f"ni {count}", timeout=30.0)
    _require_gdb_success(r, "next instruction")
    return r.text


@mcp.tool()
@require_stopped
async def si(
    count: Annotated[int, "Instructions to step into"] = 1,
) -> str:
    """Step into one or more instructions (mirrors GDB `si`)"""
    count = _validate_bounded_int(count, field="count", minimum=1, maximum=4096)
    ctrl = await get_controller()
    r = await ctrl.run_command(f"si {count}", timeout=30.0)
    _require_gdb_success(r, "step instruction")
    return r.text


@mcp.tool()
@require_stopped
async def continue_() -> str:
    """Continue execution until the next breakpoint, signal, or exit (mirrors GDB `continue`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("continue", timeout=60.0)
    _require_gdb_success(r, "continue")
    return r.text


@mcp.tool()
@require_stopped
async def finish() -> str:
    """Run until the current function returns (mirrors GDB `finish`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("finish", timeout=60.0)
    _require_gdb_success(r, "finish")
    return r.text


@mcp.tool()
@require_stopped
async def up(
    count: Annotated[int, "Frames to move up the call stack"] = 1,
) -> str:
    """Move up the call stack (mirrors GDB `up`)"""
    count = _validate_bounded_int(count, field="count", minimum=1, maximum=4096)
    ctrl = await get_controller()
    r = await ctrl.run_command(f"up {count}")
    _require_gdb_success(r, "move up stack")
    return r.text


@mcp.tool()
@require_stopped
async def down(
    count: Annotated[int, "Frames to move down the call stack"] = 1,
) -> str:
    """Move down the call stack (mirrors GDB `down`)"""
    count = _validate_bounded_int(count, field="count", minimum=1, maximum=4096)
    ctrl = await get_controller()
    r = await ctrl.run_command(f"down {count}")
    _require_gdb_success(r, "move down stack")
    return r.text


@mcp.tool()
@require_stopped_or_interrupt
async def kill() -> str:
    """Kill the inferior (mirrors GDB `kill`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("kill")
    _require_gdb_success(r, "kill inferior")
    await ctrl.drain_process_output(timeout=0.1)
    return r.text
