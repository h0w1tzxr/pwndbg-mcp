"""Process bootstrap: run, start, sstart, starti, entry"""

from __future__ import annotations

from typing import Annotated

from pwndbg_mcp.bridge import GdbResponse
from pwndbg_mcp.bridge import GdbState
from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import _require_gdb_success
from pwndbg_mcp.errors import require_loaded
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.util import _quote_gdb_arguments


def _text_or_error(resp: GdbResponse, *drains: GdbResponse) -> str:
    parts = [part for part in (resp.text, *(drain.text for drain in drains)) if part]
    if parts:
        return "\n".join(parts)
    for drain in drains:
        if drain.error:
            return drain.error
    return resp.error or ""


async def _run_with_args(
    command: str,
    args: list[str] | None,
    *,
    wait_for_stop: bool,
) -> str:
    quoted = _quote_gdb_arguments(args) if args is not None else None
    ctrl = await get_controller()
    async with ctrl.mi_transaction():
        if quoted is not None:
            args_command = "-exec-arguments"
            if quoted:
                args_command += f" {' '.join(quoted)}"
            configured = await ctrl.run_command(args_command)
            _require_gdb_success(configured, "configure executable arguments")
        drain_process_output = getattr(ctrl, "drain_process_output", None)
        if drain_process_output is not None:
            await drain_process_output(timeout=0.0)
        resp = await ctrl.run_command(command, timeout=30.0)
        _require_gdb_success(resp, command)
        if not wait_for_stop:
            return resp.text

        drains: list[GdbResponse] = []
        if ctrl.state not in (GdbState.STOPPED, GdbState.EXITED):
            drains.append(await ctrl.drain_until_stopped(timeout=30.0))
        if ctrl.state != GdbState.RUNNING:
            drains.append(await ctrl.drain_pending_output(timeout=0.5))
        for response in drains:
            _require_gdb_success(response, command)
        return _text_or_error(resp, *drains)


@mcp.tool()
@require_loaded
async def run(
    args: Annotated[list[str] | None, "Optional CLI args (overrides previously-set args)"] = None,
) -> str:
    """Run the inferior to completion or first stop (mirrors GDB `run`)"""
    return await _run_with_args("run", args, wait_for_stop=False)


@mcp.tool()
@require_loaded
async def start(
    args: Annotated[list[str] | None, "Optional CLI args"] = None,
) -> str:
    """Run the inferior and stop at main/_start/_init (mirrors `start`)"""
    return await _run_with_args("start", args, wait_for_stop=True)


@mcp.tool()
@require_loaded
async def sstart() -> str:
    """Run and stop at __libc_start_main (mirrors `sstart`)"""
    return await _run_with_args("sstart", None, wait_for_stop=True)


@mcp.tool()
@require_loaded
async def starti(
    args: Annotated[list[str] | None, "Optional CLI args"] = None,
) -> str:
    """Run and stop at the very first instruction (mirrors GDB `starti`)"""
    return await _run_with_args("starti", args, wait_for_stop=True)


@mcp.tool()
@require_loaded
async def entry(
    args: Annotated[list[str] | None, "Optional CLI args"] = None,
) -> str:
    """Run and stop at the binary's entrypoint address (mirrors `entry`)"""
    return await _run_with_args("entry", args, wait_for_stop=True)
