"""Pwndbg navigation: xuntil, nextcall, nextjmp, nextret, stepret, stepuntilasm, nextsyscall"""

from __future__ import annotations

from typing import Annotated

from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import _require_gdb_success
from pwndbg_mcp.errors import require_stopped
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.util import _safe_gdb_arg
from pwndbg_mcp.util import _validate_text_size


@mcp.tool()
@require_stopped
async def xuntil(
    location: Annotated[str, "Address, function, or `*0xADDR`"],
) -> str:
    """Continue until an address or function (mirrors `xuntil`)"""
    location = _safe_gdb_arg(
        _validate_text_size(location, field="xuntil location"), field="xuntil location"
    )
    ctrl = await get_controller()
    r = await ctrl.run_command(f"xuntil {location}", timeout=60.0)
    _require_gdb_success(r, "continue to location")
    return r.text


@mcp.tool()
@require_stopped
async def nextcall() -> str:
    """Continue until the next call instruction (mirrors `nextcall`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("nextcall", timeout=60.0)
    _require_gdb_success(r, "continue to next call")
    return r.text


@mcp.tool()
@require_stopped
async def nextjmp() -> str:
    """Continue until the next jump instruction (mirrors `nextjmp`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("nextjmp", timeout=60.0)
    _require_gdb_success(r, "continue to next jump")
    return r.text


@mcp.tool()
@require_stopped
async def nextret() -> str:
    """Continue until the next return-like instruction (mirrors `nextret`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("nextret", timeout=60.0)
    _require_gdb_success(r, "continue to next return")
    return r.text


@mcp.tool()
@require_stopped
async def nextsyscall() -> str:
    """Continue until the next syscall instruction (mirrors `nextsyscall`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("nextsyscall", timeout=60.0)
    _require_gdb_success(r, "continue to next syscall")
    return r.text


@mcp.tool()
@require_stopped
async def stepret() -> str:
    """Step until a `ret` instruction is reached (mirrors `stepret`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("stepret", timeout=60.0)
    _require_gdb_success(r, "step to return")
    return r.text


@mcp.tool()
@require_stopped
async def stepuntilasm(
    mnemonic: Annotated[
        str, "Assembly mnemonic to halt at (e.g. 'syscall', 'jne', 'mov rax, rbx')"
    ],
) -> str:
    """Step until a given assembly instruction/mnemonic is reached (mirrors `stepuntilasm`)"""
    mnemonic = _safe_gdb_arg(
        _validate_text_size(mnemonic, field="stepuntilasm mnemonic"),
        field="stepuntilasm mnemonic",
    )
    ctrl = await get_controller()
    r = await ctrl.run_command(f"stepuntilasm {mnemonic}", timeout=60.0)
    _require_gdb_success(r, "step to assembly instruction")
    return r.text
