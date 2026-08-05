"""Disassembly tools: disasm, nearpc, u, asm_assemble"""

from __future__ import annotations

from typing import Annotated

from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import InvalidArgument
from pwndbg_mcp.errors import _require_gdb_success
from pwndbg_mcp.errors import require_stopped
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.types import DisasmResult
from pwndbg_mcp.util import _quote_gdb_string
from pwndbg_mcp.util import _truncate_list
from pwndbg_mcp.util import _validate_assembly_instructions
from pwndbg_mcp.util import _validate_bounded_int
from pwndbg_mcp.util import _validate_limit
from pwndbg_mcp.util import _validate_readonly_location
from pwndbg_mcp.util import _validate_safe_token

_DISASM_SNIPPET = (
    "import pwndbg.aglib.disasm.disassembly as _dis\n"
    "import pwndbg.aglib.memory\n"
    "import pwndbg.aglib.symbol\n"
    "_insns = _dis.get(_addr, instructions=_count)\n"
    "out = []\n"
    "for _i in _insns:\n"
    "    try:\n"
    "        _bytes = bytes(pwndbg.aglib.memory.read(_i.address, _i.size))\n"
    "    except Exception:\n"
    "        _bytes = b''\n"
    "    out.append({\n"
    "        'addr': hex(_i.address),\n"
    "        'bytes_hex': _bytes.hex(' '),\n"
    "        'mnemonic': _i.mnemonic,\n"
    "        'op_str': _i.op_str,\n"
    "        'symbol': pwndbg.aglib.symbol.resolve_addr(_i.address) or None,\n"
    "        'is_branch': bool(getattr(_i, 'jump_like', False) or getattr(_i, 'is_conditional_jump', False)),\n"
    "        'target': hex(int(_i.target)) if getattr(_i, 'target', None) is not None else None,\n"
    "    })\n"
    "mcp_emit(out)"
)


@mcp.tool()
@require_stopped
async def disasm(
    address: Annotated[str, "Start address (default $pc)"] = "$pc",
    count: Annotated[int, "Instructions to disassemble"] = 10,
    limit: Annotated[int | None, "Max entries. None removes the soft cap; hard cap is 4096"] = 200,
) -> DisasmResult:
    """Disassemble instructions at an address (mirrors `nearpc`'s forward path)

    Each entry: ``{addr, bytes_hex, mnemonic, op_str, symbol, is_branch, target}``
    """
    address = _validate_readonly_location(address, field="disassembly address")
    count = _validate_bounded_int(count, field="count", minimum=1, maximum=4096)
    limit = _validate_limit(limit, field="limit")
    address_expr = f"(unsigned long)({address})"
    ctrl = await get_controller()
    expr = (
        f"_addr = int(pwndbg.dbg.selected_inferior().evaluate_expression({address_expr!r}));\n"
        f"_count = {count}\n"
    ) + _DISASM_SNIPPET
    items = await ctrl.pi_query(expr, timeout=10.0)
    return _truncate_list(items, limit)


@mcp.tool()
@require_stopped
async def nearpc(
    count: Annotated[int, "Number of forward instructions from $pc"] = 6,
    limit: Annotated[int | None, "Max entries. None removes the soft cap; hard cap is 4096"] = 200,
) -> DisasmResult:
    """Forward instructions from current $pc (mirrors `nearpc` forward window)"""
    count = _validate_bounded_int(count, field="count", minimum=1, maximum=4096)
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    expr = (
        "from pwndbg.aglib import regs as _regs\n"
        "_addr = int(_regs.read_reg('pc'))\n"
        f"_count = {count}\n"
    ) + _DISASM_SNIPPET
    items = await ctrl.pi_query(expr, timeout=10.0)
    return _truncate_list(items, limit)


@mcp.tool()
@require_stopped
async def u(
    address: Annotated[str, "Address"] = "$pc",
    count: Annotated[int, "Instructions"] = 10,
    limit: Annotated[int | None, "Max entries. None removes the soft cap; hard cap is 4096"] = 200,
) -> DisasmResult:
    """Disassemble in plain style - same shape as `disasm` (mirrors `u`)"""
    address = _validate_readonly_location(address, field="disassembly address")
    count = _validate_bounded_int(count, field="count", minimum=1, maximum=4096)
    limit = _validate_limit(limit, field="limit")
    address_expr = f"(unsigned long)({address})"
    ctrl = await get_controller()
    expr = (
        f"_addr = int(pwndbg.dbg.selected_inferior().evaluate_expression({address_expr!r}));\n"
        f"_count = {count}\n"
    ) + _DISASM_SNIPPET
    items = await ctrl.pi_query(expr, timeout=10.0)
    return _truncate_list(items, limit)


@mcp.tool()
async def asm_assemble(
    code: Annotated[str, "Assembly source (one or more instructions)"],
    arch: Annotated[
        str | None,
        "Target arch (e.g. 'amd64','i386','arm','aarch64','mips'); None=pwndbg default",
    ] = None,
    fmt: Annotated[
        str,
        "Output format: 'hex' or 'string'",
    ] = "hex",
) -> str:
    """Assemble instructions to bytes (mirrors `asm`)

    Calls pwndbg's `asm`, which uses pwntools. Output is hex bytes, or a string with fmt='string'
    """
    code = _validate_assembly_instructions(code, field="assembly code")
    if arch is not None:
        arch = _validate_safe_token(arch, field="architecture")
    if fmt not in ("hex", "string"):
        raise InvalidArgument("assembly format must be 'hex' or 'string'")
    ctrl = await get_controller()
    cmd = "asm"
    if fmt and fmt != "hex":
        cmd += f" -f {fmt}"
    if arch:
        cmd += f" --arch {arch}"
    cmd += f" -- {_quote_gdb_string(code, field='code')}"
    r = await ctrl.run_command(cmd)
    _require_gdb_success(r, "assemble instructions")
    return r.text
