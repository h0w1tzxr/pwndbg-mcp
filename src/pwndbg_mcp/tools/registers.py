"""Register read/write tools"""

from __future__ import annotations

from typing import Annotated

from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import InvalidArgument
from pwndbg_mcp.errors import PwndbgError
from pwndbg_mcp.errors import _require_gdb_success
from pwndbg_mcp.errors import require_stopped_or_interrupt
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.util import _safe_gdb_arg
from pwndbg_mcp.util import _validate_bounded_int
from pwndbg_mcp.util import _validate_safe_identifier
from pwndbg_mcp.util import _validate_text_size


@mcp.tool()
@require_stopped_or_interrupt
async def regs() -> dict[str, str]:
    """All architectural registers as a dict of name -> hex string (mirrors `regs`)"""
    ctrl = await get_controller()
    # regs is a lazy attribute, not a real submodule, so it needs a `from`-import
    expr = (
        "import itertools\n"
        "from pwndbg.aglib import regs as r\n"
        "_source = itertools.chain(r.current.gpr, r.current.misc or (), ('pc','sp','bp'))\n"
        "names = list(itertools.islice(_source, 4097))\n"
        "if len(names) > 4096:\n"
        "    mcp_emit({'_producer_overflow': True})\n"
        "else:\n"
        "    names = list(dict.fromkeys(names))\n"
        "    out = {}\n"
        "    for n in names:\n"
        "        try:\n"
        "            v = r.read_reg(n)\n"
        "        except Exception:\n"
        "            v = None\n"
        "        if v is not None:\n"
        "            out[n] = hex(int(v))\n"
        "    mcp_emit(out)"
    )
    result = await ctrl.pi_query(expr)
    if result.get("_producer_overflow") is True:
        raise PwndbgError(
            "pwndbg produced more than 4096 register names; cannot return a complete register set"
        )
    return result


@mcp.tool()
@require_stopped_or_interrupt
async def regs_named(
    names: Annotated[list[str], "Register names to read (e.g. ['rax','rsp','rip'])"],
) -> dict[str, str | None]:
    """Read a specific subset of registers as hex strings"""
    if not isinstance(names, list):
        raise InvalidArgument("register names must be a list")
    _validate_bounded_int(
        len(names), field="register names", minimum=0, maximum=4096
    )
    validated: list[str] = []
    total = 0
    for name in names:
        name = _validate_safe_identifier(name, field="register name")
        total += len(name.encode("utf-8")) + bool(validated)
        if total > 65536:
            raise InvalidArgument("register names must be at most 65536 UTF-8 bytes")
        validated.append(name)
    names = validated
    ctrl = await get_controller()
    expr = (
        f"names = {names!r}\n"
        "from pwndbg.aglib import regs as r\n"
        "out = {}\n"
        "for n in names:\n"
        "    try:\n"
        "        v = r.read_reg(n)\n"
        "    except Exception:\n"
        "        v = None\n"
        "    out[n] = hex(int(v)) if v is not None else None\n"
        "mcp_emit(out)"
    )
    return await ctrl.pi_query(expr)


@mcp.tool()
@require_stopped_or_interrupt
async def set_register(
    name: Annotated[str, "Register name (rax, rsp, rip, ...)"],
    value: Annotated[str, "Value (hex/dec)"],
) -> str:
    """Write a value to a register (mirrors GDB `set $reg = value`)"""
    name = _safe_gdb_arg(
        _validate_text_size(name, field="register name"), field="register name"
    )
    value = _safe_gdb_arg(
        _validate_text_size(value, field="register value"), field="register value"
    )
    ctrl = await get_controller()
    r = await ctrl.run_command(f"set ${name} = {value}")
    _require_gdb_success(r, "set register")
    return r.text or "set"


@mcp.tool()
@require_stopped_or_interrupt
async def fsbase() -> str:
    """Print the FS segment base register (x86-64 only)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("fsbase")
    _require_gdb_success(r, "read FS base")
    return r.text


@mcp.tool()
@require_stopped_or_interrupt
async def gsbase() -> str:
    """Print the GS segment base register (x86-64 only)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("gsbase")
    _require_gdb_success(r, "read GS base")
    return r.text


@mcp.tool()
@require_stopped_or_interrupt
async def cpsr() -> str:
    """Print CPSR/XPSR/PSTATE flags (ARM/AArch64)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("cpsr")
    _require_gdb_success(r, "read status register")
    return r.text


@mcp.tool()
@require_stopped_or_interrupt
async def setflag(
    flag: Annotated[str, "Flag name (e.g. CF, ZF for x86; depends on arch)"],
    value: Annotated[int, "0 Or 1"],
) -> str:
    """Set a CPU flag bit (mirrors `setflag`)"""
    flag = _safe_gdb_arg(
        _validate_text_size(flag, field="flag name"), field="flag name"
    )
    value = _validate_bounded_int(value, field="flag value", minimum=0, maximum=1)
    ctrl = await get_controller()
    r = await ctrl.run_command(f"setflag {flag} {value}")
    _require_gdb_success(r, "set CPU flag")
    return r.text or "set"
