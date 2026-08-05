"""GDB primitive wrappers: print, examine, info subcommands, apropos"""

from __future__ import annotations

from typing import Annotated

from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import InvalidArgument
from pwndbg_mcp.errors import _require_gdb_success
from pwndbg_mcp.errors import require_loaded
from pwndbg_mcp.errors import require_stopped
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.util import _quote_gdb_arguments
from pwndbg_mcp.util import _safe_gdb_arg
from pwndbg_mcp.util import _validate_bounded_int
from pwndbg_mcp.util import _validate_text_size

_GDB_EXAMINE_FORMATS = set("oxdutfaicsz")
_GDB_EXAMINE_SIZES = set("bhwg")


def _validate_examine_format(value: str) -> str:
    valid = isinstance(value, str) and (
        (len(value) == 1 and value in _GDB_EXAMINE_FORMATS | _GDB_EXAMINE_SIZES)
        or (
            len(value) == 2
            and (
                (value[0] in _GDB_EXAMINE_SIZES and value[1] in _GDB_EXAMINE_FORMATS)
                or (value[0] in _GDB_EXAMINE_FORMATS and value[1] in _GDB_EXAMINE_SIZES)
            )
        )
    )
    if not valid:
        raise InvalidArgument(
            f"examine format must contain one GDB format letter and optional size letter (got {value!r})"
        )
    return value


@mcp.tool()
@require_stopped
async def gdb_print(
    expression: Annotated[str, "GDB expression (C-syntax with $reg, symbols, casts)"],
    formatter: Annotated[
        str | None,
        "Optional GDB print format letter (x=hex, d=dec, s=string, c=char, ...)",
    ] = None,
) -> str:
    """Evaluate a GDB expression with `print` (mirrors GDB `print`)"""
    expression = _safe_gdb_arg(
        _validate_text_size(expression, field="print expression"),
        field="print expression",
    )
    if formatter is not None and formatter not in _GDB_EXAMINE_FORMATS:
        raise InvalidArgument("print formatter must be one GDB format letter")
    ctrl = await get_controller()
    cmd = f"print/{formatter} {expression}" if formatter else f"print {expression}"
    r = await ctrl.run_command(cmd)
    _require_gdb_success(r, "print expression")
    return r.text


@mcp.tool()
@require_stopped
async def gdb_examine(
    address: Annotated[str, "Address or expression to examine"],
    fmt: Annotated[
        str,
        "Format string like 'gx', 'wd', 'i', or 's'; count is a separate argument",
    ] = "gx",
    count: Annotated[int, "Number of units"] = 8,
) -> str:
    """Examine memory at the given address (mirrors GDB `x`)"""
    address = _safe_gdb_arg(
        _validate_text_size(address, field="examine address"),
        field="examine address",
    )
    fmt = _validate_examine_format(fmt)
    count = _validate_bounded_int(count, field="count", minimum=1, maximum=4096)
    ctrl = await get_controller()
    r = await ctrl.run_command(f"x/{count}{fmt} {address}")
    _require_gdb_success(r, "examine memory")
    return r.text


@mcp.tool()
async def gdb_set_args(
    args: Annotated[list[str], "Argument list to pass when the inferior is run/started"],
) -> str:
    """Set the arguments that will be passed to the inferior on next `run`/`start`"""
    quoted = " ".join(_quote_gdb_arguments(args))
    ctrl = await get_controller()
    r = await ctrl.run_command(f"set args {quoted}")
    _require_gdb_success(r, "set executable arguments")
    return r.text or "args set"


@mcp.tool()
@require_loaded
async def info_threads() -> str:
    """List threads in the inferior (mirrors GDB `info threads`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("info threads")
    _require_gdb_success(r, "list threads")
    return r.text or "(no threads)"


@mcp.tool()
async def apropos(
    topic: Annotated[str, "Word to search for in command names and descriptions"],
) -> str:
    """Find GDB/pwndbg commands matching a topic (mirrors GDB `apropos`)"""
    topic = _safe_gdb_arg(
        _validate_text_size(topic, field="apropos topic"), field="apropos topic"
    )
    ctrl = await get_controller()
    r = await ctrl.run_command(f"apropos {topic}")
    _require_gdb_success(r, "apropos")
    return r.text or "(no matches)"
