"""Memory inspection and byte-level mutation tools"""

from __future__ import annotations

from typing import Annotated
from typing import Any

from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import InvalidArgument
from pwndbg_mcp.errors import _require_gdb_success
from pwndbg_mcp.errors import require_stopped
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.types import HexdumpResult
from pwndbg_mcp.types import ReadMemoryResult
from pwndbg_mcp.types import TelescopeResult
from pwndbg_mcp.types import VmmapResult
from pwndbg_mcp.util import _quote_gdb_string
from pwndbg_mcp.util import _safe_gdb_arg
from pwndbg_mcp.util import _truncate_list
from pwndbg_mcp.util import _validate_assembly_instructions
from pwndbg_mcp.util import _validate_bounded_int
from pwndbg_mcp.util import _validate_limit
from pwndbg_mcp.util import _validate_payload_size
from pwndbg_mcp.util import _validate_readonly_location
from pwndbg_mcp.util import _validate_safe_token
from pwndbg_mcp.util import _validate_text_size

_SEARCH_TYPES = frozenset(
    {"byte", "short", "word", "dword", "qword", "pointer", "string", "bytes", "asm"}
)


@mcp.tool()
@require_stopped
async def vmmap(
    pattern: Annotated[
        str | None,
        "Filter pages whose objfile/permissions contain this substring",
    ] = None,
) -> VmmapResult:
    """List virtual memory mappings with optional filtering"""
    if pattern is not None:
        pattern = _validate_text_size(pattern, field="pattern")
    ctrl = await get_controller()
    pat_repr = repr(pattern)
    expr = (
        "import itertools;\n"
        "pages = pwndbg.aglib.vmmap.get();\n"
        f"_pat = {pat_repr};\n"
        "_total = len(pages);\n"
        "_out = [];\n"
        "_scanned = 0;\n"
        "_truncated = False;\n"
        "for p in itertools.islice(pages, 65536):\n"
        "    _scanned += 1\n"
        "    perm = ''\n"
        "    if hasattr(p, 'permstr'):\n"
        "        perm = str(p.permstr)\n"
        "    elif hasattr(p, 'flags_str_short'):\n"
        "        perm = str(p.flags_str_short)\n"
        "    objfile = getattr(p, 'objfile', '')\n"
        "    if _pat and (_pat not in objfile and _pat not in perm):\n"
        "        continue\n"
        "    if len(_out) >= 4096:\n"
        "        _truncated = True\n"
        "        break\n"
        "    _out.append({\n"
        "        'start': hex(p.start), 'end': hex(p.end),\n"
        "        'size': p.end - p.start,\n"
        "        'perm': perm,\n"
        "        'offset': hex(getattr(p, 'offset', 0) or 0),\n"
        "        'objfile': objfile,\n"
        "        'flags': str(getattr(p, 'flags', '')),\n"
        "    })\n"
        "_truncated = _truncated or _scanned < _total\n"
        "mcp_emit({'matched': _out, 'total_pages': _total, 'pattern': _pat, "
        "'scanned': _scanned, 'truncated': _truncated})"
    )
    return await ctrl.pi_query(expr)


@mcp.tool()
@require_stopped
async def telescope(
    address: Annotated[str, "Start address; accepts hex/dec/symbol/$reg"] = "$sp",
    count: Annotated[int, "Number of pointer-sized cells"] = 8,
    limit: Annotated[int | None, "Max entries. None removes the soft cap; hard cap is 4096"] = 200,
) -> TelescopeResult:
    """Dereference pointer-sized cells and return formatted chains"""
    address = _validate_readonly_location(address, field="telescope address")
    count = _validate_bounded_int(count, field="count", minimum=1, maximum=4096)
    limit = _validate_limit(limit, field="limit")
    address_expr = f"(unsigned long)({address})"
    ctrl = await get_controller()
    expr = (
        "from pwndbg.aglib import arch as _arch\n"
        "import re\n"
        "import pwndbg.aglib.memory, pwndbg.chain\n"
        "_ansi_re = re.compile(r'\\x1b\\[[0-9;]*[A-Za-z]')\n"
        "def _clean_chain(_value):\n"
        "    _text = _ansi_re.sub('', str(_value))\n"
        "    _lines = [_line for _line in _text.splitlines() if _line]\n"
        "    return _text, (_lines or [_text])\n"
        f"_start = int(pwndbg.dbg.selected_inferior().evaluate_expression({address_expr!r}));\n"
        f"_count = {count}\n"
        "_ptr_size = _arch.ptrsize\n"
        "out = []\n"
        "for _i in range(_count):\n"
        "    _addr = _start + _i * _ptr_size\n"
        "    try:\n"
        "        _chain_text, _chain = _clean_chain(pwndbg.chain.format(_addr))\n"
        "    except Exception as _e:\n"
        "        _chain_text, _chain = _clean_chain(f'<unreadable: {_e}>')\n"
        "    out.append({\n"
        "        'addr': hex(_addr),\n"
        "        'offset': _i,\n"
        "        'chain': _chain_text,\n"
        "        'chain_text': _chain_text,\n"
        "        'chain_parts': _chain,\n"
        "    })\n"
        "mcp_emit(out)"
    )
    items = await ctrl.pi_query(expr, timeout=10.0)
    return _truncate_list(items, limit)


@mcp.tool()
@require_stopped
async def hexdump(
    address: Annotated[str, "Address"] = "$sp",
    count: Annotated[int, "Bytes to dump"] = 64,
) -> HexdumpResult:
    """Return a hex and ASCII dump for memory at an address"""
    address = _validate_readonly_location(address, field="hexdump address")
    count = _validate_bounded_int(count, field="count", minimum=1, maximum=65536)
    address_expr = f"(unsigned long)({address})"
    ctrl = await get_controller()
    expr = (
        f"addr = int(pwndbg.dbg.selected_inferior().evaluate_expression({address_expr!r}));\n"
        f"data = bytes(pwndbg.aglib.memory.read(addr, {count}));\n"
        "rows = [];\n"
        "for i in range(0, len(data), 16):\n"
        "    chunk = data[i:i+16];\n"
        "    rows.append({\n"
        "        'addr': hex(addr + i),\n"
        "        'bytes_hex': chunk.hex(' '),\n"
        "        'ascii': ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk),\n"
        "    });\n"
        "mcp_emit({'addr': hex(addr), 'rows': rows})"
    )
    # let pi_query raise typed errors instead of fabricating dump rows
    return await ctrl.pi_query(expr, timeout=10.0)


@mcp.tool()
@require_stopped
async def p2p(
    mappings: Annotated[
        list[str],
        "Mapping names to chain through, e.g. ['stack','libc'] finds stack->libc pointers",
    ],
) -> str:
    """Search pointer chains across memory mappings"""
    if not isinstance(mappings, list):
        raise InvalidArgument("p2p mappings must be a list")
    _validate_bounded_int(
        len(mappings), field="p2p mappings", minimum=1, maximum=4096
    )
    validated: list[str] = []
    total = 0
    for mapping in mappings:
        mapping = _validate_safe_token(mapping, field="p2p mappings")
        total += len(mapping.encode("utf-8")) + bool(validated)
        if total > 65536:
            raise InvalidArgument("p2p mappings must be at most 65536 UTF-8 bytes")
        validated.append(mapping)
    mappings = validated
    args = " ".join(mappings)
    _validate_text_size(args, field="p2p mappings")
    ctrl = await get_controller()
    r = await ctrl.run_command(f"p2p {args}")
    _require_gdb_success(r, "search pointer chains")
    return r.text


@mcp.tool()
@require_stopped
async def xinfo(
    address: Annotated[str, "Address (hex/dec/symbol/$reg)"],
) -> str:
    """Show offsets from useful process locations"""
    address = _validate_readonly_location(address, field="xinfo address")
    ctrl = await get_controller()
    r = await ctrl.run_command(f"xinfo {address}")
    _require_gdb_success(r, "inspect address")
    return r.text


@mcp.tool()
@require_stopped
async def search(
    needle: Annotated[str, "Bytes/string/expression to search for"],
    type_: Annotated[
        str | None,
        "Optional `--type`: byte, short, word, dword, qword, pointer, string, bytes, asm",
    ] = None,
    location: Annotated[
        str | None, "Optional address/mapping name (e.g. 'libc') to constrain the search"
    ] = None,
    hex_input: Annotated[
        bool,
        "Treat needle as contiguous hex bytes; valid only with type omitted or 'bytes'",
    ] = False,
    executable: Annotated[bool, "Search executable segments only (-e)"] = False,
    writable: Annotated[bool, "Search writable segments only (-w)"] = False,
    limit: Annotated[
        int | None,
        "Max results before quitting (-l). Default 64 caps the match count to "
        "protect the AI's context window; None removes the soft cap but retains "
        "the hard cap of 4096",
    ] = 64,
) -> str:
    """Search memory for bytes, strings, pointers, or integers"""
    needle = _validate_text_size(needle, field="needle")
    if type_ is not None:
        if not isinstance(type_, str) or type_ not in _SEARCH_TYPES:
            raise InvalidArgument("search type must be a documented non-option type")
    if type_ == "asm":
        needle = _validate_assembly_instructions(needle, field="search instruction")
    else:
        needle = _safe_gdb_arg(needle, field="needle")
    if not needle:
        raise InvalidArgument(
            "needle must be non-empty (hex input must also be even-length hex)"
        )
    if location is not None:
        location = _safe_gdb_arg(
            _validate_text_size(location, field="location"), field="location"
        )
    for field, value in (
        ("hex_input", hex_input),
        ("executable", executable),
        ("writable", writable),
    ):
        if not isinstance(value, bool):
            raise InvalidArgument(f"{field} must be a boolean")
    if hex_input:
        if type_ not in (None, "bytes"):
            raise InvalidArgument("hex_input is valid only with search type 'bytes'")
        if (
            not needle
            or len(needle) % 2
            or any(character not in "0123456789abcdefABCDEF" for character in needle)
        ):
            raise InvalidArgument("needle must be a non-empty, even-length hex string")
    limit = _validate_limit(limit, field="limit", allow_zero=False)
    ctrl = await get_controller()
    cmd = "search"
    if type_:
        cmd += f" --type {type_}"
    if hex_input:
        cmd += " -x"
    if executable:
        cmd += " -e"
    if writable:
        cmd += " -w"
    cmd += f" -l {limit}"
    cmd += f" -- {_quote_gdb_string(needle, field='needle')}"
    if location is not None:
        cmd += f" {_quote_gdb_string(location, field='location')}"
    r = await ctrl.run_command(cmd, timeout=30.0)
    _require_gdb_success(r, "search memory")
    return r.text


@mcp.tool()
@require_stopped
async def distance(
    a: Annotated[str, "First address/expression"],
    b: Annotated[str, "Second address/expression"],
) -> str:
    """Compute the difference between two addresses"""
    a = _validate_readonly_location(a, field="first distance address")
    b = _validate_readonly_location(b, field="second distance address")
    ctrl = await get_controller()
    r = await ctrl.run_command(f"distance {a} {b}")
    _require_gdb_success(r, "measure address distance")
    return r.text


@mcp.tool()
@require_stopped
async def read_memory(
    address: Annotated[str, "Start address"],
    size: Annotated[int, "Number of bytes"],
) -> ReadMemoryResult:
    """Read raw inferior memory and return hex plus size metadata"""
    address = _validate_readonly_location(address, field="read address")
    size = _validate_bounded_int(size, field="size", minimum=1, maximum=1 << 20)
    address_expr = f"(unsigned long)({address})"
    ctrl = await get_controller()
    expr = (
        f"addr = int(pwndbg.dbg.selected_inferior().evaluate_expression({address_expr!r}));\n"
        f"_req = {size};\n"
        "data = bytes(pwndbg.aglib.memory.read(addr, _req));\n"
        "mcp_emit({\n"
        "    'addr': hex(addr),\n"
        "    'size': len(data),\n"
        "    'requested_size': _req,\n"
        "    'hex': data.hex(),\n"
        "    'truncated': len(data) < _req,\n"
        "})"
    )
    return await ctrl.pi_query(expr, timeout=10.0)


@mcp.tool()
@require_stopped
async def write_memory(
    address: Annotated[str, "Start address"],
    hex_data: Annotated[str, "Hex-encoded bytes (no whitespace, e.g. '4141414142')"],
) -> str:
    """Write raw bytes to inferior memory and mutate process state"""
    address = _validate_readonly_location(address, field="write address")
    address_expr = f"(unsigned long)({address})"
    if not isinstance(hex_data, str):
        raise InvalidArgument("write_memory hex_data must be a string")
    if len(hex_data) > 4 << 20:
        raise InvalidArgument("write_memory hex_data source must be at most 4194304 characters")
    cleaned = hex_data.replace(" ", "").replace("\\x", "")
    if len(cleaned) > 2 << 20:
        raise InvalidArgument(
            f"write_memory hex_data must encode at most {1 << 20} bytes"
        )
    if len(cleaned) % 2:
        raise InvalidArgument(
            f"write_memory hex_data must have even length (got len={len(cleaned)})"
        )
    try:
        payload = bytes.fromhex(cleaned)
    except ValueError as e:
        raise InvalidArgument(f"write_memory hex_data is not valid hex: {e}") from e
    _validate_payload_size(payload, field="write_memory hex_data")
    ctrl = await get_controller()
    expr = (
        f"addr = int(pwndbg.dbg.selected_inferior().evaluate_expression({address_expr!r}));\n"
        f"data = bytes.fromhex({cleaned!r});\n"
        "pwndbg.aglib.memory.write(addr, data);\n"
        "mcp_emit({'wrote': len(data), 'addr': hex(addr)})"
    )
    result: dict[str, Any] = await ctrl.pi_query(expr, timeout=10.0)
    return f"wrote {result['wrote']} bytes at {result['addr']}"


@mcp.tool()
@require_stopped
async def mprotect(
    address: Annotated[str, "Start of region (will be page-aligned)"],
    length: Annotated[int, "Region length in bytes"],
    prot: Annotated[
        str,
        "Permission string: combination of 'r','w','x' (e.g. 'rwx')",
    ],
) -> str:
    """Change memory protection on a region (mirrors `mprotect`)"""
    address = _validate_readonly_location(address, field="mprotect address")
    length = _validate_bounded_int(
        length, field="length", minimum=1, maximum=1 << 30
    )
    if (
        not isinstance(prot, str)
        or not 1 <= len(prot) <= 3
        or set(prot) - set("rwx")
        or len(set(prot)) != len(prot)
    ):
        raise InvalidArgument("prot must contain unique characters from 'rwx'")
    ctrl = await get_controller()
    r = await ctrl.run_command(f"mprotect {address} {length} {prot}")
    _require_gdb_success(r, "change memory protection")
    return r.text
