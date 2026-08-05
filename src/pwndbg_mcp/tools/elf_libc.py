"""ELF, libc, and dynamic-loader inspection"""

from __future__ import annotations

from typing import Annotated

from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import InvalidArgument
from pwndbg_mcp.errors import _require_gdb_success
from pwndbg_mcp.errors import require_loaded
from pwndbg_mcp.errors import require_stopped
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.types import ChecksecReport
from pwndbg_mcp.types import ElfSectionsResult
from pwndbg_mcp.types import ErrnoResult
from pwndbg_mcp.types import GotEntriesResult
from pwndbg_mcp.types import LibcInfo
from pwndbg_mcp.types import LinkmapResult
from pwndbg_mcp.util import _safe_gdb_arg
from pwndbg_mcp.util import _truncate_list
from pwndbg_mcp.util import _validate_bounded_int
from pwndbg_mcp.util import _validate_limit
from pwndbg_mcp.util import _validate_text_size


@mcp.tool()
@require_loaded
async def checksec() -> ChecksecReport:
    """Return checksec fields plus raw output"""
    ctrl = await get_controller()
    r = await ctrl.run_command("checksec")
    _require_gdb_success(r, "checksec")
    raw = r.text or ""
    out: ChecksecReport = {"raw": raw}
    low = raw.lower()
    # parse only unambiguous fields, callers read raw for the rest
    out["pie"] = "pie:" in low and "no pie" not in low
    out["canary"] = "canary found" in low
    out["nx"] = "nx enabled" in low
    if "full relro" in low:
        out["relro"] = "Full"
    elif "partial relro" in low:
        out["relro"] = "Partial"
    elif "no relro" in low:
        out["relro"] = "No"
    else:
        out["relro"] = "Unknown"
    return out


@mcp.tool()
@require_stopped
async def piebase() -> str:
    """Print the PIE base address"""
    ctrl = await get_controller()
    r = await ctrl.run_command("piebase")
    _require_gdb_success(r, "piebase")
    return r.text


@mcp.tool()
@require_stopped
async def got(
    filter_: Annotated[str | None, "Optional symbol substring filter"] = None,
    limit: Annotated[int | None, "Max entries. None removes the soft cap; hard cap is 4096"] = 200,
) -> GotEntriesResult:
    """Return live got entries with current resolved pointers"""
    if filter_ is not None:
        filter_ = _validate_text_size(filter_, field="GOT filter")
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    filter_repr = repr(filter_) if filter_ else "None"
    expr = (
        "import pwndbg.aglib.file\n"
        "import pwndbg.aglib.proc\n"
        "import pwndbg.aglib.memory\n"
        "import pwndbg.lib.got\n"
        "import pwndbg.wrappers.checksec\n"
        f"_filter = {filter_repr}\n"
        "_exe = pwndbg.aglib.proc.exe()\n"
        "_local = pwndbg.aglib.file.get_file(_exe, try_local_path=True)\n"
        "_pie = pwndbg.wrappers.checksec.pie_status(_local)\n"
        "_base = pwndbg.aglib.proc.binary_base_addr() if 'PIE enabled' in _pie else 0\n"
        "_got = pwndbg.lib.got.get_got_entry(_local)\n"
        "out = []\n"
        "_total = 0\n"
        "_truncated = False\n"
        "_walked = 0\n"
        "for _cat, _entries in _got.items():\n"
        "    for _e in _entries:\n"
        "        if _walked >= 65536:\n"
        "            break\n"
        "        _walked += 1\n"
        "        _name = str(_e.get('name', '') or '')\n"
        "        if _filter and _filter not in _name:\n"
        "            continue\n"
        "        _total += 1\n"
        "        if len(out) >= 4096:\n"
        "            _truncated = True\n"
        "            continue\n"
        "        _addr = int(_e['offset']) + _base\n"
        "        try:\n"
        "            _resolved = pwndbg.aglib.memory.read_pointer_width(_addr)\n"
        "            _resolved_str = hex(int(_resolved))\n"
        "        except Exception:\n"
        "            _resolved_str = None\n"
        "        out.append({\n"
        "            'addr': hex(_addr),\n"
        "            'symbol': _name or '????',\n"
        "            'resolved': _resolved_str,\n"
        "        })\n"
        "    if _walked >= 65536:\n"
        "        break\n"
        "if _walked >= 65536:\n"
        "    _truncated = True\n"
        "out.sort(key=lambda r: int(r['addr'], 16))\n"
        "mcp_emit({'_entries': out, '_total': _total, '_truncated': _truncated})"
    )
    items = await ctrl.pi_query(expr, timeout=15.0)
    return _truncate_list(items, limit)


@mcp.tool()
@require_stopped
async def gotplt(
    limit: Annotated[int | None, "Max entries. None removes the soft cap; hard cap is 4096"] = 200,
) -> GotEntriesResult:
    """Symbols found in the ``.got.plt`` section (mirrors `gotplt`)

    Returns entries with ``{addr, symbol}`` - ``resolved`` is omitted (these
    are static section slots, not live function pointers like ``got``)
    """
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    expr = (
        "import pwndbg.aglib.file\n"
        "import pwndbg.aglib.proc\n"
        "import pwndbg.aglib.symbol\n"
        "import pwndbg.aglib.typeinfo\n"
        "from elftools.elf.elffile import ELFFile\n"
        "_exe = pwndbg.aglib.proc.exe()\n"
        "_local = pwndbg.aglib.file.get_file(_exe, try_local_path=True)\n"
        "with open(_local, 'rb') as _f:\n"
        "    _elf = ELFFile(_f)\n"
        "    _sect = _elf.get_section_by_name('.got.plt')\n"
        "    _start = _sect['sh_addr'] if _sect else None\n"
        "    _size = _sect['sh_size'] if _sect else 0\n"
        "out = []\n"
        "_total = 0\n"
        "_truncated = False\n"
        "_walked = 0\n"
        "if _start is not None:\n"
        "    _end = _start + _size\n"
        "    if pwndbg.aglib.proc.alive():\n"
        "        _bin_base = pwndbg.aglib.proc.binary_base_addr()\n"
        "        if _start < _bin_base:\n"
        "            _start += _bin_base\n"
        "            _end += _bin_base\n"
        "    _ptr_size = pwndbg.aglib.typeinfo.pvoid.sizeof\n"
        "    _addr = _start\n"
        "    while _addr < _end and _walked < 65536:\n"
        "        _walked += 1\n"
        "        _name = pwndbg.aglib.symbol.resolve_addr(_addr)\n"
        "        if _name and '+' not in _name and '@got.plt' in _name:\n"
        "            _total += 1\n"
        "            if len(out) < 4096:\n"
        "                out.append({'addr': hex(_addr), 'symbol': _name})\n"
        "            else:\n"
        "                _truncated = True\n"
        "        _addr += _ptr_size\n"
        "if _walked >= 65536:\n"
        "    _truncated = True\n"
        "mcp_emit({'_entries': out, '_total': _total, '_truncated': _truncated})"
    )
    items = await ctrl.pi_query(expr, timeout=15.0)
    return _truncate_list(items, limit)


@mcp.tool()
@require_stopped
async def plt(
    limit: Annotated[int | None, "Max entries. None removes the soft cap; hard cap is 4096"] = 200,
) -> GotEntriesResult:
    """Symbols in the PLT family of sections (mirrors `plt`)

    Walks ``.plt``, ``.plt.sec``, ``.plt.got``, ``.plt.bnd``. Each entry:
    ``{addr, symbol}`` for symbols whose name ends ``@plt``
    """
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    expr = (
        "import pwndbg.aglib.file\n"
        "import pwndbg.aglib.proc\n"
        "import pwndbg.aglib.symbol\n"
        "import pwndbg.aglib.typeinfo\n"
        "from elftools.elf.elffile import ELFFile\n"
        "_PLT_NAMES = ('.plt', '.plt.sec', '.plt.got', '.plt.bnd')\n"
        "_exe = pwndbg.aglib.proc.exe()\n"
        "_local = pwndbg.aglib.file.get_file(_exe, try_local_path=True)\n"
        "_bin_base = pwndbg.aglib.proc.binary_base_addr() if pwndbg.aglib.proc.alive() else 0\n"
        "_sections = []\n"
        "with open(_local, 'rb') as _f:\n"
        "    _elf = ELFFile(_f)\n"
        "    for _name in _PLT_NAMES:\n"
        "        _sect = _elf.get_section_by_name(_name)\n"
        "        if _sect is None:\n"
        "            continue\n"
        "        _start = _sect['sh_addr']\n"
        "        _size = _sect['sh_size']\n"
        "        if _start is None:\n"
        "            continue\n"
        "        _end = _start + _size\n"
        "        if _start < _bin_base:\n"
        "            _start += _bin_base\n"
        "            _end += _bin_base\n"
        "        _sections.append((_start, _end))\n"
        "out = []\n"
        "_total = 0\n"
        "_truncated = False\n"
        "_walked = 0\n"
        "_ptr_size = pwndbg.aglib.typeinfo.pvoid.sizeof\n"
        "for _s, _e in _sections:\n"
        "    if _walked >= 65536:\n"
        "        break\n"
        "    _addr = _s\n"
        "    while _addr < _e and _walked < 65536:\n"
        "        _walked += 1\n"
        "        _name = pwndbg.aglib.symbol.resolve_addr(_addr)\n"
        "        if _name and '+' not in _name and '@plt' in _name:\n"
        "            _total += 1\n"
        "            if len(out) < 4096:\n"
        "                out.append({'addr': hex(_addr), 'symbol': _name})\n"
        "            else:\n"
        "                _truncated = True\n"
        "        _addr += _ptr_size\n"
        "if _walked >= 65536:\n"
        "    _truncated = True\n"
        "mcp_emit({'_entries': out, '_total': _total, '_truncated': _truncated})"
    )
    items = await ctrl.pi_query(expr, timeout=15.0)
    return _truncate_list(items, limit)


@mcp.tool()
@require_stopped
async def tls() -> str:
    """Print thread-local storage address (mirrors `tls`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("tls")
    _require_gdb_success(r, "tls")
    return r.text


@mcp.tool()
@require_stopped
async def libcinfo() -> LibcInfo:
    """Return libc info as a record (mirrors `libcinfo`)

    Fields: ``{libc_type, version, base, path, ld_base, ld_path,
    has_exported_symbols, has_internal_symbols, has_debug_info}``
    """
    ctrl = await get_controller()
    expr = (
        "import pwndbg.libc\n"
        "import pwndbg.libc.facade\n"
        "_version = pwndbg.libc.facade.version()\n"
        "_vstr = '.'.join(map(str, _version)) if _version else 'unknown'\n"
        "if _vstr == '-1.-1':\n"
        "    _vstr = 'no version information'\n"
        "_base = pwndbg.libc.addr()\n"
        "_ld_base = pwndbg.libc.loader_addr()\n"
        "mcp_emit({\n"
        "    'libc_type': str(pwndbg.libc.which().value),\n"
        "    'version': _vstr,\n"
        "    'base': hex(int(_base)) if _base is not None else None,\n"
        "    'path': str(pwndbg.libc.filepath()) if pwndbg.libc.filepath() else None,\n"
        "    'ld_base': hex(int(_ld_base)) if _ld_base is not None else None,\n"
        "    'ld_path': str(pwndbg.libc.loader_filepath()) if pwndbg.libc.loader_filepath() else None,\n"
        "    'has_exported_symbols': bool(pwndbg.libc.has_exported_symbols()),\n"
        "    'has_internal_symbols': bool(pwndbg.libc.has_internal_symbols()),\n"
        "    'has_debug_info': bool(pwndbg.libc.has_debug_info()),\n"
        "})"
    )
    return await ctrl.pi_query(expr, timeout=10.0)


@mcp.tool()
@require_loaded
async def elfsections(
    no_rebase: Annotated[bool, "Use raw ELF offsets (don't rebase by binary_base_addr)"] = False,
    limit: Annotated[int | None, "Max entries. None removes the soft cap; hard cap is 4096"] = 200,
) -> ElfSectionsResult:
    """List ELF section mappings (mirrors `elfsections`)

    Each entry: ``{name, start, end, size, perm}``. ``perm`` is a 3-char
    string of "rwx" / "-" flags from the section's sh_flags. Only sections
    with SHF_ALLOC are emitted (matches pwndbg's behavior)
    """
    if not isinstance(no_rebase, bool):
        raise InvalidArgument("no_rebase must be a boolean")
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    expr = (
        "import pwndbg.aglib.file\n"
        "import pwndbg.aglib.proc\n"
        "from elftools.elf.elffile import ELFFile\n"
        f"_no_rebase = {no_rebase!r}\n"
        "_exe = pwndbg.aglib.proc.exe()\n"
        "_local = pwndbg.aglib.file.get_file(_exe, try_local_path=True)\n"
        "_bin_base = pwndbg.aglib.proc.binary_base_addr() if pwndbg.aglib.proc.alive() else 0\n"
        "_SH_WRITE = 1 << 0\n"
        "_SH_ALLOC = 1 << 1\n"
        "_SH_EXEC  = 1 << 2\n"
        "out = []\n"
        "_total = 0\n"
        "_truncated = False\n"
        "_walked = 0\n"
        "with open(_local, 'rb') as _f:\n"
        "    _elf = ELFFile(_f)\n"
        "    for _sect in _elf.iter_sections():\n"
        "        if _walked >= 65536:\n"
        "            break\n"
        "        _walked += 1\n"
        "        _start = _sect['sh_addr']\n"
        "        _flags = _sect['sh_flags']\n"
        "        if not (_flags & _SH_ALLOC):\n"
        "            continue\n"
        "        _total += 1\n"
        "        if len(out) >= 4096:\n"
        "            _truncated = True\n"
        "            continue\n"
        "        _size = _sect['sh_size']\n"
        "        if not _no_rebase and _start < _bin_base:\n"
        "            _start = _bin_base + _start\n"
        "        _perm = (\n"
        "            ('r' if _flags & _SH_ALLOC else '-')\n"
        "            + ('w' if _flags & _SH_WRITE else '-')\n"
        "            + ('x' if _flags & _SH_EXEC  else '-')\n"
        "        )\n"
        "        out.append({\n"
        "            'name': _sect.name,\n"
        "            'start': hex(_start),\n"
        "            'end': hex(_start + _size),\n"
        "            'size': int(_size),\n"
        "            'perm': _perm,\n"
        "        })\n"
        "if _walked >= 65536:\n"
        "    _truncated = True\n"
        "out.sort(key=lambda r: int(r['start'], 16))\n"
        "mcp_emit({'_entries': out, '_total': _total, '_truncated': _truncated})"
    )
    items = await ctrl.pi_query(expr, timeout=15.0)
    return _truncate_list(items, limit)


@mcp.tool()
@require_loaded
async def track_got(
    action: Annotated[
        str,
        "Subcommand: 'enable', 'disable', 'info', or 'query'",
    ],
    target: Annotated[
        str | None,
        "GOT entry to query (only for action='query'; symbol name or address)",
    ] = None,
) -> str:
    """Track GOT modifications across execution (mirrors `track-got <action>`)

    enable/disable counts as MUTATING; info/query are read-only but the same dispatch
    is used for both - flagged MUTATING in the registry to keep approval gating sane
    """
    if action not in ("enable", "disable", "info", "query"):
        raise InvalidArgument(
            f"track_got action must be 'enable', 'disable', 'info', or 'query' (got {action!r})"
        )
    if action == "query" and not target:
        raise InvalidArgument(
            "track_got action='query' requires the `target` arg (symbol name or address)"
        )
    if target is not None:
        target = _safe_gdb_arg(
            _validate_text_size(target, field="GOT target"), field="GOT target"
        )
    ctrl = await get_controller()
    cmd = f"track-got {action}"
    if action == "query":
        cmd += f" {target}"
    r = await ctrl.run_command(cmd, timeout=15.0)
    _require_gdb_success(r, "track GOT")
    return r.text


@mcp.tool()
@require_stopped
async def linkmap(
    limit: Annotated[int | None, "Max entries. None removes the soft cap; hard cap is 4096"] = 200,
) -> LinkmapResult:
    """Dynamic linker's link_map as a list (mirrors `linkmap`)

    Each entry: ``{link_map_address, objfile, load_bias, dynamic}``
    """
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    expr = (
        "import pwndbg.aglib.dynamic\n"
        "import pwndbg.aglib.proc\n"
        "out = []\n"
        "_total = 0\n"
        "_is_first = True\n"
        "_truncated = False\n"
        "_walked = 0\n"
        "for _obj in pwndbg.aglib.dynamic.link_map():\n"
        "    if _walked >= 65536:\n"
        "        break\n"
        "    _walked += 1\n"
        "    _total += 1\n"
        "    if len(out) >= 4096:\n"
        "        _truncated = True\n"
        "        continue\n"
        "    _name = _obj.name().decode('utf-8', errors='ignore')\n"
        "    if _name == '':\n"
        "        _name = '<Unknown'\n"
        "        if _is_first:\n"
        "            _is_first = False\n"
        "            _name += f', likely {pwndbg.aglib.proc.exe()}'\n"
        "        _name += '>'\n"
        "    out.append({\n"
        "        'link_map_address': hex(int(_obj.link_map_address)),\n"
        "        'objfile': _name,\n"
        "        'load_bias': hex(int(_obj.load_bias())),\n"
        "        'dynamic': hex(int(_obj.dynamic())),\n"
        "    })\n"
        "if _walked >= 65536:\n"
        "    _truncated = True\n"
        "mcp_emit({'_entries': out, '_total': _total, '_truncated': _truncated})"
    )
    items = await ctrl.pi_query(expr, timeout=10.0)
    return _truncate_list(items, limit)


@mcp.tool()
@require_stopped
async def errno(
    value: Annotated[
        int | None, "Optional errno value to look up; default = current libc errno"
    ] = None,
) -> ErrnoResult:
    """Return the libc errno value and name as a record (mirrors `errno`)

    Fields: ``{errno, name}``. With no arg, reads __errno_location's current
    value. With an arg, looks up the symbolic name for that errno
    """
    if value is not None:
        value = _validate_bounded_int(
            value,
            field="errno value",
            minimum=-(1 << 31),
            maximum=(1 << 31) - 1,
        )
    ctrl = await get_controller()
    value_clause = "None" if value is None else f"int({value})"
    expr = (
        "import errno as _errno_mod\n"
        "import pwndbg.aglib.errno\n"
        f"_value = {value_clause}\n"
        "if _value is None:\n"
        "    _err, _err_str = pwndbg.aglib.errno.get()\n"
        "    _value = int(_err) if _err is not None else 0\n"
        "_name = 'OK' if int(_value) == 0 else _errno_mod.errorcode.get(int(_value), 'Unknown error code')\n"
        "mcp_emit({'errno': int(_value), 'name': _name})"
    )
    return await ctrl.pi_query(expr, timeout=10.0)
