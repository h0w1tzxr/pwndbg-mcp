"""Glibc heap exploitation helpers"""

from __future__ import annotations

from typing import Annotated

from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import _require_gdb_success
from pwndbg_mcp.errors import require_stopped
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.types import BinEntriesResult
from pwndbg_mcp.types import HeapChunk
from pwndbg_mcp.util import _truncate_list
from pwndbg_mcp.util import _validate_limit
from pwndbg_mcp.util import _validate_readonly_location

# bin walkers share one aglib shape, so a single snippet builder covers them

_BOUNDED_CHAIN_SNIPPET = (
    "import itertools\n"
    "_chain_entries = 0\n"
    "def _take_chain(_values, _remaining):\n"
    "    _raw = list(itertools.islice(iter(_values), _remaining + 1))\n"
    "    return [hex(int(a)) for a in _raw[:_remaining]], len(_raw) > _remaining\n"
)

_BIN_SNIPPET_TEMPLATE = (
    "from pwndbg.aglib import heap as H\n"
    "h = H.current\n"
    "out = []\n"
    "_total = 0\n"
    "_truncated = False\n"
    "_walked = 0\n"
    + _BOUNDED_CHAIN_SNIPPET
    +
    "{walkers}\n"
    "if _walked >= 65536:\n"
    "    _truncated = True\n"
    "mcp_emit({{'_entries': out, '_total': _total, '_truncated': _truncated}})"
)


def _bin_walker_block(walker_name: str) -> str:
    """Build the pi snippet for one bin walker"""
    return (
        f"bins_obj = h.{walker_name}()\n"
        "if bins_obj is not None:\n"
        "    for _size, _b in bins_obj.bins.items():\n"
        "        if _walked >= 65536:\n"
        "            break\n"
        "        _walked += 1\n"
        "        _total += 1\n"
        "        if len(out) >= 4096:\n"
        "            _truncated = True\n"
        "            continue\n"
        "        _fd_chain, _fd_cut = _take_chain(_b.fd_chain, 4096 - _chain_entries)\n"
        "        _chain_entries += len(_fd_chain)\n"
        "        if _b.bk_chain:\n"
        "            _bk_chain, _bk_cut = _take_chain(_b.bk_chain, 4096 - _chain_entries)\n"
        "            _chain_entries += len(_bk_chain)\n"
        "        else:\n"
        "            _bk_chain, _bk_cut = None, False\n"
        "        _truncated = _truncated or _fd_cut or _bk_cut\n"
        "        out.append({\n"
        "            'bin_type': str(bins_obj.bin_type),\n"
        "            'size': _size if isinstance(_size, int) else str(_size),\n"
        "            'fd_chain': _fd_chain,\n"
        "            'bk_chain': _bk_chain,\n"
        "            'count': _b.count,\n"
        "            'is_corrupted': bool(_b.is_corrupted),\n"
        "        })\n"
    )


@mcp.tool()
@require_stopped
async def bins(
    limit: Annotated[int | None, "Max entries. None removes the soft cap; hard cap is 4096"] = 200,
) -> BinEntriesResult:
    """Return arena bins and tcache entries as one list"""
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    walkers = "\n".join(
        _bin_walker_block(w)
        for w in ("fastbins", "tcachebins", "unsortedbin", "smallbins", "largebins")
    )
    expr = _BIN_SNIPPET_TEMPLATE.format(walkers=walkers)
    items = await ctrl.pi_query(expr, timeout=15.0)
    return _truncate_list(items, limit)


@mcp.tool()
@require_stopped
async def fastbins(
    limit: Annotated[int | None, "Max entries. None removes the soft cap; hard cap is 4096"] = 200,
) -> BinEntriesResult:
    """Return fastbins as bin entries"""
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    expr = _BIN_SNIPPET_TEMPLATE.format(walkers=_bin_walker_block("fastbins"))
    items = await ctrl.pi_query(expr)
    return _truncate_list(items, limit)


@mcp.tool()
@require_stopped
async def smallbins(
    limit: Annotated[int | None, "Max entries. None removes the soft cap; hard cap is 4096"] = 200,
) -> BinEntriesResult:
    """Smallbins as a list of BinEntry"""
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    expr = _BIN_SNIPPET_TEMPLATE.format(walkers=_bin_walker_block("smallbins"))
    items = await ctrl.pi_query(expr)
    return _truncate_list(items, limit)


@mcp.tool()
@require_stopped
async def largebins(
    limit: Annotated[int | None, "Max entries. None removes the soft cap; hard cap is 4096"] = 200,
) -> BinEntriesResult:
    """Largebins as a list of BinEntry"""
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    expr = _BIN_SNIPPET_TEMPLATE.format(walkers=_bin_walker_block("largebins"))
    items = await ctrl.pi_query(expr)
    return _truncate_list(items, limit)


@mcp.tool()
@require_stopped
async def unsorted_bin(
    limit: Annotated[int | None, "Max entries. None removes the soft cap; hard cap is 4096"] = 200,
) -> BinEntriesResult:
    """Unsorted bin as a list of BinEntry"""
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    expr = _BIN_SNIPPET_TEMPLATE.format(walkers=_bin_walker_block("unsortedbin"))
    items = await ctrl.pi_query(expr)
    return _truncate_list(items, limit)


@mcp.tool()
@require_stopped
async def tcache(
    limit: Annotated[int | None, "Max entries. None removes the soft cap; hard cap is 4096"] = 200,
) -> BinEntriesResult:
    """Thread tcache as a list of BinEntry (mirrors `tcache`)"""
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    expr = _BIN_SNIPPET_TEMPLATE.format(walkers=_bin_walker_block("tcachebins"))
    items = await ctrl.pi_query(expr)
    return _truncate_list(items, limit)


@mcp.tool()
@require_stopped
async def find_fake_fast(
    address: Annotated[str, "Target address potentially overlapping a fast/tcache chunk"],
    align: Annotated[
        bool, "Require MALLOC_ALIGNMENT-aligned candidates (needed for tcache and Safe Linking)"
    ] = False,
    partial_overwrite: Annotated[bool, "Consider partial-overwrite candidates"] = False,
) -> str:
    """Find candidate fake fast/tcache chunks overlapping the specified address (mirrors `find-fake-fast`)"""
    address = _validate_readonly_location(address, field="fake chunk address")
    ctrl = await get_controller()
    cmd = f"find-fake-fast {address}"
    if align:
        cmd += " --align"
    if partial_overwrite:
        cmd += " --partial-overwrite"
    r = await ctrl.run_command(cmd, timeout=15.0)
    _require_gdb_success(r, "find fake fast chunk")
    return r.text


@mcp.tool()
@require_stopped
async def try_free(
    address: Annotated[str, "Address to simulate free() on"],
) -> str:
    """Simulate `free(address)` and report any safety-check violations (mirrors `try-free`)"""
    address = _validate_readonly_location(address, field="free address")
    ctrl = await get_controller()
    r = await ctrl.run_command(f"try-free {address}", timeout=15.0)
    _require_gdb_success(r, "simulate free")
    return r.text


@mcp.tool()
@require_stopped
async def tcachebins(
    address: Annotated[
        str | None,
        "Optional tcache bin base address; default = current thread's tcache",
    ] = None,
    limit: Annotated[int | None, "Max entries. None removes the soft cap; hard cap is 4096"] = 200,
) -> BinEntriesResult:
    """Thread tcachebins as a list of BinEntry (mirrors `tcachebins`)

    Empty bins appear as `count: 0` entries; clients can filter client-side
    """
    if address is not None:
        address = _validate_readonly_location(address, field="tcache address")
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    address_expr = f"(unsigned long)({address})" if address else None
    addr_clause = (
        f"int(pwndbg.dbg.selected_inferior().evaluate_expression({address_expr!r}))"
        if address_expr
        else "None"
    )
    expr = (
        "from pwndbg.aglib import heap as H\n"
        "h = H.current\n"
        f"_tcache_addr = {addr_clause}\n"
        "out = []\n"
        "_total = 0\n"
        "_truncated = False\n"
        "_walked = 0\n"
        + _BOUNDED_CHAIN_SNIPPET
        +
        "bins_obj = h.tcachebins(_tcache_addr)\n"
        "if bins_obj is not None:\n"
        "    for _size, _b in bins_obj.bins.items():\n"
        "        if _walked >= 65536:\n"
        "            break\n"
        "        _walked += 1\n"
        "        _total += 1\n"
        "        if len(out) >= 4096:\n"
        "            _truncated = True\n"
        "            continue\n"
        "        _fd_chain, _fd_cut = _take_chain(_b.fd_chain, 4096 - _chain_entries)\n"
        "        _chain_entries += len(_fd_chain)\n"
        "        if _b.bk_chain:\n"
        "            _bk_chain, _bk_cut = _take_chain(_b.bk_chain, 4096 - _chain_entries)\n"
        "            _chain_entries += len(_bk_chain)\n"
        "        else:\n"
        "            _bk_chain, _bk_cut = None, False\n"
        "        _truncated = _truncated or _fd_cut or _bk_cut\n"
        "        out.append({\n"
        "            'bin_type': str(bins_obj.bin_type),\n"
        "            'size': _size if isinstance(_size, int) else str(_size),\n"
        "            'fd_chain': _fd_chain,\n"
        "            'bk_chain': _bk_chain,\n"
        "            'count': _b.count,\n"
        "            'is_corrupted': bool(_b.is_corrupted),\n"
        "        })\n"
        "if _walked >= 65536:\n"
        "    _truncated = True\n"
        "mcp_emit({'_entries': out, '_total': _total, '_truncated': _truncated})"
    )
    items = await ctrl.pi_query(expr)
    return _truncate_list(items, limit)


@mcp.tool()
@require_stopped
async def hi(
    address: Annotated[str, "Address to look up in any heap"],
    fake: Annotated[bool, "Allow fake chunks (treat any memory as a chunk)"] = False,
) -> HeapChunk:
    """Heap inspector: find which chunk an address belongs to (mirrors `hi`)

    Returns the containing chunk as a HeapChunk dict with all supported fields;
    clients can filter the returned structure
    """
    address = _validate_readonly_location(address, field="heap address")
    address_expr = f"(unsigned long)({address})"
    ctrl = await get_controller()
    expr = (
        "from pwndbg.aglib.heap.ptmalloc import Heap, Chunk\n"
        f"_addr = int(pwndbg.dbg.selected_inferior().evaluate_expression({address_expr!r}));\n"
        f"_allow_fake = {fake!r}\n"
        "_heap = Heap(_addr)\n"
        "if not _allow_fake and _heap.arena is None:\n"
        "    raise RuntimeError(f'address {hex(_addr)} is not in a known heap (use fake=True to force-interpret)')\n"
        "_found = None\n"
        "_walked = 0\n"
        "for _ch in _heap:\n"
        "    if _walked >= 65536:\n"
        "        break\n"
        "    _walked += 1\n"
        "    if _addr in _ch:\n"
        "        _found = _ch\n"
        "        break\n"
        "if _found is None:\n"
        "    raise RuntimeError(f'no chunk containing {hex(_addr)} found in heap')\n"
        "_ch = _found\n"
        "mcp_emit({\n"
        "    'addr': hex(_ch.address),\n"
        "    'size': int(_ch.size) if _ch.size is not None else 0,\n"
        "    'real_size': int(_ch.real_size) if _ch.real_size is not None else 0,\n"
        "    'fd': hex(int(_ch.fd)) if getattr(_ch, 'fd', None) is not None else None,\n"
        "    'bk': hex(int(_ch.bk)) if getattr(_ch, 'bk', None) is not None else None,\n"
        "    'fd_nextsize': hex(int(_ch.fd_nextsize)) if getattr(_ch, 'fd_nextsize', None) is not None else None,\n"
        "    'bk_nextsize': hex(int(_ch.bk_nextsize)) if getattr(_ch, 'bk_nextsize', None) is not None else None,\n"
        "    'is_top': bool(_ch.is_top_chunk),\n"
        "    'flags': {\n"
        "        'prev_inuse': bool(_ch.prev_inuse),\n"
        "        'is_mmapped': bool(_ch.is_mmapped),\n"
        "        'non_main_arena': bool(_ch.non_main_arena),\n"
        "    },\n"
        "})"
    )
    return await ctrl.pi_query(expr, timeout=15.0)
