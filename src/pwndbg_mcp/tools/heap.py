"""Heap inspection tools"""

from __future__ import annotations

from typing import Annotated

from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import InvalidArgument
from pwndbg_mcp.errors import _require_gdb_success
from pwndbg_mcp.errors import require_loaded
from pwndbg_mcp.errors import require_not_running
from pwndbg_mcp.errors import require_stopped
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.types import HeapChunk
from pwndbg_mcp.types import HeapChunksResult
from pwndbg_mcp.util import _truncate_lines
from pwndbg_mcp.util import _truncate_list
from pwndbg_mcp.util import _validate_bounded_int
from pwndbg_mcp.util import _validate_limit
from pwndbg_mcp.util import _validate_readonly_location
from pwndbg_mcp.util import _validate_safe_token

# shared snippet for single-chunk emitters
_CHUNK_EMIT_SNIPPET = (
    "from pwndbg.aglib.heap.ptmalloc import Chunk\n"
    "_ch = Chunk(_addr)\n"
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


@mcp.tool()
@require_stopped
async def heap(
    address: Annotated[str | None, "Optional arena/chunk address"] = None,
    limit: Annotated[
        int | None,
        "Max output lines. None removes the soft cap; hard cap is 4096",
    ] = 200,
) -> str:
    """Walk heap chunks using pwndbg's text output"""
    if address is not None:
        address = _validate_readonly_location(address, field="heap address")
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    cmd = f"heap {address}" if address else "heap"
    r = await ctrl.run_command(cmd, timeout=20.0)
    _require_gdb_success(r, "walk heap")
    return _truncate_lines(r.text, limit)


@mcp.tool()
@require_stopped
async def heap_chunks(
    address: Annotated[str | None, "Optional arena address; default=main arena"] = None,
    limit: Annotated[int, "Max chunks to walk"] = 64,
) -> HeapChunksResult:
    """Return heap chunks through aglib"""
    if address is not None:
        address = _validate_readonly_location(address, field="arena address")
    limit = _validate_bounded_int(limit, field="limit", minimum=1, maximum=4096)
    ctrl = await get_controller()
    address_expr = f"(unsigned long)({address})" if address else None
    addr_clause = (
        f"int(pwndbg.dbg.selected_inferior().evaluate_expression({address_expr!r}))"
        if address_expr
        else "None"
    )
    expr = (
        "from pwndbg.aglib import heap as H\n"
        "from pwndbg.aglib.heap.ptmalloc import Arena, Heap\n"
        "from pwndbg.commands import OnlyWithResolvedHeapSyms\n"
        f"arena_addr = {addr_clause}\n"
        "@OnlyWithResolvedHeapSyms\n"
        "def _heap_symbols_ready():\n"
        "    return True\n"
        "if _heap_symbols_ready() is not True:\n"
        "    raise MemoryError('heap symbols are unresolved or libc is unavailable; run until libc is loaded, then retry')\n"
        "def _collect_heap_chunks():\n"
        "    h = H.current\n"
        "    if h is None or not h.is_initialized():\n"
        "        raise MemoryError('heap is not initialized; run until the allocator has serviced an allocation, then retry')\n"
        "    arena = h.main_arena if arena_addr is None else Arena(arena_addr)\n"
        "    if arena is None or not getattr(arena, 'top', None):\n"
        "        raise MemoryError('heap is not initialized; run until the allocator has serviced an allocation, then retry')\n"
        "    _regions = []\n"
        "    _region_addresses = set()\n"
        "    _truncated = False\n"
        "    _active = arena.active_heap\n"
        "    while _active is not None:\n"
        "        _region_address = int(_active.start)\n"
        "        if _region_address in _region_addresses or len(_regions) >= 65536:\n"
        "            _truncated = True\n"
        "            break\n"
        "        _region_addresses.add(_region_address)\n"
        "        _regions.append(_active)\n"
        "        if arena.is_main_arena:\n"
        "            break\n"
        "        _previous = _active.prev\n"
        "        _active = Heap(_previous, arena=arena) if _previous else None\n"
        "    if arena.is_main_arena:\n"
        "        _sbrk = h.get_sbrk_heap_region()\n"
        "        if _sbrk is not None and int(arena.top) not in _sbrk:\n"
        "            _sbrk_address = int(_sbrk.start)\n"
        "            if _sbrk_address in _region_addresses or len(_regions) >= 65536:\n"
        "                _truncated = True\n"
        "            else:\n"
        "                _region_addresses.add(_sbrk_address)\n"
        "                _regions.append(Heap(_sbrk_address, arena=arena))\n"
        "    _regions.reverse()\n"
        "    out = []\n"
        "    _total = 0\n"
        "    _walked = 0\n"
        "    _stop = False\n"
        "    for region in _regions:\n"
        "        ch = region.first_chunk\n"
        "        while ch is not None:\n"
        "            if _walked >= 65536:\n"
        "                _truncated = True\n"
        "                _stop = True\n"
        "                break\n"
        "            _walked += 1\n"
        "            _total += 1\n"
        "            if len(out) >= 4096:\n"
        "                _truncated = True\n"
        "            else:\n"
        "                out.append({\n"
        "                    'addr': hex(ch.address),\n"
        "                    'size': int(ch.size) if ch.size is not None else 0,\n"
        "                    'real_size': int(ch.real_size) if ch.real_size is not None else 0,\n"
        "                    'fd': hex(int(ch.fd)) if getattr(ch, 'fd', None) is not None else None,\n"
        "                    'bk': hex(int(ch.bk)) if getattr(ch, 'bk', None) is not None else None,\n"
        "                    'is_top': bool(ch.is_top_chunk),\n"
        "                    'flags': {\n"
        "                        'prev_inuse': bool(ch.prev_inuse),\n"
        "                        'is_mmapped': bool(ch.is_mmapped),\n"
        "                        'non_main_arena': bool(ch.non_main_arena),\n"
        "                    },\n"
        "                })\n"
        "            if ch.is_top_chunk:\n"
        "                break\n"
        "            nxt = ch.next_chunk()\n"
        "            if nxt is None or nxt.address <= ch.address:\n"
        "                _truncated = True\n"
        "                break\n"
        "            ch = nxt\n"
        "        if _stop:\n"
        "            break\n"
        "    return {'_entries': out, '_total': _total, '_truncated': _truncated}\n"
        "_result = _collect_heap_chunks()\n"
        "mcp_emit(_result)"
    )
    items = await ctrl.pi_query(expr, timeout=30.0)
    return _truncate_list(items, limit)


@mcp.tool()
@require_stopped
async def vis_heap_chunks(
    count: Annotated[int, "Number of chunks to visualize"] = 10,
    address: Annotated[str | None, "Optional starting address"] = None,
) -> str:
    """Visual ASCII layout of heap chunks (mirrors `vis-heap-chunks`)"""
    if address is not None:
        address = _validate_readonly_location(address, field="heap address")
    count = _validate_bounded_int(count, field="count", minimum=1, maximum=4096)
    ctrl = await get_controller()
    cmd = f"vis-heap-chunks {count} {address}" if address else f"vis-heap-chunks {count}"
    r = await ctrl.run_command(cmd, timeout=20.0)
    _require_gdb_success(r, "visualize heap chunks")
    return r.text


@mcp.tool()
@require_stopped
async def malloc_chunk(
    address: Annotated[str, "Chunk address"],
) -> HeapChunk:
    """Metadata for a single chunk as a HeapChunk dict (mirrors `malloc-chunk`)"""
    address = _validate_readonly_location(address, field="chunk address")
    address_expr = f"(unsigned long)({address})"
    ctrl = await get_controller()
    expr = (
        f"_addr = int(pwndbg.dbg.selected_inferior().evaluate_expression({address_expr!r}));\n"
        + _CHUNK_EMIT_SNIPPET
    )
    return await ctrl.pi_query(expr, timeout=15.0)


@mcp.tool()
@require_stopped
async def top_chunk(
    address: Annotated[
        str | None, "Optional arena address; default=current thread's arena"
    ] = None,
) -> HeapChunk:
    """The arena's top chunk as a HeapChunk dict (mirrors `top-chunk`)"""
    if address is not None:
        address = _validate_readonly_location(address, field="arena address")
    ctrl = await get_controller()
    address_expr = f"(unsigned long)({address})" if address else None
    arena_clause = (
        f"int(pwndbg.dbg.selected_inferior().evaluate_expression({address_expr!r}))"
        if address_expr
        else "None"
    )
    expr = (
        "from pwndbg.aglib import heap as H\n"
        "from pwndbg.aglib.heap.ptmalloc import Arena\n"
        f"_arena_addr = {arena_clause}\n"
        "if _arena_addr is not None:\n"
        "    _arena = Arena(_arena_addr)\n"
        "else:\n"
        "    _arena = H.current.thread_arena\n"
        "    if _arena is None:\n"
        "        _arena = H.current.main_arena\n"
        "_addr = int(_arena.top)\n" + _CHUNK_EMIT_SNIPPET
    )
    return await ctrl.pi_query(expr, timeout=15.0)


@mcp.tool()
@require_stopped
async def arenas() -> str:
    """List all arenas in the process (mirrors `arenas`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("arenas")
    _require_gdb_success(r, "list arenas")
    return r.text


@mcp.tool()
@require_stopped
async def arena_info(
    address: Annotated[str | None, "Optional arena address; default=main arena"] = None,
) -> str:
    """Show metadata for one arena"""
    if address is not None:
        address = _validate_readonly_location(address, field="arena address")
    ctrl = await get_controller()
    cmd = f"arena {address}" if address else "arena"
    r = await ctrl.run_command(cmd)
    _require_gdb_success(r, "show arena")
    return r.text


@mcp.tool()
@require_stopped
async def mp_struct() -> str:
    """Show the malloc_par structure (`mp`), the global allocator parameters"""
    ctrl = await get_controller()
    r = await ctrl.run_command("mp")
    _require_gdb_success(r, "show malloc parameters")
    return r.text


@mcp.tool()
@require_not_running
async def heap_config(
    filter_pattern: Annotated[
        str | None,
        "Filter to apply to config parameter names/descriptions",
    ] = None,
) -> str:
    """Show pwndbg's glibc heap heuristic configuration (mirrors `heap-config`)"""
    if filter_pattern is not None:
        filter_pattern = _validate_safe_token(
            filter_pattern, field="heap config filter"
        )
    ctrl = await get_controller()
    cmd = f"heap-config {filter_pattern}" if filter_pattern else "heap-config"
    r = await ctrl.run_command(cmd)
    _require_gdb_success(r, "show heap configuration")
    return r.text


@mcp.tool()
@require_loaded
async def track_heap(
    action: Annotated[
        str,
        "Subcommand: 'enable', 'disable', or 'toggle-break'",
    ],
) -> str:
    """Enable/disable pwndbg's glibc heap usage tracker (UAF/double-free detector)

    Mirrors `track-heap <action>`. Installs GDB breakpoints on malloc/free/realloc
    when enabled, so it counts as MUTATING
    """
    if action not in ("enable", "disable", "toggle-break"):
        raise InvalidArgument(
            f"track_heap action must be 'enable', 'disable', or 'toggle-break' (got {action!r})"
        )
    ctrl = await get_controller()
    r = await ctrl.run_command(f"track-heap {action}", timeout=15.0)
    _require_gdb_success(r, "configure heap tracking")
    return r.text
