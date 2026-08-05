"""Stack inspection: retaddr, canary, stack_view"""

from __future__ import annotations

from typing import Annotated

from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import require_stopped
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.types import CanaryInfo
from pwndbg_mcp.types import StackReturnAddrsResult
from pwndbg_mcp.types import TelescopeResult
from pwndbg_mcp.util import _truncate_list
from pwndbg_mcp.util import _validate_bounded_int
from pwndbg_mcp.util import _validate_limit


@mcp.tool()
@require_stopped
async def retaddr(
    limit: Annotated[int | None, "Max entries. None removes the soft cap; hard cap is 4096"] = 200,
) -> StackReturnAddrsResult:
    """Return addresses found on the current stack (mirrors `retaddr`)

    Each entry: ``{addr, value, symbol}`` - addr is the stack slot, value
    is the return-address pointer stored there, symbol is its resolved name
    """
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    expr = (
        "import itertools\n"
        "from pwndbg.aglib import arch as _arch, regs as _regs, stack as _stack, vmmap as _vmmap, memory as _memory\n"
        "import pwndbg.aglib.symbol\n"
        "_addresses = list(itertools.islice(_stack.callstack(), 4097))\n"
        "_truncated = len(_addresses) > 4096\n"
        "_addresses = _addresses[:4096]\n"
        "_sp = int(_regs.sp)\n"
        "_page = _vmmap.find(_sp)\n"
        "out = []\n"
        "_total = 0\n"
        "_scanned = 0\n"
        "if _page is not None:\n"
        "    _start = _page.vaddr\n"
        "    _stop = _start + _page.memsz\n"
        "    _addrs = list(_addresses)\n"
        "    while _addrs and _start < _sp < _stop and _scanned < 65536:\n"
        "        _scanned += 1\n"
        "        try:\n"
        "            _value = _memory.u(_sp)\n"
        "        except Exception:\n"
        "            _value = None\n"
        "        if _value is not None and _value in _addrs:\n"
        "            _total += 1\n"
        "            _idx = _addrs.index(_value)\n"
        "            del _addrs[:_idx]\n"
        "            if len(out) >= 4096:\n"
        "                _truncated = True\n"
        "            else:\n"
        "                out.append({\n"
        "                    'addr': hex(_sp),\n"
        "                    'value': hex(_value),\n"
        "                    'symbol': pwndbg.aglib.symbol.resolve_addr(_value) or None,\n"
        "                })\n"
        "        _sp += _arch.ptrsize\n"
        "if _scanned >= 65536:\n"
        "    _truncated = True\n"
        "mcp_emit({'_entries': out, '_total': _total, '_truncated': _truncated})"
    )
    items = await ctrl.pi_query(expr, timeout=10.0)
    return _truncate_list(items, limit)


@mcp.tool()
@require_stopped
async def canary() -> CanaryInfo:
    """Stack canary info as a CanaryInfo dict (mirrors `canary`)

    Fields ``{canary, tls_addr, on_stack, scanned, on_stack_truncated}``:
    global canary value, TLS slot, bounded stack hits, and scan provenance
    """
    ctrl = await get_controller()
    expr = (
        "import itertools\n"
        "from pwndbg.aglib import arch as _arch, stack as _stack, memory as _memory, tls as _tls\n"
        "import pwndbg.auxv\n"
        "import pwndbg.search\n"
        "from pwndbg.commands.canary import canary_value, find_tls_canary_addr\n"
        "_canary, _at_random = canary_value()\n"
        "_tls_addr = find_tls_canary_addr()\n"
        "_on_stack = []\n"
        "_scanned = 0\n"
        "_truncated = False\n"
        "if _canary is not None:\n"
        "    _packed = _arch.pack(_canary)\n"
        "    _thread_stacks = _stack.get() or {}\n"
        "    _truncated = len(_thread_stacks) > 4096\n"
        "    for _thread, _stk in itertools.islice(_thread_stacks.items(), 4096):\n"
        "        for _hit in pwndbg.search.search(_packed, start=_stk.start, end=_stk.end):\n"
        "            if _scanned >= 65536:\n"
        "                _truncated = True\n"
        "                break\n"
        "            _scanned += 1\n"
        "            if len(_on_stack) < 4096:\n"
        "                _on_stack.append(hex(int(_hit)))\n"
        "            else:\n"
        "                _truncated = True\n"
        "        if _scanned >= 65536:\n"
        "            break\n"
        "mcp_emit({\n"
        "    'canary': hex(int(_canary)) if _canary is not None else None,\n"
        "    'tls_addr': hex(int(_tls_addr)) if _tls_addr is not None else None,\n"
        "    'on_stack': _on_stack,\n"
        "    'scanned': _scanned,\n"
        "    'on_stack_truncated': _truncated,\n"
        "})"
    )
    return await ctrl.pi_query(expr, timeout=15.0)


@mcp.tool()
@require_stopped
async def stack_view(
    count: Annotated[int, "Number of telescope rows from $sp"] = 16,
    limit: Annotated[int | None, "Max entries. None removes the soft cap; hard cap is 4096"] = 200,
) -> TelescopeResult:
    """Telescope view of the stack starting at $sp (mirrors `stack`)

    Same per-entry shape as `telescope`: ``{addr, offset, chain}``
    """
    count = _validate_bounded_int(count, field="count", minimum=1, maximum=4096)
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    expr = (
        "from pwndbg.aglib import arch as _arch, regs as _regs\n"
        "import re\n"
        "import pwndbg.chain\n"
        "_ansi_re = re.compile(r'\\x1b\\[[0-9;]*[A-Za-z]')\n"
        "def _clean_chain(_value):\n"
        "    _text = _ansi_re.sub('', str(_value))\n"
        "    _lines = [_line for _line in _text.splitlines() if _line]\n"
        "    return _text, (_lines or [_text])\n"
        f"_count = {count}\n"
        "def _read_sp():\n"
        "    try:\n"
        "        return int(_regs.sp)\n"
        "    except Exception:\n"
        "        pass\n"
        "    for _name in (getattr(_arch, 'sp', None), getattr(_arch, 'stack_pointer', None), 'sp'):\n"
        "        if not _name:\n"
        "            continue\n"
        "        try:\n"
        "            return int(_regs.read_reg(_name))\n"
        "        except Exception:\n"
        "            pass\n"
        "    return int(_regs.read_reg('sp'))\n"
        "_sp = _read_sp()\n"
        "_ptr_size = _arch.ptrsize\n"
        "out = []\n"
        "for _i in range(_count):\n"
        "    _addr = _sp + _i * _ptr_size\n"
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
