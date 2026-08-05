"""Linux kernel debugging surface (QEMU/kgdb)"""

from __future__ import annotations

from typing import Annotated

from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import _require_gdb_success
from pwndbg_mcp.errors import require_kernel
from pwndbg_mcp.errors import require_stopped
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.types import KTask
from pwndbg_mcp.types import KTaskListResult
from pwndbg_mcp.util import _truncate_lines
from pwndbg_mcp.util import _truncate_list
from pwndbg_mcp.util import _validate_bounded_int
from pwndbg_mcp.util import _validate_limit
from pwndbg_mcp.util import _validate_readonly_location
from pwndbg_mcp.util import _validate_safe_token


@mcp.tool()
@require_kernel
async def kbase() -> str:
    """Find the Linux kernel base address (mirrors `kbase`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("kbase", timeout=30.0)
    _require_gdb_success(r, "find kernel base")
    return r.text


@mcp.tool()
@require_kernel
async def kbpf() -> str:
    """List loaded eBPF programs (mirrors `kbpf`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("kbpf", timeout=20.0)
    _require_gdb_success(r, "list eBPF programs")
    return r.text


@mcp.tool()
@require_kernel
async def kchecksec() -> str:
    """Show kernel mitigations status (mirrors `kchecksec`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("kchecksec", timeout=20.0)
    _require_gdb_success(r, "check kernel security")
    return r.text


@mcp.tool()
@require_kernel
async def kcmdline() -> str:
    """Show the kernel command line (mirrors `kcmdline`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("kcmdline")
    _require_gdb_success(r, "show kernel command line")
    return r.text


@mcp.tool()
@require_kernel
async def kcurrent() -> KTask:
    """The current kernel task as a KTask dict (mirrors `kcurrent`)

    Fields: ``{pid, comm, addr}``. Requires a QEMU/kgdb kernel target
    """
    ctrl = await get_controller()
    expr = (
        "import pwndbg.aglib.kernel\n"
        "import pwndbg.aglib.memory\n"
        "_cur = pwndbg.aglib.kernel.current_task()\n"
        "_task = pwndbg.aglib.memory.get_typed_pointer('struct task_struct', _cur)\n"
        "mcp_emit({\n"
        "    'pid': int(_task['pid']),\n"
        "    'comm': _task['comm'].string(),\n"
        "    'addr': hex(int(_task)),\n"
        "})"
    )
    return await ctrl.pi_query(expr, timeout=15.0)


@mcp.tool()
@require_kernel
async def kdmesg(
    limit: Annotated[int | None, "Max output lines. None removes the soft cap; hard cap is 4096"] = 200,
) -> str:
    """Print the kernel's dmesg buffer (mirrors `kdmesg`)"""
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    r = await ctrl.run_command("kdmesg", timeout=30.0)
    _require_gdb_success(r, "read kernel messages")
    return _truncate_lines(r.text, limit)


@mcp.tool()
@require_kernel
@require_stopped
async def klookup(
    address: Annotated[str, "Kernel address to look up symbol for"],
) -> str:
    """Look up a kernel symbol by address (mirrors `klookup`)"""
    address = _validate_readonly_location(address, field="klookup address")
    ctrl = await get_controller()
    r = await ctrl.run_command(f"klookup {address}")
    _require_gdb_success(r, "look up kernel symbol")
    return r.text


@mcp.tool()
@require_kernel
async def kmod(
    limit: Annotated[int | None, "Max output lines. None removes the soft cap; hard cap is 4096"] = 200,
) -> str:
    """List loaded kernel modules (mirrors `kmod`)"""
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    r = await ctrl.run_command("kmod", timeout=20.0)
    _require_gdb_success(r, "list kernel modules")
    return _truncate_lines(r.text, limit)


@mcp.tool()
@require_kernel
async def knft() -> str:
    """Dump nftables state (mirrors `knft`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("knft", timeout=30.0)
    _require_gdb_success(r, "dump nftables")
    return r.text


@mcp.tool()
@require_kernel
async def ksyscalls(
    limit: Annotated[int | None, "Max output lines. None removes the soft cap; hard cap is 4096"] = 200,
) -> str:
    """Display the syscall table (mirrors `ksyscalls`)"""
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    r = await ctrl.run_command("ksyscalls", timeout=30.0)
    _require_gdb_success(r, "list kernel syscalls")
    return _truncate_lines(r.text, limit)


@mcp.tool()
@require_kernel
async def ktask(
    pid: Annotated[int | None, "Optional PID to focus on"] = None,
    limit: Annotated[int | None, "Max entries. None removes the soft cap; hard cap is 4096"] = 200,
) -> KTaskListResult:
    """Kernel tasks as a list of KTask dicts (mirrors `ktask`)

    Each entry: ``{pid, comm, addr}``. Requires a QEMU/kgdb kernel target
    """
    if pid is not None:
        pid = _validate_bounded_int(
            pid, field="pid", minimum=0, maximum=(1 << 31) - 1
        )
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    pid_clause = "None" if pid is None else f"int({pid})"
    expr = (
        "import pwndbg.commands.ktask as _kt\n"
        f"_filter_pid = {pid_clause}\n"
        "_tasks = _kt.get_ktasks() or ()\n"
        "out = []\n"
        "_total = 0\n"
        "_truncated = False\n"
        "_walked = 0\n"
        "for _task in _tasks:\n"
        "    for _thr in _task.threads:\n"
        "        if _walked >= 65536:\n"
        "            break\n"
        "        _walked += 1\n"
        "        if _filter_pid is not None and _thr.pid != _filter_pid:\n"
        "            continue\n"
        "        _total += 1\n"
        "        if len(out) >= 4096:\n"
        "            _truncated = True\n"
        "            continue\n"
        "        out.append({\n"
        "            'pid': int(_thr.pid),\n"
        "            'comm': str(_thr.name),\n"
        "            'addr': hex(int(_thr.thread)),\n"
        "        })\n"
        "    if _walked >= 65536:\n"
        "        break\n"
        "if _walked >= 65536:\n"
        "    _truncated = True\n"
        "mcp_emit({'_entries': out, '_total': _total, '_truncated': _truncated})"
    )
    items = await ctrl.pi_query(expr, timeout=30.0)
    return _truncate_list(items, limit)


@mcp.tool()
@require_kernel
async def kversion() -> str:
    """Show kernel version (mirrors `kversion`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("kversion")
    _require_gdb_success(r, "show kernel version")
    return r.text


@mcp.tool()
@require_kernel
@require_stopped
async def slab_info(
    name: Annotated[str, "Slab cache name (e.g. 'kmalloc-64')"],
) -> str:
    """Inspect kernel SLUB/SLAB caches (mirrors `slab info`)"""
    name = _validate_safe_token(name, field="slab name")
    ctrl = await get_controller()
    r = await ctrl.run_command(f"slab info {name}", timeout=30.0)
    _require_gdb_success(r, "show slab information")
    return r.text


@mcp.tool()
@require_kernel
async def binder() -> str:
    """Dump Android Binder state (mirrors `binder`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("binder", timeout=30.0)
    _require_gdb_success(r, "inspect binder")
    return r.text


@mcp.tool()
@require_kernel
async def buddydump() -> str:
    """Dump kernel buddy allocator state (mirrors `buddydump`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("buddydump", timeout=30.0)
    _require_gdb_success(r, "dump buddy allocator")
    return r.text
