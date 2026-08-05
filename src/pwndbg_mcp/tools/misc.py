"""Miscellaneous pwndbg utilities: patch, plist, procinfo, dumpargs, cyclic, spray, probeleak,
valist, sigreturn, hijack-fd, mmap, dt, version"""

from __future__ import annotations

from typing import Annotated

from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import InvalidArgument
from pwndbg_mcp.errors import _require_gdb_success
from pwndbg_mcp.errors import require_not_running
from pwndbg_mcp.errors import require_stopped
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.util import _safe_gdb_arg
from pwndbg_mcp.util import _truncate_lines
from pwndbg_mcp.util import _validate_bounded_int
from pwndbg_mcp.util import _validate_limit
from pwndbg_mcp.util import _validate_readonly_location
from pwndbg_mcp.util import _validate_safe_identifier
from pwndbg_mcp.util import _validate_safe_type_name
from pwndbg_mcp.util import _validate_text_size


@mcp.tool()
@require_stopped
async def patch(
    address: Annotated[str, "Address to patch"],
    instructions: Annotated[
        str,
        "Either assembly source (e.g. 'nop;nop;nop') or hex bytes (e.g. '90 90 90')",
    ],
) -> str:
    """Patch memory with assembly or bytes (mirrors `patch`)"""
    address = _safe_gdb_arg(address, field="patch address")
    instructions = _validate_text_size(instructions, field="instructions")
    instructions = _safe_gdb_arg(instructions, field="patch instructions")
    ctrl = await get_controller()
    r = await ctrl.run_command(f"patch {address} '{instructions}'")
    _require_gdb_success(r, "patch memory")
    return r.text or "patched"


@mcp.tool()
async def patch_list() -> str:
    """List currently-applied patches (mirrors `patch-list`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("patch-list")
    _require_gdb_success(r, "list patches")
    return r.text or "(none)"


@mcp.tool()
async def patch_revert(
    address: Annotated[str, "Address of the previously-applied patch to revert"],
) -> str:
    """Revert a previously-applied patch by its address (mirrors `patch-revert`)"""
    address = _validate_readonly_location(address, field="patch address")
    ctrl = await get_controller()
    r = await ctrl.run_command(f"patch-revert {address}")
    _require_gdb_success(r, "revert patch")
    return r.text or "reverted"


@mcp.tool()
@require_stopped
async def plist(
    address: Annotated[str, "Address of the linked-list head"],
    next_field: Annotated[str, "Field name pointing to the next element (e.g. 'next')"],
    limit: Annotated[int, "Max elements to dump"] = 32,
) -> str:
    """Dump a linked-list starting from an address (mirrors `plist`)"""
    address = _validate_readonly_location(address, field="list address")
    next_field = _validate_safe_identifier(next_field, field="next field")
    limit = _validate_bounded_int(limit, field="limit", minimum=1, maximum=4096)
    ctrl = await get_controller()
    r = await ctrl.run_command(f"plist {address} {next_field} -c {limit}", timeout=30.0)
    _require_gdb_success(r, "walk linked list")
    return r.text


@mcp.tool()
@require_stopped
async def procinfo() -> str:
    """Show /proc/<PID> summary for the inferior (mirrors `procinfo`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("procinfo")
    _require_gdb_success(r, "show process information")
    return r.text


@mcp.tool()
@require_stopped
async def dumpargs(
    limit: Annotated[int | None, "Max output lines. None removes the soft cap; hard cap is 4096"] = 64,
) -> str:
    """Dump function arguments at the current call site (mirrors `dumpargs`)"""
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    r = await ctrl.run_command("dumpargs")
    _require_gdb_success(r, "dump arguments")
    return _truncate_lines(r.text, limit)


@mcp.tool()
async def cyclic(
    length: Annotated[int, "Pattern length"] = 64,
    n: Annotated[int, "Subsequence length (4 for 32-bit, 8 for 64-bit)"] = 4,
) -> str:
    """Generate a cyclic De Bruijn pattern (mirrors `cyclic`)"""
    length = _validate_bounded_int(
        length, field="length", minimum=1, maximum=1 << 20
    )
    n = _validate_bounded_int(n, field="n", minimum=1, maximum=16)
    ctrl = await get_controller()
    r = await ctrl.run_command(f"cyclic {length} -n {n}")
    _require_gdb_success(r, "generate cyclic pattern")
    return r.text


@mcp.tool()
@require_not_running
async def cyclic_find(
    value: Annotated[str, "Hex value (e.g. '0x6161616a' or 'aaaajaa')"],
    n: Annotated[int, "Subsequence length used to generate the pattern"] = 4,
) -> str:
    """Find the offset of a value in a cyclic pattern (mirrors `cyclic --find`)"""
    value = _validate_readonly_location(value, field="cyclic lookup value")
    n = _validate_bounded_int(n, field="n", minimum=1, maximum=16)
    ctrl = await get_controller()
    r = await ctrl.run_command(f"cyclic -l {value} -n {n}")
    _require_gdb_success(r, "find cyclic offset")
    return r.text


@mcp.tool()
@require_stopped
async def spray(
    address: Annotated[str, "Start address"],
    length: Annotated[int, "Bytes to spray (1..1048576)"] = 4096,
    value: Annotated[
        str | None,
        "Optional value to spray. Prefix with '0x' for hex (big-endian). Default = pwndbg cyclic pattern",
    ] = None,
    only_funcptrs: Annotated[
        bool, "Spray only addresses whose values point to executable pages"
    ] = False,
) -> str:
    """Spray memory with cyclic() values, or with a fixed value (mirrors `spray`)"""
    address = _validate_readonly_location(address, field="spray address")
    length = _validate_bounded_int(
        length, field="length", minimum=1, maximum=1 << 20
    )
    if value is not None:
        value = _safe_gdb_arg(
            _validate_text_size(value, field="spray value"), field="spray value"
        )
    if not isinstance(only_funcptrs, bool):
        raise InvalidArgument("only_funcptrs must be a boolean")
    ctrl = await get_controller()
    cmd = "spray"
    if value is not None:
        cmd += f" --value {value}"
    if only_funcptrs:
        cmd += " -x"
    cmd += f" {address}"
    cmd += f" {length}"
    r = await ctrl.run_command(cmd)
    _require_gdb_success(r, "spray memory")
    return r.text or "sprayed"


@mcp.tool()
@require_stopped
async def probeleak(
    address: Annotated[str, "Region start"],
    length: Annotated[int, "Region length in bytes"] = 0x100,
    limit: Annotated[int | None, "Max output lines. None removes the soft cap; hard cap is 4096"] = 200,
) -> str:
    """Probe a memory region for likely pointer leaks (mirrors `probeleak`)"""
    address = _validate_readonly_location(address, field="probeleak address")
    length = _validate_bounded_int(
        length, field="length", minimum=1, maximum=1 << 20
    )
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    r = await ctrl.run_command(f"probeleak {address} {length}")
    _require_gdb_success(r, "probe memory leaks")
    return _truncate_lines(r.text, limit)


@mcp.tool()
@require_stopped
async def parse_seccomp(
    address: Annotated[str, "Address of a `struct sock_fprog`"],
) -> str:
    """Parse and pretty-print a seccomp filter from memory (mirrors `parse-seccomp`)"""
    address = _validate_readonly_location(address, field="seccomp address")
    ctrl = await get_controller()
    r = await ctrl.run_command(f"parse-seccomp {address}", timeout=20.0)
    _require_gdb_success(r, "parse seccomp")
    return r.text


@mcp.tool()
@require_stopped
async def valist(
    address: Annotated[str, "Address of the va_list struct"],
    count: Annotated[int, "Number of arguments to dump"] = 8,
) -> str:
    """Dump the arguments of a va_list (mirrors `valist`)"""
    address = _validate_readonly_location(address, field="va_list address")
    count = _validate_bounded_int(count, field="count", minimum=1, maximum=4096)
    ctrl = await get_controller()
    r = await ctrl.run_command(f"valist {address} {count}")
    _require_gdb_success(r, "dump va_list")
    return r.text


@mcp.tool()
@require_stopped
async def sigreturn(
    address: Annotated[
        str | None,
        "Optional address to read the sigreturn frame from. Default = $sp",
    ] = None,
    show_all: Annotated[bool, "Show every value in the frame (not just common registers)"] = False,
    print_addrs: Annotated[bool, "Show addresses of frame values"] = False,
) -> str:
    """Display a SigreturnFrame at the given address - useful for SROP work (mirrors `sigreturn`)"""
    if address is not None:
        address = _validate_readonly_location(address, field="sigreturn address")
    ctrl = await get_controller()
    cmd = "sigreturn"
    if show_all:
        cmd += " -a"
    if print_addrs:
        cmd += " -p"
    if address:
        cmd += f" {address}"
    r = await ctrl.run_command(cmd)
    _require_gdb_success(r, "show sigreturn frame")
    return r.text


@mcp.tool()
@require_stopped
async def hijack_fd(
    fd_num: Annotated[int, "File descriptor number to replace in the inferior"],
    new_target: Annotated[
        str,
        "New target. File: '/path/...'; socket: '127.0.0.1:80', 'tcp://[::1]:80', 'udp://example.com:80'",
    ],
) -> str:
    """Replace one of the inferior's file descriptors (mirrors `hijack-fd`)

    DANGEROUS: changes inferior I/O state. Caller approval required
    """
    fd_num = _validate_bounded_int(
        fd_num, field="file descriptor", minimum=0, maximum=1 << 20
    )
    new_target = _safe_gdb_arg(
        _validate_text_size(new_target, field="new target"), field="new target"
    )
    ctrl = await get_controller()
    r = await ctrl.run_command(f"hijack-fd {fd_num} {new_target}", timeout=15.0)
    _require_gdb_success(r, "hijack file descriptor")
    return r.text or "hijacked"


@mcp.tool()
@require_stopped
async def mmap_syscall(
    address: Annotated[str, "Address hint to give to mmap (use 0 to let kernel choose)"],
    length: Annotated[int, "Mapping length in bytes"],
    prot: Annotated[
        str,
        "Protection: int or string e.g. '7' (RWX) / 'PROT_READ|PROT_WRITE|PROT_EXEC'",
    ] = "7",
    flags: Annotated[
        str,
        "Flags: int or string e.g. '0x22' / 'MAP_PRIVATE|MAP_ANONYMOUS'",
    ] = "0x22",
    fd: Annotated[int, "File descriptor (-1 if MAP_ANONYMOUS)"] = -1,
    offset: Annotated[int, "Offset within file (only for file-backed mappings)"] = 0,
) -> str:
    """Call mmap(2) inside the inferior and return the resulting address (mirrors `mmap`)

    DANGEROUS: executes a syscall in the inferior. Caller approval required
    """
    length = _validate_bounded_int(
        length, field="length", minimum=1, maximum=1 << 30
    )
    address = _safe_gdb_arg(
        _validate_text_size(address, field="mmap address"), field="mmap address"
    )
    prot = _safe_gdb_arg(
        _validate_text_size(prot, field="mmap protection"), field="mmap protection"
    )
    flags = _safe_gdb_arg(
        _validate_text_size(flags, field="mmap flags"), field="mmap flags"
    )
    fd = _validate_bounded_int(
        fd, field="file descriptor", minimum=-1, maximum=(1 << 31) - 1
    )
    offset = _validate_bounded_int(
        offset, field="offset", minimum=0, maximum=(1 << 63) - 1
    )
    ctrl = await get_controller()
    r = await ctrl.run_command(
        f"mmap {address} {length} {prot} {flags} {fd} {offset}",
        timeout=15.0,
    )
    _require_gdb_success(r, "map inferior memory")
    return r.text


@mcp.tool()
@require_not_running
async def dt(
    typename: Annotated[str, "Type name to dump (e.g. 'ucontext_t', 'struct malloc_state')"],
    address: Annotated[
        str | None,
        "Optional address to overlay the type onto",
    ] = None,
    limit: Annotated[int | None, "Max output lines. None removes the soft cap; hard cap is 4096"] = 64,
) -> str:
    """Dump information on a type, optionally overlaid at an address (mirrors `dt`)"""
    typename = _validate_safe_type_name(typename, field="type name")
    if address is not None:
        address = _validate_readonly_location(address, field="type address")
    limit = _validate_limit(limit, field="limit")
    ctrl = await get_controller()
    quoted = typename if " " not in typename else f'"{typename}"'
    cmd = f"dt {quoted}"
    if address:
        cmd += f" {address}"
    r = await ctrl.run_command(cmd)
    _require_gdb_success(r, "dump type")
    return _truncate_lines(r.text, limit)


@mcp.tool()
@require_not_running
async def version_info() -> str:
    """Display Pwndbg, GDB, and important dependency versions (mirrors `version`)"""
    ctrl = await get_controller()
    r = await ctrl.run_command("version")
    _require_gdb_success(r, "show version")
    return r.text
