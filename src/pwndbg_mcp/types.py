# ruff: noqa: I002
"""Typed dict shapes for structured MCP tool returns"""

from typing import Required

# python < 3.12 needs runtime typing-extensions for fastmcp schemas
from typing_extensions import TypedDict


class StatusReport(TypedDict, total=False):
    state: str
    uptime_s: float
    gdb_pid: int | None
    last_error: str | None
    last_stop_reason: str | None
    executable: str | None
    decompiler_connected: bool
    pty: str | None
    arch: str | None
    pid: int | None
    pwndbg_loaded: bool


class DecompilerStatus(TypedDict):
    pwndbg_version: str | None
    command_available: bool
    host: str | None
    port: int | None
    connected: bool
    provider: str | None
    dependency_available: bool
    dependency_version: str | None
    dependency_required: str | None
    error: str | None


class DecompilerActionResult(TypedDict):
    output: str
    connected: bool


class AttachResult(TypedDict):
    requested_target: str
    pid: int
    state: str
    executable: str | None
    architecture: str | None


class VmmapEntry(TypedDict, total=False):
    start: str
    end: str
    size: int
    perm: str
    offset: str
    objfile: str
    flags: str


class VmmapResult(TypedDict):
    """Result of `vmmap` with filter provenance"""

    matched: list[VmmapEntry]
    total_pages: int
    pattern: str | None
    scanned: int
    truncated: bool


class TelescopeEntry(TypedDict, total=False):
    addr: str
    offset: int
    chain: str
    chain_text: str
    chain_parts: list[str]
    symbol: str | None
    register: str | None


class TelescopeResult(TypedDict):
    """List wrapper for telescope and stack_view"""

    entries: list[TelescopeEntry]
    total: int
    truncated: bool


class HexdumpRow(TypedDict):
    addr: str
    bytes_hex: str
    ascii: str


class HexdumpResult(TypedDict):
    addr: str
    rows: list[HexdumpRow]


class ReadMemoryResult(TypedDict):
    """Memory read result with requested-size metadata"""

    addr: str
    size: int
    requested_size: int
    hex: str
    truncated: bool


class ReadProcessResult(TypedDict):
    """Inferior PTY read result with lossless hex and decoded text"""

    size: int
    hex: str
    text: str | None
    lossy: bool


class RemotePwncatSessionInfo(TypedDict):
    """Metadata for a managed pwncat session"""

    session_id: str
    host: str
    port: int
    pid: int | None
    running: bool
    returncode: int | None
    age_s: float
    mode: str


class RemotePwncatOpenResult(RemotePwncatSessionInfo):
    """Result of a pwncat open, with optional initial output"""

    initial: ReadProcessResult


class RemotePwncatReadResult(ReadProcessResult):
    """Managed pwncat read result"""

    session_id: str
    eof: bool


class ExploitTemplateResult(TypedDict):
    """Generated exploit template and optional write path"""

    script: str
    wrote_path: str | None


class BreakpointListResult(TypedDict):
    """Breakpoint listing with raw text and empty-output metadata"""

    text: str
    gdb_ok: bool
    gdb_error: str | None
    is_empty: bool


class DisasmEntry(TypedDict, total=False):
    addr: str
    bytes_hex: str
    mnemonic: str
    op_str: str
    symbol: str | None
    is_branch: bool
    target: str | None


class DisasmResult(TypedDict):
    """List wrapper for disasm, nearpc, and u"""

    entries: list[DisasmEntry]
    total: int
    truncated: bool


class HeapChunk(TypedDict, total=False):
    addr: str
    size: int
    real_size: int
    flags: dict[str, bool]
    fd: str | None
    bk: str | None
    fd_nextsize: str | None
    bk_nextsize: str | None
    is_top: bool
    is_inuse: bool


class HeapChunksResult(TypedDict):
    """Bounded structured heap walk with truncation provenance"""

    entries: list[HeapChunk]
    total: int
    truncated: bool


class BinEntry(TypedDict, total=False):
    bin_type: str
    size: int | str
    fd_chain: list[str]
    bk_chain: list[str] | None
    count: int | None
    is_corrupted: bool


class BinEntriesResult(TypedDict):
    """List wrapper for bin views"""

    entries: list[BinEntry]
    total: int
    truncated: bool


class ChecksecReport(TypedDict, total=False):
    pie: bool
    canary: bool
    nx: bool
    relro: str
    fortify: bool
    rpath: bool
    runpath: bool
    symbols: bool
    raw: str


class GotEntry(TypedDict, total=False):
    addr: str
    symbol: str
    resolved: str | None
    resolved_symbol: str | None


class GotEntriesResult(TypedDict):
    """List wrapper for got, gotplt, and plt"""

    entries: list[GotEntry]
    total: int
    truncated: bool


class CanaryInfo(TypedDict, total=False):
    """Canary value plus bounded stack-search provenance"""

    canary: str | None
    tls_addr: str | None
    on_stack: list[str]
    scanned: Required[int]
    on_stack_truncated: Required[bool]
    raw: str


class StackReturnAddr(TypedDict, total=False):
    addr: str
    value: str
    symbol: str | None


class StackReturnAddrsResult(TypedDict):
    """List wrapper for retaddr"""

    entries: list[StackReturnAddr]
    total: int
    truncated: bool


class ContextReport(TypedDict, total=False):
    regs: list[str]
    disasm: list[str]
    code: list[str]
    stack: list[str]
    backtrace: list[str]
    args: list[str]
    threads: list[str]
    last_signal: list[str]
    expressions: list[str]
    raw: str
    emitted_rows: Required[int]
    truncated: Required[bool]


class ContextSectionResult(TypedDict):
    rows: list[str]
    truncated: bool


class OneGadget(TypedDict, total=False):
    offset: str
    constraints: str


class KTask(TypedDict, total=False):
    pid: int
    comm: str
    state: str
    addr: str


class KTaskListResult(TypedDict):
    """List wrapper for ktask"""

    entries: list[KTask]
    total: int
    truncated: bool


class ElfSection(TypedDict, total=False):
    """One ELF section entry"""

    name: str
    start: str
    end: str
    size: int
    perm: str


class ElfSectionsResult(TypedDict):
    """List wrapper for elfsections"""

    entries: list[ElfSection]
    total: int
    truncated: bool


class LinkmapEntry(TypedDict, total=False):
    """One link_map entry"""

    link_map_address: str
    objfile: str
    load_bias: str
    dynamic: str


class LinkmapResult(TypedDict):
    """List wrapper for linkmap"""

    entries: list[LinkmapEntry]
    total: int
    truncated: bool


class LibcInfo(TypedDict, total=False):
    """Structured record of libc info"""

    libc_type: str
    version: str
    base: str | None
    path: str | None
    ld_base: str | None
    ld_path: str | None
    has_exported_symbols: bool
    has_internal_symbols: bool
    has_debug_info: bool


class ErrnoResult(TypedDict, total=False):
    """Record of errno with numeric value and symbolic name"""

    errno: int
    name: str
