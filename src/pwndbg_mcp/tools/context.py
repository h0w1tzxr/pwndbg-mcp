"""Context display: full and per-section access to pwndbg's context windows"""

from __future__ import annotations

from typing import Annotated

from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import InvalidArgument
from pwndbg_mcp.errors import _require_gdb_success
from pwndbg_mcp.errors import require_stopped
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.types import ContextReport
from pwndbg_mcp.types import ContextSectionResult
from pwndbg_mcp.util import _safe_gdb_arg
from pwndbg_mcp.util import _validate_bounded_int

_SECTION_KEYS = (
    "regs",
    "disasm",
    "code",
    "stack",
    "backtrace",
    "args",
    "threads",
    "last_signal",
    "expressions",
)


async def _section(name: str, limit: int) -> ContextSectionResult:
    """Fetch a single context section as list[str] via pwndbg.commands.context.context_*"""
    limit = _validate_bounded_int(
        limit, field="context row limit", minimum=1, maximum=4096
    )
    ctrl = await get_controller()
    expr = (
        "import pwndbg.commands.context as cc;\n"
        f"fn = getattr(cc, 'context_{name}', None);\n"
        "if fn is None:\n"
        f"    raise AttributeError('current pwndbg has no context_{name} backend')\n"
        "else:\n"
        "    out = fn()\n"
        "    if not isinstance(out, list):\n"
        "        out = [str(out)]\n"
        f"    mcp_emit({{'rows': out[:{limit}], 'truncated': len(out) > {limit}}})"
    )
    return await ctrl.pi_query(expr, timeout=15.0)


@mcp.tool()
@require_stopped
async def context(
    sections: Annotated[
        list[str] | None,
        "Subset of: regs, disasm, code, stack, backtrace, args, threads, last_signal, expressions. "
        "None = all sections",
    ] = None,
) -> ContextReport:
    """Pwndbg context windows (mirrors `context`), structured as a dict of section -> list[str]"""
    if sections is None:
        wanted = list(_SECTION_KEYS)
    else:
        if not isinstance(sections, list) or len(sections) > len(_SECTION_KEYS):
            raise InvalidArgument(
                f"sections must be a list of at most {len(_SECTION_KEYS)} names"
            )
        if not all(isinstance(name, str) and name in _SECTION_KEYS for name in sections):
            raise InvalidArgument("sections contains an unsupported section name")
        wanted = list(dict.fromkeys(sections))
    out: ContextReport = {"emitted_rows": 0, "truncated": False}
    remaining = 4096
    for name in wanted:
        if remaining == 0:
            out[name] = []  # type: ignore[literal-required]
            out["truncated"] = True
            continue
        section = await _section(name, remaining)
        rows = section["rows"]
        out[name] = rows  # type: ignore[literal-required]
        remaining -= len(rows)
        out["truncated"] = out["truncated"] or section["truncated"]
    out["emitted_rows"] = 4096 - remaining
    return out


async def _section_only(name: str) -> list[str]:
    section = await _section(name, 4096)
    if not section["truncated"]:
        return section["rows"]
    return section["rows"][:4095] + [
        "<truncated: context section exceeded 4096 rows>"
    ]


@mcp.tool()
@require_stopped
async def context_regs_only() -> list[str]:
    """Just the registers section of pwndbg context"""
    return await _section_only("regs")


@mcp.tool()
@require_stopped
async def context_disasm_only() -> list[str]:
    """Just the disassembly section of pwndbg context"""
    return await _section_only("disasm")


@mcp.tool()
@require_stopped
async def context_code_only() -> list[str]:
    """Just the source-code section of pwndbg context"""
    return await _section_only("code")


@mcp.tool()
@require_stopped
async def context_stack_only() -> list[str]:
    """Just the stack telescope section of pwndbg context"""
    return await _section_only("stack")


@mcp.tool()
@require_stopped
async def context_backtrace_only() -> list[str]:
    """Just the backtrace section of pwndbg context"""
    return await _section_only("backtrace")


@mcp.tool()
@require_stopped
async def context_args_only() -> list[str]:
    """Just the function arguments section of pwndbg context"""
    return await _section_only("args")


@mcp.tool()
@require_stopped
async def context_threads_only() -> list[str]:
    """Just the threads section of pwndbg context"""
    return await _section_only("threads")


@mcp.tool()
@require_stopped
async def context_last_signal_only() -> list[str]:
    """Just the last-signal section of pwndbg context"""
    return await _section_only("last_signal")


@mcp.tool()
async def ctx_watch_add(
    mode: Annotated[str, "'Eval' or 'execute'"],
    expression: Annotated[str, "Expression or command to add to context"],
) -> str:
    """Add an expression to pwndbg's context watch list (mirrors `ctx-watch eval|execute`)"""
    if mode not in ("eval", "execute"):
        raise InvalidArgument(f"ctx_watch_add mode must be 'eval' or 'execute' (got {mode!r})")
    expression = _safe_gdb_arg(expression, field="context watch expression")
    ctrl = await get_controller()
    r = await ctrl.run_command(f"ctx-watch {mode} {expression}")
    _require_gdb_success(r, "add context watch")
    return r.text or "added"


@mcp.tool()
async def ctx_watch_del(
    index: Annotated[int, "Index of the watch to delete"],
) -> str:
    """Remove an entry from pwndbg's context watch list"""
    ctrl = await get_controller()
    r = await ctrl.run_command(f"contextunwatch {index}")
    _require_gdb_success(r, "remove context watch")
    return r.text or "removed"
