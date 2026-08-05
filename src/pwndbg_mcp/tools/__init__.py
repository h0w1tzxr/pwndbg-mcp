"""Tool registry - importing this package registers every @MCP.tool() decorator"""

from __future__ import annotations

from importlib import import_module

# importing every module runs the decorators, order is kept stable for tools/list
_TOOL_MODULES = (
    "advanced",
    "breakpoints",
    "context",
    "core",
    "disasm",
    "elf_libc",
    "flow",
    "gdb_core",
    "heap",
    "heap_hacking",
    "integrations",
    "kernel",
    "memory",
    "misc",
    "navigation",
    "process_io",
    "pwndbg_meta",
    "registers",
    "remote",
    "stack",
    "start",
)

for module_name in _TOOL_MODULES:
    import_module(f"pwndbg_mcp.tools.{module_name}")

from pwndbg_mcp.tools._registry import mcp

__all__ = ["mcp"]
