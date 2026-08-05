"""Fastmcp singleton and approval inventories

The Claude installer writes exact safe rules to allow and exact mutating rules
to ask unless `--unsafe` is selected
"""

from __future__ import annotations

from fastmcp import FastMCP
from fastmcp.tools.tool import Tool
from mcp.types import ToolAnnotations

# read-only tools allowed by the default Claude policy
SAFE_TOOLS: list[str] = [
    # core/meta
    "mcp_status",
    "pwndbg_help",
    "config_get",
    "theme_get",
    "tip",
    "list_pwndbg_commands",
    "apropos",
    # gdb introspection
    "info_threads",
    "break_list",
    # context (read-only)
    "context",
    "context_regs_only",
    "context_disasm_only",
    "context_code_only",
    "context_stack_only",
    "context_backtrace_only",
    "context_args_only",
    "context_threads_only",
    "context_last_signal_only",
    # memory inspection
    "vmmap",
    "telescope",
    "hexdump",
    "p2p",
    "xinfo",
    "distance",
    "read_memory",
    # stack/regs
    "retaddr",
    "canary",
    "stack_view",
    # disasm
    "disasm",
    "nearpc",
    "u",
    # elf/libc
    "piebase",
    "tls",
    "libcinfo",
    "linkmap",
    "errno",
    # heap (read-only)
    "heap",
    "heap_chunks",
    "vis_heap_chunks",
    "malloc_chunk",
    "top_chunk",
    "arenas",
    "arena_info",
    "mp_struct",
    "heap_config",
    "bins",
    "fastbins",
    "smallbins",
    "largebins",
    "unsorted_bin",
    "tcache",
    "tcachebins",
    "hi",
    "find_fake_fast",
    # misc inspection
    "patch_list",
    "plist",
    "procinfo",
    "cyclic",
    "cyclic_find",
    "dumpargs",
    "probeleak",
    "parse_seccomp",
    "valist",
    "sigreturn",
    "dt",
    "version_info",
    # kernel inspection
    "kbase",
    "kbpf",
    "kchecksec",
    "kcmdline",
    "kcurrent",
    "kdmesg",
    "klookup",
    "kmod",
    "knft",
    "ksyscalls",
    "ktask",
    "kversion",
    "slab_info",
    "binder",
    "buddydump",
    # integrations (read-only analyzers)
    "leakfind",
    "decompiler_status",
    "remote_pwncat_list",
]

# mutating tools kept in Claude's ask policy by default
MUTATING_TOOLS: list[str] = [
    # bootstrap/control
    "mcp_load_executable",
    "mcp_attach_pid",
    "mcp_hard_reset",
    "gdb_set_args",
    # gdb expression/state mutation
    "gdb_print",
    "gdb_examine",
    # start
    "start",
    "sstart",
    "starti",
    "entry",
    "run",
    # flow
    "step",
    "next",
    "ni",
    "si",
    "continue_",
    "finish",
    "up",
    "down",
    "kill",
    # navigation that mutates
    "xuntil",
    "nextcall",
    "nextjmp",
    "nextret",
    "nextsyscall",
    "stepret",
    "stepuntilasm",
    # breakpoints
    "break_set",
    "break_delete",
    "break_disable",
    "break_enable",
    "break_condition",
    "watch_set",
    # memory mutation
    "write_memory",
    "search",
    "regs",
    "regs_named",
    "set_register",
    "mprotect",
    "fsbase",
    "gsbase",
    "cpsr",
    "setflag",
    # heap exploit primitives
    "try_free",
    "track_heap",
    "track_got",
    # patching
    "patch",
    "patch_revert",
    "spray",
    # syscall / fd manipulation
    "hijack_fd",
    "remote_hijack_fd",
    "mmap_syscall",
    # inferior i/o
    "send_to_process",
    "eval_to_send_to_process",
    "read_from_process",
    "interrupt_process",
    "remote_pwncat_open",
    "remote_pwncat_read",
    "remote_pwncat_send",
    "remote_pwncat_close",
    # binds a local port and may exec a command for whoever connects
    "remote_pwncat_listen",
    # emits connection attempts to a third-party host
    "remote_pwncat_scan",
    # remote debugging / exploit scaffolding
    "gdb_target_remote",
    "gdb_target_extended_remote",
    "remote_exploit_template",
    # config / theme write
    "config_set",
    "theme_set",
    "ctx_watch_add",
    "ctx_watch_del",
    # current pwndbg decompiler integration
    "decompiler_connect",
    "decompiler_disconnect",
    "decompiler_sync",
    "decomp",
    # raw escape hatches
    "execute_command",
    "pi_eval",
    "set_param",
    "asm_assemble",
    # analyzers with subprocess, cache, temporary-file, or remote-file effects
    "checksec",
    "got",
    "gotplt",
    "plt",
    "elfsections",
    "rop",
    "ropper",
    "onegadget",
]


class _InventoryFastMCP(FastMCP):
    """Attach conservative standard hints from the approval inventories"""

    def add_tool(self, tool: Tool) -> Tool:
        safe = tool.name in SAFE_TOOLS
        mutating = tool.name in MUTATING_TOOLS
        if safe and mutating:
            raise RuntimeError(f"tool {tool.name!r} appears in both approval inventories")
        if not safe and not mutating:
            raise RuntimeError(f"tool {tool.name!r} is absent from approval inventories")
        tool.annotations = ToolAnnotations(
            readOnlyHint=safe,
            destructiveHint=mutating,
        )
        return super().add_tool(tool)


mcp = _InventoryFastMCP("pwndbg-mcp", strict_input_validation=True)


__all__ = ["mcp", "SAFE_TOOLS", "MUTATING_TOOLS"]
