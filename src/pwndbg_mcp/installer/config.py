"""Build and validate Claude Code MCP server configuration"""

from __future__ import annotations

import re

SERVER_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


def build_args(*, gdb_path: str = "gdb") -> list[str]:
    return ["--transport", "stdio", "--pwndbg", gdb_path]


def build_mcp_entry(
    *,
    command: str,
    server_args: list[str],
) -> dict[str, object]:
    """Construct a Claude JSON `mcpServers` entry"""
    return {
        "type": "stdio",
        "command": command,
        "args": server_args,
    }


def validate_server_name(name: str) -> str:
    if SERVER_NAME_RE.fullmatch(name) is None:
        raise ValueError("server name must match [A-Za-z0-9_-]{1,64}")
    return name
