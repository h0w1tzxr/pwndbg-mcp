"""Discovery helpers: locate binaries, sniff ~/.gdbinit, validate Python version"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def find_pwndbg_mcp_binary() -> Path | None:
    """Return the path to the installed `pwndbg-mcp` entry-point binary, or None"""
    candidate = Path.home() / ".local/bin/pwndbg-mcp"
    if candidate.exists():
        return candidate
    which = shutil.which("pwndbg-mcp")
    if which:
        return Path(which)
    return None


def find_claude_cli() -> Path | None:
    """Return the path to the `claude` CLI, or None"""
    which = shutil.which("claude")
    return Path(which) if which else None


def find_codex_cli() -> Path | None:
    """Return the path to the `codex` CLI, or None"""
    which = shutil.which("codex")
    return Path(which) if which else None


def find_gdb() -> Path | None:
    which = shutil.which("gdb")
    return Path(which) if which else None


def gdb_version(gdb: Path | None) -> str:
    if gdb is None:
        return ""
    try:
        out = subprocess.run([str(gdb), "--version"], capture_output=True, text=True, timeout=5)
        return out.stdout.splitlines()[0] if out.stdout else ""
    except Exception:
        return ""


def pwndbg_sourced_in_gdbinit() -> bool:
    """Heuristic: scan ~/.gdbinit for pwndbg

    Looks for the substring `pwndbg` or `gdbinit.py` (the pwndbg loader's filename)
    """
    init_path = Path.home() / ".gdbinit"
    if not init_path.exists():
        return False
    try:
        content = init_path.read_text(errors="ignore").lower()
    except OSError:
        return False
    return "pwndbg" in content or "gdbinit.py" in content


def detect_environment() -> dict[str, Any]:
    gdb = find_gdb()
    return {
        "pwndbg_mcp": find_pwndbg_mcp_binary(),
        "gdb": gdb,
        "gdb_version": gdb_version(gdb),
        "pwndbg_sourced": pwndbg_sourced_in_gdbinit(),
        "claude": find_claude_cli(),
        "codex": find_codex_cli(),
        "python": sys.executable,
        "python_version": ".".join(map(str, sys.version_info[:3])),
        "python_ok": sys.version_info >= (3, 11),
        "home": str(Path.home()),
        "path_has_local_bin": ":" + str(Path.home() / ".local/bin") + ":"
        in (":" + os.environ.get("PATH", "") + ":"),
    }
