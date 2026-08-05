"""Public installer entrypoints - called by CLI.py"""

from __future__ import annotations

import argparse
import sys

from pwndbg_mcp.installer.claude_cli import install_via_cli
from pwndbg_mcp.installer.claude_cli import list_via_cli
from pwndbg_mcp.installer.claude_cli import uninstall_via_cli
from pwndbg_mcp.installer.config import build_args
from pwndbg_mcp.installer.config import build_mcp_entry
from pwndbg_mcp.installer.detect import detect_environment
from pwndbg_mcp.installer.detect import find_pwndbg_mcp_binary
from pwndbg_mcp.installer.json_fallback import install_via_json
from pwndbg_mcp.installer.json_fallback import uninstall_via_json
from pwndbg_mcp.installer.outcome import OperationResult
from pwndbg_mcp.installer.outcome import OperationStatus


def _error(detail: str) -> int:
    print(f"error: {detail}", file=sys.stderr)
    return 1


def _install_result(result: OperationResult, *, name: str, scope: str, backend: str) -> int:
    if result.status == OperationStatus.ERROR:
        return _error(result.detail or f"{backend} install failed")
    if result.status == OperationStatus.EXISTS:
        print(
            f"  MCP server '{name}' already registered via {backend} (scope={scope}); "
            "Claude permissions synchronized."
        )
        return 0
    if result.status == OperationStatus.ADDED:
        print(f"  Added MCP server '{name}' via {backend} (scope={scope}).")
        return 0
    return _error(result.detail or f"unexpected {backend} install result: {result.status}")


def install(args: argparse.Namespace) -> int:
    binary = find_pwndbg_mcp_binary()
    if binary is None:
        print(
            "error: pwndbg-mcp binary not found on PATH. Run `uv tool install --editable .` first."
        )
        return 1

    server_args = build_args(gdb_path=args.gdb_path)
    entry = build_mcp_entry(command=str(binary), server_args=server_args)

    try:
        if args.no_claude_cli:
            result = install_via_json(
                name=args.name,
                entry=entry,
                scope=args.scope,
                force=args.force,
                unsafe=args.unsafe,
            )
            backend = "Claude JSON configuration"
        else:
            result = install_via_cli(
                name=args.name,
                scope=args.scope,
                command=str(binary),
                server_args=server_args,
                force=args.force,
                unsafe=args.unsafe,
            )
            backend = "Claude CLI"
            if result.status == OperationStatus.UNAVAILABLE:
                result = install_via_json(
                    name=args.name,
                    entry=entry,
                    scope=args.scope,
                    force=args.force,
                    unsafe=args.unsafe,
                )
                backend = "Claude JSON configuration"
    except (OSError, ValueError) as error:
        return _error(str(error))

    rc = _install_result(result, name=args.name, scope=args.scope, backend=backend)
    if rc == 0:
        if args.unsafe:
            print("  Claude permissions: read-only and mutating tools allowed.")
        else:
            print("  Claude permissions: read-only tools allowed; mutating tools require approval.")
    return rc


def uninstall(args: argparse.Namespace) -> int:
    try:
        if args.no_claude_cli:
            result = uninstall_via_json(args.name, args.scope)
            backend = "Claude JSON configuration"
        else:
            result = uninstall_via_cli(args.name, args.scope)
            backend = "Claude CLI"
            if result.status == OperationStatus.UNAVAILABLE:
                result = uninstall_via_json(args.name, args.scope)
                backend = "Claude JSON configuration"
    except (OSError, ValueError) as error:
        return _error(str(error))

    if result.status == OperationStatus.REMOVED:
        print(f"  Removed MCP server '{args.name}' via {backend} (scope={args.scope}).")
        return 0
    if result.status == OperationStatus.NOT_FOUND:
        print(f"  No MCP server named '{args.name}' was registered via {backend}.")
        return 0
    if result.status == OperationStatus.ERROR:
        return _error(result.detail or f"{backend} uninstall failed")
    return _error(result.detail or f"unexpected {backend} uninstall result: {result.status}")


def status(args: argparse.Namespace) -> int:
    env = detect_environment()
    print(f"  pwndbg-mcp binary  : {env['pwndbg_mcp'] or '<not found>'}")
    print(f"  gdb                : {env['gdb'] or '<not found>'} ({env['gdb_version']})")
    print(f"  pwndbg in .gdbinit : {env['pwndbg_sourced']}")
    print(f"  claude CLI         : {env['claude'] or '<not found>'}")
    print(f"  codex CLI          : {env.get('codex') or '<not found>'}")
    print(f"  python             : {env['python']} ({env['python_version']})")
    if env["claude"]:
        servers = list_via_cli()
        marker = (
            "registered"
            if any(s.partition(":")[0].strip() == "pwndbg" for s in servers)
            else "not registered"
        )
        print(f"  Claude MCP entry   : {marker}")
        for s in servers:
            print(f"    - {s}")
    return 0


def doctor(args: argparse.Namespace) -> int:
    env = detect_environment()
    rc = 0

    def _check(label: str, ok: bool, hint: str = "") -> None:
        nonlocal rc
        if ok:
            print(f"  PASS  {label}")
        else:
            rc = 1
            print(f"  FAIL  {label}", file=sys.stderr)
            if hint:
                print(f"        -> {hint}", file=sys.stderr)

    _check(
        "gdb on PATH",
        env["gdb"] is not None,
        "Install gdb (e.g. `sudo pacman -S gdb`).",
    )
    _check(
        "pwndbg sourced in ~/.gdbinit",
        env["pwndbg_sourced"],
        "Add `source /path/to/pwndbg/gdbinit.py` to your ~/.gdbinit.",
    )
    _check(
        "pwndbg-mcp on PATH",
        env["pwndbg_mcp"] is not None,
        "Run `uv tool install --editable .` from this project.",
    )
    _check(
        "MCP client CLI",
        env.get("claude") is not None or env.get("codex") is not None,
        "Install Claude Code or Codex.",
    )
    _check(
        "python >= 3.11",
        env["python_ok"],
        "Use a newer Python (uv tool install will pick this up automatically).",
    )

    return rc


__all__ = ["install", "uninstall", "status", "doctor"]
