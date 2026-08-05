"""Command-line interface for pwndbg-MCP

Subcommands:
- (default)  : run the MCP server
- install    : wire pwndbg-MCP into the client
- uninstall  : remove from the client
- status     : show install state
- doctor     : run diagnostics
"""

from __future__ import annotations

import argparse
import logging
import sys

from pwndbg_mcp import __version__

DESC = "MCP server for current pwndbg and GDB workflows."


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pwndbg-mcp", description=DESC)
    p.add_argument("-V", "--version", action="version", version=f"pwndbg-mcp {__version__}")

    # top-level args repeat below so `pwndbg-mcp --transport stdio` runs with no subcommand
    p.add_argument(
        "--transport",
        "-t",
        choices=["stdio", "http", "sse"],
        default="stdio",
        help="Transport mode (default: stdio - matches the client)",
    )
    p.add_argument("--host", "-H", default="127.0.0.1", help="Host for http/sse")
    p.add_argument("--port", "-p", type=int, default=8780, help="Port for http/sse")
    p.add_argument(
        "--pwndbg",
        "-b",
        default="gdb",
        metavar="BIN",
        help="GDB binary (default: gdb; ~/.gdbinit must source pwndbg)",
    )
    p.add_argument("--log-level", default="INFO", help="Python log level (DEBUG/INFO/WARNING/...)")
    p.add_argument("--gdb-timeout", type=float, default=5.0, help="Default GDB MI timeout (s)")

    sub = p.add_subparsers(dest="cmd")

    pi = sub.add_parser("install", help="Wire pwndbg-mcp into the client")
    pi.add_argument("--scope", choices=["user", "local", "project"], default="user")
    pi.add_argument("--name", default="pwndbg", help="MCP server name (default: pwndbg)")
    pi.add_argument("--gdb-path", default="gdb", help="gdb binary the server should launch")
    pi.add_argument(
        "--unsafe",
        action="store_true",
        help="Allow mutating Claude MCP tools without prompts (default: ask)",
    )
    pi.add_argument("--force", action="store_true", help="Overwrite existing entry without prompt")
    pi.add_argument(
        "--no-claude-cli",
        action="store_true",
        help="Use Claude JSON fallback directly (user/project scopes only)",
    )

    pu = sub.add_parser("uninstall", help="Remove from the client")
    pu.add_argument("--scope", choices=["user", "local", "project"], default="user")
    pu.add_argument("--name", default="pwndbg")
    pu.add_argument(
        "--no-claude-cli",
        action="store_true",
        help="Use Claude JSON fallback directly (user/project scopes only)",
    )

    sub.add_parser("status", help="Show install state")

    sub.add_parser("doctor", help="Run diagnostics")

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # stderr only, stdout carries mcp stdio frames
    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    if args.cmd == "install":
        from pwndbg_mcp.installer import install

        return install(args)
    if args.cmd == "uninstall":
        from pwndbg_mcp.installer import uninstall

        return uninstall(args)
    if args.cmd == "status":
        from pwndbg_mcp.installer import status

        return status(args)
    if args.cmd == "doctor":
        from pwndbg_mcp.installer import doctor

        return doctor(args)

    from pwndbg_mcp.server import serve

    return serve(args)


if __name__ == "__main__":
    raise SystemExit(main())
