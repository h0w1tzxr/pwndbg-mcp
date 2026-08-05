"""MCP server entrypoint"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import logging

from pwndbg_mcp.bridge import AsyncGdbController
from pwndbg_mcp.bridge import set_controller

logger = logging.getLogger(__name__)


async def _bootstrap(ctrl: AsyncGdbController) -> None:
    await ctrl.start()
    set_controller(ctrl)


def serve(args: argparse.Namespace) -> int:
    """Run the MCP server until the transport closes"""
    # import tools before mcp.run so every decorator registers
    importlib.import_module("pwndbg_mcp.tools")
    from pwndbg_mcp.tools._registry import mcp as fastmcp_instance
    from pwndbg_mcp.tools.remote import close_all_pwncat_sessions

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    ctrl: AsyncGdbController | None = None
    try:
        try:
            ctrl = AsyncGdbController(
                gdb_path=args.pwndbg,
                timeout=args.gdb_timeout,
            )
            loop.run_until_complete(_bootstrap(ctrl))
        except Exception as e:
            logger.exception("bootstrap failed: %s", e)
            return 1

        try:
            if args.transport == "stdio":
                loop.run_until_complete(fastmcp_instance.run_async("stdio"))
            else:
                loop.run_until_complete(
                    fastmcp_instance.run_async(
                        args.transport,
                        host=args.host,
                        port=args.port,
                    )
                )
        except KeyboardInterrupt:
            logger.info("interrupted; shutting down")
    finally:
        try:
            loop.run_until_complete(close_all_pwncat_sessions())
        except BaseException as e:
            logger.warning("pwncat shutdown failed: %s", e, exc_info=True)
        if ctrl is not None:
            try:
                loop.run_until_complete(ctrl.close())
            except BaseException as e:
                logger.warning("GDB shutdown failed: %s", e, exc_info=True)
        loop.close()
        asyncio.set_event_loop(None)
    return 0
