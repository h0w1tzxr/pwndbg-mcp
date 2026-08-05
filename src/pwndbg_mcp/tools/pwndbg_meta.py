"""Pwndbg meta-commands: help, config, theme, tip, list"""

from __future__ import annotations

from typing import Annotated

from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import InvalidArgument
from pwndbg_mcp.errors import _require_gdb_success
from pwndbg_mcp.errors import require_not_running
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.util import _safe_gdb_arg
from pwndbg_mcp.util import _validate_text_size


@mcp.tool()
@require_not_running
async def pwndbg_help(
    topic: Annotated[str | None, "Optional pwndbg topic/category"] = None,
) -> str:
    """Show pwndbg's command help (mirrors `pwndbg [topic]`)"""
    if topic is not None:
        topic = _safe_gdb_arg(
            _validate_text_size(topic, field="pwndbg help topic"),
            field="pwndbg help topic",
        )
    ctrl = await get_controller()
    cmd = f"pwndbg {topic}" if topic else "pwndbg"
    r = await ctrl.run_command(cmd)
    _require_gdb_success(r, "show pwndbg help")
    return r.text


@mcp.tool()
@require_not_running
async def list_pwndbg_commands(
    filter_pattern: Annotated[
        str | None,
        "Optional substring filter applied to command names/docs",
    ] = None,
    category: Annotated[
        str | None,
        "Optional category to filter by (see `--list-categories`)",
    ] = None,
) -> str:
    """List all pwndbg commands by category (mirrors `pwndbg [filter]`)"""
    if filter_pattern is not None:
        filter_pattern = _safe_gdb_arg(
            _validate_text_size(filter_pattern, field="pwndbg command filter"),
            field="pwndbg command filter",
        )
    if category is not None:
        category = _safe_gdb_arg(
            _validate_text_size(category, field="pwndbg command category"),
            field="pwndbg command category",
        )
    ctrl = await get_controller()
    cmd = "pwndbg"
    if category:
        cmd += f" -c {category}"
    if filter_pattern:
        cmd += f" {filter_pattern}"
    r = await ctrl.run_command(cmd)
    _require_gdb_success(r, "list pwndbg commands")
    return r.text


@mcp.tool()
@require_not_running
async def config_get(
    name: Annotated[str | None, "Config parameter name; None to show all"] = None,
) -> str:
    """Show pwndbg/GDB configuration (mirrors `config` / `show <name>`)"""
    if name is not None:
        name = _safe_gdb_arg(
            _validate_text_size(name, field="config parameter name"),
            field="config parameter name",
        )
    ctrl = await get_controller()
    if name:
        r = await ctrl.run_command(f"show {name}")
    else:
        r = await ctrl.run_command("config")
    _require_gdb_success(r, "show configuration")
    return r.text


@mcp.tool()
async def config_set(
    name: Annotated[str, "Parameter name"],
    value: Annotated[str, "New value (string; will be passed to GDB `set <name> <value>`)"],
) -> str:
    """Update a pwndbg/GDB configuration parameter"""
    name = _safe_gdb_arg(
        _validate_text_size(name, field="config parameter name"),
        field="config parameter name",
    )
    value = _safe_gdb_arg(
        _validate_text_size(value, field="config parameter value"),
        field="config parameter value",
    )
    ctrl = await get_controller()
    r = await ctrl.run_command(f"set {name} {value}")
    _require_gdb_success(r, "set configuration")
    return r.text or "set"


@mcp.tool()
@require_not_running
async def theme_get(
    name: Annotated[str | None, "Theme parameter name; None to show all"] = None,
) -> str:
    """Show pwndbg theme parameters (mirrors `theme`)"""
    if name is not None:
        name = _safe_gdb_arg(
            _validate_text_size(name, field="theme parameter name"),
            field="theme parameter name",
        )
    ctrl = await get_controller()
    cmd = f"theme {name}" if name else "theme"
    r = await ctrl.run_command(cmd)
    _require_gdb_success(r, "show theme")
    return r.text


@mcp.tool()
async def theme_set(
    name: Annotated[str, "Theme parameter name"],
    value: Annotated[str, "New value"],
) -> str:
    """Update a pwndbg theme parameter"""
    name = _safe_gdb_arg(
        _validate_text_size(name, field="theme parameter name"),
        field="theme parameter name",
    )
    value = _safe_gdb_arg(
        _validate_text_size(value, field="theme parameter value"),
        field="theme parameter value",
    )
    ctrl = await get_controller()
    r = await ctrl.run_command(f"set {name} {value}")
    _require_gdb_success(r, "set theme")
    return r.text or "set"


@mcp.tool()
async def tip(
    all_tips: Annotated[bool, "Show all tips (mirrors `tip --all`)"] = False,
) -> str:
    """Show a pwndbg tip (or all tips)"""
    if not isinstance(all_tips, bool):
        raise InvalidArgument("all_tips must be a boolean")
    ctrl = await get_controller()
    cmd = "tip --all" if all_tips else "tip"
    r = await ctrl.run_command(cmd)
    _require_gdb_success(r, "show tip")
    return r.text
