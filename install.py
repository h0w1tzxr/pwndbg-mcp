#!/usr/bin/env python3
"""interactive installer for pwndbg-mcp."""

from __future__ import annotations

import argparse
import errno
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

CLIENTS = {
    "claude": {"claude"},
    "codex": {"codex"},
    "both": {"claude", "codex"},
    "none": set(),
}

PALETTE = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "mint": "\033[38;5;157m",
    "blue": "\033[38;5;153m",
    "lavender": "\033[38;5;183m",
    "peach": "\033[38;5;223m",
    "rose": "\033[38;5;217m",
    "gray": "\033[38;5;245m",
}

SERVER_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


@dataclass(frozen=True)
class CodexConfigResult:
    action: str
    path: Path
    backup_path: Path | None = None


class UI:
    def __init__(self, *, color: bool = True) -> None:
        self.color = color and sys.stdout.isatty()

    def paint(self, text: str, color: str, *, bold: bool = False) -> str:
        if not self.color:
            return text
        prefix = PALETTE.get(color, "")
        if bold:
            prefix = PALETTE["bold"] + prefix
        return f"{prefix}{text}{PALETTE['reset']}"

    def title(self) -> None:
        print()
        print(self.paint("pwndbg-mcp setup", "lavender", bold=True))
        print(self.paint("Set up the MCP server for Claude Code, Codex, or both.", "gray"))

    def section(self, text: str) -> None:
        print()
        print(self.paint(text, "blue", bold=True))

    def status(self, label: str, state: str, detail: str = "", *, kind: str = "ok") -> None:
        color = {"ok": "mint", "warn": "peach", "err": "rose", "info": "lavender"}[kind]
        suffix = f"  {self.paint(detail, 'gray')}" if detail else ""
        print(f"  {label:<24} {self.paint(state, color, bold=True)}{suffix}")

    def note(self, text: str) -> None:
        print(f"  {self.paint(text, 'gray')}")

    def warn(self, text: str) -> None:
        print(f"  {self.paint('warning:', 'peach', bold=True)} {text}")

    def command(self, cmd: list[str]) -> None:
        print(f"  {self.paint('$', 'gray')} {' '.join(cmd)}")


def parse_clients(value: str) -> set[str]:
    normalized = value.strip().lower()
    if normalized not in CLIENTS:
        allowed = ", ".join(CLIENTS)
        raise argparse.ArgumentTypeError(f"expected one of: {allowed}")
    return set(CLIENTS[normalized])


def server_name(value: str) -> str:
    if SERVER_NAME_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("server name must match [A-Za-z0-9_-]{1,64}")
    return value


def clients_label(clients: set[str]) -> str:
    if clients == {"claude", "codex"}:
        return "Claude Code and Codex"
    if clients == {"claude"}:
        return "Claude Code"
    if clients == {"codex"}:
        return "Codex"
    return "none"


def ask_choice(ui: UI, question: str, choices: list[tuple[str, str]], default: str) -> str:
    print()
    print(ui.paint(question, "blue", bold=True))
    for key, label in choices:
        marker = " (default)" if key == default else ""
        print(f"  {ui.paint(key, 'lavender', bold=True)}  {label}{ui.paint(marker, 'gray')}")
    answer = input(ui.paint(f"select [{default}]: ", "lavender")).strip().lower()
    return answer or default


def ask_yes_no(ui: UI, question: str, *, default: bool) -> bool:
    suffix = "Y/n" if default else "y/N"
    answer = input(ui.paint(f"  {question} [{suffix}]: ", "lavender")).strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


def command_exists(name: str) -> str | None:
    return shutil.which(name)


def pwndbg_sourced(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        text = path.read_text(errors="ignore").lower()
    except OSError:
        return False
    return "pwndbg" in text or "gdbinit.py" in text


def build_server_args(*, gdb_path: str) -> list[str]:
    return ["--transport", "stdio", "--pwndbg", gdb_path]


def find_installed_binary() -> Path | None:
    candidates = [Path.home() / ".local" / "bin" / "pwndbg-mcp"]
    uv = shutil.which("uv")
    if uv:
        proc = subprocess.run([uv, "tool", "dir"], capture_output=True, text=True, check=False)
        if proc.returncode == 0 and proc.stdout.strip():
            candidates.append(Path(proc.stdout.strip()) / "pwndbg-mcp" / "bin" / "pwndbg-mcp")
    which = shutil.which("pwndbg-mcp")
    if which:
        candidates.append(Path(which))
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def run_command(cmd: list[str], ui: UI, *, dry_run: bool, interactive: bool = True) -> int:
    ui.command(cmd)
    if dry_run:
        return 0
    if interactive:
        return subprocess.run(cmd, check=False).returncode
    return subprocess.run(cmd, capture_output=True, text=True, check=False).returncode


def toml_string(value: str) -> str:
    return json.dumps(value)


def codex_block(
    *,
    name: str,
    command: str,
    server_args: list[str],
) -> str:
    name = server_name(name)
    lines = [f"[mcp_servers.{name}]", f"command = {toml_string(command)}", "args = ["]
    lines.extend(f"  {toml_string(arg)}," for arg in server_args)
    lines.append("]")
    return "\n".join(lines) + "\n"


def section_name(line: str) -> str | None:
    stripped = line.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        return stripped.strip("[]")
    return None


def remove_codex_server_sections(text: str, name: str) -> tuple[str, bool]:
    targets = (f"mcp_servers.{name}", f'mcp_servers."{name}"')
    lines = text.splitlines()
    kept: list[str] = []
    skipping = False
    removed = False

    for line in lines:
        section = section_name(line)
        if section is not None:
            skipping = any(section == target or section.startswith(target + ".") for target in targets)
            removed = removed or skipping
        if not skipping:
            kept.append(line)

    return "\n".join(kept).rstrip() + ("\n" if kept else ""), removed


def regular_file_exists(path: Path, label: str) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode):
        raise ValueError(f"{label} must not be a symbolic link: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"{label} must be a regular file: {path}")
    return True


def read_regular_file(path: Path, label: str) -> tuple[bytes, int] | None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ValueError(f"{label} must not be a symbolic link: {path}") from error
        raise
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError(f"{label} must be a regular file: {path}")
        mode = stat.S_IMODE(opened.st_mode)
        stream = os.fdopen(descriptor, "rb")
        descriptor = -1
        with stream:
            return stream.read(), mode
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def write_backup(path: Path, data: bytes, mode: int) -> None:
    regular_file_exists(path, "Codex backup")
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            os.fchmod(temporary.fileno(), mode)
            temporary.write(data)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def configure_codex(
    *,
    config_path: Path,
    name: str,
    command: str,
    server_args: list[str],
    force: bool,
    dry_run: bool,
) -> CodexConfigResult:
    name = server_name(name)
    original_file = read_regular_file(config_path, "Codex config")
    config_exists = original_file is not None
    original_bytes, original_mode = original_file if original_file is not None else (b"", 0o600)
    original = original_bytes.decode() if config_exists else ""
    parsed = tomllib.loads(original)
    servers = parsed.get("mcp_servers", {})
    if not isinstance(servers, dict):
        raise ValueError("mcp_servers must be a TOML table")
    existed = name in servers
    stripped, removed = remove_codex_server_sections(original, name)
    if existed and not force:
        return CodexConfigResult(action="skipped", path=config_path)
    if existed and not removed:
        raise ValueError(
            f"inline or unsupported mcp_servers entry for '{name}' cannot be safely replaced; "
            "edit it into a [mcp_servers.<name>] table, then retry"
        )

    new_block = codex_block(name=name, command=command, server_args=server_args)
    new_text = (stripped.rstrip() + "\n\n" + new_block).lstrip()
    tomllib.loads(new_text)

    backup_path: Path | None = None
    if dry_run:
        return CodexConfigResult(action="would-update" if existed else "would-create", path=config_path)

    config_path.parent.mkdir(parents=True, exist_ok=True)
    if config_exists:
        backup_path = config_path.with_suffix(config_path.suffix + ".bak")
        write_backup(
            backup_path,
            original_bytes,
            original_mode,
        )
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=config_path.parent,
            prefix=f".{config_path.name}.",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(new_text)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, config_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return CodexConfigResult(action="updated" if existed else "created", path=config_path, backup_path=backup_path)


def resolve_clients(args: argparse.Namespace, ui: UI) -> set[str]:
    if args.clients != "ask":
        return parse_clients(args.clients)
    if args.yes:
        return {"claude", "codex"}

    choices = [
        ("1", "Claude Code"),
        ("2", "Codex"),
        ("3", "Both"),
        ("4", "Skip client config"),
    ]
    while True:
        answer = ask_choice(ui, "client config", choices, "3")
        if answer in {"1", "claude", "claude code"}:
            return {"claude"}
        if answer in {"2", "codex"}:
            return {"codex"}
        if answer in {"3", "both"}:
            return {"claude", "codex"}
        if answer in {"4", "skip", "none"}:
            return set()
        ui.warn("Choose 1, 2, 3, or 4.")


def resolve_codex_config(args: argparse.Namespace, clients: set[str]) -> None:
    if args.codex_config is None and "codex" in clients and args.scope != "user":
        raise SystemExit(
            "--scope applies only to Claude Code; pass --codex-config explicitly for Codex "
            "project or local configuration"
        )
    if args.codex_config is None:
        args.codex_config = Path.home() / ".codex" / "config.toml"


def preflight(ui: UI, repo_root: Path) -> None:
    ui.section("system checks")
    python_ok = sys.version_info >= (3, 11)
    ui.status("python", "ok" if python_ok else "fail", sys.version.split()[0], kind="ok" if python_ok else "err")
    if not python_ok:
        raise SystemExit("Python 3.11 or newer is required.")

    uv = command_exists("uv")
    ui.status("uv", "ok" if uv else "missing", uv or "install from https://docs.astral.sh/uv/", kind="ok" if uv else "err")
    if uv is None:
        raise SystemExit("uv is required.")

    gdb = command_exists("gdb")
    ui.status("gdb", "ok" if gdb else "missing", gdb or "install with your package manager", kind="ok" if gdb else "warn")

    gdbinit = Path.home() / ".gdbinit"
    sourced = pwndbg_sourced(gdbinit)
    ui.status(
        "pwndbg in ~/.gdbinit",
        "ok" if sourced else "not detected",
        str(gdbinit),
        kind="ok" if sourced else "warn",
    )
    ui.status("repo", "ok", str(repo_root), kind="ok")


def install_tool(ui: UI, repo_root: Path, *, dry_run: bool) -> Path:
    ui.section("tool install")
    rc = run_command(["uv", "tool", "install", "--editable", str(repo_root), "--reinstall"], ui, dry_run=dry_run)
    if rc != 0:
        raise SystemExit(rc)
    binary = find_installed_binary()
    if dry_run and binary is None:
        binary = Path.home() / ".local" / "bin" / "pwndbg-mcp"
    if binary is None:
        raise SystemExit("pwndbg-mcp was installed, but the entry point could not be found.")
    ui.status("pwndbg-mcp", "ready", str(binary), kind="ok")
    return binary


def configure_claude(*, binary: Path, args: argparse.Namespace, ui: UI) -> int:
    cmd = [
        str(binary),
        "install",
        "--scope",
        args.scope,
        "--name",
        args.name,
        "--gdb-path",
        args.gdb_path,
    ]
    if args.unsafe:
        cmd.append("--unsafe")
    if args.force:
        cmd.append("--force")
    if args.no_claude_cli:
        cmd.append("--no-claude-cli")
    return run_command(cmd, ui, dry_run=args.dry_run)


def configure_clients(
    *,
    clients: set[str],
    binary: Path,
    args: argparse.Namespace,
    ui: UI,
) -> int:
    if not clients:
        ui.section("client setup")
        ui.status("clients", "skipped", "no MCP client selected", kind="info")
        return 0

    ui.section("client setup")
    server_args = build_server_args(gdb_path=args.gdb_path)
    client_rc = 0
    if "claude" in clients:
        client_rc = configure_claude(binary=binary, args=args, ui=ui)
        if client_rc != 0:
            ui.warn("Claude Code setup failed. You can rerun `pwndbg-mcp install` later.")
    if "codex" in clients:
        try:
            result = configure_codex(
                config_path=args.codex_config,
                name=args.name,
                command=str(binary),
                server_args=server_args,
                force=args.force,
                dry_run=args.dry_run,
            )
        except (OSError, ValueError) as error:
            client_rc = client_rc or 1
            ui.status("Codex config", "failed", str(error), kind="err")
        else:
            detail = str(result.path)
            if result.backup_path:
                detail += f" (backup: {result.backup_path})"
            kind = "warn" if result.action == "skipped" else "ok"
            ui.status("Codex config", result.action, detail, kind=kind)
            if result.action == "skipped":
                ui.note("Pass --force to replace the existing Codex MCP entry.")
    return client_rc


def print_plan(ui: UI, *, clients: set[str], args: argparse.Namespace) -> None:
    ui.section("plan")
    ui.status("install tool", "yes", "uv tool install --editable", kind="info")
    ui.status("clients", clients_label(clients), "", kind="info")
    if "codex" in clients:
        ui.status("Codex target", "config", str(args.codex_config), kind="info")
    if args.dry_run:
        ui.status("mode", "dry-run", "no files or config will be changed", kind="warn")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Set up pwndbg-mcp for Claude Code, Codex, or both.")
    parser.add_argument(
        "--clients",
        choices=["ask", "claude", "codex", "both", "none"],
        default="ask",
        help="Client config target (default: ask interactively, --yes defaults to both)",
    )
    parser.add_argument(
        "--scope",
        choices=["user", "local", "project"],
        default="user",
        help="Claude Code configuration scope (does not select a Codex config path)",
    )
    parser.add_argument("--name", type=server_name, default="pwndbg")
    parser.add_argument("--gdb-path", default="gdb")
    parser.add_argument(
        "--unsafe",
        action="store_true",
        help="Allow mutating Claude MCP tools without prompts; does not configure Codex approvals",
    )
    parser.add_argument("--force", action="store_true", help="Replace existing client entries")
    parser.add_argument(
        "--no-claude-cli",
        action="store_true",
        help="Use Claude JSON fallback (user/project scopes only)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Show actions without changing files")
    parser.add_argument("--yes", "-y", action="store_true", help="Use defaults without prompts")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument(
        "--codex-config",
        type=Path,
        default=None,
        help="Codex config.toml path (default: ~/.codex/config.toml for user scope)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    ui = UI(color=not args.no_color)
    repo_root = Path(__file__).resolve().parent

    ui.title()
    clients = resolve_clients(args, ui)
    resolve_codex_config(args, clients)
    preflight(ui, repo_root)
    print_plan(ui, clients=clients, args=args)
    if not args.yes and not args.dry_run:
        if not ask_yes_no(ui, "Continue with these changes?", default=True):
            ui.warn("cancelled")
            return 1

    binary = install_tool(ui, repo_root, dry_run=args.dry_run)
    client_rc = configure_clients(clients=clients, binary=binary, args=args, ui=ui)

    ui.section("summary")
    ui.status("pwndbg-mcp", "installed" if not args.dry_run else "planned", str(binary), kind="ok")
    ui.status(
        "clients",
        "incomplete" if client_rc else clients_label(clients),
        "one or more client configurations failed" if client_rc else "",
        kind="err" if client_rc else "ok",
    )
    ui.note("Run `pwndbg-mcp doctor` to verify the debugger environment.")
    print()
    return client_rc


if __name__ == "__main__":
    raise SystemExit(main())
