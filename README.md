<h1 align="center">pwndbg-mcp</h1>

<p align="center">
  <strong>Debug binaries with pwndbg and GDB from your AI client</strong>
</p>

<p align="center">
  <a href="#configure-clients"><img alt="Claude Code Supported" src="https://img.shields.io/badge/Claude%20Code-Supported-D8B4A0?style=flat-square&logo=claude&logoColor=white"></a>
  <a href="#configure-clients"><img alt="Codex Supported" src="https://img.shields.io/badge/Codex-Supported-B8C0E0?style=flat-square&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA1MTIgNTEyIj48cGF0aCBmaWxsPSIjZmZmIiBkPSJNMTk2LjQgMTg1LjhsMC00OC42YzAtNC4xIDEuNS03LjIgNS4xLTkuMmw5Ny44LTU2LjNjMTMuMy03LjcgMjkuMi0xMS4zIDQ1LjYtMTEuMyA2MS40IDAgMTAwLjQgNDcuNiAxMDAuNCA5OC4zIDAgMy42IDAgNy43LS41IDExLjhMMzQzLjMgMTExLjFjLTYuMS0zLjYtMTIuMy0zLjYtMTguNCAwTDE5Ni40IDE4NS44ek00MjQuNyAzNzUuMmwwLTExNi4yYzAtNy4yLTMuMS0xMi4zLTkuMi0xNS45TDI4NyAxNjguNCAzMjkgMTQ0LjNjMy42LTIgNi43LTIgMTAuMiAwTDQzNyAyMDAuN2MyOC4yIDE2LjQgNDcuMSA1MS4yIDQ3LjEgODUgMCAzOC45LTIzIDc0LjgtNTkuNCA4OS42bDAgMHpNMTY2LjIgMjcyLjhsLTQyLTI0LjZjLTMuNi0yLTUuMS01LjEtNS4xLTkuMmwwLTExMi42YzAtNTQuOCA0Mi05Ni4zIDk4LjgtOTYuMyAyMS41IDAgNDEuNSA3LjIgNTguNCAyMEwxNzUuNCAxMDguNWMtNi4xIDMuNi05LjIgOC43LTkuMiAxNS45bDAgMTQ4LjUgMCAwem05MC40IDUyLjJsLTYwLjItMzMuOCAwLTcxLjcgNjAuMi0zMy44IDYwLjIgMzMuOCAwIDcxLjctNjAuMiAzMy44em0zOC43IDE1NS43Yy0yMS41IDAtNDEuNS03LjItNTguNC0yMGwxMDAuOS01OC40YzYuMS0zLjYgOS4yLTguNyA5LjItMTUuOWwwLTE0OC41IDQyLjUgMjQuNmMzLjYgMiA1LjEgNS4xIDUuMSA5LjJsMCAxMTIuNmMwIDU0LjgtNDIuNSA5Ni4zLTk5LjMgOTYuM2wwIDB6TTE3My44IDM2Ni41TDc2LjEgMzEwLjJjLTI4LjItMTYuNC00Ny4xLTUxLjItNDcuMS04NSAwLTM5LjQgMjMuNi03NC44IDU5LjktODkuNmwwIDExNi43YzAgNy4yIDMuMSAxMi4zIDkuMiAxNS45bDEyOCA3NC4yLTQyIDI0LjFjLTMuNiAyLTYuNyAyLTEwLjIgMHptLTUuNiA4NGMtNTcuOSAwLTEwMC40LTQzLjUtMTAwLjQtOTcuMyAwLTQuMSAuNS04LjIgMS0xMi4zbDEwMC45IDU4LjRjNi4xIDMuNiAxMi4zIDMuNiAxOC40IDBsMTI4LjUtNzQuMiAwIDQ4LjZjMCA0LjEtMS41IDcuMi01LjEgOS4ybC05Ny44IDU2LjNjLTEzLjMgNy43LTI5LjIgMTEuMy00NS42IDExLjNsMCAwem0xMjcgNjAuOWM2MiAwIDExMy43LTQ0IDEyNS40LTEwMi40IDU3LjMtMTQuOSA5NC4yLTY4LjYgOTQuMi0xMjMuNCAwLTM1LjgtMTUuNC03MC43LTQzLTk1LjcgMi42LTEwLjggNC4xLTIxLjUgNC4xLTMyLjMgMC03My4yLTU5LjQtMTI4LTEyOC0xMjgtMTMuOCAwLTI3LjEgMi00MC40IDYuNy0yMy0yMi41LTU0LjgtMzYuOS04OS42LTM2LjktNjIgMC0xMTMuNyA0NC0xMjUuNCAxMDIuNC01Ny4zIDE0LjgtOTQuMiA2OC42LTk0LjIgMTIzLjQgMCAzNS44IDE1LjQgNzAuNyA0MyA5NS43LTIuNiAxMC44LTQuMSAyMS41LTQuMSAzMi4zIDAgNzMuMiA1OS40IDEyOCAxMjggMTI4IDEzLjggMCAyNy4xLTIgNDAuNC02LjcgMjMgMjIuNSA1NC44IDM2LjkgODkuNiAzNi45eiIvPjwvc3ZnPg%3D%3D"></a>
  <a href="https://www.python.org/"><img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-A8C7E6?style=flat-square&logo=python&logoColor=white"></a>
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-BFD8B8?style=flat-square&logo=github&logoColor=white"></a>
  <a href="#installation"><img alt="Linux platform" src="https://img.shields.io/badge/platform-Linux-C8C2B8?style=flat-square&logo=linux&logoColor=white"></a>
</p>

---

## Overview

`pwndbg-mcp` runs a local GDB session with [pwndbg](https://github.com/pwndbg/pwndbg) loaded and exposes it to an MCP client. The client reads live debugger state and runs approved commands against it. Built for pentesting, CTF pwn, exploit development, and crash analysis.

Run the server on the analysis machine, next to GDB and the target. It starts GDB in MI mode and expects your own GDB setup to load pwndbg. The inferior gets a PTY, so clients can read it, write to it, and interrupt interactive programs. The server tracks inferior state, and any tool that needs it stopped checks first.

## Background

This started from [RocketMaDev/pwndbg-mcp](https://github.com/RocketMaDev/pwndbg-mcp), which drives pwndbg over MCP for ELF and CTF pwn work in 19 tools, and whose PTY and controller scaffold this project's `bridge.py` is derived from. That project in turn credits [pwno-mcp](https://github.com/pwno-io/pwno-mcp) as its bootstrap framework.

What this adds: 169 tools against their 19, attach by PID or process name, remote gdbserver over `target remote` and `target extended-remote`, decompiler context through pwndbg's `di` commands rather than decomp2dbg directly, and an installer that writes a per-tool approval inventory into the client's config.

## Features

169 registered tools, split 84 read-only and 85 mutating. Serve them over stdio, HTTP, or SSE.

| Area | What it covers |
| --- | --- |
| **Debugger control** | Load binaries, attach by PID or name, set arguments, reset GDB, run/start variants, step/next/continue/finish, move stack frames, kill the inferior. |
| **State and context** | Server and inferior state, pwndbg help and command listings, config/theme get and set, context sections, `ctx_watch` entries. |
| **Inspection** | Mappings, memory, registers, stack, disassembly, breakpoints, ELF/libc state, heap chunks, bins, process info. |
| **Mutation and exploit helpers** | Write memory and registers, breakpoints and watchpoints, patch code, spray memory, cyclic patterns, ROP/ropper/one-gadget/leakfind, syscall and fd helpers. |
| **Remote workflows** | pwncat sessions: open, listen, list, read, send, close, and a zero-I/O scan. Plus `target remote`, `target extended-remote`, and a remote exploit template. |
| **Kernel views** | pwndbg kernel helpers for BPF, binder, buddy allocator, nftables, tasks, modules, syscalls, slabs, dmesg, and kernel metadata. |
| **Decompiler integration** | Check the `di` endpoint, connect, disconnect, sync symbols, request `decomp [addr] [lines]`. |

For the full list, read [`src/pwndbg_mcp/tools/_registry.py`](src/pwndbg_mcp/tools/_registry.py) or ask a client for `tools/list`.

Large results are capped, and anything truncated says so in its response. [`src/pwndbg_mcp/util.py`](src/pwndbg_mcp/util.py) holds the limits. A GDB command that fails comes back as an MCP error, not as partial output that looks like success.

## Installation

Prerequisites: Linux, Python 3.11+, [`uv`](https://docs.astral.sh/uv/), GDB, pwndbg.

From a clone, with client configuration:

```bash
git clone https://github.com/h0w1tzxr/pwndbg-mcp.git
cd pwndbg-mcp
python install.py
pwndbg-mcp doctor
```

Tool only:

```bash
uv tool install git+https://github.com/h0w1tzxr/pwndbg-mcp.git
pwndbg-mcp doctor
```

## Configure clients

Two entry points:

- **`python install.py`** is interactive. It installs the tool and configures Claude Code, Codex, or both. Only it accepts `--clients` and `--codex-config`.
- **`pwndbg-mcp install`** does Claude Code only. It has no Codex flags.

The server uses FastMCP, whose CLI exposes stdio (the default), HTTP, and SSE. Any client that can launch a stdio server works; configure those yourself.

### Claude Code

```bash
pwndbg-mcp install --scope user
pwndbg-mcp status
```

That registers the server over stdio and writes one exact rule per tool: read-only tools into `permissions.allow`, mutating tools into `permissions.ask`. Use `--unsafe` only in an isolated test environment. It moves both inventories to `allow`.

User, project, and local policies live in `~/.claude/settings.json`, `.claude/settings.json`, and `.claude/settings.local.json`. `--scope` selects only the Claude Code scope. Without the Claude CLI, the JSON fallback supports user and project scopes, and local scope requires the CLI.

### Codex

Configure Codex through `python install.py --codex-config` (default `~/.codex/config.toml`). Any Claude scope other than `user` leaves the Codex path unset, so pass `--codex-config` yourself when you configure both. Codex manages approvals itself, and the installer's per-tool inventory is not written there.

Manual configuration:

```toml
[mcp_servers.pwndbg]
command = "pwndbg-mcp"
args = [
  "--transport", "stdio",
  "--pwndbg", "gdb",
]
```

If the client cannot find the binary, use the absolute path from `command -v pwndbg-mcp`.

`tools/list` publishes standard MCP `readOnlyHint` and `destructiveHint` annotations from the same inventories. They are advisory; the client's approval policy decides.

## Decompiler integration

Requires pwndbg 2026.02.18 or newer, which exposes one `decompiler-integration` command (aliased `di`) for IDA, Binary Ninja, Ghidra, and angr-management. A local provider also needs `decomp2dbg` in pwndbg's own Python environment. That is not a `pwndbg-mcp` dependency.

Stop the inferior first, then:

1. Call `decompiler_status`. It reports the command, pwndbg version, host, port, live provider, and the installed and required dependency versions.
2. Install a matching plugin with pwndbg's `di install <provider>`. This writes files and may download a plugin, so run it through the approval-gated `execute_command` tool only after review.
3. Open the same binary in the decompiler and start its server with `Ctrl+Shift+D`.
4. Call `decompiler_connect`, then `decompiler_sync` once the inferior starts.
5. Call `decomp` with an optional address and line count. Call `decompiler_disconnect` when done.

A dependency or provider mismatch raises `MissingDependency`. A closed listener raises `RemoteConnectionError` naming its endpoint. For a local provider, pass literal `localhost` to `decompiler_connect` so pwndbg runs its local dependency and version checks.

> **IDA and Ghidra expose unauthenticated, unencrypted XML-RPC.** Bind their listeners only to `127.0.0.1:3662` and confirm the socket with `ss`. Linux may show the same IPv4-mapped loopback as `[::ffff:127.0.0.1]:3662`. Reject wildcard and non-loopback listeners.

## Remote debugging

Load local symbols before connecting:

```gdb
file /path/to/local/binary
set sysroot /path/to/target-root
```

Then call `gdb_target_remote` for a regular gdbserver target, or `gdb_target_extended_remote` for extended mode. A failed connection names the endpoint. To recover, restart gdbserver, run `disconnect` through the approval-gated `execute_command` tool before reconnecting, or call `mcp_hard_reset` when GDB stops responding.

`remote_pwncat_*` needs [`pwncat`](https://github.com/cytopia/pwncat) (`uv tool install pwncat`). ROP helpers report a missing `ROPgadget`, `ropper`, `one_gadget`, or pwntools and name the install. `leakfind` ships with pwndbg and needs no external binary.

To find your way around, call `version_info`, then `list_pwndbg_commands`, then `pwndbg_help` on whatever looks useful. Clients can also use `tools/list`.

## Development

Clone it, then work with `uv` directly:

```bash
uv tool install --editable . --reinstall   # link for development
uv run --extra dev ruff check src/         # lint
uv run --extra dev mypy src/               # typecheck
uv run --extra dev ruff format src/        # format
uv build                                   # wheel + sdist
pwndbg-mcp doctor                          # check gdb, pwndbg, and PATH
```

List the tool surface over stdio:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | pwndbg-mcp --transport stdio --pwndbg gdb
```

Before publishing or handing off:

```bash
uv run --extra dev ruff check src/
uv run --extra dev mypy src/
uv build
uv lock --check
git diff HEAD --check
```

Check the registry split:

```bash
uv run --extra dev python - <<'PY'
from pwndbg_mcp.tools._registry import SAFE_TOOLS, MUTATING_TOOLS
print(len(SAFE_TOOLS), len(MUTATING_TOOLS), len(SAFE_TOOLS) + len(MUTATING_TOOLS))
PY
```

Expected output:

```text
84 85 169
```

Layout:

- `src/pwndbg_mcp/bridge.py`: GDB/MI controller, PTY handling, state tracking, response parsing.
- `src/pwndbg_mcp/tools/`: tool modules grouped by debugging domain.
- `src/pwndbg_mcp/tools/_registry.py`: FastMCP singleton and the read-only and mutating inventories.
- `src/pwndbg_mcp/installer/`: client registration and config helpers.
- `install.py`: interactive installer.

## Credits

Built on [pwndbg](https://github.com/pwndbg/pwndbg), whose command surface this server exposes, and [GDB](https://www.sourceware.org/gdb/) underneath it.

[RocketMaDev/pwndbg-mcp](https://github.com/RocketMaDev/pwndbg-mcp) (MIT, Copyright (C) 2025-present RocketDev) is where the PTY and controller scaffold in `bridge.py` comes from, along with much of the tool naming. It credits [pwno-mcp](https://github.com/pwno-io/pwno-mcp) as its own bootstrap framework. [pwntools](https://github.com/Gallopsled/pwntools) does the payload-oriented process I/O.

Also [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp), [FastMCP](https://github.com/jlowin/fastmcp), and [pygdbmi](https://github.com/cs01/pygdbmi).

## License

MIT. See [LICENSE](LICENSE).
