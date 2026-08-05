"""Async GDB/MI controller with PTY-backed inferior I/O"""

from __future__ import annotations

import asyncio
import errno
import json
import logging
import math
import os
import pty
import select
import signal
import subprocess
import termios
import time
import tty
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutTimeout
from contextlib import asynccontextmanager
from dataclasses import dataclass
from dataclasses import field
from enum import StrEnum
from typing import Any

from pygdbmi.gdbcontroller import GdbController

from pwndbg_mcp.errors import GdbCrashed
from pwndbg_mcp.errors import InferiorStateError
from pwndbg_mcp.errors import InvalidArgument
from pwndbg_mcp.errors import ParseError
from pwndbg_mcp.errors import PwndbgError
from pwndbg_mcp.errors import PwndbgNotLoaded
from pwndbg_mcp.errors import TimeoutExceeded
from pwndbg_mcp.types import AttachResult
from pwndbg_mcp.util import ANSI_RE
from pwndbg_mcp.util import _quote_gdb_string
from pwndbg_mcp.util import _safe_gdb_arg

logger = logging.getLogger(__name__)

_MAX_PTY_PAYLOAD = 1 << 20
_MAX_PTY_WRITE_TIMEOUT = 30.0
_MAX_PTY_READ_TIMEOUT = 300.0
_PTY_POLL_INTERVAL = 0.01
_PTY_CONTROL_DELIVERY_DELAY = 0.05


class _OwnershipTimeout(Exception):
    pass


def _validate_pty_timeout(
    value: float,
    *,
    field: str,
    maximum: float,
    allow_zero: bool,
) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError, OverflowError) as e:
        raise InvalidArgument(f"invalid {field} {value!r}") from e
    lower_bound_ok = timeout >= 0.0 if allow_zero else timeout > 0.0
    if (
        isinstance(value, bool)
        or not math.isfinite(timeout)
        or not lower_bound_ok
        or timeout > maximum
    ):
        minimum = "0" if allow_zero else "greater than 0"
        raise InvalidArgument(
            f"{field} must be {minimum}..{maximum:g} seconds (got {value!r})"
        )
    return timeout


class GdbState(StrEnum):
    NOT_LOADED = "not_loaded"
    LOADED = "loaded"
    RUNNING = "running"
    STOPPED = "stopped"
    EXITED = "exited"
    ERROR = "error"


@dataclass
class GdbResponse:
    """Flattened pygdbmi response for one command round-trip"""

    console: list[str] = field(default_factory=list)
    log: list[str] = field(default_factory=list)
    target: list[str] = field(default_factory=list)
    notifications: list[dict[str, Any]] = field(default_factory=list)
    result_class: str | None = None
    result_payload: dict[str, Any] | None = None
    error: str | None = None
    raw: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None and self.result_class in (
            None,
            "done",
            "running",
            "connected",
        )

    @property
    def text(self) -> str:
        return "".join(self.console).rstrip()


def _definite_log_error(logs: list[str]) -> str | None:
    lines = [line.strip() for chunk in logs for line in chunk.splitlines() if line.strip()]
    lowered = [line.lower() for line in lines]
    if any(line.startswith("usage:") for line in lowered) and any(
        ": error:" in line for line in lowered
    ):
        return "\n".join(lines)

    for line, lower in zip(lines, lowered, strict=True):
        if (
            lower.startswith("undefined command:")
            or "the program is not being run." in lower
            or "the program is not running." in lower
            or lower == "pwndbg commands require a target binary to be selected"
            or (lower.startswith("pwndbg command") and " failed" in lower)
            or ": there is no file loaded." in lower
            or ": this command may only be run " in lower
            or ": heap is not initialized yet." in lower
            or "currently active libc isn't glibc" in lower
            or "fail to resolve the symbol:" in lower
            or "can't find glibc version required" in lower
            or "failed to determine which arena" in lower
            or "this version of glibc was not compiled with tcache support" in lower
            or "an unknown error occurred when resolved the heap" in lower
            or "an unknown error occurred when running this command" in lower
        ):
            return line
    return None


def _definite_console_error(console: list[str]) -> str | None:
    for chunk in console:
        for line in chunk.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith(("exception occurred:", "could not find mapping")):
                return stripped
    return None


def _bucket(raw: list[dict[str, Any]]) -> GdbResponse:
    """Convert pygdbmi's list-of-dicts into a structured response"""
    r = GdbResponse(raw=list(raw))
    pending = ""
    for m in raw:
        t = m.get("type")
        msg = m.get("message")
        pl = m.get("payload")
        if t == "console":
            text = ANSI_RE.sub("", pl or "")
            if text and not text.endswith("\n"):
                pending += text
            else:
                if pending:
                    text = pending + text
                    pending = ""
                if text:
                    r.console.append(text)
        elif t == "log":
            r.log.append(ANSI_RE.sub("", pl or ""))
        elif t == "target":
            r.target.append(ANSI_RE.sub("", pl or ""))
        elif t == "notify":
            r.notifications.append({"message": msg, "payload": pl})
        elif t == "result":
            r.result_class = msg
            r.result_payload = pl if isinstance(pl, dict) else None
            if msg == "error":
                r.error = (pl or {}).get("msg") if isinstance(pl, dict) else str(pl)
    if pending:
        r.console.append(pending)
    if r.error is None:
        r.error = _definite_log_error(r.log) or _definite_console_error(r.console)
    return r


def _extend_response(resp: GdbResponse, extra: GdbResponse) -> GdbResponse:
    """Append a drained response chunk to an existing command response"""
    resp.console.extend(extra.console)
    resp.log.extend(extra.log)
    resp.target.extend(extra.target)
    resp.notifications.extend(extra.notifications)
    resp.raw.extend(extra.raw)
    if resp.result_class is None:
        resp.result_class = extra.result_class
        resp.result_payload = extra.result_payload
    if extra.error:
        if resp.error and resp.error != extra.error:
            resp.error = f"{resp.error}; {extra.error}"
        else:
            resp.error = extra.error
    return resp


def _normalize_stop_reason(value: Any) -> str | None:
    """Coerce GDB MI stop reasons to the status schema's string-or-null shape"""
    if value is None:
        return None
    if isinstance(value, str):
        return value or None
    if isinstance(value, (list, tuple)):
        parts = [_normalize_stop_reason(item) for item in value]
        parts = [part for part in parts if part]
        if not parts:
            return None
        return ",".join(parts)
    return str(value)


# whole-line anchors from mcp_emit, so marker-like text inside json stays safe
_MCP_JSON_OPEN = "<<<MCP_JSON>>>:"
_MCP_ERROR_OPEN = "<<<MCP_ERROR>>>:"
_MCP_END = ":<<<END>>>"


# dispatch tables keep sentinel and native gdb errors on one hierarchy

# these mean the inferior memory is gone. generic python errors are api drift instead
_INFERIOR_STATE_EXC_TYPES = frozenset(
    {
        "MemoryError",
        # gdb's python bindings prefix some classes with "gdb."
        "gdb.MemoryError",
    }
)

_API_COMPAT_EXC_TYPES = frozenset(
    {
        "AttributeError",
        "KeyError",
        "TypeError",
        "ImportError",
        "ModuleNotFoundError",
        "gdb.error",
        "gdb.GdbError",
    }
)


# message fragments with the same absent-domain meaning
_INFERIOR_STATE_MSG_PATTERNS = (
    "cannot access memory",
    "no symbol",
    "currently active libc isn't glibc",
    "heap is not initialized",
    "fail to resolve the symbol",
    "can't find glibc version required",
    "failed to determine which arena",
    "could not find mapping",
)


def _classify_pi_error(exc_type: str, message: str) -> type[PwndbgError]:
    """Map an MCP_ERROR sentinel payload to a PwndbgError subclass

    Missing root pwndbg imports mean pwndbg was not sourced. Generic Python
    shape/import errors mean this tool does not match the installed pwndbg API.
    Memory and explicit domain messages remain inferior-state failures.
    Unknown → GdbCrashed
    """
    normalized = message.strip().rstrip(".").replace('"', "'").lower()
    if exc_type in {"ImportError", "ModuleNotFoundError"} and normalized in {
        "no module named 'pwndbg'",
        "no module named pwndbg",
    }:
        return PwndbgNotLoaded
    low = message.lower()
    if any(pat in low for pat in _INFERIOR_STATE_MSG_PATTERNS):
        return InferiorStateError
    if exc_type in _INFERIOR_STATE_EXC_TYPES:
        return InferiorStateError
    if exc_type in _API_COMPAT_EXC_TYPES:
        return PwndbgError
    return GdbCrashed


def _classify_gdb_error(error_text: str) -> type[PwndbgError]:
    """Map GDB ^error text to a typed bridge error"""
    if not error_text:
        return GdbCrashed
    low = error_text.lower()
    if any(pat in low for pat in _INFERIOR_STATE_MSG_PATTERNS):
        return InferiorStateError
    return GdbCrashed


def _parse_pi_result(resp: GdbResponse) -> Any:
    """Decode the sentinel-delimited payload from a `pi_query` response

    Scans `resp.text` lines bottom-up. The first line starting with one of our
    open markers AND ending with our close marker is the result. ``MCP_ERROR``
    blocks raise the typed project error selected from the exception class and
    message
    """
    lines = resp.text.splitlines()
    if not lines:
        raise ParseError(f"empty pi output (logs: {resp.log[:3]})")

    for line in reversed(lines):
        if line.startswith(_MCP_JSON_OPEN) and line.endswith(_MCP_END):
            payload = line[len(_MCP_JSON_OPEN) : -len(_MCP_END)]
            try:
                return json.loads(payload)
            except json.JSONDecodeError as e:
                raise ParseError(
                    f"sentinel-framed payload is not valid JSON: {payload[:200]}"
                ) from e
        if line.startswith(_MCP_ERROR_OPEN) and line.endswith(_MCP_END):
            payload = line[len(_MCP_ERROR_OPEN) : -len(_MCP_END)]
            try:
                err = json.loads(payload)
            except json.JSONDecodeError as e:
                raise ParseError(
                    f"sentinel-framed error payload is not valid JSON: {payload[:200]}"
                ) from e
            exc_type = err.get("type", "Exception")
            message = err.get("message", "")
            cls = _classify_pi_error(exc_type, message)
            traceback = err.get("traceback", "")
            if cls is PwndbgNotLoaded:
                raise cls(
                    f"pwndbg is not loaded ({exc_type}: {message}); source pwndbg "
                    "from ~/.gdbinit, then call mcp_hard_reset"
                )
            if cls is PwndbgError:
                raise cls(
                    f"pwndbg API compatibility failure ({exc_type}: {message}); "
                    "use matching current pwndbg and pwndbg-mcp versions"
                    + (f"\n{traceback}" if traceback else "")
                )
            raise cls(f"{exc_type}: {message}\n{traceback}")

    raise ParseError(f"no MCP sentinel in pi output (last 3 lines: {lines[-3:]!r})")


def _state_from_notifications(ns: list[dict[str, Any]]) -> tuple[GdbState | None, str | None]:
    new_state: GdbState | None = None
    reason: str | None = None
    for n in ns:
        m = n.get("message")
        pl = n.get("payload") or {}
        if m == "running":
            new_state = GdbState.RUNNING
        elif m == "stopped":
            reason = _normalize_stop_reason(pl.get("reason") if isinstance(pl, dict) else None)
            if reason and "exit" in reason:
                new_state = GdbState.EXITED
            else:
                new_state = GdbState.STOPPED
        elif m == "thread-group-exited":
            exit_code = pl.get("exit-code") if isinstance(pl, dict) else None
            reason = "thread-group-exited"
            if exit_code is not None:
                reason += f" (exit-code={exit_code})"
            new_state = GdbState.EXITED
    return new_state, reason


class _IsolatedGdbController(GdbController):
    """Spawn GDB in its own session so process-group signals stay scoped"""

    def spawn_new_gdb_subprocess(self) -> int:
        if self.gdb_process:
            logger.debug("Killing current gdb subprocess (pid %d)", self.gdb_process.pid)
            self.exit()
        from pygdbmi.IoManager import IoManager

        self.gdb_process = subprocess.Popen(
            self.command,
            shell=False,
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            start_new_session=True,
        )
        assert self.gdb_process.stdin is not None
        assert self.gdb_process.stdout is not None
        self.io_manager = IoManager(
            self.gdb_process.stdin,
            self.gdb_process.stdout,
            self.gdb_process.stderr,
            self.time_to_check_for_additional_output_sec,
        )
        return self.gdb_process.pid


class AsyncGdbController:
    """Own one GDB MI subprocess and one PTY-backed inferior"""

    def __init__(self, gdb_path: str = "gdb", timeout: float = 5.0) -> None:
        self.gdb_path = gdb_path
        self.timeout = timeout
        self._decompiler_connected = False
        self._controller: GdbController | None = None
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="gdb-mi")
        self._mi_lock = asyncio.Lock()
        self._mi_owner: asyncio.Task[Any] | None = None
        self._mi_depth = 0
        self._pty_mutation_lock = asyncio.Lock()
        self._pty_mutation_owner: asyncio.Task[Any] | None = None
        self._pty_mutation_depth = 0
        self._pty_read_lock = asyncio.Lock()
        self._pty_generation = 0
        self._pty_read_stash = bytearray()
        self._pty_read_stash_generation = 0

        self.state: GdbState = GdbState.NOT_LOADED
        self._pty_master: int | None = None
        self._pty_slave: int | None = None
        self._pty_name: str | None = None
        self._pty_attrs: list[Any] | None = None
        self._poller: select.poll | None = None

        self._loaded_path: str | None = None
        self._last_error: str | None = None
        self._last_stop_reason: str | None = None
        self._started_at: float = 0.0

    def _apply_response_state(self, resp: GdbResponse) -> None:
        """Apply state-bearing async records from a GDB response"""
        new_state, reason = _state_from_notifications(resp.notifications)
        if new_state:
            self.state = new_state
            self._last_stop_reason = reason
        if resp.error:
            self._last_error = resp.error

    def _poison_mi(self, message: str) -> str:
        error = f"{message}; call mcp_hard_reset to recover"
        self.state = GdbState.ERROR
        self._last_error = error
        return error

    def _poison_pty(self, message: str) -> str:
        error = message
        if "mcp_hard_reset" not in error:
            error += "; call mcp_hard_reset to recover"
        self.state = GdbState.ERROR
        self._last_error = error
        return error

    def _require_live_pty_state(self, operation: str) -> None:
        if self.state in {GdbState.RUNNING, GdbState.STOPPED}:
            return
        if self.state == GdbState.ERROR:
            detail = getattr(self, "_last_error", None) or "debugger is in ERROR state"
            if "mcp_hard_reset" not in detail:
                detail += "; call mcp_hard_reset to recover"
            raise InferiorStateError(detail)
        raise InferiorStateError(
            f"cannot {operation} while inferior state={self.state}; start or attach "
            "an inferior, or call mcp_hard_reset if debugger state is stale"
        )

    def _assert_pty_current(
        self,
        master: int,
        generation: int,
        poller: Any | None = None,
    ) -> None:
        changed = (
            getattr(self, "_pty_generation", 0) != generation
            or self._pty_master != master
        )
        if poller is not None:
            changed = changed or self._poller is not poller
        if changed:
            raise GdbCrashed(
                "inferior PTY changed during I/O; retry against current debugger state"
            )

    @asynccontextmanager
    async def _pty_mutation_transaction(
        self, deadline: float | None = None
    ) -> AsyncIterator[None]:
        """Serialize payload writes and temporary terminal-mode mutations"""
        task = asyncio.current_task()
        if task is None:
            raise RuntimeError("PTY mutations require an asyncio task")

        if getattr(self, "_pty_mutation_owner", None) is task:
            self._pty_mutation_depth += 1
            try:
                yield
            finally:
                self._pty_mutation_depth -= 1
            return

        lock = getattr(self, "_pty_mutation_lock", None)
        if lock is None:  # Supports lean __new__-based test controllers.
            lock = self._pty_mutation_lock = asyncio.Lock()
            self._pty_mutation_owner = None
            self._pty_mutation_depth = 0
        if deadline is None:
            await lock.acquire()
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _OwnershipTimeout
            try:
                await asyncio.wait_for(lock.acquire(), timeout=remaining)
            except TimeoutError as e:
                raise _OwnershipTimeout from e
        self._pty_mutation_owner = task
        self._pty_mutation_depth = 1
        try:
            yield
        finally:
            self._pty_mutation_depth = 0
            self._pty_mutation_owner = None
            lock.release()

    @asynccontextmanager
    async def _pty_read_transaction(self, deadline: float) -> AsyncIterator[bool]:
        """Acquire the read lock within the caller's read deadline"""
        lock = getattr(self, "_pty_read_lock", None)
        if lock is None:  # Supports lean __new__-based test controllers.
            lock = self._pty_read_lock = asyncio.Lock()

        if lock.locked():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                yield False
                return
            try:
                await asyncio.wait_for(lock.acquire(), timeout=remaining)
            except TimeoutError:
                yield False
                return
        else:
            await lock.acquire()
        try:
            yield True
        finally:
            lock.release()

    @asynccontextmanager
    async def mi_transaction(self, deadline: float | None = None) -> AsyncIterator[None]:
        """Give one asyncio task exclusive, reentrant ownership of the MI stream"""
        task = asyncio.current_task()
        if task is None:
            raise RuntimeError("MI transactions require an asyncio task")

        if getattr(self, "_mi_owner", None) is task:
            self._mi_depth += 1
            try:
                yield
            finally:
                self._mi_depth -= 1
            return

        lock = getattr(self, "_mi_lock", None)
        if lock is None:  # Supports lean __new__-based test controllers.
            lock = self._mi_lock = asyncio.Lock()
            self._mi_owner = None
            self._mi_depth = 0
        if deadline is None:
            await lock.acquire()
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _OwnershipTimeout
            try:
                await asyncio.wait_for(lock.acquire(), timeout=remaining)
            except TimeoutError as e:
                raise _OwnershipTimeout from e
        self._mi_owner = task
        self._mi_depth = 1
        try:
            yield
        finally:
            self._mi_depth = 0
            self._mi_owner = None
            lock.release()


    async def start(self) -> None:
        async with self.mi_transaction():
            if self._controller is not None:
                return

            try:
                await self._start_once()
            except Exception as e:
                self._cleanup_failed_start(e)
                raise GdbCrashed(self._last_error or "GDB startup failed") from e

    async def _start_once(self) -> None:

        # echo off so our writes do not mirror back into the read buffer
        self._pty_master, self._pty_slave = pty.openpty()
        self._pty_name = os.ttyname(self._pty_slave)
        self._pty_attrs = list(termios.tcgetattr(self._pty_slave))
        self._pty_attrs[3] = int(self._pty_attrs[3]) & ~termios.ECHO
        termios.tcsetattr(self._pty_slave, termios.TCSANOW, self._pty_attrs)
        tty.setraw(self._pty_slave)
        tty.setraw(self._pty_master)
        os.set_blocking(self._pty_master, False)
        self._pty_generation += 1
        self._pty_read_stash.clear()
        self._pty_read_stash_generation = self._pty_generation
        self._poller = select.poll()
        self._poller.register(self._pty_master, select.POLLIN)

        argv = [
            self.gdb_path,
            "-q",
            "--interpreter=mi3",
            # mi-async lets interrupt commands dispatch while the target runs
            "-iex",
            "set mi-async on",
            "-iex",
            "set pagination off",
            "-iex",
            "set confirm off",
            "-iex",
            "set print pretty on",
            "-iex",
            "set host-charset UTF-8",
            "-iex",
            "set target-charset UTF-8",
            "-iex",
            "set width 0",
            "-iex",
            "set height 0",
            "-ex",
            "set context-output /dev/null",
            "-ex",
            "set show-tips off",
            "-ex",
            f"set inferior-tty {self._pty_name}",
        ]

        spawn = self._executor.submit(lambda: _IsolatedGdbController(command=argv))
        wrapped = asyncio.wrap_future(spawn)
        try:
            controller = await asyncio.shield(wrapped)
        except asyncio.CancelledError as e:
            try:
                controller = await asyncio.wait_for(
                    asyncio.shield(wrapped),
                    timeout=min(max(self.timeout, 0.0), 1.0) + 0.1,
                )
            except (TimeoutError, FutTimeout):
                def reap_late_spawn(done: Any) -> None:
                    try:
                        self._terminate_controller(done.result())
                    except BaseException:
                        pass

                spawn.add_done_callback(reap_late_spawn)
            except Exception:
                pass
            else:
                self._controller = controller
            self._cleanup_failed_start(e)
            raise
        self._controller = controller
        self.state = GdbState.NOT_LOADED
        startup = await self._run_command_owned("-gdb-show mi-async")
        if startup.error or startup.result_class != "done":
            detail = startup.error or (
                f"unexpected result class {startup.result_class!r}"
            )
            raise GdbCrashed(
                f"GDB startup synchronization failed: {detail}; "
                "call mcp_hard_reset to retry"
            )
        self._started_at = time.monotonic()
        logger.info("gdb started: pty=%s pid=%s", self._pty_name, self._controller.gdb_process.pid)

    @staticmethod
    def _terminate_controller(controller: Any) -> None:
        process = getattr(controller, "gdb_process", None)
        if process is not None:
            try:
                process.terminate()
                process.wait(timeout=2)
            except Exception:
                try:
                    process.kill()
                    process.wait(timeout=2)
                except Exception:
                    pass

    def _cleanup_failed_start(self, error: BaseException) -> None:
        self._terminate_controller(self._controller)
        self._controller = None
        self._close_pty()
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
        self._started_at = 0.0
        self._decompiler_connected = False
        self._loaded_path = None
        self._last_stop_reason = None
        self.state = GdbState.ERROR
        detail = "cancelled" if isinstance(error, asyncio.CancelledError) else (
            f"{type(error).__name__}: {error}"
        )
        self._last_error = f"GDB startup failed ({detail}); call mcp_hard_reset to retry"

    async def close(self) -> None:
        async with self.mi_transaction():
            await self._close_owned()

    async def _close_owned(self) -> None:
        controller = self._controller
        process = getattr(controller, "gdb_process", None)
        try:
            if controller:
                await self._exec_blocking(
                    controller.exit,
                    timeout=2.0,
                    operation="GDB shutdown",
                )
        except Exception:
            pass
        finally:
            if process:
                try:
                    process.terminate()
                    process.wait(timeout=2)
                except Exception:
                    try:
                        process.kill()
                        process.wait(timeout=2)
                    except Exception:
                        pass
            self._controller = None
            self._close_pty()
            try:
                self._executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
            self.state = GdbState.NOT_LOADED

    def _close_pty(self) -> None:
        self._pty_generation = getattr(self, "_pty_generation", 0) + 1
        stash = getattr(self, "_pty_read_stash", None)
        if stash is not None:
            stash.clear()
        self._pty_read_stash_generation = self._pty_generation
        for fd in (self._pty_master, self._pty_slave):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self._pty_master = None
        self._pty_slave = None
        self._pty_name = None
        self._pty_attrs = None
        self._poller = None


    async def _exec_blocking(
        self,
        fn: Any,
        timeout: float | None = None,
        *,
        operation: str = "GDB MI operation",
    ) -> Any:
        loop = asyncio.get_running_loop()
        fut = loop.run_in_executor(self._executor, fn)

        def consume_exception(done: asyncio.Future[Any]) -> None:
            if not done.cancelled():
                done.exception()

        fut.add_done_callback(consume_exception)
        grace = 0.1
        try:
            if timeout is None:
                return await asyncio.shield(fut)
            return await asyncio.wait_for(
                asyncio.shield(fut),
                timeout=max(timeout, 0.0) + grace,
            )
        except asyncio.CancelledError:
            try:
                if timeout is None:
                    await asyncio.shield(fut)
                else:
                    await asyncio.wait_for(
                        asyncio.shield(fut),
                        timeout=max(timeout, 0.0) + grace,
                    )
            except BaseException:
                pass
            self._poison_mi(f"{operation} cancelled with executor work in flight")
            raise
        except (TimeoutError, FutTimeout):
            self._poison_mi(f"{operation} exceeded its bounded executor wait")
            raise

    async def run_command(self, cmd: str, timeout: float | None = None) -> GdbResponse:
        async with self.mi_transaction():
            return await self._run_command_owned(cmd, timeout)

    async def _run_command_owned(
        self,
        cmd: str,
        timeout: float | None = None,
        *,
        terminal_states: set[GdbState] | None = None,
        poison_timeout: bool = True,
    ) -> GdbResponse:
        """Send a CLI/MI command, return flattened response. State machine updates included

        Reads GDB's stdout in a loop until we see a ``^done`` / ``^error`` /
        ``^running`` result class for this command. Doing so closes the pygdbmi
        read race: pygdbmi shrinks its read deadline to 200 ms after the first
        chunk of output (``time_to_check_for_additional_output_sec`` in
        ``IoManager``), and pwndbg's slow commands routinely pause longer than
        that mid-output (ROPgadget scanning between binaries, source-info
        downloads, multiprocessing forks, etc.). Without this loop the response
        is split across our ``write()`` and the next caller's ``write()``, so the
        next tool receives the prior command's tail
        """
        cmd = _safe_gdb_arg(cmd, field="GDB command")
        if self._controller is None:
            return GdbResponse(error="controller not started")
        if self.state == GdbState.RUNNING and cmd.strip() != "-exec-interrupt":
            await self.refresh_state()
        if self.state == GdbState.ERROR:
            error = self._last_error or "GDB MI controller is in an error state"
            if "mcp_hard_reset" not in error:
                error += "; call mcp_hard_reset to recover"
            raise InferiorStateError(error)
        if self.state == GdbState.RUNNING and cmd.strip() != "-exec-interrupt":
            raise InferiorStateError(
                "GDB CLI is unavailable while the inferior is RUNNING. "
                "Call interrupt_process, wait for a stop, then retry."
            )
        controller = self._controller
        t = timeout if timeout is not None else self.timeout
        deadline = time.monotonic() + t
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            self._last_error = f"timeout after {t}s before GDB command dispatch"
            return GdbResponse(error=f"timeout after {t}s waiting for command dispatch")

        # own read loop, pygdbmi's single-shot read drops trailing records
        try:
            await self._exec_blocking(
                lambda: controller.write(
                    cmd,
                    timeout_sec=0,
                    raise_error_on_timeout=False,
                    read_response=False,
                ),
                timeout=min(5.0, remaining),
                operation="GDB MI command write",
            )
        except (TimeoutError, FutTimeout):
            return GdbResponse(
                error=self._last_error
                or "GDB MI command write timed out; call mcp_hard_reset to recover"
            )
        except (BrokenPipeError, EOFError, OSError) as e:
            logger.error("gdb pipe broken on write: %s", e)
            return GdbResponse(error=self._poison_mi(f"gdb pipe broken on write: {e}"))
        except Exception as e:
            logger.error("unexpected GDB MI write error (%s)", type(e).__name__)
            return GdbResponse(error=self._poison_mi("unexpected GDB MI write error"))

        # read until a result class arrives or the caller's budget expires
        raw: list[dict[str, Any]] = []
        saw_result = False
        saw_terminal_state = False
        cleanup_deadline: float | None = None
        while not saw_result:
            active_deadline = cleanup_deadline if cleanup_deadline is not None else deadline
            remaining = active_deadline - time.monotonic()
            if remaining <= 0:
                break
            slice_ = min(remaining, 1.0)
            try:
                chunk = await self._exec_blocking(
                    lambda s=slice_: controller.get_gdb_response(
                        timeout_sec=s, raise_error_on_timeout=False
                    ),
                    timeout=slice_,
                    operation="GDB MI response read",
                )
            except (TimeoutError, FutTimeout):
                if self.state == GdbState.ERROR:
                    resp = _bucket(raw)
                    resp.error = self._last_error
                    return resp
                chunk = []
            except (BrokenPipeError, EOFError, OSError) as e:
                logger.error("gdb pipe broken on read: %s", e)
                resp = _bucket(raw)
                resp.error = self._poison_mi(f"gdb pipe broken on read: {e}")
                return resp
            except Exception as e:
                logger.error("unexpected GDB MI read error (%s)", type(e).__name__)
                resp = _bucket(raw)
                resp.error = self._poison_mi("unexpected GDB MI read error")
                return resp

            if chunk:
                raw.extend(chunk)
                self._apply_response_state(_bucket(chunk))
                saw_terminal_state = bool(
                    terminal_states and self.state in terminal_states
                )
                if saw_terminal_state and cleanup_deadline is None:
                    cleanup_deadline = time.monotonic() + 0.1
                for msg in chunk:
                    if msg.get("type") == "result":
                        saw_result = True
                        break

        if not saw_result:
            resp = _bucket(raw)
            self._apply_response_state(resp)
            if saw_terminal_state:
                error = self._poison_mi(
                    "GDB reached a terminal state without its command result record"
                )
            else:
                error = f"timeout after {t}s waiting for a GDB result record"
            if not saw_terminal_state and poison_timeout:
                error = self._poison_mi(error)
            elif not saw_terminal_state:
                self._last_error = error
            resp.error = error
            return resp

        resp = _bucket(raw)
        self._apply_response_state(resp)
        if resp.error is None:
            self._last_error = None
        return resp

    async def _drain_until_state(
        self,
        desired: set[GdbState],
        timeout: float,
    ) -> GdbResponse:
        async with self.mi_transaction():
            return await self._drain_until_state_owned(desired, timeout)

    async def _drain_until_state_owned(
        self,
        desired: set[GdbState],
        timeout: float,
    ) -> GdbResponse:
        """Drain async GDB notifications until the controller reaches a desired state"""
        if self._controller is None:
            return GdbResponse(error="controller not started")
        if self.state == GdbState.ERROR:
            return GdbResponse(
                error=self._last_error
                or "GDB MI controller is in an error state; call mcp_hard_reset to recover"
            )
        if self.state in desired:
            return GdbResponse(result_class="done")
        controller = self._controller

        deadline = time.monotonic() + timeout
        raw: list[dict[str, Any]] = []
        while self.state not in desired:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            slice_ = min(remaining, 0.25)
            try:
                chunk = await self._exec_blocking(
                    lambda s=slice_: controller.get_gdb_response(
                        timeout_sec=s,
                        raise_error_on_timeout=False,
                    ),
                    timeout=slice_,
                    operation="GDB MI state drain",
                )
            except (TimeoutError, FutTimeout):
                if self.state == GdbState.ERROR:
                    resp = _bucket(raw)
                    resp.error = self._last_error
                    return resp
                chunk = []
            except (BrokenPipeError, EOFError, OSError) as e:
                error = self._poison_mi(f"gdb pipe broken during state drain: {e}")
                resp = _bucket(raw)
                resp.error = error
                return resp
            except Exception as e:
                error = self._poison_mi(f"unexpected GDB MI state drain error: {e}")
                logger.error("unexpected GDB MI state drain error (%s)", type(e).__name__)
                resp = _bucket(raw)
                resp.error = error
                return resp

            if chunk:
                raw.extend(chunk)
                resp = _bucket(chunk)
                self._apply_response_state(resp)

        resp = _bucket(raw)
        if self.state in desired:
            resp.result_class = resp.result_class or "done"
            return resp

        self._last_error = (
            f"timeout after {timeout}s waiting for state "
            f"{', '.join(sorted(str(s) for s in desired))} (state={self.state})"
        )
        resp.error = self._last_error
        return resp

    async def drain_pending_output(
        self,
        timeout: float = 0.5,
        idle_timeout: float = 0.05,
    ) -> GdbResponse:
        async with self.mi_transaction():
            return await self._drain_pending_output_owned(timeout, idle_timeout)

    async def _drain_pending_output_owned(
        self,
        timeout: float = 0.5,
        idle_timeout: float = 0.05,
    ) -> GdbResponse:
        """Drain output that is already queued after a command result"""
        if self._controller is None:
            return GdbResponse(error="controller not started")
        if self.state == GdbState.ERROR:
            return GdbResponse(
                error=self._last_error
                or "GDB MI controller is in an error state; call mcp_hard_reset to recover"
            )
        controller = self._controller

        deadline = time.monotonic() + timeout
        raw: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            slice_ = min(idle_timeout, remaining)
            try:
                chunk = await self._exec_blocking(
                    lambda s=slice_: controller.get_gdb_response(
                        timeout_sec=s,
                        raise_error_on_timeout=False,
                    ),
                    timeout=slice_,
                    operation="GDB MI pending-output drain",
                )
            except (TimeoutError, FutTimeout):
                if self.state == GdbState.ERROR:
                    resp = _bucket(raw)
                    resp.error = self._last_error
                    return resp
                chunk = []
            except (BrokenPipeError, EOFError, OSError) as e:
                error = self._poison_mi(f"gdb pipe broken during output drain: {e}")
                resp = _bucket(raw)
                resp.error = error
                return resp
            except Exception as e:
                error = self._poison_mi(f"unexpected GDB MI output drain error: {e}")
                logger.error("unexpected GDB MI output drain error (%s)", type(e).__name__)
                resp = _bucket(raw)
                resp.error = error
                return resp

            if not chunk:
                break
            raw.extend(chunk)
            self._apply_response_state(_bucket(chunk))

        return _bucket(raw)

    async def run_command_and_drain(
        self,
        cmd: str,
        timeout: float | None = None,
        *,
        drain_timeout: float = 0.5,
        idle_timeout: float = 0.05,
    ) -> GdbResponse:
        """Run one command and collect its bounded late output without yielding MI ownership"""
        async with self.mi_transaction():
            response = await self.run_command(cmd, timeout=timeout)
            return await self.drain_after_result(
                response,
                timeout=drain_timeout,
                idle_timeout=idle_timeout,
            )

    async def refresh_state(self, timeout: float = 0.05) -> GdbResponse:
        """Consume already-queued async notifications before making a state decision"""
        async with self.mi_transaction():
            if self._controller is None or self.state == GdbState.ERROR:
                return GdbResponse(result_class="done")
            return await self._drain_pending_output_owned(
                timeout=timeout,
                idle_timeout=min(0.01, timeout),
            )

    async def drain_after_result(
        self,
        resp: GdbResponse,
        timeout: float = 0.5,
        idle_timeout: float = 0.05,
    ) -> GdbResponse:
        """Merge bounded late console output that arrives after a result record"""
        if self.state == GdbState.RUNNING or (resp.error and resp.result_class is None):
            return resp
        return _extend_response(
            resp,
            await self.drain_pending_output(timeout=timeout, idle_timeout=idle_timeout),
        )

    async def drain_until_stopped(self, timeout: float = 30.0) -> GdbResponse:
        """Drain async output until the inferior stops or exits"""
        return await self._drain_until_state(
            {GdbState.STOPPED, GdbState.EXITED},
            timeout=timeout,
        )

    async def interrupt_inferior(self, timeout: float = 3.0) -> GdbResponse:
        async with self.mi_transaction():
            return await self._interrupt_inferior_owned(timeout)

    async def _interrupt_inferior_owned(self, timeout: float = 3.0) -> GdbResponse:
        """Interrupt a running inferior and confirm GDB reaches STOPPED"""
        await self.refresh_state()
        if self.state == GdbState.STOPPED:
            return GdbResponse(result_class="done")
        if self.state != GdbState.RUNNING:
            return GdbResponse(
                error=(
                    f"cannot interrupt inferior while state={self.state}; "
                    "call mcp_hard_reset to recover"
                )
            )

        deadline = time.monotonic() + timeout

        async def finish_stopped(resp: GdbResponse) -> GdbResponse:
            has_result = any(message.get("type") == "result" for message in resp.raw)
            if not has_result:
                cleanup = await self._drain_pending_output_owned(
                    timeout=0.1,
                    idle_timeout=0.1,
                )
                _extend_response(resp, cleanup)
                has_result = any(
                    message.get("type") == "result" for message in resp.raw
                )
                if not has_result:
                    if cleanup.error:
                        resp.error = cleanup.error
                    else:
                        resp.error = self._poison_mi(
                            "GDB stopped after interrupt without its command result record"
                        )
                    return resp
            if resp.result_class == "error":
                resp.result_payload = None
            resp.result_class = "done"
            resp.error = None
            self._last_error = None
            remaining = max(0.0, deadline - time.monotonic())
            if remaining > 0:
                _extend_response(
                    resp,
                    await self.drain_pending_output(
                        timeout=remaining,
                        idle_timeout=min(0.05, remaining),
                    ),
                )
            return resp

        mi_resp = await self._run_command_owned(
            "-exec-interrupt",
            timeout=min(timeout, 2.0),
            terminal_states={GdbState.STOPPED, GdbState.EXITED},
            poison_timeout=False,
        )
        if self.state == GdbState.STOPPED:
            return await finish_stopped(mi_resp)
        if self.state == GdbState.EXITED:
            mi_resp.error = "inferior exited while interrupting; call mcp_hard_reset to recover"
            self._last_error = mi_resp.error
            return mi_resp

        remaining = max(0.0, deadline - time.monotonic())
        if not mi_resp.error and remaining > 0:
            wait_resp = await self._drain_until_state(
                {GdbState.STOPPED, GdbState.EXITED},
                timeout=remaining,
            )
            _extend_response(mi_resp, wait_resp)
            if self.state == GdbState.STOPPED:
                return await finish_stopped(mi_resp)
            if self.state == GdbState.EXITED:
                mi_resp.error = (
                    "inferior exited while interrupting; call mcp_hard_reset to recover"
                )
                self._last_error = mi_resp.error
                return mi_resp

        try:
            self.signal_gdb(signal.SIGINT)
        except GdbCrashed as e:
            detail = mi_resp.error or "inferior did not stop after -exec-interrupt"
            mi_resp.error = (
                f"{detail}; SIGINT fallback failed: {e}; call mcp_hard_reset to recover"
            )
            self.state = GdbState.ERROR
            self._last_error = mi_resp.error
            return mi_resp

        remaining = max(0.0, deadline - time.monotonic())
        if remaining <= 0:
            mi_resp.error = (
                f"timeout after {timeout}s interrupting inferior (state={self.state}); "
                "call mcp_hard_reset to recover"
            )
            self.state = GdbState.ERROR
            self._last_error = mi_resp.error
            return mi_resp

        fallback_resp = await self._drain_until_state(
            {GdbState.STOPPED, GdbState.EXITED},
            timeout=remaining,
        )
        _extend_response(mi_resp, fallback_resp)
        if self.state == GdbState.STOPPED:
            return await finish_stopped(mi_resp)
        if self.state == GdbState.EXITED:
            mi_resp.error = (
                "inferior exited while interrupting; call mcp_hard_reset to recover"
            )
        elif mi_resp.error:
            if "mcp_hard_reset" not in mi_resp.error:
                mi_resp.error += "; call mcp_hard_reset to recover"
        else:
            mi_resp.error = (
                f"inferior did not stop after interrupt (state={self.state}); "
                "call mcp_hard_reset to recover"
            )
        if self.state not in {GdbState.STOPPED, GdbState.EXITED}:
            self.state = GdbState.ERROR
        self._last_error = mi_resp.error
        return mi_resp

    async def run_python(self, py: str, timeout: float = 10.0) -> GdbResponse:
        """Execute python inside GDB, failing fast while the inferior runs"""
        if self.state == GdbState.RUNNING:
            raise InferiorStateError(
                "pi requires gdb's CLI dispatcher free, but the inferior is "
                "RUNNING. Send interrupt_process (or wait for a breakpoint), "
                "then retry."
            )
        if "\0" in py:
            raise InvalidArgument("Python source must not contain NUL")
        if "\n" in py or "\r" in py:
            cmd = f"pi exec({json.dumps(py, ensure_ascii=False)})"
        else:
            cmd = f"pi {py}"
        return await self.run_command(cmd, timeout=timeout)

    async def pi_query(self, py_expr: str, timeout: float = 10.0) -> Any:
        """Execute python in GDB and decode the sentinel JSON payload"""
        # prelude defines sentinel emitters before optional aglib imports
        prelude_head = (
            "import json\n"
            "import sys\n"
            "import traceback\n"
            # json.dumps stays one-line because no indent is passed
            "def mcp_emit(_obj):\n"
            f"    sys.stdout.write({_MCP_JSON_OPEN!r} + json.dumps(_obj) + {_MCP_END!r} + '\\n')\n"
            "    sys.stdout.flush()\n"
            "def _mcp_emit_error(_exc):\n"
            "    _payload = {\n"
            "        'type': type(_exc).__name__,\n"
            "        'message': str(_exc),\n"
            "        'traceback': ''.join(traceback.format_exception(type(_exc), _exc, _exc.__traceback__))[-2000:],\n"
            "    }\n"
            f"    sys.stdout.write({_MCP_ERROR_OPEN!r} + json.dumps(_payload) + {_MCP_END!r} + '\\n')\n"
            "    sys.stdout.flush()\n"
            "try:\n"
            "    import pwndbg\n"
            "    for _m in ('aglib','aglib.regs','aglib.vmmap','aglib.heap','aglib.memory',"
            "'aglib.proc','aglib.stack','aglib.disasm','aglib.symbol','aglib.elf'):\n"
            "        try:\n"
            "            __import__('pwndbg.' + _m)\n"
            "        except Exception:\n"
            "            pass\n"
            "    try:\n"
            "        import pwndbg.chain\n"
            "    except Exception:\n"
            "        pass\n"
        )
        # indent caller code into the prelude's try block
        indented = "\n".join("    " + ln for ln in py_expr.splitlines())
        prelude_tail = "\nexcept BaseException as _exc:\n    _mcp_emit_error(_exc)\n"
        full = prelude_head + indented + prelude_tail
        resp = await self.run_python(f"exec({full!r}, {{}})", timeout)
        if not resp.ok:
            # gdb can convert memory errors to ^error before python catches them
            cls = _classify_gdb_error(resp.error or "")
            raise cls(resp.error or "pi query failed")

        return _parse_pi_result(resp)


    async def write_process(self, data: bytes, timeout: float = 30.0) -> int:
        if not isinstance(data, bytes):
            raise InvalidArgument("inferior PTY payload must be bytes")
        if len(data) > _MAX_PTY_PAYLOAD:
            raise InvalidArgument(
                f"inferior PTY payload must be at most {_MAX_PTY_PAYLOAD} bytes"
            )
        timeout = _validate_pty_timeout(
            timeout,
            field="PTY write timeout",
            maximum=_MAX_PTY_WRITE_TIMEOUT,
            allow_zero=False,
        )
        self._require_live_pty_state("write to the inferior PTY")
        master = self._pty_master
        if master is None:
            raise GdbCrashed("PTY not allocated; call mcp_hard_reset to recover")
        generation = getattr(self, "_pty_generation", 0)
        deadline = time.monotonic() + timeout
        written = 0
        payload = memoryview(data)
        try:
            async with self._pty_mutation_transaction(deadline):
                self._assert_pty_current(master, generation)
                self._require_live_pty_state("write to the inferior PTY")
                while written < len(data):
                    self._assert_pty_current(master, generation)
                    self._require_live_pty_state("write to the inferior PTY")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise GdbCrashed(
                            self._poison_pty(
                                f"inferior PTY write timed out after {timeout:g}s "
                                f"({written}/{len(data)} bytes written)"
                            )
                        )
                    try:
                        count = os.write(master, payload[written:])
                    except InterruptedError:
                        await asyncio.sleep(0)
                        continue
                    except BlockingIOError:
                        count = None
                    except OSError as e:
                        self._assert_pty_current(master, generation)
                        raise GdbCrashed(
                            self._poison_pty(f"inferior PTY write failed: {e}")
                        ) from e

                    if count is not None:
                        if count <= 0:
                            raise GdbCrashed(
                                self._poison_pty(
                                    "inferior PTY write returned no progress"
                                )
                            )
                        written += count
                        if written < len(data):
                            await asyncio.sleep(0)
                        continue

                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise GdbCrashed(
                            self._poison_pty(
                                f"inferior PTY write timed out after {timeout:g}s "
                                f"({written}/{len(data)} bytes written)"
                            )
                        )
                    await asyncio.sleep(min(_PTY_POLL_INTERVAL, remaining))
                return written
        except _OwnershipTimeout as e:
            self._assert_pty_current(master, generation)
            raise TimeoutExceeded(
                f"inferior PTY write timed out after {timeout:g}s waiting for "
                "mutation ownership; no bytes were written, retry"
            ) from e
        except asyncio.CancelledError:
            if written:
                try:
                    self._assert_pty_current(master, generation)
                except GdbCrashed:
                    pass
                else:
                    self._poison_pty(
                        "inferior PTY write cancelled after a partial payload "
                        f"({written}/{len(data)} bytes written)"
                    )
            raise

    async def read_process(
        self,
        size: int = 4096,
        timeout: float = 5.0,
        quiet_timeout: float = 0.05,
    ) -> bytes:
        try:
            parsed_size = int(size)
            numeric_size = float(size)
        except (TypeError, ValueError, OverflowError) as e:
            raise InvalidArgument(f"invalid PTY read size {size!r}") from e
        if (
            isinstance(size, bool)
            or not math.isfinite(numeric_size)
            or numeric_size != parsed_size
            or not 1 <= parsed_size <= _MAX_PTY_PAYLOAD
        ):
            raise InvalidArgument(
                f"PTY read size must be in 1..{_MAX_PTY_PAYLOAD} (got {size!r})"
            )
        timeout = _validate_pty_timeout(
            timeout,
            field="PTY read timeout",
            maximum=_MAX_PTY_READ_TIMEOUT,
            allow_zero=True,
        )
        quiet_timeout = _validate_pty_timeout(
            quiet_timeout,
            field="PTY read quiet timeout",
            maximum=_MAX_PTY_READ_TIMEOUT,
            allow_zero=True,
        )
        master = self._pty_master
        poller = self._poller
        if master is None or poller is None:
            raise GdbCrashed("PTY not allocated; call mcp_hard_reset to recover")
        generation = getattr(self, "_pty_generation", 0)
        deadline = time.monotonic() + timeout
        async with self._pty_read_transaction(deadline) as acquired:
            self._assert_pty_current(master, generation, poller)
            if not acquired:
                return b""
            out = bytearray()
            stash = getattr(self, "_pty_read_stash", None)
            stash_generation = getattr(self, "_pty_read_stash_generation", generation)
            if stash_generation != generation:
                stash = self._pty_read_stash = bytearray()
                self._pty_read_stash_generation = generation
            elif stash:
                take = min(parsed_size, len(stash))
                out.extend(stash[:take])
                del stash[:take]
            quiet_deadline = (
                min(deadline, time.monotonic() + quiet_timeout) if out else None
            )
            try:
                while len(out) < parsed_size:
                    self._assert_pty_current(master, generation, poller)
                    try:
                        events = poller.poll(0)
                    except InterruptedError:
                        events = []
                    except OSError as e:
                        self._assert_pty_current(master, generation, poller)
                        raise GdbCrashed(
                            self._poison_pty(f"inferior PTY poll failed: {e}")
                        ) from e

                    got_data = False
                    saw_hup = False
                    for event_fd, event in events:
                        self._assert_pty_current(master, generation, poller)
                        if event_fd != master or event & select.POLLNVAL:
                            raise GdbCrashed(
                                self._poison_pty("inferior PTY disconnected")
                            )
                        if event & (select.POLLIN | select.POLLHUP):
                            saw_hup = bool(event & select.POLLHUP)
                            try:
                                chunk = os.read(
                                    master, min(4095, parsed_size - len(out))
                                )
                            except InterruptedError:
                                chunk = b""
                            except BlockingIOError:
                                chunk = b""
                            except OSError as e:
                                if e.errno == errno.EIO:
                                    return bytes(out)
                                self._assert_pty_current(master, generation, poller)
                                raise GdbCrashed(
                                    self._poison_pty(
                                        f"inferior PTY read failed: {e}"
                                    )
                                ) from e
                            if chunk:
                                out.extend(chunk)
                                got_data = True
                        if event & select.POLLERR:
                            if out:
                                return bytes(out)
                            raise GdbCrashed(
                                self._poison_pty("inferior PTY disconnected")
                            )

                    if saw_hup:
                        return bytes(out)
                    if got_data:
                        quiet_deadline = min(
                            deadline, time.monotonic() + quiet_timeout
                        )
                        if len(out) < parsed_size:
                            await asyncio.sleep(0)
                        continue

                    active_deadline = quiet_deadline if out else deadline
                    remaining = active_deadline - time.monotonic()
                    if remaining <= 0:
                        return bytes(out)
                    await asyncio.sleep(min(_PTY_POLL_INTERVAL, remaining))
                return bytes(out)
            except asyncio.CancelledError:
                if out:
                    try:
                        self._assert_pty_current(master, generation, poller)
                    except GdbCrashed:
                        pass
                    else:
                        stash = getattr(self, "_pty_read_stash", None)
                        if (
                            stash is None
                            or getattr(
                                self, "_pty_read_stash_generation", generation
                            )
                            != generation
                        ):
                            stash = self._pty_read_stash = bytearray()
                            self._pty_read_stash_generation = generation
                        stash[:0] = out
                raise

    async def drain_process_output(
        self,
        size: int = 1 << 20,
        timeout: float = 0.0,
        quiet_timeout: float = 0.02,
    ) -> bytes:
        """Discard already-buffered inferior PTY output"""
        return await self.read_process(
            size=size,
            timeout=timeout,
            quiet_timeout=quiet_timeout,
        )

    async def send_signal_to_process(
        self, ch: bytes, timeout: float = 3.0
    ) -> None:
        """Briefly switch PTY out of raw mode so signal chars (Ctrl-C/D/Z) are recognized"""
        if not isinstance(ch, bytes) or len(ch) != 1:
            raise InvalidArgument("inferior PTY signal must be exactly one byte")
        timeout = _validate_pty_timeout(
            timeout,
            field="PTY signal timeout",
            maximum=_MAX_PTY_WRITE_TIMEOUT,
            allow_zero=False,
        )
        self._require_live_pty_state("send a signal to the inferior PTY")
        master = self._pty_master
        slave = self._pty_slave
        if master is None or slave is None or self._pty_attrs is None:
            raise GdbCrashed("PTY not allocated; call mcp_hard_reset to recover")
        generation = getattr(self, "_pty_generation", 0)
        deadline = time.monotonic() + timeout

        try:
            async with self._pty_mutation_transaction(deadline):
                self._assert_pty_current(master, generation)
                if self._pty_slave != slave:
                    raise GdbCrashed(
                        "inferior PTY changed during I/O; retry against current debugger state"
                    )
                self._require_live_pty_state("send a signal to the inferior PTY")
                try:
                    saved = termios.tcgetattr(slave)
                except OSError as e:
                    self._assert_pty_current(master, generation)
                    raise GdbCrashed(
                        self._poison_pty(f"inferior PTY signal setup failed: {e}")
                    ) from e

                if deadline - time.monotonic() <= 0:
                    raise _OwnershipTimeout
                try:
                    attrs = list(saved)
                    attrs[3] = int(attrs[3]) | termios.ISIG | termios.ICANON
                    termios.tcsetattr(slave, termios.TCSANOW, attrs)
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise GdbCrashed(
                            self._poison_pty(
                                "inferior PTY signal timed out after changing terminal mode"
                            )
                        )
                    await self.write_process(
                        ch, timeout=min(remaining, _MAX_PTY_WRITE_TIMEOUT)
                    )
                    self._assert_pty_current(master, generation)
                    remaining = deadline - time.monotonic()
                    if remaining < _PTY_CONTROL_DELIVERY_DELAY:
                        raise GdbCrashed(
                            self._poison_pty(
                                "inferior PTY signal timed out during delivery"
                            )
                        )
                    await asyncio.sleep(_PTY_CONTROL_DELIVERY_DELAY)
                    self._assert_pty_current(master, generation)
                except OSError as e:
                    self._assert_pty_current(master, generation)
                    raise GdbCrashed(
                        self._poison_pty(f"inferior PTY signal failed: {e}")
                    ) from e
                finally:
                    if (
                        getattr(self, "_pty_generation", 0) == generation
                        and self._pty_master == master
                        and self._pty_slave == slave
                    ):
                        try:
                            termios.tcsetattr(slave, termios.TCSANOW, saved)
                        except OSError as e:
                            raise GdbCrashed(
                                self._poison_pty(f"inferior PTY restore failed: {e}")
                            ) from e
        except _OwnershipTimeout as e:
            self._assert_pty_current(master, generation)
            raise TimeoutExceeded(
                f"inferior PTY signal timed out after {timeout:g}s waiting for "
                "mutation ownership; no bytes were written, retry"
            ) from e

    async def send_eof_to_process(self, timeout: float = 3.0) -> None:
        timeout = _validate_pty_timeout(
            timeout,
            field="PTY EOF timeout",
            maximum=_MAX_PTY_WRITE_TIMEOUT,
            allow_zero=False,
        )
        self._require_live_pty_state("send EOF")
        master = self._pty_master
        slave = self._pty_slave
        if master is None or slave is None or self._pty_attrs is None:
            raise GdbCrashed("PTY not allocated; call mcp_hard_reset to recover")
        generation = getattr(self, "_pty_generation", 0)
        deadline = time.monotonic() + timeout
        try:
            async with self.mi_transaction(deadline):
                self._assert_pty_current(master, generation)
                if self._pty_slave != slave:
                    raise GdbCrashed(
                        "inferior PTY changed during I/O; retry against current debugger state"
                    )
                async with self._pty_mutation_transaction(deadline):
                    self._assert_pty_current(master, generation)
                    if self._pty_slave != slave:
                        raise GdbCrashed(
                            "inferior PTY changed during I/O; retry against current debugger state"
                        )
                    self._require_live_pty_state("send EOF")
                    await self._send_eof_to_process_owned(
                        deadline, master, slave, generation
                    )
        except _OwnershipTimeout as e:
            self._assert_pty_current(master, generation)
            raise TimeoutExceeded(
                f"inferior PTY EOF timed out after {timeout:g}s waiting for "
                "debugger or mutation ownership; no bytes were written, retry"
            ) from e

    async def _send_eof_to_process_owned(
        self,
        deadline: float,
        master: int,
        slave: int,
        generation: int,
    ) -> None:
        """Restart a pending raw read in canonical mode, then send VEOF"""
        self._assert_pty_current(master, generation)
        if self._pty_slave != slave:
            raise GdbCrashed(
                "inferior PTY changed during I/O; retry against current debugger state"
        )
        self._require_live_pty_state("send EOF")
        if self.state == GdbState.RUNNING:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _OwnershipTimeout
            stopped = await self.interrupt_inferior(
                timeout=remaining
            )
            self._assert_pty_current(master, generation)
            if stopped.error or self.state != GdbState.STOPPED:
                detail = stopped.error or f"inferior did not stop (state={self.state})"
                error = f"could not stop inferior for EOF: {detail}; call mcp_hard_reset to recover"
                self._last_error = error
                raise GdbCrashed(error)

        if deadline - time.monotonic() <= 0:
            raise _OwnershipTimeout
        try:
            self._assert_pty_current(master, generation)
            saved = termios.tcgetattr(slave)
        except OSError as e:
            raise GdbCrashed(
                self._poison_pty(f"inferior PTY EOF setup failed: {e}")
            ) from e

        try:
            canonical = list(saved)
            canonical[6] = list(saved[6])
            canonical[3] = int(canonical[3]) | termios.ISIG | termios.ICANON
            canonical[6][termios.VEOF] = b"\x04"
            termios.tcsetattr(slave, termios.TCSANOW, canonical)

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                error = self._poison_pty("timeout preparing inferior EOF")
                raise GdbCrashed(error)
            continued = await self.run_command("continue", timeout=remaining)
            self._assert_pty_current(master, generation)
            continue_succeeded = (
                continued.error is None
                and continued.result_class == "running"
                and self.state == GdbState.RUNNING
            )
            if not continue_succeeded:
                detail = continued.error or (
                    f"unexpected result={continued.result_class!r} (state={self.state})"
                )
                error = f"inferior continue for EOF failed: {detail}; call mcp_hard_reset to recover"
                definite_rejection = (
                    continued.result_class == "error" and self.state == GdbState.STOPPED
                )
                if not definite_rejection:
                    self.state = GdbState.ERROR
                self._last_error = error
                raise GdbCrashed(error)

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GdbCrashed(self._poison_pty("timeout sending inferior EOF"))
            await self.write_process(
                b"\x04", timeout=min(remaining, _MAX_PTY_WRITE_TIMEOUT)
            )
            self._assert_pty_current(master, generation)
            remaining = deadline - time.monotonic()
            if remaining < _PTY_CONTROL_DELIVERY_DELAY:
                raise GdbCrashed(
                    self._poison_pty("timeout delivering inferior EOF")
                )
            await asyncio.sleep(_PTY_CONTROL_DELIVERY_DELAY)
            self._assert_pty_current(master, generation)
        except OSError as e:
            raise GdbCrashed(
                self._poison_pty(f"inferior PTY EOF setup failed: {e}")
            ) from e
        finally:
            if (
                getattr(self, "_pty_generation", 0) == generation
                and self._pty_master == master
                and self._pty_slave == slave
            ):
                try:
                    termios.tcsetattr(slave, termios.TCSANOW, saved)
                except OSError as e:
                    raise GdbCrashed(
                        self._poison_pty(f"inferior PTY restore failed: {e}")
                    ) from e


    async def load_executable(self, path: str, args: list[str] | None = None) -> GdbResponse:
        async with self.mi_transaction():
            return await self._load_executable_owned(path, args)

    async def _load_executable_owned(
        self, path: str, args: list[str] | None = None
    ) -> GdbResponse:
        quoted_path = _quote_gdb_string(path, field="executable path")
        quoted_args = [
            _quote_gdb_string(arg, field="executable argument") for arg in (args or [])
        ]
        if not os.path.isfile(path):
            return GdbResponse(error=f"file not found: {path}")

        response = await self.run_command(
            f"-file-exec-and-symbols {quoted_path}", timeout=15.0
        )
        if response.result_class != "done" or response.error:
            if response.result_class != "error" and self.state != GdbState.ERROR:
                response.error = self._poison_mi(
                    "executable load result is indeterminate"
                )
            return response

        self.state = GdbState.LOADED
        self._loaded_path = path
        args_command = "-exec-arguments"
        if quoted_args:
            args_command += f" {' '.join(quoted_args)}"
        args_response = await self.run_command(
            args_command
        )
        if args_response.result_class == "done" and not args_response.error:
            return response

        if args_response.result_class == "error" and self.state != GdbState.ERROR:
            detail = args_response.error or args_response.text or "GDB rejected the arguments"
            args_response.error = (
                f"failed to set executable arguments: {detail}; executable remains loaded; "
                "correct the arguments and retry"
            )
            self._last_error = args_response.error
            return args_response

        if self.state != GdbState.ERROR:
            error = self._poison_mi("executable argument setup is indeterminate")
        else:
            error = self._last_error or args_response.error or (
                "executable argument setup is indeterminate; "
                "call mcp_hard_reset to recover"
            )
            if "mcp_hard_reset" not in error:
                error += "; call mcp_hard_reset to recover"
            self._last_error = error
        args_response.error = error
        return args_response

    async def attach(self, target: str | int) -> AttachResult:
        async with self.mi_transaction():
            return await self._attach_owned(target)

    async def _attach_owned(self, target: str | int) -> AttachResult:
        previous_state = self.state
        value = str(target).strip()
        if not value:
            raise InvalidArgument("attach target cannot be empty")
        if self.state in {GdbState.RUNNING, GdbState.STOPPED, GdbState.ERROR}:
            raise InferiorStateError(
                f"cannot attach while state={self.state}; kill/detach the current inferior "
                "or call mcp_hard_reset first"
            )

        try:
            pid = int(value, 0)
        except ValueError:
            name = _quote_gdb_string(value, field="attach target")
            response = await self.run_command_and_drain(
                f"attachp {name}",
                timeout=15.0,
                drain_timeout=1.0,
            )
        else:
            if pid <= 0:
                raise InvalidArgument(f"attach PID must be positive (got {pid})")
            response = await self.run_command_and_drain(
                f"-target-attach {pid}",
                timeout=15.0,
                drain_timeout=1.0,
            )
        if response.error or response.result_class != "done":
            detail = response.error or response.text or "no GDB result"
            if response.result_class == "error" and self.state == previous_state:
                failure = (
                    f"attach to {value!r} failed: {detail}; verify the process exists "
                    "and ptrace_scope permits attachment"
                )
            else:
                failure = (
                    f"attach to {value!r} is indeterminate: {detail}; "
                    "call mcp_hard_reset before retrying"
                )
                if self.state != GdbState.ERROR:
                    self.state = GdbState.ERROR
            self._last_error = failure
            raise PwndbgError(failure)

        try:
            info = await self.pi_query(
                "mcp_emit({"
                "'alive': bool(pwndbg.aglib.proc.alive()),"
                "'pid': pwndbg.aglib.proc.pid() if pwndbg.aglib.proc.alive() else None,"
                "'executable': pwndbg.aglib.proc.exe() if pwndbg.aglib.proc.alive() else None,"
                "'architecture': str(pwndbg.aglib.arch.name) if pwndbg.aglib.arch else None"
                "})",
                timeout=5.0,
            )
        except Exception as e:
            failure = (
                f"attach to {value!r} could not verify target metadata: {e}; "
                "call mcp_hard_reset before retrying"
            )
            self.state = GdbState.ERROR
            self._last_error = failure
            raise PwndbgError(failure) from e

        if not info.get("alive") or info.get("pid") is None:
            failure = (
                f"attach to {value!r} produced no live inferior; check ptrace_scope, "
                "process-name resolution, and target lifetime, then call mcp_hard_reset"
            )
            self.state = GdbState.ERROR
            self._last_error = failure
            raise PwndbgError(failure)

        self.state = GdbState.STOPPED
        self._loaded_path = info.get("executable")
        return {
            "requested_target": value,
            "pid": int(info["pid"]),
            "state": str(self.state),
            "executable": info.get("executable"),
            "architecture": info.get("architecture"),
        }


    def status(self) -> dict[str, Any]:
        return {
            "state": str(self.state),
            "uptime_s": (time.monotonic() - self._started_at) if self._started_at else 0.0,
            "gdb_pid": self._controller.gdb_process.pid if self._controller else None,
            "last_error": self._last_error,
            "last_stop_reason": self._last_stop_reason,
            "executable": self._loaded_path,
            "decompiler_connected": self._decompiler_connected,
            "pty": self._pty_name,
        }


    def signal_gdb(self, sig: int) -> None:
        """Send a posix signal directly to the isolated GDB process"""
        if not self._controller or not self._controller.gdb_process:
            raise GdbCrashed("gdb not running")
        try:
            os.kill(self._controller.gdb_process.pid, sig)
        except (ProcessLookupError, PermissionError) as e:
            raise GdbCrashed(f"could not signal gdb: {e}") from e


    async def hard_reset(self) -> GdbResponse:
        async with self.mi_transaction():
            return await self._hard_reset_owned()

    async def _hard_reset_owned(self) -> GdbResponse:
        """Terminate GDB and respawn with the same args"""
        logger.warning("hard_reset (state was %s)", self.state)

        # terminate gdb directly, its isolated session keeps this server alive
        try:
            if self._controller and self._controller.gdb_process:
                self._controller.gdb_process.terminate()
        except (ProcessLookupError, PermissionError, OSError):
            pass

        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

        self._close_pty()

        if self._controller:
            try:
                self._controller.gdb_process.kill()
                self._controller.gdb_process.wait(timeout=2)
            except Exception:
                pass

        self._controller = None
        self.state = GdbState.NOT_LOADED
        self._last_error = None
        self._last_stop_reason = None
        self._loaded_path = None
        self._decompiler_connected = False
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="gdb-mi")
        await self.start()
        return GdbResponse(result_class="done")


# module-level singleton, initialized by the server entrypoint

_controller: AsyncGdbController | None = None


def set_controller(ctrl: AsyncGdbController) -> None:
    global _controller
    _controller = ctrl


async def get_controller() -> AsyncGdbController:
    global _controller
    if _controller is None:
        # lazy default for dev runs where bootstrap did not execute
        _controller = AsyncGdbController(gdb_path="gdb")
        await _controller.start()
    elif (
        _controller._controller is None
        and _controller.state == GdbState.NOT_LOADED
    ):
        await _controller.start()
    return _controller
