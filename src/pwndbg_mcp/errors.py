"""Error hierarchy and state guards"""

from __future__ import annotations

import functools
from collections.abc import AsyncIterator
from collections.abc import Awaitable
from collections.abc import Callable
from contextlib import asynccontextmanager
from typing import Any


class PwndbgError(Exception):
    """Base error returned to MCP clients as JSON"""

    code: str = "PWNDBG_ERROR"

    def __init__(self, message: str = "") -> None:
        super().__init__(message)
        self.message = message


class NotRunning(PwndbgError):
    code = "NOT_RUNNING"


class BinaryNotLoaded(PwndbgError):
    code = "NO_BINARY"


class PwndbgNotLoaded(PwndbgError):
    """GDB is running without pwndbg sourced"""

    code = "NO_PWNDBG"


class InferiorStateError(PwndbgError):
    """The queried inferior domain is not available right now"""

    code = "INFERIOR_STATE"


class GdbCrashed(PwndbgError):
    code = "GDB_CRASHED"


class ParseError(PwndbgError):
    code = "PARSE_ERROR"


class TimeoutExceeded(PwndbgError):
    code = "TIMEOUT"


class KernelOnly(PwndbgError):
    code = "KERNEL_ONLY"


class InvalidArgument(PwndbgError):
    code = "INVALID_ARGUMENT"


class MissingDependency(PwndbgError):
    code = "MISSING_DEPENDENCY"


class RemoteConnectionError(PwndbgError):
    code = "REMOTE_CONNECTION"


class EvalError(PwndbgError):
    """Python ``eval()`` failed inside an escape-hatch tool"""

    code = "EVAL_ERROR"

    def __init__(
        self,
        original_type: str,
        original_message: str,
        message: str = "",
    ) -> None:
        super().__init__(message or f"{original_type}: {original_message}")
        self.original_type = original_type
        self.original_message = original_message


def _require_gdb_success(response: Any, operation: str) -> None:
    if response.ok:
        return
    detail = response.error or response.text or "unknown GDB error"
    if len(detail) > 4096:
        detail = detail[:4096] + "..."
    raise PwndbgError(
        f"{operation} failed: {detail}; call mcp_hard_reset if GDB no longer responds, "
        "then retry"
    )


@asynccontextmanager
async def _refreshed_controller() -> AsyncIterator[Any]:
    from pwndbg_mcp.bridge import get_controller

    ctrl = await get_controller()
    async with ctrl.mi_transaction():
        refresh = getattr(ctrl, "refresh_state", None)
        if refresh is not None:
            await refresh()
        yield ctrl


def _reject_unsafe_cli_state(ctrl: Any) -> None:
    from pwndbg_mcp.bridge import GdbState

    if ctrl.state == GdbState.RUNNING:
        raise InferiorStateError(
            "GDB CLI is unavailable while the inferior is RUNNING. "
            "Call interrupt_process, wait for a stop, then retry."
        )
    if ctrl.state == GdbState.ERROR:
        raise InferiorStateError(
            "GDB is in ERROR state. Call mcp_hard_reset, then retry."
        )


def require_loaded(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    """Ensure an executable has been loaded into GDB"""

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        from pwndbg_mcp.bridge import GdbState

        async with _refreshed_controller() as ctrl:
            _reject_unsafe_cli_state(ctrl)
            if ctrl.state in (GdbState.NOT_LOADED,):
                raise BinaryNotLoaded(
                    "No executable loaded. Call mcp_load_executable or mcp_attach_pid first."
                )
            return await fn(*args, **kwargs)

    return wrapper


def require_started(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    """Ensure the inferior is alive, either running or stopped"""

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        from pwndbg_mcp.bridge import GdbState

        async with _refreshed_controller() as ctrl:
            if ctrl.state not in (GdbState.STOPPED, GdbState.RUNNING):
                raise NotRunning(
                    f"Inferior is not running (state={ctrl.state}). Use start/mcp_attach_pid/run."
                )
            return await fn(*args, **kwargs)

    return wrapper


def require_stopped(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    """Require stopped state so tools can read memory and registers"""

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        from pwndbg_mcp.bridge import GdbState

        async with _refreshed_controller() as ctrl:
            if ctrl.state == GdbState.ERROR:
                _reject_unsafe_cli_state(ctrl)
            if ctrl.state != GdbState.STOPPED:
                raise NotRunning(
                    f"Inferior must be stopped (state={ctrl.state}). Send interrupt or hit a breakpoint."
                )
            return await fn(*args, **kwargs)

    return wrapper


def require_stopped_or_interrupt(
    fn: Callable[..., Awaitable[Any]],
) -> Callable[..., Awaitable[Any]]:
    """Require stopped state, interrupting a running inferior first

    This is intentionally narrower than require_stopped: tools using it may
    mutate process state by stopping execution
    """

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        from pwndbg_mcp.bridge import GdbState

        async with _refreshed_controller() as ctrl:
            if ctrl.state == GdbState.ERROR:
                _reject_unsafe_cli_state(ctrl)
            if ctrl.state == GdbState.RUNNING:
                response = await ctrl.interrupt_inferior(timeout=3.0)
                if response.error or ctrl.state != GdbState.STOPPED:
                    raise TimeoutExceeded(
                        response.error
                        or f"Interrupted inferior but did not reach STOPPED (state={ctrl.state})"
                    )

            if ctrl.state != GdbState.STOPPED:
                raise NotRunning(
                    f"Inferior must be stopped (state={ctrl.state}). Use start/mcp_attach_pid/run "
                    "and wait for a breakpoint, or interrupt a running inferior."
                )
            return await fn(*args, **kwargs)

    return wrapper


def require_not_running(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    """Allow CLI work in idle states but reject a running inferior"""

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        async with _refreshed_controller() as ctrl:
            _reject_unsafe_cli_state(ctrl)
            return await fn(*args, **kwargs)

    return wrapper


def require_kernel(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    """Gate kernel tools behind a stopped target verified by pwndbg"""

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        from pwndbg_mcp.bridge import GdbState

        async with _refreshed_controller() as ctrl:
            _reject_unsafe_cli_state(ctrl)
            if ctrl.state != GdbState.STOPPED:
                raise KernelOnly(
                    f"Kernel tool requires an attached kernel target "
                    f"(state={ctrl.state}). Attach to a QEMU/kgdb kernel session "
                    f"first (target remote :1234)."
                )
            try:
                is_kernel = await ctrl.pi_query(
                    "import pwndbg.aglib.qemu\n"
                    "mcp_emit(bool(pwndbg.aglib.qemu.is_qemu_kernel()))"
                )
            except PwndbgError:
                raise
            except Exception as e:
                raise PwndbgError(
                    f"kernel target probe failed: {e}; verify pwndbg kernel support "
                    "or call mcp_hard_reset, then retry"
                ) from e
            if not is_kernel:
                raise KernelOnly(
                    "Target is stopped but is not a kernel debugging session; "
                    "attach to QEMU/kgdb, then retry."
                )
            return await fn(*args, **kwargs)

    return wrapper
