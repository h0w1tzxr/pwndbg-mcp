"""Remote exploit workflow helpers"""

from __future__ import annotations

import asyncio
import itertools
import logging
import math
import os
import re
import shutil
import stat
import tempfile
import time
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import Annotated

from pydantic import StrictInt

from pwndbg_mcp.bridge import AsyncGdbController
from pwndbg_mcp.bridge import GdbResponse
from pwndbg_mcp.bridge import GdbState
from pwndbg_mcp.bridge import _extend_response
from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import InferiorStateError
from pwndbg_mcp.errors import InvalidArgument
from pwndbg_mcp.errors import MissingDependency
from pwndbg_mcp.errors import PwndbgError
from pwndbg_mcp.errors import RemoteConnectionError
from pwndbg_mcp.errors import require_not_running
from pwndbg_mcp.errors import require_stopped
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.types import ExploitTemplateResult
from pwndbg_mcp.types import ReadProcessResult
from pwndbg_mcp.types import RemotePwncatOpenResult
from pwndbg_mcp.types import RemotePwncatReadResult
from pwndbg_mcp.types import RemotePwncatSessionInfo
from pwndbg_mcp.util import _decode_bytes
from pwndbg_mcp.util import _encode_text
from pwndbg_mcp.util import _validate_host
from pwndbg_mcp.util import _validate_port

logger = logging.getLogger(__name__)

_SESSION_ID_RE = re.compile(r"^pwncat-[1-9][0-9]*$")
_PWNCAT_COUNTER = itertools.count(1)
_PWNCAT_SESSIONS: dict[str, PwncatSession] = {}
_MAX_TIMEOUT = 300.0
_MAX_READ_SIZE = 1 << 20
_MAX_SEND_SIZE = 1 << 20
_MAX_TEMPLATE_PATH_BYTES = 4096
_PWNCAT_STDERR_LIMIT = 4096
_PWNCAT_REAP_TIMEOUT = 1.0
_PWNCAT_WRITE_TIMEOUT = 30.0
_CRLF_MODES = ("lf", "crlf", "cr", "no")
_MAX_EXEC_LEN = 4096
_MAX_SAFE_WORD_LEN = 256
_PORTSPEC_RE = re.compile(r"^\d{1,5}([,+-]\d{1,5})*$")

# no colour in the read buffer and no half-close on stdin eof, managed sessions need both
_PWNCAT_MANAGED_FLAGS = ("-c", "never", "--no-shutdown")
# pwncat already flushes stdout, this just guards against that changing
_PWNCAT_ENV = {**os.environ, "PYTHONUNBUFFERED": "1"}


def _pwncat_binary() -> str:
    path = shutil.which("pwncat")
    if not path:
        raise MissingDependency(
            "pwncat is unavailable; install it with `uv tool install pwncat` "
            "(cytopia/pwncat) and retry. Note ncat/nmap are not a fallback on hosts where "
            "they were removed by a package update."
        )
    return path


def _validate_crlf(value: str | None) -> str | None:
    if value is None:
        return None
    if value not in _CRLF_MODES:
        raise InvalidArgument(f"crlf must be one of {_CRLF_MODES} (got {value!r})")
    return value


def _validate_short_text(value: str | None, *, field: str, limit: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or "\0" in value:
        raise InvalidArgument(f"{field} must be a NUL-free string")
    if not value or len(value.encode("utf-8")) > limit:
        raise InvalidArgument(f"{field} must be 1..{limit} UTF-8 bytes")
    return value


def _validate_portspec(value: str) -> str:
    """Accept pwncat's multi-port syntax: '80', '80,443', '8000-8010', '8000+9'"""
    if not isinstance(value, str) or not _PORTSPEC_RE.fullmatch(value):
        raise InvalidArgument(
            f"ports must be a single port, list (80,443), range (8000-8010), or "
            f"increment (8000+9) (got {value!r})"
        )
    for chunk in re.split(r"[,+-]", value):
        _validate_port(int(chunk), field="scan port")
    return value


def _protocol_flags(udp: bool, ipv4_only: bool, ipv6_only: bool) -> list[str]:
    if ipv4_only and ipv6_only:
        raise InvalidArgument("ipv4_only and ipv6_only are mutually exclusive")
    flags: list[str] = []
    if udp:
        flags.append("-u")
    if ipv4_only:
        flags.append("-4")
    if ipv6_only:
        flags.append("-6")
    return flags


def _transform_flags(script_send: str | None, script_recv: str | None) -> list[str]:
    flags: list[str] = []
    for flag, value in (("--script-send", script_send), ("--script-recv", script_recv)):
        path = _validate_template_path(value, flag.lstrip("-"))
        if path is None:
            continue
        if not Path(path).is_file():
            raise InvalidArgument(f"{flag} script not found: {path}")
        flags.extend((flag, path))
    return flags


@dataclass
class PwncatSession:
    """One managed pwncat subprocess"""

    session_id: str
    host: str
    port: int
    proc: asyncio.subprocess.Process
    created_at: float
    mode: str = "connect"
    read_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    write_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    close_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    closing: bool = False


def _format_host_port(host: str, port: int) -> str:
    host = _validate_host(host, field="remote host")
    port = _validate_port(port, field="remote port")
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        host = f"[{host}]"
    return f"{host}:{port}"


def _socket_host(host: str) -> str:
    host = _validate_host(host, field="remote host")
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def _target_remote_command(host: str, port: int, *, extended: bool) -> str:
    mode = "extended-remote" if extended else "remote"
    return f"target {mode} {_format_host_port(host, port)}"


def _validate_session_id(value: str) -> str:
    if not _SESSION_ID_RE.fullmatch(value):
        raise InvalidArgument(f"invalid pwncat session_id {value!r}")
    return value


def _validate_read_args(size: int, timeout: float) -> tuple[int, float]:
    if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= _MAX_READ_SIZE:
        raise InvalidArgument(f"read size must be in 1..1048576 (got {size!r})")
    return size, _validate_timeout(timeout, field="read timeout", allow_zero=True)


def _validate_timeout(value: float, *, field: str, allow_zero: bool) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidArgument(f"invalid {field} {value!r}")
    try:
        timeout = float(value)
    except OverflowError as error:
        raise InvalidArgument(f"{field} must be a finite number") from error
    lower_bound_ok = timeout >= 0.0 if allow_zero else timeout > 0.0
    if not math.isfinite(timeout) or not lower_bound_ok:
        minimum = "0" if allow_zero else "greater than 0"
        raise InvalidArgument(
            f"{field} must be {minimum}..{_MAX_TIMEOUT:g} seconds (got {value!r})"
        )
    if timeout > _MAX_TIMEOUT:
        raise InvalidArgument(f"{field} must be at most {_MAX_TIMEOUT:g} seconds (got {value!r})")
    return timeout


def _read_result(data: bytes) -> ReadProcessResult:
    text, lossy = _decode_bytes(data)
    return {
        "size": len(data),
        "hex": data.hex(),
        "text": text,
        "lossy": lossy,
    }


async def _read_stream(
    reader: asyncio.StreamReader | None,
    size: int,
    timeout: float,
) -> tuple[bytes, bool]:
    if reader is None:
        raise RemoteConnectionError("pwncat stdout is unavailable; close and reopen the session")
    try:
        data = await asyncio.wait_for(reader.read(size), timeout=max(timeout, 0.0))
    except TimeoutError:
        return b"", False
    except (OSError, RuntimeError) as e:
        raise RemoteConnectionError(f"pwncat read failed: {e}; close and reopen the session") from e
    return data, data == b""


def _session_info(session: PwncatSession) -> RemotePwncatSessionInfo:
    proc = session.proc
    return {
        "session_id": session.session_id,
        "host": session.host,
        "port": session.port,
        "pid": proc.pid,
        "running": proc.returncode is None,
        "returncode": proc.returncode,
        "age_s": time.monotonic() - session.created_at,
        "mode": session.mode,
    }


def _get_session(session_id: str) -> PwncatSession:
    session_id = _validate_session_id(session_id)
    try:
        return _PWNCAT_SESSIONS[session_id]
    except KeyError as e:
        raise InvalidArgument(f"unknown pwncat session_id {session_id!r}") from e


def _coerce_payload(data: str, encoding: str) -> bytes:
    payload = _encode_text(data, encoding)
    if len(payload) > _MAX_SEND_SIZE:
        raise InvalidArgument(
            f"encoded pwncat payload must be at most {_MAX_SEND_SIZE} bytes (got {len(payload)})"
        )
    return payload


def _validate_template_path(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    label = "output path (write_path)" if field == "write_path" else field
    if not isinstance(value, str) or "\0" in value:
        raise InvalidArgument(f"{label} must be a NUL-free string")
    try:
        encoded_size = len(value.encode("utf-8"))
    except UnicodeEncodeError as e:
        raise InvalidArgument(f"{label} must contain valid UTF-8 text") from e
    if encoded_size > _MAX_TEMPLATE_PATH_BYTES:
        raise InvalidArgument(
            f"{label} must be at most {_MAX_TEMPLATE_PATH_BYTES} UTF-8 bytes "
            f"(got {encoded_size})"
        )
    return value


def _require_open_session(session: PwncatSession, operation: str) -> None:
    if session.closing:
        raise RemoteConnectionError(
            f"pwncat session {session.session_id!r} is closing; wait for close to finish, "
            "then reopen the session"
        )
    if session.proc.returncode is not None:
        raise RemoteConnectionError(
            f"pwncat session {session.session_id!r} already closed "
            f"(returncode={session.proc.returncode}); close and reopen the session before "
            f"trying to {operation}"
        )


async def _write_session(session: PwncatSession, payload: bytes) -> int:
    async with session.write_lock:
        _require_open_session(session, "send")
        if session.proc.stdin is None:
            raise RemoteConnectionError("pwncat stdin is unavailable; close and reopen the session")
        try:
            session.proc.stdin.write(payload)
            await asyncio.wait_for(session.proc.stdin.drain(), timeout=_PWNCAT_WRITE_TIMEOUT)
        except TimeoutError as e:
            raise RemoteConnectionError(
                f"pwncat session {session.session_id!r} write drain timed out after "
                f"{_PWNCAT_WRITE_TIMEOUT:g}s; close and reopen the session"
            ) from e
        except asyncio.CancelledError:
            raise
        except (BrokenPipeError, ConnectionError, OSError, RuntimeError) as e:
            raise RemoteConnectionError(
                f"pwncat session {session.session_id!r} write failed: {e}; "
                "close and reopen the session"
            ) from e
        _require_open_session(session, "send")
        return len(payload)


async def _read_pwncat_stderr(proc: asyncio.subprocess.Process) -> str:
    if proc.stderr is None:
        return ""
    try:
        data = await asyncio.wait_for(
            proc.stderr.read(_PWNCAT_STDERR_LIMIT),
            timeout=0.1,
        )
    except (TimeoutError, OSError):
        return ""
    text, _ = _decode_bytes(data)
    return (text or "").strip()


async def _shutdown_pwncat(session: PwncatSession, timeout: float) -> RemotePwncatSessionInfo:
    proc = session.proc
    errors: list[str] = []

    if proc.stdin is not None:
        try:
            proc.stdin.close()
        except (OSError, RuntimeError) as e:
            errors.append(str(e))

    if proc.returncode is None:
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
        except (OSError, RuntimeError) as e:
            errors.append(str(e))

    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout)
    except TimeoutError:
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            except (OSError, RuntimeError) as e:
                errors.append(str(e))
        try:
            await asyncio.wait_for(proc.wait(), timeout=_PWNCAT_REAP_TIMEOUT)
        except (TimeoutError, OSError, RuntimeError) as e:
            errors.append(str(e))
    except (OSError, RuntimeError) as e:
        errors.append(str(e))

    if proc.returncode is None:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        except (OSError, RuntimeError) as e:
            errors.append(str(e))
        try:
            await asyncio.wait_for(proc.wait(), timeout=_PWNCAT_REAP_TIMEOUT)
        except (TimeoutError, OSError, RuntimeError) as e:
            errors.append(str(e))

    if proc.returncode is None:
        errors.append("child is still running")
    if errors:
        raise RemoteConnectionError(
            f"pwncat cleanup failed: {'; '.join(errors)}; retry remote_pwncat_close"
        )
    return _session_info(session)


async def _cleanup_pwncat_session(session: PwncatSession, timeout: float) -> RemotePwncatSessionInfo:
    if session.closing:
        raise RemoteConnectionError(
            f"pwncat session {session.session_id!r} is already closing; wait for it to finish"
        )
    async with session.close_lock:
        if session.closing:
            raise RemoteConnectionError(
                f"pwncat session {session.session_id!r} is already closing; wait for it to finish"
            )
        session.closing = True
        cleanup = asyncio.create_task(_shutdown_pwncat(session, timeout))
        cancellation: asyncio.CancelledError | None = None
        try:
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError as error:
                    if cleanup.cancelled():
                        raise
                    if cancellation is None:
                        cancellation = error
                except Exception:
                    break
            try:
                result = cleanup.result()
            except BaseException as error:
                if cancellation is not None:
                    cancellation.add_note(f"pwncat cleanup also failed: {error}")
                    raise cancellation
                raise
            if cancellation is not None:
                raise cancellation
            return result
        finally:
            if session.proc.returncode is not None:
                _PWNCAT_SESSIONS.pop(session.session_id, None)
            else:
                session.closing = False


@mcp.tool()
async def remote_pwncat_open(
    host: Annotated[str, "Remote service host or IP"],
    port: Annotated[int, "Remote service TCP port"],
    read_size: Annotated[int, "Bytes to read immediately after connect"] = 4096,
    read_timeout: Annotated[float, "Seconds to wait for initial data"] = 0.25,
    crlf: Annotated[
        str | None,
        "Force line endings: 'lf', 'crlf', 'cr', or 'no'. Many CTF services hang on the "
        "wrong one; leave unset to send exactly what you write",
    ] = None,
    udp: Annotated[bool, "Use UDP instead of TCP"] = False,
    ipv4_only: Annotated[bool, "Force IPv4 (default is dualstack)"] = False,
    ipv6_only: Annotated[bool, "Force IPv6 (default is dualstack)"] = False,
    nodns: Annotated[bool, "Skip DNS resolution"] = False,
    safe_word: Annotated[str | None, "Shut the session down on receiving this string"] = None,
    script_send: Annotated[
        str | None, "Path to a pwncat transform script applied before sending"
    ] = None,
    script_recv: Annotated[
        str | None, "Path to a pwncat transform script applied after receiving"
    ] = None,
) -> RemotePwncatOpenResult:
    """Open a managed pwncat TCP/UDP session to a remote service"""
    host = _validate_host(host, field="remote host")
    port = _validate_port(port, field="remote port")
    read_size, read_timeout = _validate_read_args(read_size, read_timeout)
    argv = [
        *_PWNCAT_MANAGED_FLAGS,
        *_protocol_flags(udp, ipv4_only, ipv6_only),
        *_transform_flags(script_send, script_recv),
    ]
    if crlf := _validate_crlf(crlf):
        argv.extend(("-C", crlf))
    if nodns:
        argv.append("-n")
    if safe_word := _validate_short_text(
        safe_word, field="safe_word", limit=_MAX_SAFE_WORD_LEN
    ):
        argv.extend(("--safe-word", safe_word))
    argv.extend((_socket_host(host), str(port)))
    return await _spawn_session(
        host=host,
        port=port,
        argv=argv,
        mode="connect",
        read_size=read_size,
        read_timeout=read_timeout,
        label=_format_host_port(host, port),
    )


async def _spawn_session(
    *,
    host: str,
    port: int,
    argv: list[str],
    mode: str,
    read_size: int,
    read_timeout: float,
    label: str,
    allow_empty_initial: bool = False,
) -> RemotePwncatOpenResult:
    """Spawn a managed pwncat child, register it, and return its first read

    Shared by connect and listen mode so the forced flags, session bookkeeping and
    failure-cleanup path cannot drift apart between them.

    `allow_empty_initial` is what separates the two modes semantically: in connect mode an
    immediate EOF means the service refused us and the session is worthless, but a listener
    that has no client yet is working exactly as intended
    """
    pwncat = _pwncat_binary()
    try:
        proc = await asyncio.create_subprocess_exec(
            pwncat,
            *argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_PWNCAT_ENV,
        )
    except OSError as error:
        raise RemoteConnectionError(
            f"failed to launch pwncat for {label}: {error}; "
            "verify the pwncat executable, permissions, and process resources, then retry"
        ) from error
    session_id = f"pwncat-{next(_PWNCAT_COUNTER)}"
    session = PwncatSession(
        session_id=session_id,
        host=host,
        port=port,
        proc=proc,
        created_at=time.monotonic(),
        mode=mode,
    )
    _PWNCAT_SESSIONS[session_id] = session
    try:
        async with session.read_lock:
            data, eof = await _read_stream(proc.stdout, read_size, read_timeout)
        died = proc.returncode is not None
        if died or (eof and not allow_empty_initial):
            stderr = await _read_pwncat_stderr(proc)
            detail = f": {stderr}" if stderr else ""
            raise RemoteConnectionError(
                f"pwncat {label} closed during initial read "
                f"(returncode={proc.returncode}){detail}; verify the service and retry"
            )
        async with session.close_lock:
            if _PWNCAT_SESSIONS.get(session_id) is not session:
                raise RemoteConnectionError(
                    f"pwncat session {session_id!r} closed during initial read; "
                    "reopen the session"
                )
            _require_open_session(session, "finish opening")
            return RemotePwncatOpenResult(initial=_read_result(data), **_session_info(session))
    except BaseException as error:
        try:
            await _cleanup_pwncat_session(session, _PWNCAT_REAP_TIMEOUT)
        except asyncio.CancelledError:
            raise
        except BaseException as shutdown_error:
            error.add_note(f"pwncat session {session_id!r} cleanup failed: {shutdown_error}")
        raise


async def close_all_pwncat_sessions(
    timeout: float = _PWNCAT_REAP_TIMEOUT,
) -> list[str]:
    """Best-effort cleanup for every managed pwncat child on this event loop"""
    failures: list[str] = []
    cancellation: asyncio.CancelledError | None = None
    for session in list(_PWNCAT_SESSIONS.values()):
        try:
            await _cleanup_pwncat_session(session, timeout)
        except asyncio.CancelledError as error:
            if cancellation is None:
                cancellation = error
            detail = str(error) or type(error).__name__
            message = f"pwncat session {session.session_id!r} shutdown failed: {detail}"
            failures.append(message)
            logger.warning(message)
        except Exception as error:
            message = f"pwncat session {session.session_id!r} shutdown failed: {error}"
            failures.append(message)
            logger.warning(message)
    if cancellation is not None:
        raise cancellation
    return failures


@mcp.tool()
async def remote_pwncat_listen(
    port: Annotated[int, "Local TCP/UDP port to listen on"],
    host: Annotated[str, "Local address to bind"] = "0.0.0.0",
    read_size: Annotated[int, "Bytes to read once a client connects"] = 4096,
    read_timeout: Annotated[
        float, "Seconds to wait for the first client. 0 returns immediately"
    ] = 0.25,
    keep_open: Annotated[bool, "Keep listening after a client disconnects"] = False,
    exec_cmd: Annotated[
        str | None, "Command to execute and wire to the connection (e.g. '/bin/bash')"
    ] = None,
    crlf: Annotated[str | None, "Force line endings: 'lf', 'crlf', 'cr', or 'no'"] = None,
    udp: Annotated[bool, "Listen on UDP instead of TCP"] = False,
    ipv4_only: Annotated[bool, "Force IPv4"] = False,
    ipv6_only: Annotated[bool, "Force IPv6"] = False,
    safe_word: Annotated[str | None, "Shut the listener down on receiving this string"] = None,
    script_send: Annotated[str | None, "Path to a pwncat send-transform script"] = None,
    script_recv: Annotated[str | None, "Path to a pwncat recv-transform script"] = None,
) -> RemotePwncatOpenResult:
    """Start a managed pwncat listener, e.g. to catch a reverse shell

    Mutating: binds a local port and may execute a command for whoever connects
    """
    host = _validate_host(host, field="listen host")
    port = _validate_port(port, field="listen port")
    read_size, read_timeout = _validate_read_args(read_size, read_timeout)
    argv = [
        *_PWNCAT_MANAGED_FLAGS,
        "-l",
        *_protocol_flags(udp, ipv4_only, ipv6_only),
        *_transform_flags(script_send, script_recv),
    ]
    if keep_open:
        argv.append("-k")
    if exec_cmd := _validate_short_text(exec_cmd, field="exec_cmd", limit=_MAX_EXEC_LEN):
        argv.extend(("-e", exec_cmd))
    if crlf := _validate_crlf(crlf):
        argv.extend(("-C", crlf))
    if safe_word := _validate_short_text(
        safe_word, field="safe_word", limit=_MAX_SAFE_WORD_LEN
    ):
        argv.extend(("--safe-word", safe_word))
    argv.extend((_socket_host(host), str(port)))
    return await _spawn_session(
        host=host,
        port=port,
        argv=argv,
        mode="listen",
        read_size=read_size,
        read_timeout=read_timeout,
        label=f"listener on {_format_host_port(host, port)}",
        # a listener with no client yet reads nothing, not a failure
        allow_empty_initial=True,
    )


@mcp.tool()
async def remote_pwncat_scan(
    host: Annotated[str, "Host or IP to scan"],
    ports: Annotated[
        str,
        "Port spec: single '80', list '80,443', range '8000-8010', or increment '8000+9'",
    ],
    banner: Annotated[bool, "Attempt banner/version detection on open ports"] = False,
    udp: Annotated[bool, "Scan UDP instead of TCP"] = False,
    timeout: Annotated[float, "Seconds to wait for the scan to finish"] = 30.0,
) -> ReadProcessResult:
    """Zero-I/O port scan via pwncat

    A local complement to rustscan, which has a recorded miss mode and no nmap fallback on
    hosts where nmap was removed. Mutating: emits connection attempts to the target
    """
    host = _validate_host(host, field="scan host")
    ports = _validate_portspec(ports)
    timeout = _validate_timeout(timeout, field="scan timeout", allow_zero=False)
    argv = ["-c", "never", "-z", *_protocol_flags(udp, False, False)]
    if banner:
        argv.append("--banner")
    argv.extend((_socket_host(host), ports))
    proc = await asyncio.create_subprocess_exec(
        _pwncat_binary(),
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=_PWNCAT_ENV,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError as error:
        proc.kill()
        await proc.wait()
        raise RemoteConnectionError(
            f"pwncat scan of {host}:{ports} exceeded {timeout:g}s; narrow the port spec "
            "or raise the timeout"
        ) from error
    # pwncat reports scan results on stderr, merged into stdout above
    return _read_result(stdout or b"")


@mcp.tool()
async def remote_pwncat_list() -> list[RemotePwncatSessionInfo]:
    """List managed pwncat sessions"""
    return [_session_info(session) for session in _PWNCAT_SESSIONS.values()]


@mcp.tool()
async def remote_pwncat_read(
    session_id: Annotated[str, "Session id returned by remote_pwncat_open"],
    size: Annotated[int, "Max bytes to read"] = 4096,
    timeout: Annotated[float, "Seconds to wait for data"] = 1.0,
) -> RemotePwncatReadResult:
    """Read from a managed pwncat session"""
    session = _get_session(session_id)
    size, timeout = _validate_read_args(size, timeout)
    async with session.read_lock:
        _require_open_session(session, "read")
        data, eof = await _read_stream(session.proc.stdout, size, timeout)
        _require_open_session(session, "read")
    return RemotePwncatReadResult(
        session_id=session_id,
        eof=eof,
        **_read_result(data),
    )


@mcp.tool()
async def remote_pwncat_send(
    session_id: Annotated[str, "Session id returned by remote_pwncat_open"],
    data: Annotated[str, "String to encode and send"],
    encoding: Annotated[
        str,
        "Encoding: 'latin1' (byte-safe) or 'utf-8'",
    ] = "latin1",
) -> str:
    """Send bytes to a managed pwncat session"""
    session = _get_session(session_id)
    payload = _coerce_payload(data, encoding)
    n = await _write_session(session, payload)
    return f"sent {n} bytes to {session_id}"


@mcp.tool()
async def remote_pwncat_close(
    session_id: Annotated[str, "Session id returned by remote_pwncat_open"],
    timeout: Annotated[float, "Seconds to wait after terminate before kill"] = 1.0,
) -> RemotePwncatSessionInfo:
    """Close and forget a managed pwncat session"""
    timeout = _validate_timeout(timeout, field="close timeout", allow_zero=True)
    session = _get_session(session_id)
    return await _cleanup_pwncat_session(session, timeout)


async def _connect_gdb_target(
    host: str,
    port: int,
    timeout: float,
    *,
    extended: bool,
) -> str:
    host = _validate_host(host, field="remote host")
    port = _validate_port(port, field="remote port")
    timeout = _validate_timeout(timeout, field="connection timeout", allow_zero=False)
    deadline = time.monotonic() + timeout
    ctrl = await get_controller()
    endpoint = _format_host_port(host, port)

    async with ctrl.mi_transaction():
        previous_state = ctrl.state
        if previous_state not in {
            GdbState.NOT_LOADED,
            GdbState.LOADED,
            GdbState.EXITED,
        }:
            if previous_state == GdbState.RUNNING:
                action = "interrupt it, then kill or detach it before connecting a target"
            elif previous_state == GdbState.STOPPED:
                action = "kill or detach it before connecting a target"
            else:
                action = "call mcp_hard_reset before connecting a target"
            raise InferiorStateError(
                f"cannot connect a GDB target while debugger state is "
                f"{previous_state.value}; {action}"
            )
        return await _connect_gdb_target_owned(
            ctrl,
            host,
            port,
            deadline,
            previous_state,
            endpoint,
            extended=extended,
        )


async def _connect_gdb_target_owned(
    ctrl: AsyncGdbController,
    host: str,
    port: int,
    deadline: float,
    previous_state: GdbState,
    endpoint: str,
    *,
    extended: bool,
) -> str:

    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0.0:
            ctrl.state = GdbState.ERROR
            raise RemoteConnectionError(
                f"GDB target connection to {endpoint} exhausted its timeout before dispatch; "
                "call mcp_hard_reset before retrying"
            )
        response = await ctrl.run_command(
            _target_remote_command(host, port, extended=extended),
            timeout=remaining,
        )

        if ctrl.state == GdbState.RUNNING:
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                _extend_response(
                    response,
                    GdbResponse(error="connection timeout expired while target was RUNNING"),
                )
            else:
                _extend_response(
                    response,
                    await ctrl.drain_until_stopped(timeout=remaining),
                )

        remaining = deadline - time.monotonic()
        if response.result_class is not None and ctrl.state != GdbState.RUNNING and remaining > 0:
            response = await ctrl.drain_after_result(response, timeout=remaining)
    except asyncio.CancelledError:
        raise
    except Exception as e:
        ctrl.state = GdbState.ERROR
        raise RemoteConnectionError(
            f"GDB target connection to {endpoint} failed during transport: {e}; "
            "call mcp_hard_reset before retrying"
        ) from e

    details = "; ".join(
        part for part in (response.error, response.text) if part
    ) or "unknown error"
    if response.result_class == "error" and ctrl.state == previous_state:
        raise RemoteConnectionError(
            f"GDB target connection to {endpoint} failed: {details}; restart gdbserver, "
            "use `disconnect` before reconnecting, or call mcp_hard_reset"
        )

    result_complete = response.error is None and response.result_class in {
        "done",
        "connected",
    }
    state_complete = (
        ctrl.state == GdbState.STOPPED
        if not extended
        else ctrl.state in {previous_state, GdbState.STOPPED}
    )
    if not result_complete or not state_complete:
        observed_state = ctrl.state
        ctrl.state = GdbState.ERROR
        raise RemoteConnectionError(
            f"GDB target connection to {endpoint} was not confirmed "
            f"(result={response.result_class!r}, state={observed_state}, detail={details}); "
            "call mcp_hard_reset before retrying"
        )
    return response.text or (
        f"connected target {'extended-remote' if extended else 'remote'} "
        f"{endpoint}"
    )


@mcp.tool()
@require_not_running
async def gdb_target_remote(
    host: Annotated[str, "GDB remote stub host or IP"],
    port: Annotated[int, "GDB remote stub TCP port"],
    timeout: Annotated[float, "Seconds to wait for GDB target connection"] = 15.0,
) -> str:
    """Connect GDB to `target remote host:port`"""
    return await _connect_gdb_target(host, port, timeout, extended=False)


@mcp.tool()
@require_not_running
async def gdb_target_extended_remote(
    host: Annotated[str, "GDB extended remote stub host or IP"],
    port: Annotated[int, "GDB extended remote stub TCP port"],
    timeout: Annotated[float, "Seconds to wait for GDB target connection"] = 15.0,
) -> str:
    """Connect GDB to `target extended-remote host:port`"""
    return await _connect_gdb_target(host, port, timeout, extended=True)


@mcp.tool()
@require_stopped
async def remote_hijack_fd(
    fd_num: Annotated[StrictInt, "Inferior file descriptor number to replace"],
    host: Annotated[str, "Remote host/IP to connect the inferior fd to"],
    port: Annotated[int, "Remote TCP/UDP port"],
    protocol: Annotated[str, "Protocol: tcp or udp"] = "tcp",
) -> str:
    """Replace an inferior fd with a validated remote socket target"""
    if isinstance(fd_num, bool) or not isinstance(fd_num, int):
        raise InvalidArgument(f"fd_num must be an integer (got {fd_num!r})")
    if not 0 <= fd_num <= 0x7FFF_FFFF:
        raise InvalidArgument("fd_num must be in range 0..2147483647")
    if not isinstance(protocol, str):
        raise InvalidArgument(f"protocol must be 'tcp' or 'udp' (got {protocol!r})")
    protocol = protocol.lower()
    if protocol not in {"tcp", "udp"}:
        raise InvalidArgument(f"protocol must be 'tcp' or 'udp' (got {protocol!r})")
    target = f"{protocol}://{_format_host_port(host, port)}"
    ctrl = await get_controller()
    r = await ctrl.run_command(f"hijack-fd {fd_num} {target}", timeout=15.0)
    if not r.ok:
        raise PwndbgError(
            f"hijack-fd {fd_num} -> {target} failed: "
            f"{r.error or r.text or 'unknown GDB error'}; verify the descriptor and target, "
            "then retry or call mcp_hard_reset if debugger state is uncertain"
        )
    return r.text or f"hijacked fd {fd_num} -> {target}"


def _build_exploit_template(
    host: str,
    port: int,
    binary_path: str | None,
    libc_path: str | None,
) -> str:
    host = _validate_host(host, field="remote host")
    port = _validate_port(port, field="remote port")
    binary_path = _validate_template_path(binary_path, "binary_path")
    libc_path = _validate_template_path(libc_path, "libc_path")
    binary_repr = repr(binary_path) if binary_path else "None"
    libc_repr = repr(libc_path) if libc_path else "None"
    return f'''#!/usr/bin/env python3
from pwn import *

HOST = args.HOST or {host!r}
PORT = int(args.PORT or {port})
BINARY_PATH = {binary_repr}
LIBC_PATH = {libc_repr}

context.log_level = args.LOG or "info"
exe = ELF(BINARY_PATH, checksec=False) if BINARY_PATH else None
libc = ELF(LIBC_PATH, checksec=False) if LIBC_PATH else None
if exe:
    context.binary = exe


def start():
    if args.LOCAL:
        if not exe:
            raise SystemExit("LOCAL mode requires BINARY_PATH")
        return process([exe.path])
    return remote(HOST, PORT)


def build_payload():
    return b""


io = start()
payload = build_payload()
if payload:
    io.sendline(payload)
io.interactive()
'''


def _write_exploit_template(path: Path, script: str) -> None:
    temp_path: str | None = None
    try:
        try:
            existing = path.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if stat.S_ISLNK(existing.st_mode):
                raise InvalidArgument(f"output path must not be a symlink: {path}")
            if not stat.S_ISREG(existing.st_mode):
                raise InvalidArgument(f"output path must be a regular file: {path}")
        mode = (
            (stat.S_IMODE(existing.st_mode) | 0o700) & 0o777
            if existing is not None
            else 0o700
        )

        fd, temp_path = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                raise InvalidArgument(f"temporary output must be a regular file: {path}")
            payload = script.encode("utf-8")
            offset = 0
            while offset < len(payload):
                written = os.write(fd, payload[offset:])
                if written <= 0:
                    raise OSError("write returned no progress")
                offset += written
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temp_path, path)
        temp_path = None
    except InvalidArgument:
        raise
    except OSError as e:
        raise PwndbgError(
            f"failed to write exploit template to {path}: {e}; "
            "choose a writable regular output path and retry"
        ) from e
    finally:
        if temp_path is not None:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass
            except OSError:
                logger.warning("failed to remove exploit-template temp file %s", temp_path)


@mcp.tool()
async def remote_exploit_template(
    host: Annotated[str, "Remote service host/IP"],
    port: Annotated[int, "Remote service TCP port"],
    binary_path: Annotated[str | None, "Optional local ELF path for context.binary"] = None,
    libc_path: Annotated[str | None, "Optional local libc path"] = None,
    write_path: Annotated[
        str | None,
        "Optional explicit output path. When omitted, the script is only returned",
    ] = None,
) -> ExploitTemplateResult:
    """Return a pwntools remote exploit template, optionally writing it to disk"""
    write_path = _validate_template_path(write_path, "write_path")
    script = _build_exploit_template(host, port, binary_path, libc_path)
    wrote_path: str | None = None
    if write_path:
        if any(separator in write_path for separator in ("\x00", "\n", "\r")):
            raise InvalidArgument(f"invalid output path {write_path!r}")
        out_path = Path(write_path).expanduser()
        if not out_path.parent.is_dir():
            raise InvalidArgument(f"parent directory does not exist: {out_path.parent}")
        _write_exploit_template(out_path, script)
        wrote_path = str(out_path)
    return {"script": script, "wrote_path": wrote_path}
