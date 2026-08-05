"""Process I/O through the inferior PTY"""

from __future__ import annotations

from typing import Annotated

from pwndbg_mcp.bridge import GdbState
from pwndbg_mcp.bridge import get_controller
from pwndbg_mcp.errors import InferiorStateError
from pwndbg_mcp.errors import InvalidArgument
from pwndbg_mcp.errors import TimeoutExceeded
from pwndbg_mcp.tools._registry import mcp
from pwndbg_mcp.tools.remote import _validate_read_args
from pwndbg_mcp.types import ReadProcessResult
from pwndbg_mcp.util import _decode_bytes
from pwndbg_mcp.util import _encode_text
from pwndbg_mcp.util import _eval_payload

_MAX_PAYLOAD_SIZE = 1 << 20
_MAX_EVAL_STATEMENT_SIZE = 1 << 16


def _require_live_process(ctrl: object, operation: str) -> None:
    state = getattr(ctrl, "state", None)
    if state not in {GdbState.RUNNING, GdbState.STOPPED}:
        raise InferiorStateError(
            f"cannot {operation} while inferior state={state}; start or attach an "
            "inferior, or call mcp_hard_reset if debugger state is stale"
        )


def _validate_payload_size(payload: bytes) -> None:
    if len(payload) > _MAX_PAYLOAD_SIZE:
        raise InvalidArgument(
            f"inferior payload must be at most {_MAX_PAYLOAD_SIZE} bytes"
        )


def _with_reset_guidance(detail: str) -> str:
    if "mcp_hard_reset" in detail:
        return detail
    return f"{detail}; call mcp_hard_reset to recover"


@mcp.tool()
async def send_to_process(
    data: Annotated[str, "String to send. Bytes 0-255 are encoded as latin1"],
    encoding: Annotated[
        str, "Encoding for high-codepoint chars: 'latin1' (byte-safe) or 'utf-8'"
    ] = "latin1",
) -> str:
    """Write data to the inferior's stdin via PTY"""
    payload = _encode_text(data, encoding)
    _validate_payload_size(payload)
    ctrl = await get_controller()
    _require_live_process(ctrl, "send data")
    n = await ctrl.write_process(payload)
    return f"sent {n} bytes"


@mcp.tool()
async def eval_to_send_to_process(
    statement: Annotated[
        str,
        "Python expression evaluated with pwntools imported, then bytes()-converted and sent. "
        'Example: "flat(0x222, 0x333) + p64(1)"',
    ],
) -> str:
    """Evaluate a Python expression (pwntools imported) and send the bytes() result to the inferior

    DANGEROUS: arbitrary Python evaluation. Don't expose to untrusted callers
    """
    if not isinstance(statement, str):
        raise InvalidArgument("eval statement must be a string")
    try:
        statement_size = len(statement.encode("utf-8"))
    except UnicodeEncodeError as e:
        raise InvalidArgument(f"eval statement is not valid UTF-8: {e}") from e
    if statement_size > _MAX_EVAL_STATEMENT_SIZE:
        raise InvalidArgument(
            f"eval statement must be at most {_MAX_EVAL_STATEMENT_SIZE} UTF-8 bytes"
        )
    ctrl = await get_controller()
    _require_live_process(ctrl, "evaluate and send data")
    payload, _result = _eval_payload(statement)
    _validate_payload_size(payload)
    n = await ctrl.write_process(payload)
    return f"sent {n} bytes from eval()"


@mcp.tool()
async def read_from_process(
    size: Annotated[int, "Max bytes to read"] = 4096,
    timeout: Annotated[float, "Seconds to wait for data"] = 5.0,
) -> ReadProcessResult:
    """Read inferior output with lossless hex and best-effort text"""
    size, timeout = _validate_read_args(size, timeout)
    ctrl = await get_controller()
    data = await ctrl.read_process(size, timeout)
    text, lossy = _decode_bytes(data)
    return {"size": len(data), "hex": data.hex(), "text": text, "lossy": lossy}


@mcp.tool()
async def interrupt_process(
    ctrl_char: Annotated[
        str,
        "Control character: 'C-c' (SIGINT default), 'C-d' (EOF), 'C-z' (SIGTSTP)",
    ] = "C-c",
) -> str:
    """Send Ctrl-C/d/z while keeping GDB state observable"""
    ctrl = await get_controller()
    if ctrl_char == "C-c":
        r = await ctrl.interrupt_inferior(timeout=3.0)
        if r.error or ctrl.state != GdbState.STOPPED:
            detail = r.error or f"inferior did not stop (state={ctrl.state})"
            raise TimeoutExceeded(_with_reset_guidance(detail))
        return f"sent SIGINT (state={ctrl.state})"
    if ctrl_char == "C-d":
        await ctrl.send_eof_to_process(timeout=3.0)
        return "sent EOF"

    ctrl_map = {
        "C-z": (b"\x1a", "SIGTSTP"),
    }
    pair = ctrl_map.get(ctrl_char)
    if not pair:
        raise InvalidArgument(
            f"interrupt_process ctrl_char must be 'C-c', 'C-d', or 'C-z' (got {ctrl_char!r})"
        )
    ch, label = pair
    await ctrl.send_signal_to_process(ch)
    if ctrl_char == "C-z":
        response = await ctrl.drain_until_stopped(timeout=3.0)
        if response.error or ctrl.state != GdbState.STOPPED:
            detail = response.error or f"inferior did not stop (state={ctrl.state})"
            raise TimeoutExceeded(
                _with_reset_guidance(detail)
            )
        return f"sent {label} (state={ctrl.state})"
    return f"sent {label}"
