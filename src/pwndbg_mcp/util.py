"""Utilities shared across the MCP layer"""

from __future__ import annotations

import ast
import ipaddress
import json
import math
import re
from typing import Any

from pwndbg_mcp.errors import EvalError
from pwndbg_mcp.errors import InvalidArgument
from pwndbg_mcp.errors import MissingDependency
from pwndbg_mcp.errors import PwndbgError

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# these split one gdb command into two, other syntax errors come from gdb
_GDB_CMD_SEPARATORS = re.compile(r"[\n\r\x00]")
_DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_GDB_NUMBER = r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)"
_GDB_LOCATION_RE = re.compile(
    rf"^(?:{_GDB_NUMBER}|\$[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_.$][A-Za-z0-9_.$:@]*)(?:[+-]{_GDB_NUMBER})?$"
)
_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_./:*+@-]+$")
_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SAFE_TYPE_NAME_RE = re.compile(
    r"^(?:(?:struct|union|enum) )?[A-Za-z_][A-Za-z0-9_:]*$"
)
_ASM_LABEL_RE = re.compile(
    r"^(?:[A-Za-z_.$][A-Za-z0-9_.$]*|[0-9]+)\s*:\s*"
)
_ENCODINGS = {"latin1", "utf-8"}
_MAX_OUTPUT_LIMIT = 4096
_MAX_PAYLOAD_BYTES = 1 << 20
_MAX_TEXT_BYTES = 1 << 16
_MAX_TIMEOUT_SECONDS = 300.0
_PWNTOOLS_EVAL_NAMES = (
    "ELF",
    "asm",
    "cyclic",
    "cyclic_find",
    "disasm",
    "flat",
    "p8",
    "p16",
    "p32",
    "p64",
    "pack",
    "rol",
    "ror",
    "u8",
    "u16",
    "u32",
    "u64",
    "unpack",
    "xor",
)


def _safe_gdb_arg(value: str, *, field: str) -> str:
    """Reject strings that would split into multiple GDB CLI commands"""
    value = _validate_text_size(value, field=field)
    if _GDB_CMD_SEPARATORS.search(value):
        raise InvalidArgument(
            f"{field} contains an embedded newline / NUL ({value!r}); refuse to forward to GDB CLI"
        )
    return value


def _quote_gdb_string(value: str, *, field: str) -> str:
    """Encode one GDB/MI C-string argument without command splitting"""
    value = _validate_text_size(value, field=field)
    if "\0" in value:
        raise InvalidArgument(f"{field} must be a NUL-free string")
    return json.dumps(value, ensure_ascii=False)


def _quote_gdb_arguments(
    args: object,
    *,
    field: str = "executable arguments",
) -> list[str]:
    if not isinstance(args, list):
        raise InvalidArgument(f"{field} must be a list")
    _validate_bounded_int(len(args), field=field, minimum=0, maximum=4096)
    quoted: list[str] = []
    total = 0
    for arg in args:
        value = _validate_text_size(arg, field="executable argument")
        encoded = _quote_gdb_string(value, field="executable argument")
        total += len(encoded.encode("utf-8")) + bool(quoted)
        if total > _MAX_TEXT_BYTES:
            raise InvalidArgument(f"{field} must be at most {_MAX_TEXT_BYTES} UTF-8 bytes")
        quoted.append(encoded)
    return quoted


def _validate_readonly_location(value: str, *, field: str) -> str:
    """Accept one non-mutating address atom with an optional numeric offset"""
    value = _validate_text_size(value, field=field)
    if not _GDB_LOCATION_RE.fullmatch(value):
        raise InvalidArgument(
            f"invalid {field}; expected a number, $register, or symbol with an optional numeric offset"
        )
    return _safe_gdb_arg(value, field=field)


def _validate_safe_token(value: str, *, field: str) -> str:
    """Accept one option-proof CLI token without interpreter syntax"""
    value = _validate_text_size(value, field=field)
    if (
        value.startswith("-")
        or not _SAFE_TOKEN_RE.fullmatch(value)
    ):
        raise InvalidArgument(f"invalid {field}; expected one plain non-option token")
    return _safe_gdb_arg(value, field=field)


def _validate_safe_identifier(value: str, *, field: str) -> str:
    """Accept one C-style identifier"""
    value = _validate_text_size(value, field=field)
    if not _SAFE_IDENTIFIER_RE.fullmatch(value):
        raise InvalidArgument(f"invalid {field}; expected an identifier")
    return value


def _validate_safe_type_name(value: str, *, field: str) -> str:
    """Accept a plain type name with an optional C tag prefix"""
    value = _validate_text_size(value, field=field)
    if not _SAFE_TYPE_NAME_RE.fullmatch(value):
        raise InvalidArgument(f"invalid {field}; expected a plain type name")
    return value


def _validate_assembly_instructions(value: object, *, field: str) -> str:
    """Allow assembler instructions and labels, but no file/size directives"""
    value = _validate_text_size(value, field=field)
    has_instruction = False
    for statement in re.split(r"[;\r\n]", value):
        remainder = statement.lstrip()
        while remainder:
            if match := _ASM_LABEL_RE.match(remainder):
                remainder = remainder[match.end() :].lstrip()
                continue
            if remainder.startswith("/*"):
                end = remainder.find("*/", 2)
                if end < 0:
                    raise InvalidArgument(f"{field} contains an unterminated comment")
                remainder = remainder[end + 2 :].lstrip()
                continue
            break
        if remainder.startswith((".", "#")):
            raise InvalidArgument(
                f"{field} must contain instructions only; assembler directives and "
                "preprocessor statements are not allowed"
            )
        has_instruction = has_instruction or bool(remainder)
    if not has_instruction:
        raise InvalidArgument(f"{field} must contain at least one instruction")
    return value


def _validate_host(value: str, *, field: str) -> str:
    value = _validate_text_size(value, field=field, maximum=253)
    if (
        not value
        or value != value.strip()
        or not value.isascii()
    ):
        raise InvalidArgument(f"invalid {field} {value!r}")

    if value.startswith("[") or value.endswith("]"):
        if not (value.startswith("[") and value.endswith("]")):
            raise InvalidArgument(f"invalid {field} {value!r}")
        address = value[1:-1]
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as e:
            raise InvalidArgument(f"invalid {field} {value!r}") from e
        if not isinstance(parsed, ipaddress.IPv6Address) or "%" in address:
            raise InvalidArgument(f"invalid {field} {value!r}")
        return _safe_gdb_arg(value, field=field)

    if "%" in value:
        raise InvalidArgument(f"invalid {field} {value!r}")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        dns_name = value[:-1] if value.endswith(".") else value
        labels = dns_name.split(".")
        numeric_dotted = "." in dns_name and all(
            character in "0123456789." for character in dns_name
        )
        if (
            not dns_name
            or len(dns_name) > 253
            or numeric_dotted
            or not all(_DNS_LABEL_RE.fullmatch(label) for label in labels)
        ):
            raise InvalidArgument(f"invalid {field}") from None
    return _safe_gdb_arg(value, field=field)


def _validate_port(value: int, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidArgument(f"{field} must be an integer")
    if not 1 <= value <= 65535:
        raise InvalidArgument(f"{field} out of range (1-65535)")
    return value


def _validate_bounded_int(
    value: object,
    *,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidArgument(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise InvalidArgument(f"{field} must be in range {minimum}..{maximum}")
    return value


def _validate_limit(
    value: object,
    *,
    field: str,
    hard_max: int = _MAX_OUTPUT_LIMIT,
    allow_zero: bool = True,
) -> int:
    if value is None:
        return hard_max
    return _validate_bounded_int(
        value,
        field=field,
        minimum=0 if allow_zero else 1,
        maximum=hard_max,
    )


def _validate_timeout(
    value: object,
    *,
    field: str,
    allow_zero: bool = False,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidArgument(f"{field} must be a finite number")
    try:
        timeout = float(value)
    except OverflowError as error:
        raise InvalidArgument(f"{field} must be a finite number") from error
    if (
        not math.isfinite(timeout)
        or timeout < 0.0
        or timeout > _MAX_TIMEOUT_SECONDS
        or (not allow_zero and timeout == 0.0)
    ):
        qualifier = "0..300" if allow_zero else ">0..300"
        raise InvalidArgument(f"{field} must be finite and in range {qualifier} seconds")
    return timeout


def _validate_payload_size(
    payload: bytes,
    *,
    field: str,
    maximum: int = _MAX_PAYLOAD_BYTES,
) -> bytes:
    if len(payload) > maximum:
        raise InvalidArgument(f"{field} must be at most {maximum} bytes (got {len(payload)})")
    return payload


def _validate_text_size(
    value: object,
    *,
    field: str,
    maximum: int = _MAX_TEXT_BYTES,
) -> str:
    if not isinstance(value, str):
        raise InvalidArgument(f"{field} must be a string")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise InvalidArgument(f"{field} must contain valid UTF-8 text") from error
    if size > maximum:
        raise InvalidArgument(f"{field} must be at most {maximum} UTF-8 bytes (got {size})")
    return value


def _encode_text(data: str, encoding: str) -> bytes:
    if encoding not in _ENCODINGS:
        raise InvalidArgument(f"encoding must be 'latin1' or 'utf-8' (got {encoding!r})")
    try:
        return data.encode(encoding)
    except UnicodeEncodeError as e:
        raise InvalidArgument(f"data cannot be encoded as {encoding}: {e}") from e


def _decode_bytes(data: bytes) -> tuple[str | None, bool]:
    if not data:
        return None, False
    text = data.decode("utf-8", errors="replace")
    return text, text.encode("utf-8", errors="replace") != data


def _truncate_list(items: list | dict[str, Any], limit: int | None) -> Any:
    """Bound list output by entry count and compact-JSON byte size"""
    producer_truncated = False
    producer_total: int | None = None
    if isinstance(items, dict):
        producer_truncated = bool(items.get("_truncated", False))
        raw_entries = items.get("_entries")
        if not isinstance(raw_entries, list):
            raise PwndbgError("bounded producer result must contain a list of entries")
        raw_total = items.get("_total", len(raw_entries))
        if (
            isinstance(raw_total, bool)
            or not isinstance(raw_total, int)
            or raw_total < len(raw_entries)
        ):
            raise PwndbgError(
                "bounded producer total must be an integer no smaller than emitted entries"
            )
        producer_total = raw_total
        items = raw_entries
    effective_limit = _validate_limit(limit, field="limit")
    total = producer_total if producer_total is not None else len(items)
    candidates = items[:effective_limit]
    admitted: list[Any] = []
    size = len(
        json.dumps(
            {"entries": [], "total": total, "truncated": False},
            separators=(",", ":"),
        ).encode("utf-8")
    )
    for entry in candidates:
        try:
            entry_size = len(
                json.dumps(entry, separators=(",", ":")).encode("utf-8")
            )
        except (TypeError, ValueError, OverflowError) as error:
            raise PwndbgError("bounded producer entry is not JSON serializable") from error
        increment = entry_size + bool(admitted)
        if size + increment > _MAX_TEXT_BYTES:
            break
        admitted.append(entry)
        size += increment
    return {
        "entries": admitted,
        "total": total,
        "truncated": producer_truncated
        or len(admitted) < len(items)
        or total > len(admitted),
    }


def _truncate_lines(text: str, limit: int | None) -> str:
    """Cap text by line count and UTF-8 byte size, with truncation provenance"""
    effective_limit = _validate_limit(limit, field="limit")
    lines = text.splitlines()
    total = len(lines)
    encoded = text.encode("utf-8")
    if total <= effective_limit and len(encoded) <= _MAX_TEXT_BYTES:
        return text
    kept_limit = min(effective_limit, _MAX_OUTPUT_LIMIT - 1)
    kept = lines[:kept_limit]
    marker = (
        f"[... pwndbg-mcp output capped: showing {len(kept)} of {total} lines "
        f"within {_MAX_TEXT_BYTES} UTF-8 bytes. Pass limit=N to select a smaller window.]"
    )
    prefix = "\n".join(kept)
    separator = "\n" if prefix else ""
    available = _MAX_TEXT_BYTES - len((separator + marker).encode("utf-8"))
    prefix = prefix.encode("utf-8")[:available].decode("utf-8", errors="ignore")
    shown = len(prefix.splitlines()) if prefix else 0
    marker = (
        f"[... pwndbg-mcp output capped: showing {shown} of {total} lines "
        f"within {_MAX_TEXT_BYTES} UTF-8 bytes. Pass limit=N to select a smaller window.]"
    )
    separator = "\n" if prefix and not prefix.endswith("\n") else ""
    return prefix + separator + marker


def _pwntools_eval_locals() -> dict[str, Any]:
    """Build the convenience namespace used by exploit payload eval helpers"""
    try:
        import pwn

        return {name: getattr(pwn, name) for name in _PWNTOOLS_EVAL_NAMES}
    except Exception:
        return {}


def _bounded_exception_details(error: Exception) -> tuple[str, str]:
    try:
        error_type = type(error).__name__
    except Exception:
        error_type = "Exception"
    if not isinstance(error_type, str):
        error_type = "Exception"
    try:
        detail = str(error)
    except Exception:
        detail = "<unprintable error>"
    return error_type[:128] or "Exception", (
        detail if len(detail) <= 512 else detail[:509] + "..."
    )


def _bounded_type_name(value: Any) -> str:
    try:
        name = type(value).__name__
    except Exception:
        return "unknown"
    return name[:128] if isinstance(name, str) else "unknown"


def _eval_payload(statement: str) -> tuple[bytes, Any]:
    """Eval an exploit payload expression and bytes-convert the result"""
    eval_locals = _pwntools_eval_locals()
    if not eval_locals:
        try:
            expression = ast.parse(statement, mode="eval")
        except SyntaxError:
            pass
        else:
            if any(
                isinstance(node, ast.Name) and node.id in _PWNTOOLS_EVAL_NAMES
                for node in ast.walk(expression)
            ):
                raise MissingDependency(
                    "pwntools is unavailable; install pwntools in the pwndbg-mcp environment"
                )
    try:
        result = eval(  # Noqa: S307 - intended exploit workflow escape hatch
            statement,
            {"__builtins__": __builtins__},
            eval_locals,
        )
    except Exception as e:
        error_type, detail = _bounded_exception_details(e)
        raise EvalError(
            original_type=error_type,
            original_message=detail,
        ) from e
    try:
        return bytes(result), result
    except Exception as e:
        error_type, detail = _bounded_exception_details(e)
        raise EvalError(
            original_type=error_type,
            original_message=(
                f"cannot convert eval result of type {_bounded_type_name(result)} "
                f"to bytes: {detail}"
            ),
        ) from e
