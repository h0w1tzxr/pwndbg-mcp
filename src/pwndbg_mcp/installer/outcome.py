"""Typed installer operation outcomes"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class OperationStatus(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    EXISTS = "exists"
    NOT_FOUND = "not_found"
    ERROR = "error"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class OperationResult:
    status: OperationStatus
    detail: str = ""
