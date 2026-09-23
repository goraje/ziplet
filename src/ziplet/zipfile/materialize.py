"""Typed extraction materialization contracts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ziplet.zipfile.info import ZipInfo


@dataclass(frozen=True)
class MaterializationResult:
    """Result returned by a member materializer."""

    target: Path
    bytes_written: int
    overwritten: bool = False


class Materializer(Protocol):
    """Protocol for regular-file, directory, and special-file materializers."""

    def __call__(
        self,
        member: ZipInfo,
        targetpath: str,
        pwd: bytes | None,
        quota_member_limit: int | None,
        quota_total_limit: int | None,
        quota_total_written: int,
        directory: str,
        dir_fd: int | None,
    ) -> MaterializationResult: ...
