"""Opt-in extraction policies and structured extraction results."""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Generic, TypeVar

if TYPE_CHECKING:
    from ziplet.zipfile.info import ZipInfo

__all__ = [
    "CustomValidator",
    "MemberAssessment",
    "ExtractMemberResult",
    "ExtractPolicy",
    "ExtractPolicyRule",
    "ExtractResult",
    "ExtractViolation",
    "ExtractionError",
    "MemberStatus",
    "OverwritePolicy",
    "ViolationAction",
]

_T = TypeVar("_T")

CustomValidator = Callable[["ZipInfo", Path], None]


class OverwritePolicy(str, Enum):
    ERROR = "error"
    SKIP = "skip"
    REPLACE = "replace"
    RENAME = "rename"


class ViolationAction(str, Enum):
    ERROR = "error"
    WARN = "warn"
    SKIP = "skip"


class MemberStatus(str, Enum):
    EXTRACTED = "extracted"
    SKIPPED = "skipped"
    FAILED = "failed"
    PREVIEWED = "previewed"


@dataclass(frozen=True)
class ExtractPolicyRule(Generic[_T]):
    """Wraps a policy field value with its own :class:`ViolationAction`.

    Lets a single field override the archive-wide ``on_violation`` default,
    e.g. ``max_compression_ratio=ExtractPolicyRule(100.0,
    on_violation=ViolationAction.ERROR)``.
    """

    value: _T
    on_violation: ViolationAction | None = None


@dataclass(frozen=True)
class ResolvedRule(Generic[_T]):
    """The value and effective :class:`ViolationAction` for one policy field.

    A plain (non-tuple) dataclass so mypy's generic inference stays exact —
    wrapping this in ``tuple[...]`` instead makes it infer an overly wide
    type for the value on some call shapes.
    """

    value: _T
    action: ViolationAction


def resolve_rule(
    field_value: _T | ExtractPolicyRule[_T] | None,
    default_action: ViolationAction,
) -> ResolvedRule[_T | None]:
    """Unwrap *field_value*, returning its value and effective action."""
    if isinstance(field_value, ExtractPolicyRule):
        return ResolvedRule(
            field_value.value, field_value.on_violation or default_action
        )
    return ResolvedRule(field_value, default_action)


@dataclass(frozen=True)
class ExtractPolicy:
    destination_root: Path | None = None
    allow_absolute_paths: bool | ExtractPolicyRule[bool] = False
    allow_parent_traversal: bool | ExtractPolicyRule[bool] = False
    allow_windows_drive_paths: bool | ExtractPolicyRule[bool] = False
    allow_symlinks: bool | ExtractPolicyRule[bool] = False
    allow_special_files: bool | ExtractPolicyRule[bool] = False
    allow_overwrite: bool = False
    overwrite_policy: OverwritePolicy = OverwritePolicy.ERROR
    max_member_size: int | ExtractPolicyRule[int] | None = 256 * 1024 * 1024
    max_total_uncompressed_size: int | ExtractPolicyRule[int] | None = (
        1 * 1024 * 1024 * 1024
    )
    max_entries: int | ExtractPolicyRule[int] | None = 10_000
    max_compression_ratio: float | ExtractPolicyRule[float] | None = 100.0
    allowed_extensions: frozenset[str] | ExtractPolicyRule[frozenset[str]] | None = None
    blocked_extensions: frozenset[str] | ExtractPolicyRule[frozenset[str]] | None = None
    require_utf8_names: bool | ExtractPolicyRule[bool] = True
    reject_duplicate_targets: bool | ExtractPolicyRule[bool] = True
    on_violation: ViolationAction = ViolationAction.ERROR
    preview_only: bool = False
    fsync_files: bool = True
    custom_validator: CustomValidator | Sequence[CustomValidator] | None = None


@dataclass(frozen=True)
class ExtractViolation:
    member: str
    code: str
    message: str
    action: ViolationAction
    target: Path | None = None


@dataclass(frozen=True)
class MemberAssessment:
    """Immutable result of evaluating one archive member for extraction."""

    info: "ZipInfo"
    target: Path | None
    violations: tuple[ExtractViolation, ...]
    is_symlink: bool
    is_special: bool

    @property
    def has_errors(self) -> bool:
        return any(v.action == ViolationAction.ERROR for v in self.violations)

    @property
    def should_skip(self) -> bool:
        return any(v.action == ViolationAction.SKIP for v in self.violations)


@dataclass(frozen=True)
class ExtractMemberResult:
    member: str
    status: MemberStatus
    target: Path | None
    is_directory: bool
    compressed_size: int
    uncompressed_size: int
    compression_ratio: float | None
    bytes_written: int
    violations: tuple[ExtractViolation, ...] = ()
    overwritten: bool = False


@dataclass(frozen=True)
class ExtractResult:
    destination: Path
    members: tuple[ExtractMemberResult, ...]
    violations: tuple[ExtractViolation, ...]
    extracted_count: int
    skipped_count: int
    failed_count: int
    bytes_written: int
    preview_only: bool


class ExtractionError(Exception):
    """Raised after a policy-enabled extraction encounters error violations."""

    def __init__(self, result: ExtractResult) -> None:
        self.result = result
        super().__init__(f"Extraction failed for {result.failed_count} member(s)")


def normalized_destination(path: str | os.PathLike[str]) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def compression_ratio(info: ZipInfo) -> float | None:
    """Return uncompressed/compressed size, or ``None`` for empty payloads."""
    return None if info.compress_size == 0 else info.file_size / info.compress_size
