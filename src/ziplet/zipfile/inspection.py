"""Structured, metadata-only archive inspection results."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ziplet.zipfile.assessment import ArchiveAssessment
from ziplet.zipfile.extract import (
    ExtractPolicy,
    ExtractViolation,
    ViolationAction,
    compression_ratio,
    resolve_rule,
)
from ziplet.zipfile.shared import MASK_ENCRYPTED

__all__ = ["InspectionMember", "InspectionResult", "build_inspection_result"]

_SUSPICIOUS_PATH_CODES = frozenset(
    {
        "absolute_path",
        "windows_path",
        "windows_drive_path",
        "parent_traversal",
        "outside_root",
    }
)


@dataclass(frozen=True)
class InspectionMember:
    """Metadata and policy findings for one central-directory entry."""

    member: str
    target: Path | None
    is_directory: bool
    compressed_size: int
    uncompressed_size: int
    compression_ratio: float | None
    encrypted: bool
    is_symlink: bool
    is_special_file: bool
    violations: tuple[ExtractViolation, ...] = ()


@dataclass(frozen=True)
class InspectionResult:
    """A side-effect-free report produced from ZIP metadata only."""

    total_entries: int
    total_compressed_size: int
    total_uncompressed_size: int
    members: tuple[InspectionMember, ...]
    duplicate_member_names: tuple[str, ...]
    duplicate_targets: tuple[Path, ...]
    suspicious_paths: tuple[str, ...]
    encrypted_members: tuple[str, ...]
    large_members: tuple[str, ...]
    compress_ratio_outliers: tuple[str, ...]
    symlinks: tuple[str, ...]
    special_files: tuple[str, ...]
    warnings: tuple[ExtractViolation, ...]
    violations: tuple[ExtractViolation, ...]
    member_count_over_limit: bool


def build_inspection_result(
    assessment: ArchiveAssessment, policy: ExtractPolicy
) -> InspectionResult:
    """Summarise *assessment* as an :class:`InspectionResult`."""
    total_entries = len(assessment.members)
    max_entries = resolve_rule(policy.max_entries, policy.on_violation)
    count_over = max_entries.value is not None and total_entries > max_entries.value
    violations = list(assessment.violations)
    if count_over:
        violations.append(
            ExtractViolation(
                "<archive>",
                "max_entries",
                f"archive contains {total_entries} entries, "
                f"limit is {max_entries.value}",
                max_entries.action,
            )
        )

    members: list[InspectionMember] = []
    encrypted: list[str] = []
    suspicious: list[str] = []
    large: list[str] = []
    ratio_outliers: list[str] = []
    symlinks: list[str] = []
    special_files: list[str] = []

    for member in assessment.members:
        info = member.info
        codes = {violation.code for violation in member.violations}
        is_encrypted = bool(info.flag_bits & MASK_ENCRYPTED)
        if is_encrypted:
            encrypted.append(info.filename)
        if member.is_symlink:
            symlinks.append(info.filename)
        if member.is_special:
            special_files.append(info.filename)
        if codes & _SUSPICIOUS_PATH_CODES:
            suspicious.append(info.filename)
        if "max_member_size" in codes:
            large.append(info.filename)
        if "compression_ratio" in codes:
            ratio_outliers.append(info.filename)
        members.append(
            InspectionMember(
                info.filename,
                member.target,
                info.is_dir(),
                info.compress_size,
                info.file_size,
                compression_ratio(info),
                is_encrypted,
                member.is_symlink,
                member.is_special,
                member.violations,
            )
        )

    return InspectionResult(
        total_entries,
        assessment.total_compressed_size,
        assessment.total_uncompressed_size,
        tuple(members),
        assessment.duplicate_member_names,
        assessment.duplicate_targets,
        tuple(dict.fromkeys(suspicious)),
        tuple(encrypted),
        tuple(large),
        tuple(ratio_outliers),
        tuple(symlinks),
        tuple(special_files),
        tuple(v for v in violations if v.action == ViolationAction.WARN),
        tuple(violations),
        count_over,
    )
