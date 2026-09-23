"""Typed models for metadata assessment and extraction coordination."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ziplet.zipfile.extract import ExtractPolicy, ExtractViolation, MemberAssessment


@dataclass(frozen=True)
class ExtractionContext:
    """Immutable per-extraction context shared by validators and materializers."""

    destination: Path
    policy_root: Path
    password: bytes | None
    policy: ExtractPolicy


@dataclass
class ValidationState:
    """Mutable archive-wide state used while assessing members."""

    total_declared: int = 0
    total_compressed: int = 0
    targets: dict[Path, str] = field(default_factory=dict)
    names: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class ArchiveAssessment:
    """Immutable archive-wide result shared by inspection and extraction."""

    destination: Path
    members: tuple[MemberAssessment, ...]
    violations: tuple[ExtractViolation, ...]
    total_compressed_size: int
    total_uncompressed_size: int
    duplicate_member_names: tuple[str, ...]
    duplicate_targets: tuple[Path, ...]
