"""Metadata-only assessment of archive members against an extraction policy."""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from dataclasses import replace
from pathlib import Path

from ziplet.zipfile.assessment import (
    ArchiveAssessment,
    ExtractionContext,
    ValidationState,
)
from ziplet.zipfile.extract import (
    ExtractPolicy,
    ExtractViolation,
    MemberAssessment,
    OverwritePolicy,
    ViolationAction,
    normalized_destination,
    resolve_rule,
)
from ziplet.zipfile.info import ZipInfo
from ziplet.zipfile.validators import (
    EXTRACT_VALIDATORS,
    ValidatorParams,
    ValidatorPipeline,
    entry_type,
    resolve_extract_target,
)

__all__ = [
    "assess_archive",
    "assess_member",
    "default_assessment_policy",
    "entry_count_violation",
]

# Findings that can never be downgraded to warnings, regardless of policy.
_HARD_VIOLATIONS = frozenset(
    {
        "absolute_path",
        "windows_drive_path",
        "windows_path",
        "parent_traversal",
        "outside_root",
        "symlink",
        "special_file",
        "unsafe_destination",
    }
)

_PIPELINE = ValidatorPipeline(EXTRACT_VALIDATORS)


def default_assessment_policy() -> ExtractPolicy:
    """Policy used when the caller supplies none: report, never enforce limits."""
    return replace(
        ExtractPolicy(),
        allow_overwrite=True,
        overwrite_policy=OverwritePolicy.REPLACE,
        max_member_size=None,
        max_total_uncompressed_size=None,
        max_entries=None,
        max_compression_ratio=None,
    )


def entry_count_violation(count: int, policy: ExtractPolicy) -> ExtractViolation | None:
    """Return the archive-level ``max_entries`` finding for *count* entries."""
    rule = resolve_rule(policy.max_entries, policy.on_violation)
    if rule.value is None or count <= rule.value:
        return None
    return ExtractViolation(
        "<archive>",
        "max_entries",
        f"archive contains {count} entries, limit is {rule.value}",
        rule.action,
    )


def _escalate_hard_violations(
    violations: Iterable[ExtractViolation],
) -> list[ExtractViolation]:
    """Turn WARN into ERROR for findings that must never be soft-failed."""
    return [
        replace(violation, action=ViolationAction.ERROR)
        if violation.code in _HARD_VIOLATIONS
        and violation.action == ViolationAction.WARN
        else violation
        for violation in violations
    ]


def assess_member(
    info: ZipInfo,
    destination: Path,
    policy_root: Path,
    policy: ExtractPolicy,
    state: ValidationState,
) -> MemberAssessment:
    """Validate one member, updating the archive-wide *state*."""
    target, _drive, _parts = resolve_extract_target(info, destination)
    context = ExtractionContext(destination, policy_root, None, policy)
    violations = _PIPELINE.validate(ValidatorParams(info, target, context, state))
    return MemberAssessment(
        info,
        target,
        tuple(_escalate_hard_violations(violations)),
        *entry_type(info),
    )


def assess_archive(
    infos: Sequence[ZipInfo],
    path: str | os.PathLike[str] | None,
    policy: ExtractPolicy | None,
) -> ArchiveAssessment:
    """Assess every member of an archive without touching its payloads."""
    policy = policy or default_assessment_policy()
    destination = normalized_destination(path or os.getcwd())
    root = normalized_destination(policy.destination_root or destination)
    state = ValidationState()
    members: list[MemberAssessment] = []
    violations: list[ExtractViolation] = []
    duplicate_targets: list[Path] = []
    seen_targets: set[Path] = set()
    for info in infos:
        state.names[info.filename] = state.names.get(info.filename, 0) + 1
        state.total_declared += info.file_size
        state.total_compressed += info.compress_size
        assessment = assess_member(info, destination, root, policy, state)
        if assessment.target is not None:
            if assessment.target in seen_targets:
                duplicate_targets.append(assessment.target)
            seen_targets.add(assessment.target)
        members.append(assessment)
        violations.extend(assessment.violations)
    count_violation = entry_count_violation(len(infos), policy)
    if count_violation is not None:
        violations.append(count_violation)
    return ArchiveAssessment(
        destination,
        tuple(members),
        tuple(violations),
        state.total_compressed,
        state.total_declared,
        tuple(name for name, count in state.names.items() if count > 1),
        tuple(dict.fromkeys(duplicate_targets)),
    )
