"""Policy-driven extraction: assess each member, then materialize what is allowed."""

from __future__ import annotations

import warnings
from collections.abc import Callable, Sequence
from pathlib import Path

from ziplet.exceptions import BadZipFile
from ziplet.zipfile.assessment import ValidationState
from ziplet.zipfile.assessor import assess_member
from ziplet.zipfile.exceptions import ExtractionFailure, ExtractionQuotaExceeded
from ziplet.zipfile.extract import (
    ExtractMemberResult,
    ExtractPolicy,
    ExtractResult,
    ExtractViolation,
    MemberStatus,
    OverwritePolicy,
    ViolationAction,
    compression_ratio,
    resolve_rule,
)
from ziplet.zipfile.info import ZipInfo
from ziplet.zipfile.materialize import ExtractionQuota, MaterializationResult

__all__ = ["Materialize", "extract_with_policy"]

Materialize = Callable[[ZipInfo, Path, ExtractionQuota], MaterializationResult]

_MATERIALIZATION_ERRORS = (
    OSError,
    ValueError,
    BadZipFile,
    RuntimeError,
    ExtractionFailure,
)

# Depth of the frame that called ``ZipFile.extract``/``extractall``, so warnings
# point at the user's code rather than at library internals.
_WARN_STACKLEVEL = 4


def _member_result(
    info: ZipInfo,
    status: MemberStatus,
    target: Path | None,
    written: int,
    violations: tuple[ExtractViolation, ...],
    overwritten: bool = False,
) -> ExtractMemberResult:
    return ExtractMemberResult(
        info.filename,
        status,
        target,
        info.is_dir(),
        info.compress_size,
        info.file_size,
        compression_ratio(info),
        written,
        violations,
        overwritten,
    )


def _unique_target(target: Path, policy: ExtractPolicy) -> Path:
    """Return *target*, or a numbered sibling when renaming on conflict."""
    if policy.overwrite_policy != OverwritePolicy.RENAME or not target.exists():
        return target
    counter = 1
    candidate = target
    while candidate.exists():
        candidate = target.with_name(f"{target.name}.{counter}")
        counter += 1
    return candidate


def extract_with_policy(
    infos: Sequence[ZipInfo],
    destination: Path,
    policy_root: Path,
    policy: ExtractPolicy,
    materialize: Materialize,
) -> ExtractResult:
    """Extract *infos* under *policy*, reporting per-member outcomes.

    Each member is assessed first; only members whose findings permit it are
    passed to *materialize*.  Failures are recorded, not raised.
    """
    violations: list[ExtractViolation] = []
    results: list[ExtractMemberResult] = []
    state = ValidationState()
    total_written = 0

    max_entries = resolve_rule(policy.max_entries, policy.on_violation)
    if max_entries.value is not None and len(infos) > max_entries.value:
        violations.append(
            ExtractViolation(
                "<archive>",
                "max_entries",
                f"archive contains {len(infos)} entries, limit is {max_entries.value}",
                max_entries.action,
            )
        )
    member_limit = resolve_rule(policy.max_member_size, policy.on_violation).value
    total_limit = resolve_rule(
        policy.max_total_uncompressed_size, policy.on_violation
    ).value

    for info in infos:
        state.total_declared += info.file_size
        state.total_compressed += info.compress_size
        assessment = assess_member(info, destination, policy_root, policy, state)
        state.member_index += 1
        target = assessment.target
        member_violations = assessment.violations
        violations.extend(member_violations)

        if assessment.has_errors:
            results.append(
                _member_result(info, MemberStatus.FAILED, target, 0, member_violations)
            )
            continue
        if assessment.should_skip:
            results.append(
                _member_result(info, MemberStatus.SKIPPED, target, 0, member_violations)
            )
            continue
        for violation in member_violations:
            warnings.warn(violation.message, stacklevel=_WARN_STACKLEVEL)

        if policy.preview_only:
            results.append(
                _member_result(
                    info, MemberStatus.PREVIEWED, target, 0, member_violations
                )
            )
            continue

        assert target is not None
        target = _unique_target(target, policy)
        was_existing = target.exists()
        quota = ExtractionQuota(member_limit, total_limit, total_written)
        try:
            materialized = materialize(info, target, quota)
        except ExtractionQuotaExceeded as exc:
            code, message = exc.code, str(exc)
        except _MATERIALIZATION_ERRORS as exc:
            code, message = "extraction_error", str(exc)
        else:
            total_written += materialized.bytes_written
            results.append(
                _member_result(
                    info,
                    MemberStatus.EXTRACTED,
                    materialized.target,
                    materialized.bytes_written,
                    member_violations,
                    was_existing,
                )
            )
            continue

        violation = ExtractViolation(
            info.filename, code, message, ViolationAction.ERROR, target
        )
        violations.append(violation)
        results.append(
            _member_result(
                info,
                MemberStatus.FAILED,
                target,
                0,
                member_violations + (violation,),
            )
        )

    extracted = sum(r.status == MemberStatus.EXTRACTED for r in results)
    skipped = sum(
        r.status in (MemberStatus.SKIPPED, MemberStatus.PREVIEWED) for r in results
    )
    failed = sum(r.status == MemberStatus.FAILED for r in results)
    if any(v.action == ViolationAction.ERROR for v in violations):
        failed = max(failed, 1)
    return ExtractResult(
        destination,
        tuple(results),
        tuple(violations),
        extracted,
        skipped,
        failed,
        sum(r.bytes_written for r in results),
        policy.preview_only,
    )
