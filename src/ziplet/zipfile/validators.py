"""Composable metadata validators for policy-enabled extraction."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ziplet.exceptions import BadZipFile
from ziplet.zipfile.assessment import ExtractionContext, ValidationState
from ziplet.zipfile.extract import (
    ExtractViolation,
    OverwritePolicy,
    ViolationAction,
    compression_ratio,
    resolve_rule,
)
from ziplet.zipfile.info import ZipInfo

_WINDOWS_ILLEGAL_NAME_CHARS = ':<>|"?*'
_WINDOWS_ILLEGAL_NAME_TABLE = str.maketrans(
    _WINDOWS_ILLEGAL_NAME_CHARS, "_" * len(_WINDOWS_ILLEGAL_NAME_CHARS)
)


@dataclass(frozen=True)
class ValidatorParams:
    """Bundles one member validator call's arguments.

    A validator only reads the fields it needs — no unused-parameter
    ceremony for the checks that ignore ``target`` or ``state``.
    """

    info: ZipInfo
    target: Path
    context: ExtractionContext
    state: ValidationState


class MemberValidator(Protocol):
    """Protocol implemented by one metadata-only member validator."""

    def __call__(self, params: ValidatorParams) -> Iterable[ExtractViolation]: ...


class ValidatorPipeline:
    """Run validators in a deterministic order."""

    def __init__(self, validators: Iterable[MemberValidator]) -> None:
        self._validators = tuple(validators)

    def validate(self, params: ValidatorParams) -> list[ExtractViolation]:
        violations: list[ExtractViolation] = []
        for validator in self._validators:
            violations.extend(validator(params))
        return violations


def _violation(
    info: ZipInfo,
    code: str,
    message: str,
    target: Path | None = None,
    action: ViolationAction = ViolationAction.ERROR,
) -> ExtractViolation:
    return ExtractViolation(info.filename, code, message, action, target)


def entry_mode(info: ZipInfo) -> int:
    return (info.external_attr >> 16) & 0o170000


def entry_type(info: ZipInfo) -> tuple[bool, bool]:
    mode = entry_mode(info)
    is_symlink = stat.S_ISLNK(mode)
    is_special = bool(
        mode and not is_symlink and not stat.S_ISREG(mode) and not stat.S_ISDIR(mode)
    )
    return is_symlink, is_special


def has_parent_component(raw_name: str) -> bool:
    """Return whether *raw_name* contains a ``..`` path component.

    Both ``/`` and ``\\`` count as separators, since archives written on
    Windows may use either.
    """
    return ".." in raw_name.replace("\\", "/").split("/")


def _sanitize_windows_name(arcname: str, pathsep: str) -> str:
    """Sanitize *arcname* for extraction on a Windows filesystem.

    Replaces characters illegal in Windows filenames with underscores and
    strips trailing spaces and dots from each path component.
    """
    arcname = arcname.translate(_WINDOWS_ILLEGAL_NAME_TABLE)
    parts = (x.rstrip(" .") for x in arcname.split(pathsep))
    return pathsep.join(x for x in parts if x)


def member_target_name(raw_name: str) -> tuple[str, list[str]]:
    target_name = raw_name.replace("/", os.path.sep)
    drive, _ = os.path.splitdrive(raw_name)
    if os.path.sep == "\\":
        target_name = _sanitize_windows_name(target_name, os.path.sep)
    parts = [
        part
        for part in target_name.split(os.path.sep)
        if part not in ("", os.path.curdir, os.path.pardir)
    ]
    return drive, parts


def resolve_extract_target(
    info: ZipInfo, destination: Path
) -> tuple[Path, str, list[str]]:
    """Resolve the filesystem target for *info*. Pure — produces no violations."""
    drive, parts = member_target_name(info.orig_filename)
    target = (destination / os.path.sep.join(parts)).resolve()
    return target, drive, parts


def check_absolute_path(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, context = params.info, params.context
    rule = resolve_rule(
        context.policy.allow_absolute_paths, context.policy.on_violation
    )
    if os.path.isabs(info.orig_filename) and not rule.value:
        yield _violation(
            info, "absolute_path", "absolute path is not allowed", action=rule.action
        )


def check_windows_drive_and_unc(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, context = params.info, params.context
    raw = info.orig_filename
    drive, _ = os.path.splitdrive(raw)
    rule = resolve_rule(
        context.policy.allow_windows_drive_paths, context.policy.on_violation
    )
    if drive and not rule.value:
        yield _violation(
            info,
            "windows_drive_path",
            "Windows drive path is not allowed",
            action=rule.action,
        )
    if (drive or raw.startswith(("\\\\", "//"))) and not rule.value:
        yield _violation(
            info, "windows_path", "Windows UNC path is not allowed", action=rule.action
        )


def check_parent_traversal(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, context = params.info, params.context
    raw = info.orig_filename
    rule = resolve_rule(
        context.policy.allow_parent_traversal, context.policy.on_violation
    )
    if has_parent_component(raw) and not rule.value:
        yield _violation(
            info,
            "parent_traversal",
            "parent traversal is not allowed",
            action=rule.action,
        )


def check_outside_root(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, context = params.info, params.target, params.context
    try:
        target.relative_to(context.policy_root.resolve())
    except ValueError:
        yield _violation(
            info,
            "outside_root",
            "target escapes destination root",
            target,
            context.policy.on_violation,
        )


def check_duplicate_target(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, context, state = (
        params.info,
        params.target,
        params.context,
        params.state,
    )
    rule = resolve_rule(
        context.policy.reject_duplicate_targets, context.policy.on_violation
    )
    if target in state.targets and rule.value:
        yield _violation(
            info,
            "duplicate_target",
            f"target duplicates {state.targets[target]!r}",
            target,
            rule.action,
        )
    else:
        state.targets[target] = info.filename


def check_overwrite_conflict(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, policy = params.info, params.target, params.context.policy
    if (
        target.exists()
        and not policy.allow_overwrite
        and policy.overwrite_policy
        not in (OverwritePolicy.REPLACE, OverwritePolicy.RENAME)
    ):
        action = (
            ViolationAction.ERROR
            if policy.overwrite_policy == OverwritePolicy.ERROR
            else ViolationAction.SKIP
        )
        yield ExtractViolation(
            info.filename, "overwrite", "target already exists", action, target
        )


def check_max_member_size(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, context = params.info, params.target, params.context
    rule = resolve_rule(context.policy.max_member_size, context.policy.on_violation)
    if rule.value is not None and info.file_size > rule.value:
        yield _violation(
            info, "max_member_size", "member exceeds size limit", target, rule.action
        )


def check_compression_ratio(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, context = params.info, params.target, params.context
    rule = resolve_rule(
        context.policy.max_compression_ratio, context.policy.on_violation
    )
    ratio = compression_ratio(info)
    if rule.value is not None and ratio is not None and ratio > rule.value:
        yield _violation(
            info,
            "compression_ratio",
            "compression ratio exceeds limit",
            target,
            rule.action,
        )


def check_extension_allowed(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, context = params.info, params.target, params.context
    rule = resolve_rule(context.policy.allowed_extensions, context.policy.on_violation)
    suffix = Path(info.filename).suffix.lower()
    if rule.value is not None and suffix not in rule.value:
        yield _violation(
            info,
            "extension_not_allowed",
            "extension is not allowed",
            target,
            rule.action,
        )


def check_extension_blocked(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, context = params.info, params.target, params.context
    rule = resolve_rule(context.policy.blocked_extensions, context.policy.on_violation)
    suffix = Path(info.filename).suffix.lower()
    if rule.value is not None and suffix in rule.value:
        yield _violation(
            info, "extension_blocked", "extension is blocked", target, rule.action
        )


def check_symlink_allowed(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, context = params.info, params.target, params.context
    rule = resolve_rule(context.policy.allow_symlinks, context.policy.on_violation)
    mode = entry_mode(info)
    if stat.S_ISLNK(mode) and not rule.value:
        yield _violation(
            info, "symlink", "symlink extraction is not allowed", target, rule.action
        )


def check_special_file_allowed(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, context = params.info, params.target, params.context
    rule = resolve_rule(context.policy.allow_special_files, context.policy.on_violation)
    mode = entry_mode(info)
    if (
        mode
        and not stat.S_ISREG(mode)
        and not stat.S_ISDIR(mode)
        and not stat.S_ISLNK(mode)
        and not rule.value
    ):
        yield _violation(
            info,
            "special_file",
            "special file extraction is not allowed",
            target,
            rule.action,
        )


def check_utf8_name(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, context = params.info, params.target, params.context
    rule = resolve_rule(context.policy.require_utf8_names, context.policy.on_violation)
    if (
        rule.value
        and not info.is_utf_filename
        and any(ord(char) > 127 for char in info.orig_filename)
    ):
        yield _violation(
            info, "non_utf8_name", "member name is not UTF-8", target, rule.action
        )


def check_custom_validator(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, policy = params.info, params.target, params.context.policy
    if policy.custom_validator is not None:
        try:
            policy.custom_validator(info, target)
        except (OSError, ValueError, BadZipFile, RuntimeError) as exc:
            yield _violation(
                info, "custom_validator", str(exc), target, policy.on_violation
            )


def check_max_entries(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, context, state = (
        params.info,
        params.target,
        params.context,
        params.state,
    )
    rule = resolve_rule(context.policy.max_entries, context.policy.on_violation)
    if rule.value is not None and state.member_index >= rule.value:
        yield _violation(
            info,
            "max_entries",
            "archive entry count exceeds policy limit",
            target,
            rule.action,
        )


def check_total_uncompressed_size(
    params: ValidatorParams,
) -> Iterable[ExtractViolation]:
    info, target, context, state = (
        params.info,
        params.target,
        params.context,
        params.state,
    )
    rule = resolve_rule(
        context.policy.max_total_uncompressed_size, context.policy.on_violation
    )
    if rule.value is not None and state.total_declared > rule.value:
        yield _violation(
            info,
            "max_total_uncompressed_size",
            "total declared uncompressed size exceeds policy limit",
            target,
            rule.action,
        )


EXTRACT_VALIDATORS: tuple[MemberValidator, ...] = (
    check_absolute_path,
    check_windows_drive_and_unc,
    check_parent_traversal,
    check_outside_root,
    check_duplicate_target,
    check_overwrite_conflict,
    check_max_member_size,
    check_compression_ratio,
    check_extension_allowed,
    check_extension_blocked,
    check_symlink_allowed,
    check_special_file_allowed,
    check_utf8_name,
    check_custom_validator,
    check_max_entries,
    check_total_uncompressed_size,
)
