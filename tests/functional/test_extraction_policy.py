from __future__ import annotations

import io
import os
import stat
from pathlib import Path

import pytest

import ziplet
from ziplet.zipfile.info import ZipInfo


def test_policy_extracts_mixed_archive_with_member_results(tmp_path: Path) -> None:
    archive = tmp_path / "policy.zip"
    destination = tmp_path / "extracted"
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("docs/readme.txt", b"readme")
        zf.writestr("data.bin", b"data")
        zf.writestr("../outside.txt", b"blocked")

    with ziplet.ZipFile(archive) as zf:
        result = zf.extractall(
            destination,
            policy=ziplet.ExtractPolicy(
                max_compression_ratio=None,
                on_violation=ziplet.ViolationAction.SKIP,
            ),
        )

    assert result.extracted_count == 2
    assert result.skipped_count == 1
    assert [member.status for member in result.members] == [
        ziplet.MemberStatus.EXTRACTED,
        ziplet.MemberStatus.EXTRACTED,
        ziplet.MemberStatus.SKIPPED,
    ]
    assert (destination / "docs/readme.txt").read_bytes() == b"readme"
    assert (destination / "data.bin").read_bytes() == b"data"
    assert not (tmp_path / "outside.txt").exists()


def test_policy_preview_is_a_real_dry_run(tmp_path: Path) -> None:
    archive = tmp_path / "preview.zip"
    destination = tmp_path / "preview"
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("file.txt", b"payload")

    with ziplet.ZipFile(archive) as zf:
        result = zf.extractall(
            destination,
            policy=ziplet.ExtractPolicy(
                max_compression_ratio=None,
                preview_only=True,
            ),
        )

    assert result.preview_only
    assert result.extracted_count == 0
    assert result.members[0].status == ziplet.MemberStatus.PREVIEWED
    assert not destination.exists()


def test_runtime_quota_preserves_existing_file(tmp_path: Path) -> None:
    archive = tmp_path / "quota.zip"
    destination = tmp_path / "out"
    destination.mkdir()
    existing = destination / "second.txt"
    existing.write_bytes(b"original")

    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("first.txt", b"1234")
        zf.writestr("second.txt", b"replacement")

    with ziplet.ZipFile(archive) as zf:
        with pytest.warns(
            UserWarning, match="total declared uncompressed size exceeds policy limit"
        ):
            with pytest.raises(ziplet.ExtractionError):
                zf.extractall(
                    destination,
                    policy=ziplet.ExtractPolicy(
                        max_total_uncompressed_size=5,
                        on_violation=ziplet.ViolationAction.WARN,
                        overwrite_policy=ziplet.OverwritePolicy.REPLACE,
                    ),
                )

    assert existing.read_bytes() == b"original"
    assert not list(destination.glob(".ziplet-*"))


def test_allowed_symlink_is_materialized_without_following_it(tmp_path: Path) -> None:
    archive = tmp_path / "symlink.zip"
    destination = tmp_path / "out"
    info = ZipInfo("link")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr(info, b"target.txt")

    with ziplet.ZipFile(archive) as zf:
        result = zf.extractall(
            destination,
            policy=ziplet.ExtractPolicy(
                allow_symlinks=True,
                max_compression_ratio=None,
            ),
        )

    link = destination / "link"
    assert result.extracted_count == 1
    assert link.is_symlink()
    assert os.readlink(link) == "target.txt"


def test_warn_still_rejects_path_escape(tmp_path: Path) -> None:
    archive = tmp_path / "escape.zip"
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("../outside.txt", b"blocked")

    with ziplet.ZipFile(archive) as zf:
        with pytest.raises(ziplet.ExtractionError):
            zf.extractall(
                tmp_path / "out",
                policy=ziplet.ExtractPolicy(
                    on_violation=ziplet.ViolationAction.WARN,
                    max_compression_ratio=None,
                ),
            )


def test_existing_symlink_directory_is_not_followed(tmp_path: Path) -> None:
    archive = tmp_path / "symlink-dir.zip"
    destination = tmp_path / "out"
    outside = tmp_path / "outside"
    destination.mkdir()
    outside.mkdir()
    (destination / "nested").symlink_to(outside, target_is_directory=True)
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("nested/payload.txt", b"blocked")

    with ziplet.ZipFile(archive) as zf:
        with pytest.raises(ziplet.ExtractionError):
            zf.extractall(
                destination,
                policy=ziplet.ExtractPolicy(max_compression_ratio=None),
            )

    assert not (outside / "payload.txt").exists()


def test_extract_policy_rule_overrides_default_violation_action(tmp_path: Path) -> None:
    archive = tmp_path / "rule-override.zip"
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("safe.txt", b"safe")
        zf.writestr("/absolute.txt", b"blocked-by-default")
        zf.writestr("../escape.txt", b"blocked-by-rule")

    with ziplet.ZipFile(archive) as zf:
        with pytest.raises(ziplet.ExtractionError) as excinfo:
            zf.extractall(
                tmp_path / "out",
                policy=ziplet.ExtractPolicy(
                    max_compression_ratio=None,
                    on_violation=ziplet.ViolationAction.SKIP,
                    allow_parent_traversal=ziplet.ExtractPolicyRule(
                        False, on_violation=ziplet.ViolationAction.ERROR
                    ),
                ),
            )

    result = excinfo.value.result
    assert result.extracted_count == 1
    assert result.skipped_count == 1
    assert result.failed_count == 1
    actions_by_code = {v.code: v.action for v in result.violations}
    assert actions_by_code["absolute_path"] == ziplet.ViolationAction.SKIP
    assert actions_by_code["parent_traversal"] == ziplet.ViolationAction.ERROR


def test_plain_extract_symlink_escape_raises_security_error(tmp_path: Path) -> None:
    archive = tmp_path / "symlink-escape.zip"
    link = ZipInfo("link")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr(link, "../outside")

    with ziplet.ZipFile(archive) as zf:
        with pytest.raises(ziplet.ExtractionSecurityError):
            zf.extract("link", tmp_path / "out")


def test_plain_extract_unsupported_special_file_raises_materialization_error(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "special-file.zip"
    device = ZipInfo("device")
    device.external_attr = stat.S_IFCHR << 16
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr(device, b"")

    with ziplet.ZipFile(archive) as zf:
        with pytest.raises(ziplet.ExtractionMaterializationError):
            zf.extract("device", tmp_path / "out")


def test_extract_policy_marks_overwritten_members(tmp_path: Path) -> None:
    archive = tmp_path / "overwrite.zip"
    destination = tmp_path / "out"
    destination.mkdir()
    (destination / "existing.txt").write_bytes(b"stale")
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("existing.txt", b"fresh")
        zf.writestr("new.txt", b"new")

    with ziplet.ZipFile(archive) as zf:
        result = zf.extractall(
            destination,
            policy=ziplet.ExtractPolicy(
                max_compression_ratio=None,
                overwrite_policy=ziplet.OverwritePolicy.REPLACE,
            ),
        )

    results_by_name = {r.member: r for r in result.members}
    assert results_by_name["existing.txt"].overwritten is True
    assert results_by_name["new.txt"].overwritten is False
    assert (destination / "existing.txt").read_bytes() == b"fresh"


def test_dir_fd_relative_directory_materialization_rejects_leaf_symlink(
    tmp_path: Path,
) -> None:
    """A directory *entry* (not an intermediate path component) whose leaf
    name is already a symlink must be rejected via the dir_fd-relative
    check in _materialize_directory, not just the path-based intermediate
    walk that test_existing_symlink_directory_is_not_followed covers."""
    archive = tmp_path / "leaf-symlink-dir.zip"
    destination = tmp_path / "out"
    outside = tmp_path / "outside"
    destination.mkdir()
    outside.mkdir()
    (destination / "payload").symlink_to(outside, target_is_directory=True)
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("payload/", b"")

    with ziplet.ZipFile(archive) as zf:
        with pytest.raises(ziplet.ExtractionSecurityError):
            zf.extract("payload/", destination)

    assert (destination / "payload").is_symlink()


def test_dir_fd_relative_regular_file_replaces_leaf_symlink_without_following(
    tmp_path: Path,
) -> None:
    """Regular-file materialization now also goes through the dir_fd-relative
    path (rename relative to the validated parent). A pre-existing symlink
    at the leaf name must be replaced outright, never followed to write
    through it to wherever it points."""
    archive = tmp_path / "leaf-symlink-file.zip"
    destination = tmp_path / "out"
    outside = tmp_path / "outside.txt"
    destination.mkdir()
    outside.write_bytes(b"original-outside-content")
    (destination / "payload.txt").symlink_to(outside)
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("payload.txt", b"new-content")

    with ziplet.ZipFile(archive) as zf:
        zf.extract("payload.txt", destination)

    assert not (destination / "payload.txt").is_symlink()
    assert (destination / "payload.txt").read_bytes() == b"new-content"
    assert outside.read_bytes() == b"original-outside-content"


@pytest.mark.parametrize(("fsync_files", "expected_calls"), [(True, 2), (False, 0)])
def test_fsync_files_policy_controls_fsync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fsync_files: bool,
    expected_calls: int,
) -> None:
    archive = tmp_path / "a.zip"
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("one.txt", b"1")
        zf.writestr("two.txt", b"2")
    calls: list[int] = []
    real_fsync = os.fsync

    def recording_fsync(fd: int) -> None:
        calls.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", recording_fsync)

    with ziplet.ZipFile(archive) as zf:
        zf.extractall(
            tmp_path / "out", policy=ziplet.ExtractPolicy(fsync_files=fsync_files)
        )

    assert len(calls) == expected_calls
    assert (tmp_path / "out" / "two.txt").read_bytes() == b"2"


def _five_entry_archive() -> io.BytesIO:
    buffer = io.BytesIO()
    with ziplet.ZipFile(buffer, "w") as zf:
        for index in range(5):
            zf.writestr(f"f{index}.txt", b"x")
    return io.BytesIO(buffer.getvalue())


def _count_violations(result: ziplet.ExtractResult) -> list[str]:
    return [v.member for v in result.violations if v.code == "max_entries"]


def test_max_entries_error_extracts_nothing_and_reports_once(tmp_path: Path) -> None:
    policy = ziplet.ExtractPolicy(max_entries=3)
    with ziplet.ZipFile(_five_entry_archive()) as zf:
        with pytest.raises(ziplet.ExtractionError) as excinfo:
            zf.extractall(tmp_path / "out", policy=policy)

    result = excinfo.value.result
    assert not (tmp_path / "out").exists() or not list((tmp_path / "out").iterdir())
    assert (result.extracted_count, result.failed_count) == (0, 5)
    assert _count_violations(result) == ["<archive>"]
    assert all(m.status == ziplet.MemberStatus.FAILED for m in result.members)


def test_max_entries_skip_extracts_only_the_first_entries(tmp_path: Path) -> None:
    policy = ziplet.ExtractPolicy(
        max_entries=3, on_violation=ziplet.ViolationAction.SKIP
    )
    with ziplet.ZipFile(_five_entry_archive()) as zf:
        result = zf.extractall(tmp_path, policy=policy)

    assert sorted(p.name for p in tmp_path.iterdir()) == ["f0.txt", "f1.txt", "f2.txt"]
    assert (result.extracted_count, result.skipped_count) == (3, 2)
    assert _count_violations(result) == ["<archive>"]


def test_max_entries_warn_extracts_everything_with_one_warning(tmp_path: Path) -> None:
    policy = ziplet.ExtractPolicy(
        max_entries=3, on_violation=ziplet.ViolationAction.WARN
    )
    with ziplet.ZipFile(_five_entry_archive()) as zf:
        with pytest.warns(UserWarning, match="limit is 3") as caught:
            result = zf.extractall(tmp_path, policy=policy)

    assert len(caught) == 1
    assert result.extracted_count == 5
    assert _count_violations(result) == ["<archive>"]


def test_inspection_reports_entry_count_once() -> None:
    policy = ziplet.ExtractPolicy(max_entries=3)
    with ziplet.ZipFile(_five_entry_archive()) as zf:
        report = zf.inspect(policy=policy)

    assert report.member_count_over_limit
    assert [v.member for v in report.violations if v.code == "max_entries"] == [
        "<archive>"
    ]


def _reject_temp_files(info: ZipInfo, target: Path) -> None:
    if info.filename.endswith(".tmp"):
        raise ValueError(f"{info.filename}: temporary files are not allowed")


def _reject_large_names(info: ZipInfo, target: Path) -> None:
    if len(info.filename) > 8:
        raise ValueError(f"{info.filename}: name is too long")


def _custom_archive() -> io.BytesIO:
    buffer = io.BytesIO()
    with ziplet.ZipFile(buffer, "w") as zf:
        zf.writestr("ok.txt", b"1")
        zf.writestr("a.tmp", b"2")
        zf.writestr("very_long_name.tmp", b"3")
    return io.BytesIO(buffer.getvalue())


def _custom_messages(assessment: ziplet.ArchiveAssessment) -> list[str]:
    return [v.message for v in assessment.violations if v.code == "custom_validator"]


def test_single_custom_validator_still_works(tmp_path: Path) -> None:
    policy = ziplet.ExtractPolicy(custom_validator=_reject_temp_files)
    with ziplet.ZipFile(_custom_archive()) as zf:
        assessment = zf.assess(tmp_path, policy)
    assert _custom_messages(assessment) == [
        "a.tmp: temporary files are not allowed",
        "very_long_name.tmp: temporary files are not allowed",
    ]


def test_custom_validator_chain_reports_every_rejection(tmp_path: Path) -> None:
    policy = ziplet.ExtractPolicy(
        custom_validator=(_reject_temp_files, _reject_large_names)
    )
    with ziplet.ZipFile(_custom_archive()) as zf:
        assessment = zf.assess(tmp_path, policy)
    assert _custom_messages(assessment) == [
        "a.tmp: temporary files are not allowed",
        "very_long_name.tmp: temporary files are not allowed",
        "very_long_name.tmp: name is too long",
    ]
    ok, temp, long_temp = assessment.members
    assert not ok.violations
    assert len(temp.violations) == 1
    assert len(long_temp.violations) == 2


def test_custom_validator_chain_can_skip_members(tmp_path: Path) -> None:
    policy = ziplet.ExtractPolicy(
        custom_validator=[_reject_temp_files, _reject_large_names],
        on_violation=ziplet.ViolationAction.SKIP,
    )
    with ziplet.ZipFile(_custom_archive()) as zf:
        result = zf.extractall(tmp_path, policy=policy)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["ok.txt"]
    assert (result.extracted_count, result.skipped_count) == (1, 2)


def test_custom_validator_unexpected_error_propagates(tmp_path: Path) -> None:
    def broken(info: ZipInfo, target: Path) -> None:
        raise KeyError("bug in validator")

    with ziplet.ZipFile(_custom_archive()) as zf:
        with pytest.raises(KeyError):
            zf.assess(tmp_path, ziplet.ExtractPolicy(custom_validator=broken))
