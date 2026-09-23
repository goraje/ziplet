from pathlib import Path

import pytest

import ziplet


def test_inspection_does_not_open_payloads_or_modify_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "metadata-only.zip"
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("unchanged")
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("payload.txt", b"payload")

    with ziplet.ZipFile(archive) as zf:
        monkeypatch.setattr(
            zf,
            "open",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                AssertionError("inspection opened a payload")
            ),
        )
        report = zf.inspect(tmp_path / "output")

    assert report.members[0].member == "payload.txt"
    assert sentinel.read_text() == "unchanged"
    assert not (tmp_path / "output").exists()


def test_assess_returns_shared_archive_assessment(tmp_path: Path) -> None:
    archive = tmp_path / "assessment.zip"
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("payload.txt", b"payload")

    with ziplet.ZipFile(archive) as zf:
        assessment = zf.assess(tmp_path / "output")

    assert assessment.total_uncompressed_size == len(b"payload")
    assert assessment.members[0].info.filename == "payload.txt"
    assert not (tmp_path / "output").exists()


def test_assess_reports_archive_wide_policy_violations(tmp_path: Path) -> None:
    archive = tmp_path / "assessment-limits.zip"
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("first.txt", b"1234567890")
        zf.writestr("second.txt", b"more")

    with ziplet.ZipFile(archive) as zf:
        assessment = zf.assess(
            tmp_path / "output",
            ziplet.ExtractPolicy(
                max_entries=1,
                max_total_uncompressed_size=5,
                max_compression_ratio=None,
                on_violation=ziplet.ViolationAction.SKIP,
            ),
        )

    codes = {v.code for v in assessment.violations}
    assert "max_entries" in codes
    assert "max_total_uncompressed_size" in codes
    assert not (tmp_path / "output").exists()
