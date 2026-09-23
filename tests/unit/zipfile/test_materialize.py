from __future__ import annotations

import io
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import IO

import pytest

from ziplet.zipfile.exceptions import (
    ExtractionMaterializationError,
    ExtractionQuotaExceeded,
    ExtractionSecurityError,
)
from ziplet.zipfile.info import ZipInfo
from ziplet.zipfile.materialize import (
    ExtractionQuota,
    MaterializationResult,
    materialize_directory,
    materialize_member,
    materialize_regular_file,
    materialize_special,
    materialize_symlink,
    select_materializer,
)

posix_only = pytest.mark.skipif(os.name != "posix", reason="requires POSIX")


@pytest.fixture(params=["descriptor", "path_fallback"])
def mode(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    if request.param == "path_fallback":
        monkeypatch.setattr(os, "supports_dir_fd", set())
    elif os.name != "posix":
        pytest.skip("requires dir_fd support")
    return str(request.param)


def _member(name: str, file_mode: int | None = None) -> ZipInfo:
    info = ZipInfo(name)
    if file_mode is not None:
        info.external_attr = file_mode << 16
    return info


def _opener(payload: bytes) -> Callable[[], IO[bytes]]:
    return lambda: io.BytesIO(payload)


def _extract(
    tmp_path: Path,
    name: str,
    payload: bytes = b"",
    file_mode: int | None = None,
    quota: ExtractionQuota | None = None,
) -> MaterializationResult:
    return materialize_member(
        _member(name, file_mode),
        str(tmp_path / name),
        _opener(payload),
        str(tmp_path),
        quota,
    )


def test_selects_materializer_by_entry_type() -> None:
    assert select_materializer(_member("d/")) is materialize_directory
    assert select_materializer(_member("f")) is materialize_regular_file
    assert select_materializer(_member("f", stat.S_IFREG | 0o644)) is (
        materialize_regular_file
    )
    assert select_materializer(_member("l", stat.S_IFLNK | 0o777)) is (
        materialize_symlink
    )
    assert select_materializer(_member("p", stat.S_IFIFO | 0o644)) is (
        materialize_special
    )


def test_regular_file_is_written_and_reports_size(mode: str, tmp_path: Path) -> None:
    result = _extract(tmp_path, "sub/f.txt", b"hello")
    assert (tmp_path / "sub" / "f.txt").read_bytes() == b"hello"
    assert result.bytes_written == 5
    assert not result.overwritten
    assert [p.name for p in (tmp_path / "sub").iterdir()] == ["f.txt"]


def test_regular_file_overwrite_is_reported(mode: str, tmp_path: Path) -> None:
    (tmp_path / "f.txt").write_bytes(b"old")
    result = _extract(tmp_path, "f.txt", b"new")
    assert result.overwritten
    assert (tmp_path / "f.txt").read_bytes() == b"new"


def test_regular_file_over_directory_is_refused(mode: str, tmp_path: Path) -> None:
    (tmp_path / "victim").mkdir()
    with pytest.raises(ExtractionMaterializationError, match="directory"):
        _extract(tmp_path, "victim", b"data")
    assert (tmp_path / "victim").is_dir()


@pytest.mark.parametrize(
    ("quota", "code"),
    [
        (ExtractionQuota(member_limit=4), "actual_member_size"),
        (
            ExtractionQuota(total_limit=10, total_written=8),
            "actual_total_uncompressed_size",
        ),
    ],
)
def test_quota_violation_keeps_existing_file_and_leaves_no_temp(
    mode: str, tmp_path: Path, quota: ExtractionQuota, code: str
) -> None:
    (tmp_path / "f.txt").write_bytes(b"keep")
    with pytest.raises(ExtractionQuotaExceeded) as excinfo:
        _extract(tmp_path, "f.txt", b"too much data", quota=quota)
    assert excinfo.value.code == code
    assert (tmp_path / "f.txt").read_bytes() == b"keep"
    assert [p.name for p in tmp_path.iterdir()] == ["f.txt"]


def test_quota_within_limits_succeeds(mode: str, tmp_path: Path) -> None:
    quota = ExtractionQuota(member_limit=5, total_limit=10, total_written=5)
    _extract(tmp_path, "f.txt", b"12345", quota=quota)
    assert (tmp_path / "f.txt").read_bytes() == b"12345"


def test_directory_created_then_reported_as_existing(mode: str, tmp_path: Path) -> None:
    first = _extract(tmp_path, "d/")
    second = _extract(tmp_path, "d/")
    assert (tmp_path / "d").is_dir()
    assert not first.overwritten
    assert second.overwritten


@posix_only
def test_directory_refuses_symlink_leaf(mode: str, tmp_path: Path) -> None:
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "d").symlink_to(tmp_path / "elsewhere", target_is_directory=True)
    with pytest.raises(ExtractionSecurityError):
        _extract(tmp_path, "d/")


@posix_only
def test_symlink_is_created_without_following(mode: str, tmp_path: Path) -> None:
    _extract(tmp_path, "link", b"target.txt", stat.S_IFLNK | 0o777)
    assert os.readlink(tmp_path / "link") == "target.txt"


@posix_only
def test_symlink_replaces_existing_file(mode: str, tmp_path: Path) -> None:
    (tmp_path / "link").write_text("old")
    result = _extract(tmp_path, "link", b"target.txt", stat.S_IFLNK | 0o777)
    assert result.overwritten
    assert os.readlink(tmp_path / "link") == "target.txt"


@posix_only
@pytest.mark.parametrize("link_target", [b"/etc/passwd", b"../escape", b"a/../../b"])
def test_symlink_escaping_root_is_refused(
    mode: str, tmp_path: Path, link_target: bytes
) -> None:
    with pytest.raises(ExtractionSecurityError):
        _extract(tmp_path, "link", link_target, stat.S_IFLNK | 0o777)
    assert not (tmp_path / "link").is_symlink()


@posix_only
def test_symlink_over_directory_is_refused(mode: str, tmp_path: Path) -> None:
    (tmp_path / "link").mkdir()
    with pytest.raises(ExtractionMaterializationError):
        _extract(tmp_path, "link", b"t", stat.S_IFLNK | 0o777)
    assert (tmp_path / "link").is_dir()


@posix_only
def test_fifo_is_created_with_member_permissions(tmp_path: Path) -> None:
    _extract(tmp_path, "pipe", b"", stat.S_IFIFO | 0o640)
    mode = (tmp_path / "pipe").stat().st_mode
    assert stat.S_ISFIFO(mode)
    assert stat.S_IMODE(mode) == 0o640 & ~os.umask(0)


def test_unsupported_special_file_type_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ExtractionMaterializationError, match="special file"):
        _extract(tmp_path, "dev", b"", stat.S_IFCHR | 0o600)


@posix_only
def test_destination_path_may_contain_symlinks(mode: str, tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    materialize_member(
        _member("sub/f.txt"),
        str(link / "sub" / "f.txt"),
        _opener(b"data"),
        str(link),
    )
    assert (real / "sub" / "f.txt").read_bytes() == b"data"


@posix_only
def test_symlink_below_destination_is_refused(mode: str, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "sub").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="unsafe extraction path"):
        materialize_member(
            _member("sub/f.txt"),
            str(dest / "sub" / "f.txt"),
            _opener(b"data"),
            str(dest),
        )
    assert list(outside.iterdir()) == []


def test_target_outside_destination_is_refused(mode: str, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="outside the destination"):
        materialize_member(
            _member("f.txt"),
            str(tmp_path / "other" / "f.txt"),
            _opener(b"data"),
            str(tmp_path / "dest"),
        )
