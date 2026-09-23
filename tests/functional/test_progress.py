from __future__ import annotations

import io
import os
import stat
from pathlib import Path

import pytest

import ziplet
from ziplet import MemberStatus, ProgressEvent, ProgressPhase
from ziplet.zipfile import materialize, progress
from ziplet.zipfile.info import ZipInfo

posix_only = pytest.mark.skipif(os.name != "posix", reason="requires symlinks")

START = ProgressPhase.START
PROGRESS = ProgressPhase.PROGRESS
FINISH = ProgressPhase.FINISH
BIG = 1_000_000


def _archive(files: dict[str, bytes]) -> io.BytesIO:
    buffer = io.BytesIO()
    with ziplet.ZipFile(buffer, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return io.BytesIO(buffer.getvalue())


def _phases(events: list[ProgressEvent]) -> list[tuple[ProgressPhase, str]]:
    return [(event.phase, event.member) for event in events]


@pytest.fixture
def small_step(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(progress, "_PROGRESS_STEP", 100_000)


def test_extractall_reports_start_and_finish_for_every_member(tmp_path: Path) -> None:
    events: list[ProgressEvent] = []
    files = {"a.txt": b"x" * 10, "d/": b"", "b.txt": b"y" * 20}
    with ziplet.ZipFile(_archive(files)) as zf:
        zf.extractall(tmp_path, progress=events.append)

    assert _phases(events) == [
        (START, "a.txt"),
        (FINISH, "a.txt"),
        (START, "d/"),
        (FINISH, "d/"),
        (START, "b.txt"),
        (FINISH, "b.txt"),
    ]
    assert [e.member_index for e in events] == [0, 0, 1, 1, 2, 2]
    assert {e.member_count for e in events} == {3}
    assert {e.total_bytes for e in events} == {30}
    finishes = [e for e in events if e.phase == FINISH]
    assert [e.status for e in finishes] == [MemberStatus.EXTRACTED] * 3
    assert [e.member_bytes for e in finishes] == [10, 0, 20]
    assert [e.total_bytes_done for e in finishes] == [10, 10, 30]
    assert (tmp_path / "b.txt").read_bytes() == b"y" * 20


def test_extract_single_member_reports_one_member(tmp_path: Path) -> None:
    events: list[ProgressEvent] = []
    with ziplet.ZipFile(_archive({"a.txt": b"abc", "b.txt": b"defg"})) as zf:
        zf.extract("b.txt", tmp_path, progress=events.append)

    assert _phases(events) == [(START, "b.txt"), (FINISH, "b.txt")]
    assert {e.member_count for e in events} == {1}
    assert events[-1].total_bytes_done == 4


def test_large_member_reports_byte_progress(small_step: None, tmp_path: Path) -> None:
    events: list[ProgressEvent] = []
    with ziplet.ZipFile(_archive({"big.bin": b"z" * BIG})) as zf:
        zf.extractall(tmp_path, progress=events.append)

    updates = [e for e in events if e.phase == PROGRESS]
    assert len(updates) >= 2
    sizes = [e.member_bytes for e in updates]
    assert sizes == sorted(sizes)
    assert all(0 < size <= BIG for size in sizes)
    assert [e.total_bytes_done for e in updates] == sizes
    assert events[0].phase == START
    assert events[-1].phase == FINISH
    assert events[-1].member_bytes == events[-1].member_total == BIG


@posix_only
def test_symlinks_and_directories_have_no_byte_progress(tmp_path: Path) -> None:
    link = ZipInfo("link")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    buffer = io.BytesIO()
    with ziplet.ZipFile(buffer, "w") as zf:
        zf.writestr("dir/", b"")
        zf.writestr(link, b"target.txt")
    events: list[ProgressEvent] = []
    with ziplet.ZipFile(io.BytesIO(buffer.getvalue())) as zf:
        zf.extractall(tmp_path, progress=events.append)
    assert {e.phase for e in events} == {START, FINISH}


def test_progress_none_installs_no_wrapper(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("progress wrapper used without a callback")

    monkeypatch.setattr(materialize, "_ProgressWriter", forbidden)
    with ziplet.ZipFile(_archive({"a.txt": b"abc"})) as zf:
        zf.extractall(tmp_path)
        zf.extractall(tmp_path / "policy", policy=ziplet.ExtractPolicy())
    assert (tmp_path / "policy" / "a.txt").read_bytes() == b"abc"


def test_unknown_member_fails_before_anything_is_extracted(tmp_path: Path) -> None:
    events: list[ProgressEvent] = []
    with ziplet.ZipFile(_archive({"a.txt": b"abc"})) as zf:
        with pytest.raises(KeyError):
            zf.extractall(tmp_path, ["a.txt", "missing.txt"], progress=events.append)
    assert events == []
    assert not (tmp_path / "a.txt").exists()


# --- policy path ---------------------------------------------------------


def test_policy_finish_carries_each_member_status(tmp_path: Path) -> None:
    events: list[ProgressEvent] = []
    files = {"ok.txt": b"fine", "../escape.txt": b"nope", "also.txt": b"fine"}
    policy = ziplet.ExtractPolicy(on_violation=ziplet.ViolationAction.SKIP)
    with ziplet.ZipFile(_archive(files)) as zf:
        zf.extractall(tmp_path / "out", policy=policy, progress=events.append)

    finishes = [e for e in events if e.phase == FINISH]
    assert [e.status for e in finishes] == [
        MemberStatus.EXTRACTED,
        MemberStatus.SKIPPED,
        MemberStatus.EXTRACTED,
    ]
    assert [e.member for e in events if e.phase == START] == list(files)


def test_policy_failed_and_previewed_statuses(tmp_path: Path) -> None:
    failed: list[ProgressEvent] = []
    with ziplet.ZipFile(_archive({"../escape.txt": b"nope"})) as zf:
        with pytest.raises(ziplet.ExtractionError):
            zf.extractall(
                tmp_path / "a", policy=ziplet.ExtractPolicy(), progress=failed.append
            )
    assert failed[-1].status == MemberStatus.FAILED

    previewed: list[ProgressEvent] = []
    with ziplet.ZipFile(_archive({"a.txt": b"abc"})) as zf:
        zf.extractall(
            tmp_path / "b",
            policy=ziplet.ExtractPolicy(preview_only=True),
            progress=previewed.append,
        )
    assert previewed[-1].status == MemberStatus.PREVIEWED
    assert not (tmp_path / "b").exists()


def test_entry_limit_skip_reports_skipped_members(tmp_path: Path) -> None:
    events: list[ProgressEvent] = []
    policy = ziplet.ExtractPolicy(
        max_entries=1, on_violation=ziplet.ViolationAction.SKIP
    )
    with ziplet.ZipFile(_archive({"a": b"1", "b": b"2", "c": b"3"})) as zf:
        zf.extractall(tmp_path, policy=policy, progress=events.append)
    finishes = [e for e in events if e.phase == FINISH]
    assert [e.status for e in finishes] == [
        MemberStatus.EXTRACTED,
        MemberStatus.SKIPPED,
        MemberStatus.SKIPPED,
    ]


def test_archive_rejected_by_entry_limit_emits_no_events(tmp_path: Path) -> None:
    events: list[ProgressEvent] = []
    with ziplet.ZipFile(_archive({"a": b"1", "b": b"2"})) as zf:
        with pytest.raises(ziplet.ExtractionError):
            zf.extractall(
                tmp_path,
                policy=ziplet.ExtractPolicy(max_entries=1),
                progress=events.append,
            )
    assert events == []


# --- cancellation --------------------------------------------------------


class Cancelled(Exception):
    pass


def _cancel_when(
    phase: ProgressPhase, member: str, error: Exception
) -> progress.ProgressCallback:
    def callback(event: ProgressEvent) -> None:
        if event.phase == phase and event.member == member:
            raise error

    return callback


@pytest.mark.parametrize("use_policy", [False, True])
def test_callback_can_cancel_between_members(tmp_path: Path, use_policy: bool) -> None:
    error = Cancelled("stop")
    callback = _cancel_when(START, "second.txt", error)
    policy = ziplet.ExtractPolicy() if use_policy else None
    with ziplet.ZipFile(_archive({"first.txt": b"1", "second.txt": b"2"})) as zf:
        with pytest.raises(Cancelled) as excinfo:
            zf.extractall(tmp_path, policy=policy, progress=callback)
    assert excinfo.value is error
    assert (tmp_path / "first.txt").exists()
    assert not (tmp_path / "second.txt").exists()


@pytest.mark.parametrize("error", [Cancelled("stop"), ValueError("v"), OSError("o")])
@pytest.mark.parametrize("use_policy", [False, True])
def test_callback_error_during_byte_progress_cancels_cleanly(
    small_step: None, tmp_path: Path, error: Exception, use_policy: bool
) -> None:
    """Errors the policy path would report as member failures must still cancel."""
    callback = _cancel_when(PROGRESS, "big.bin", error)
    policy = ziplet.ExtractPolicy() if use_policy else None
    files = {"first.txt": b"1", "big.bin": b"z" * BIG}
    with ziplet.ZipFile(_archive(files)) as zf:
        with pytest.raises(type(error)) as excinfo:
            zf.extractall(tmp_path, policy=policy, progress=callback)
    assert excinfo.value is error
    assert (tmp_path / "first.txt").exists()
    assert not (tmp_path / "big.bin").exists()
    assert not list(tmp_path.glob(".ziplet-*"))
