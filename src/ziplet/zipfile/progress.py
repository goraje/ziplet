"""Progress reporting for extraction."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum

from ziplet.zipfile.extract import MemberStatus
from ziplet.zipfile.info import ZipInfo

__all__ = [
    "ProgressCallback",
    "ProgressEvent",
    "ProgressPhase",
    "ProgressReporter",
    "propagate_callback_errors",
]

# A PROGRESS event is emitted at most once per this many bytes written.
_PROGRESS_STEP = 1 << 20


class ProgressPhase(str, Enum):
    START = "start"
    PROGRESS = "progress"
    FINISH = "finish"


@dataclass(frozen=True)
class ProgressEvent:
    """One progress notification.

    ``member_total`` and ``total_bytes`` are the sizes the archive *declares*,
    which a hostile archive can misstate, so treat them as hints.  ``status``
    is set on ``FINISH`` events only.
    """

    phase: ProgressPhase
    member: str
    member_index: int
    member_count: int
    member_bytes: int
    member_total: int
    total_bytes: int
    total_bytes_done: int
    status: MemberStatus | None = None


ProgressCallback = Callable[[ProgressEvent], None]


class _CallbackFailed(BaseException):
    """Carries an exception raised by a progress callback out of extraction.

    Policy extraction turns ordinary exceptions raised while writing a member
    into per-member failures.  A callback that raises to cancel must not be
    mistaken for one, so its exception travels as a ``BaseException`` and is
    unwrapped by :func:`propagate_callback_errors`.
    """

    def __init__(self, original: Exception) -> None:
        super().__init__(original)
        self.original = original


@contextmanager
def propagate_callback_errors() -> Iterator[None]:
    """Re-raise an exception raised by a progress callback unchanged."""
    try:
        yield
    except _CallbackFailed as failure:
        raise failure.original from None


class ProgressReporter:
    """Turns extraction steps into :class:`ProgressEvent` callbacks."""

    def __init__(
        self, callback: ProgressCallback, member_count: int, total_bytes: int
    ) -> None:
        self._callback = callback
        self._member_count = member_count
        self._total_bytes = total_bytes
        self._done_before_member = 0
        self._member: ZipInfo | None = None
        self._index = 0
        self._member_bytes = 0
        self._last_reported = 0

    def start(self, index: int, info: ZipInfo) -> None:
        self._member = info
        self._index = index
        self._member_bytes = 0
        self._last_reported = 0
        self._emit(ProgressPhase.START)

    def advance(self, nbytes: int) -> None:
        """Record *nbytes* written for the current member."""
        self._member_bytes += nbytes
        if self._member_bytes - self._last_reported >= _PROGRESS_STEP:
            self._last_reported = self._member_bytes
            self._emit(ProgressPhase.PROGRESS)

    def finish(self, status: MemberStatus, bytes_written: int) -> None:
        """Close the current member; *bytes_written* is what stayed on disk."""
        self._member_bytes = bytes_written
        self._done_before_member += bytes_written
        self._emit(ProgressPhase.FINISH, status, done=self._done_before_member)

    def _emit(
        self,
        phase: ProgressPhase,
        status: MemberStatus | None = None,
        done: int | None = None,
    ) -> None:
        assert self._member is not None
        event = ProgressEvent(
            phase,
            self._member.filename,
            self._index,
            self._member_count,
            self._member_bytes,
            self._member.file_size,
            self._total_bytes,
            self._done_before_member + self._member_bytes if done is None else done,
            status,
        )
        try:
            self._callback(event)
        except Exception as exc:
            raise _CallbackFailed(exc) from exc
