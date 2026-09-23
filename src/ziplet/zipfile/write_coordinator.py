"""Archive-level coordination for the single active ZIP writer."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum


class WriterArchiveState(str, Enum):
    IDLE = "idle"
    ACTIVE = "active"
    FINALIZING = "finalizing"
    FAILED = "failed"


@dataclass(frozen=True)
class WriterReservation:
    """Opaque identity used to prevent stale writer cleanup."""

    identity: object


class WriteCoordinator:
    """Own archive-level writer reservation and notification state."""

    def __init__(self, lock: threading.RLock) -> None:
        self._condition = threading.Condition(lock)
        self._state = WriterArchiveState.IDLE
        self._reservation: WriterReservation | None = None

    @property
    def condition(self) -> threading.Condition:
        return self._condition

    @property
    def active(self) -> bool:
        """Whether a writer currently holds (or is finalizing) a reservation.

        ``FAILED`` is deliberately excluded: it's a terminal state reached
        after a write already released its reservation (see :meth:`fail`),
        and nothing should stay blocked because of a writer that no longer
        exists. Without this, the archive would be permanently unusable
        after any single failed write.
        """
        return self._state in (
            WriterArchiveState.ACTIVE,
            WriterArchiveState.FINALIZING,
        )

    def reserve(self) -> WriterReservation:
        with self._condition:
            if self.active:
                raise ValueError(
                    "Can't write to the ZIP file while there is "
                    "another write handle open"
                )
            reservation = WriterReservation(object())
            self._reservation = reservation
            self._state = WriterArchiveState.ACTIVE
            return reservation

    def begin_finalization(self, reservation: WriterReservation) -> None:
        with self._condition:
            self._require(reservation)
            self._state = WriterArchiveState.FINALIZING

    def commit(self, reservation: WriterReservation) -> None:
        with self._condition:
            self._require(reservation)
            self._state = WriterArchiveState.IDLE
            self._reservation = None
            self._condition.notify_all()

    def fail(self, reservation: WriterReservation) -> None:
        with self._condition:
            self._require(reservation)
            self._state = WriterArchiveState.FAILED
            self._reservation = None
            self._condition.notify_all()

    def release(self, reservation: WriterReservation) -> None:
        with self._condition:
            if self._reservation == reservation:
                self._state = WriterArchiveState.IDLE
                self._reservation = None
                self._condition.notify_all()

    def wait_for_finalization(self) -> None:
        with self._condition:
            if self._state == WriterArchiveState.FINALIZING:
                self._condition.wait_for(lambda: not self.active)

    def ensure_readable(self) -> None:
        with self._condition:
            if self.active:
                raise ValueError(
                    "Can't read from the ZIP file while there is an open writing "
                    "handle on it. Close the writing handle before trying to read."
                )

    def ensure_writable(self) -> None:
        with self._condition:
            if self.active:
                raise ValueError(
                    "Can't write to ZIP archive while an open writing handle exists"
                )

    def _require(self, reservation: WriterReservation) -> None:
        if self._reservation != reservation:
            raise RuntimeError("ZIP writer reservation is no longer active")
