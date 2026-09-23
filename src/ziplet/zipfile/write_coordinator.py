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
    def state(self) -> WriterArchiveState:
        return self._state

    @property
    def active(self) -> bool:
        return self._state != WriterArchiveState.IDLE

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
                raise ValueError("Cannot read while a ZIP writer is active")

    def _require(self, reservation: WriterReservation) -> None:
        if self._reservation != reservation:
            raise RuntimeError("ZIP writer reservation is no longer active")
