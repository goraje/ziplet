from __future__ import annotations

import threading
from collections.abc import Callable

import pytest

from ziplet.zipfile.write_coordinator import (
    WriteCoordinator,
    WriterArchiveState,
    WriterReservation,
)


@pytest.fixture
def coordinator() -> WriteCoordinator:
    return WriteCoordinator(threading.RLock())


def test_second_reserve_is_rejected_while_active(coordinator: WriteCoordinator) -> None:
    coordinator.reserve()
    with pytest.raises(ValueError, match="another write handle"):
        coordinator.reserve()


def test_commit_releases_archive(coordinator: WriteCoordinator) -> None:
    reservation = coordinator.reserve()
    coordinator.begin_finalization(reservation)
    assert coordinator.active
    coordinator.commit(reservation)
    assert not coordinator.active
    coordinator.reserve()


def test_failed_writer_does_not_lock_archive(coordinator: WriteCoordinator) -> None:
    reservation = coordinator.reserve()
    coordinator.fail(reservation)
    assert coordinator._state == WriterArchiveState.FAILED
    assert not coordinator.active
    coordinator.reserve()


def test_stale_reservation_cannot_commit_or_fail(coordinator: WriteCoordinator) -> None:
    stale = coordinator.reserve()
    coordinator.fail(stale)
    coordinator.reserve()
    for operation in (
        coordinator.begin_finalization,
        coordinator.commit,
        coordinator.fail,
    ):
        with pytest.raises(RuntimeError, match="no longer active"):
            operation(stale)


def test_stale_release_does_not_clobber_new_writer(
    coordinator: WriteCoordinator,
) -> None:
    stale = coordinator.reserve()
    coordinator.fail(stale)
    coordinator.reserve()
    coordinator.release(stale)
    assert coordinator.active


def test_release_of_current_reservation_returns_to_idle(
    coordinator: WriteCoordinator,
) -> None:
    reservation = coordinator.reserve()
    coordinator.release(reservation)
    assert not coordinator.active
    assert coordinator._state == WriterArchiveState.IDLE


@pytest.mark.parametrize(
    "check",
    [WriteCoordinator.ensure_readable, WriteCoordinator.ensure_writable],
    ids=["readable", "writable"],
)
def test_ensure_checks_block_only_while_active(
    coordinator: WriteCoordinator, check: Callable[[WriteCoordinator], None]
) -> None:
    check(coordinator)
    reservation = coordinator.reserve()
    with pytest.raises(ValueError, match="open writing handle"):
        check(coordinator)
    coordinator.commit(reservation)
    check(coordinator)


def test_wait_for_finalization_returns_immediately_when_not_finalizing(
    coordinator: WriteCoordinator,
) -> None:
    coordinator.wait_for_finalization()
    coordinator.reserve()
    coordinator.wait_for_finalization()


@pytest.mark.parametrize(
    "finish", [WriteCoordinator.commit, WriteCoordinator.fail], ids=["commit", "fail"]
)
def test_wait_for_finalization_blocks_until_writer_finishes(
    coordinator: WriteCoordinator,
    finish: Callable[[WriteCoordinator, WriterReservation], None],
) -> None:
    reservation = coordinator.reserve()
    coordinator.begin_finalization(reservation)
    waiting = threading.Event()
    done = threading.Event()

    def waiter() -> None:
        waiting.set()
        coordinator.wait_for_finalization()
        done.set()

    thread = threading.Thread(target=waiter)
    thread.start()
    assert waiting.wait(timeout=5)
    assert not done.wait(timeout=0.1)
    finish(coordinator, reservation)
    thread.join(timeout=5)
    assert done.is_set()
