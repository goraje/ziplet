from __future__ import annotations

import os
from pathlib import Path

import pytest

from ziplet.zipfile.secure_fs import SecureExtractionRoot

posix_only = pytest.mark.skipif(os.name != "posix", reason="requires dir_fd support")


@pytest.fixture(params=["descriptor", "path_fallback"])
def root(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> SecureExtractionRoot:
    if request.param == "path_fallback":
        monkeypatch.setattr(
            SecureExtractionRoot, "descriptor_supported", property(lambda self: False)
        )
    elif os.name != "posix":
        pytest.skip("requires dir_fd support")
    return SecureExtractionRoot(tmp_path / "root")


def _close(fd: int | None) -> None:
    if fd is not None:
        os.close(fd)


def test_enter_creates_root_and_exit_releases_descriptor(
    root: SecureExtractionRoot,
) -> None:
    with root:
        assert root.path.is_dir()
    assert root._descriptor is None


def test_ensure_parents_creates_nested_directories(root: SecureExtractionRoot) -> None:
    with root:
        fd = root.ensure_parents(("a", "b", "c"))
        try:
            assert (root.path / "a" / "b" / "c").is_dir()
            assert (fd is None) == (root._descriptor is None)
        finally:
            _close(fd)


def test_ensure_parents_accepts_existing_directories(
    root: SecureExtractionRoot,
) -> None:
    (root.path / "a").mkdir(parents=True)
    with root:
        _close(root.ensure_parents(("a",)))
        _close(root.ensure_parents(("a",)))


def test_ensure_parents_with_no_parts_returns_root(root: SecureExtractionRoot) -> None:
    with root:
        fd = root.ensure_parents(())
        try:
            assert (fd is None) == (root._descriptor is None)
        finally:
            _close(fd)


@posix_only
def test_ensure_parents_refuses_symlink_component(root: SecureExtractionRoot) -> None:
    outside = root.path.parent / "outside"
    outside.mkdir()
    root.path.mkdir()
    (root.path / "link").symlink_to(outside, target_is_directory=True)
    with root, pytest.raises(ValueError, match="unsafe extraction path"):
        root.ensure_parents(("link", "child"))
    assert list(outside.iterdir()) == []


@posix_only
def test_ensure_parents_refuses_dangling_symlink_component(
    root: SecureExtractionRoot,
) -> None:
    root.path.mkdir()
    (root.path / "link").symlink_to(root.path.parent / "missing")
    with root, pytest.raises(ValueError, match="unsafe extraction path"):
        root.ensure_parents(("link",))
    assert not (root.path.parent / "missing").exists()


def test_ensure_parents_refuses_file_component(root: SecureExtractionRoot) -> None:
    root.path.mkdir()
    (root.path / "file").write_text("x")
    with root, pytest.raises(ValueError, match="unsafe extraction path"):
        root.ensure_parents(("file", "child"))


@posix_only
def test_descriptor_closed_after_ensure_parents_failure(
    tmp_path: Path,
) -> None:
    root = SecureExtractionRoot(tmp_path / "root")
    (tmp_path / "root").mkdir()
    (tmp_path / "root" / "file").write_text("x")
    before = len(os.listdir("/dev/fd"))
    with root, pytest.raises(ValueError, match="unsafe extraction path"):
        root.ensure_parents(("file",))
    assert len(os.listdir("/dev/fd")) == before
