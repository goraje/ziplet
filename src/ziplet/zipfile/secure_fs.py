"""Secure extraction-root primitives.

The descriptor-backed implementation is used on platforms exposing the
required POSIX APIs.  The path-based fallback remains available for Windows
and other platforms where ``dir_fd``/``O_NOFOLLOW`` are not consistently
provided by Python.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path


class SecureExtractionRoot:
    """Create extraction parents without following existing symlink components."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._descriptor: int | None = None

    @property
    def descriptor_supported(self) -> bool:
        return (
            os.name == "posix"
            and hasattr(os, "O_NOFOLLOW")
            and os.mkdir in os.supports_dir_fd
            and os.open in os.supports_dir_fd
        )

    def __enter__(self) -> SecureExtractionRoot:
        self.path.mkdir(parents=True, exist_ok=True)
        if self.descriptor_supported:
            self._descriptor = os.open(
                self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None

    def ensure_parents(self, relative_parts: tuple[str, ...]) -> int | None:
        """Create and validate parent directories for a relative member path.

        Where descriptor support exists, each component is created and opened
        relative to its parent descriptor with ``O_NOFOLLOW``, so no
        check-then-act window exists between validation and use. Returns an
        open descriptor for the final directory; the caller owns it and must
        close it. Returns ``None`` on the path-based fallback.
        """
        if self._descriptor is None:
            current = self.path
            for part in relative_parts:
                current /= part
                if current.is_symlink():
                    raise ValueError("Refusing to traverse unsafe extraction path")
                if current.exists() and not current.is_dir():
                    raise ValueError("Refusing to traverse unsafe extraction path")
                current.mkdir(exist_ok=True)
            return None
        fd = os.dup(self._descriptor)
        try:
            for part in relative_parts:
                try:
                    os.mkdir(part, dir_fd=fd)
                except FileExistsError:
                    pass
                try:
                    child = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=fd,
                    )
                except OSError as exc:
                    if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                        raise ValueError(
                            "Refusing to traverse unsafe extraction path"
                        ) from exc
                    raise
                os.close(fd)
                fd = child
        except BaseException:
            os.close(fd)
            raise
        return fd


def _parts_below(path: str, root: str) -> tuple[str, ...]:
    """Return *path*'s components below *root*, matching it textually.

    Both the given and the symlink-resolved spelling of *root* are tried,
    because policy extraction hands over already-resolved targets.
    """
    for candidate in (os.path.abspath(root), os.path.realpath(root)):
        parts = tuple(
            part
            for part in os.path.relpath(path, candidate).split(os.sep)
            if part and part != os.curdir
        )
        if os.pardir not in parts:
            return parts
    raise ValueError("Refusing to extract outside the destination")


def open_secure_parent(path: str, root: str) -> int | None:
    """Create *path* below *root* without following symlinks beneath *root*.

    *root* is the caller's chosen destination and is trusted, so symlinks in
    its own path (``/tmp`` on macOS, a symlinked home directory) are resolved.
    Only components below it, which archive contents can influence, are
    refused when they are symlinks.

    Returns an open descriptor for the final directory where the platform
    supports ``dir_fd``-relative operations, ``None`` otherwise. The caller
    owns the descriptor and must close it, which keeps the guard alive
    through the caller's own leaf write.

    Raises:
        ValueError: If *path* is outside *root* or crosses a symlink or file.
    """
    parts = _parts_below(path, root)
    with SecureExtractionRoot(Path(os.path.realpath(root))) as secure_root:
        return secure_root.ensure_parents(parts)
