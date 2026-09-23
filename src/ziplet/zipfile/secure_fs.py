"""Secure extraction-root primitives.

The descriptor-backed implementation is used on platforms exposing the
required POSIX APIs.  The path-based fallback remains available for Windows
and other platforms where ``dir_fd``/``O_NOFOLLOW`` are not consistently
provided by Python.
"""

from __future__ import annotations

import os
from pathlib import Path


class SecureExtractionRoot:
    """Create extraction parents without following existing symlink components."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._descriptor: int | None = None

    @property
    def descriptor_supported(self) -> bool:
        return os.name == "posix" and hasattr(os, "O_NOFOLLOW")

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

    def ensure_parents(self, relative_parts: tuple[str, ...]) -> Path:
        """Create and validate parent directories for a relative member path."""
        current = self.path
        for part in relative_parts:
            current /= part
            if current.is_symlink():
                raise ValueError("Refusing to traverse unsafe extraction path")
            if current.exists() and not current.is_dir():
                raise ValueError("Refusing to traverse unsafe extraction path")
            current.mkdir(exist_ok=True)
        return current

    def open_leaf_parent(self, parent: Path) -> int | None:
        """Open a NOFOLLOW dir_fd for *parent*, already validated by
        :meth:`ensure_parents`, so a caller can perform a ``dir_fd``-relative
        leaf write without a TOCTOU window between validation and the write.

        Returns ``None`` where descriptor support is unavailable. The caller
        owns the returned descriptor and must close it.
        """
        if not self.descriptor_supported:
            return None
        return os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
