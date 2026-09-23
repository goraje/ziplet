"""Exceptions mirroring the standard library ``zipfile`` module.

Extraction-policy failures live in :mod:`ziplet.zipfile.exceptions`.
"""

from __future__ import annotations

__all__ = ["BadZipFile", "LargeZipFile"]


class BadZipFile(Exception):
    """Raised when a file is not a valid ZIP archive or is corrupt."""


class LargeZipFile(Exception):
    """Raised when writing a zipfile that requires ZIP64 extensions
    and they are disabled."""
