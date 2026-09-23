"""Exceptions mirroring the standard library ``zipfile`` module.

Extraction-policy failures live in :mod:`ziplet.zipfile.exceptions`.
"""

from __future__ import annotations

__all__ = [
    "BadPassword",
    "BadZipFile",
    "LargeZipFile",
    "PasswordError",
    "PasswordRequired",
]


class BadZipFile(Exception):
    """Raised when a file is not a valid ZIP archive or is corrupt."""


class LargeZipFile(Exception):
    """Raised when writing a zipfile that requires ZIP64 extensions
    and they are disabled."""


class PasswordError(RuntimeError):
    """Base class for password problems with an encrypted entry.

    Subclasses :class:`RuntimeError`, which is what the standard library
    raises for these conditions, so existing handlers keep working.
    """


class BadPassword(PasswordError):
    """Raised when a password does not match an entry's password verifier."""


class PasswordRequired(PasswordError):
    """Raised when an encrypted entry is used without any password."""
