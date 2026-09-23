"""Exceptions raised by extraction and its filesystem materialization.

Standard-library-compatible exceptions live in :mod:`ziplet.exceptions`.
"""

from __future__ import annotations


class ExtractionFailure(Exception):
    """Base class for expected extraction-operation failures."""


class ExtractionMaterializationError(ExtractionFailure):
    """Raised when a member cannot be materialized safely."""


class ExtractionSecurityError(ExtractionMaterializationError):
    """Raised when a filesystem security invariant cannot be maintained."""


class ExtractionQuotaExceeded(ExtractionFailure):
    """Raised after a member exceeds a configured extraction quota."""

    def __init__(self, code: str, limit: int) -> None:
        self.code = code
        self.limit = limit
        super().__init__(f"{code} limit exceeded: {limit}")
