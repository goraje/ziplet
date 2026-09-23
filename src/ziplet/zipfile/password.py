"""Checking passwords against encrypted archive members."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from ziplet.exceptions import BadPassword, BadZipFile
from ziplet.zipfile.ext import ZipExtFile
from ziplet.zipfile.info import ZipInfo

__all__ = [
    "MemberPasswordCheck",
    "PasswordCheckResult",
    "PasswordStatus",
    "check_member_password",
]


class PasswordStatus(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    UNENCRYPTED = "unencrypted"
    CORRUPT = "corrupt"


@dataclass(frozen=True)
class MemberPasswordCheck:
    """Outcome of checking one password against one member."""

    member: str
    status: PasswordStatus


@dataclass(frozen=True)
class PasswordCheckResult:
    """Per-member outcomes of :meth:`ZipFile.check_password`."""

    members: tuple[MemberPasswordCheck, ...]

    def _names(self, status: PasswordStatus) -> tuple[str, ...]:
        return tuple(check.member for check in self.members if check.status == status)

    @property
    def accepted(self) -> tuple[str, ...]:
        return self._names(PasswordStatus.ACCEPTED)

    @property
    def rejected(self) -> tuple[str, ...]:
        return self._names(PasswordStatus.REJECTED)

    @property
    def unencrypted(self) -> tuple[str, ...]:
        return self._names(PasswordStatus.UNENCRYPTED)

    @property
    def corrupt(self) -> tuple[str, ...]:
        return self._names(PasswordStatus.CORRUPT)

    @property
    def ok(self) -> bool:
        """``True`` when no member was rejected or found corrupt."""
        return not self.rejected and not self.corrupt


def check_member_password(
    open_member: Callable[[], ZipExtFile], info: ZipInfo, *, full: bool
) -> PasswordStatus:
    """Check the password bound into *open_member* against *info*.

    Opening an entry runs its password verifier before any payload is read,
    so the default check never touches the compressed data.  With *full*,
    the whole entry is also authenticated (see
    :meth:`ZipExtFile.verify_integrity`).
    """
    if not info.is_encrypted:
        return PasswordStatus.UNENCRYPTED
    try:
        with open_member() as stream:
            if full:
                stream.verify_integrity()
    except BadPassword:
        return PasswordStatus.REJECTED
    except BadZipFile:
        return PasswordStatus.CORRUPT
    return PasswordStatus.ACCEPTED
