"""Filesystem materialization of archive members.

Each materializer creates one kind of filesystem object (directory, symlink,
FIFO or regular file) for a member.  Where the platform supports it they work
relative to an already-validated directory descriptor (``dir_fd``) with
``O_NOFOLLOW`` semantics, so the check that the parent is safe and the write
into it cannot be separated by a symlink swap.
"""

from __future__ import annotations

import os
import secrets
import shutil
import stat
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, Protocol

from ziplet.zipfile.exceptions import (
    ExtractionMaterializationError,
    ExtractionQuotaExceeded,
    ExtractionSecurityError,
)
from ziplet.zipfile.info import ZipInfo
from ziplet.zipfile.secure_fs import open_secure_parent
from ziplet.zipfile.validators import entry_mode, has_parent_component

__all__ = [
    "ExtractionQuota",
    "MaterializationResult",
    "MaterializeParams",
    "Materializer",
    "materialize_member",
    "select_materializer",
]

_TEMP_PREFIX = ".ziplet-"


@dataclass(frozen=True)
class MaterializationResult:
    """Result returned by a member materializer."""

    target: Path
    bytes_written: int
    overwritten: bool = False


@dataclass(frozen=True)
class ExtractionQuota:
    """Size limits enforced while a member's payload is written.

    ``total_written`` is the number of bytes already extracted for earlier
    members, so ``total_limit`` applies across the whole extraction.
    """

    member_limit: int | None = None
    total_limit: int | None = None
    total_written: int = 0

    @property
    def unbounded(self) -> bool:
        return self.member_limit is None and self.total_limit is None


@dataclass(frozen=True)
class MaterializeParams:
    """Bundles one materializer call's arguments.

    A materializer only reads the fields it needs; for example directory and
    FIFO materialization never open the member's payload.
    """

    member: ZipInfo
    targetpath: str
    open_member: Callable[[], IO[bytes]]
    quota: ExtractionQuota
    directory: str
    dir_fd: int | None
    fsync: bool = True


class Materializer(Protocol):
    """Protocol for regular-file, directory, symlink and FIFO materializers."""

    def __call__(self, params: MaterializeParams) -> MaterializationResult: ...


class _QuotaWriter:
    """Write-through wrapper that raises once a size limit would be exceeded."""

    def __init__(self, target: IO[bytes], quota: ExtractionQuota) -> None:
        self._target = target
        self._quota = quota
        self._member_written = 0

    def write(self, data: bytes) -> int:
        member_total = self._member_written + len(data)
        member_limit = self._quota.member_limit
        total_limit = self._quota.total_limit
        if member_limit is not None and member_total > member_limit:
            raise ExtractionQuotaExceeded("actual_member_size", member_limit)
        if (
            total_limit is not None
            and self._quota.total_written + member_total > total_limit
        ):
            raise ExtractionQuotaExceeded("actual_total_uncompressed_size", total_limit)
        written = self._target.write(data)
        self._member_written += written
        return written


def _lstat_leaf(name: str, dir_fd: int | None) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _unlink_leaf(name: str, dir_fd: int | None) -> bool:
    """Remove a non-directory leaf; return whether one existed."""
    leaf = _lstat_leaf(name, dir_fd)
    if leaf is None:
        return False
    if stat.S_ISDIR(leaf.st_mode):
        raise ExtractionMaterializationError(
            "Refusing to replace an existing directory with a non-directory member"
        )
    try:
        os.unlink(name, dir_fd=dir_fd)
    except FileNotFoundError:
        return False
    return True


def _leaf_reference(
    params: MaterializeParams, *operations: Callable[..., Any]
) -> tuple[str, int | None]:
    """Return ``(name, dir_fd)`` for the leaf, falling back to the full path.

    The descriptor-relative form is used only when the platform supports
    ``dir_fd`` for every operation the caller is about to perform.
    """
    if params.dir_fd is not None and all(op in os.supports_dir_fd for op in operations):
        return os.path.basename(params.targetpath), params.dir_fd
    return params.targetpath, None


def _open_unique_temp_fd(dir_fd: int) -> tuple[str, int]:
    """Create a uniquely named temp file relative to *dir_fd*; return (name, fd)."""
    for _ in range(100):
        name = f"{_TEMP_PREFIX}{secrets.token_hex(8)}"
        try:
            fd = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=dir_fd
            )
        except FileExistsError:
            continue
        return name, fd
    raise OSError("Could not create a unique temporary file for extraction")


def _copy_payload(params: MaterializeParams, target: IO[bytes]) -> int:
    """Stream the member into *target*, fsync it, and return the byte count."""
    with params.open_member() as source:
        if params.quota.unbounded:
            shutil.copyfileobj(source, target)
        else:
            shutil.copyfileobj(source, _QuotaWriter(target, params.quota))
    target.flush()
    if params.fsync:
        os.fsync(target.fileno())
    return target.tell()


def materialize_directory(params: MaterializeParams) -> MaterializationResult:
    name, dir_fd = _leaf_reference(params, os.mkdir)
    leaf = _lstat_leaf(name, dir_fd)
    if leaf is not None and stat.S_ISLNK(leaf.st_mode):
        raise ExtractionSecurityError(
            "Refusing to traverse symlinked extraction directory"
        )
    existed = leaf is not None and stat.S_ISDIR(leaf.st_mode)
    if not existed:
        try:
            os.mkdir(name, dir_fd=dir_fd)
        except FileExistsError:
            recheck = _lstat_leaf(name, dir_fd)
            if recheck is None or not stat.S_ISDIR(recheck.st_mode):
                raise
    return MaterializationResult(Path(params.targetpath), 0, existed)


def materialize_symlink(params: MaterializeParams) -> MaterializationResult:
    with params.open_member() as source:
        link_target = os.fsdecode(source.read())
    if os.path.isabs(link_target) or has_parent_component(link_target):
        raise ExtractionSecurityError(
            "Refusing to create symlink outside extraction root"
        )
    name, dir_fd = _leaf_reference(params, os.symlink, os.unlink)
    existed = _unlink_leaf(name, dir_fd)
    os.symlink(link_target, name, dir_fd=dir_fd)
    return MaterializationResult(Path(params.targetpath), 0, existed)


def materialize_special(params: MaterializeParams) -> MaterializationResult:
    # ponytail: no dir_fd path for FIFO creation (os.mkfifo lacks a
    # dir_fd parameter; os.mknod's dir_fd support is Linux-only and
    # unconfirmed on this platform). Residual TOCTOU window between the
    # guarded parent walk and this path-based mkfifo call. Upgrade:
    # hasattr(os, "mknod") and os.mknod in os.supports_dir_fd, if needed.
    member = params.member
    if stat.S_ISFIFO(entry_mode(member)) and hasattr(os, "mkfifo"):
        existed = _unlink_leaf(params.targetpath, None)
        os.mkfifo(params.targetpath, stat.S_IMODE(member.external_attr >> 16))
        return MaterializationResult(Path(params.targetpath), 0, existed)
    raise ExtractionMaterializationError("Unsupported special file type")


def materialize_regular_file(params: MaterializeParams) -> MaterializationResult:
    """Write the member to a temp file and atomically move it into place.

    Existing files are therefore preserved when the member fails part-way.
    """
    name, dir_fd = _leaf_reference(params, os.open, os.rename)
    leaf = _lstat_leaf(name, dir_fd)
    if leaf is not None and stat.S_ISDIR(leaf.st_mode):
        raise ExtractionMaterializationError(
            "Refusing to replace an existing directory with a file"
        )
    existed = leaf is not None
    if dir_fd is not None:
        bytes_written = _write_via_descriptor(params, name, dir_fd)
    else:
        bytes_written = _write_via_path(params)
    return MaterializationResult(Path(params.targetpath), bytes_written, existed)


def _write_via_descriptor(params: MaterializeParams, name: str, dir_fd: int) -> int:
    temp_name: str | None = None
    try:
        temp_name, fd = _open_unique_temp_fd(dir_fd)
        with os.fdopen(fd, "wb") as target:
            bytes_written = _copy_payload(params, target)
        os.rename(temp_name, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        temp_name = None
        return bytes_written
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name, dir_fd=dir_fd)
            except FileNotFoundError:
                pass


def _write_via_path(params: MaterializeParams) -> int:
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=params.directory, prefix=_TEMP_PREFIX, delete=False
        ) as target:
            temp_name = target.name
            bytes_written = _copy_payload(params, target)
        os.replace(temp_name, params.targetpath)
        temp_name = None
        return bytes_written
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass


def select_materializer(member: ZipInfo) -> Materializer:
    """Return the materializer matching *member*'s entry type."""
    if member.is_dir():
        return materialize_directory
    mode = entry_mode(member)
    if stat.S_ISLNK(mode):
        return materialize_symlink
    if mode and not stat.S_ISREG(mode) and not stat.S_ISDIR(mode):
        return materialize_special
    return materialize_regular_file


def materialize_member(
    member: ZipInfo,
    targetpath: str,
    open_member: Callable[[], IO[bytes]],
    root: str,
    quota: ExtractionQuota | None = None,
    *,
    fsync: bool = True,
) -> MaterializationResult:
    """Create the filesystem object for *member* at *targetpath* below *root*.

    Missing parent directories are created without following symlinks
    beneath *root*.  Regular files are fsynced before being moved into place
    unless *fsync* is ``False``.
    """
    parent = os.path.dirname(targetpath)
    dir_fd = open_secure_parent(parent, root) if parent else None
    try:
        params = MaterializeParams(
            member,
            targetpath,
            open_member,
            quota or ExtractionQuota(),
            parent or ".",
            dir_fd,
            fsync,
        )
        return select_materializer(member)(params)
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
