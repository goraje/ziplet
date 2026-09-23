"""The :class:`ZipFile` archive class and the :func:`is_zipfile` helper."""

from __future__ import annotations

import os
import shutil
import threading
import warnings
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import IO, TYPE_CHECKING, Literal, TypeAlias, cast, overload

if TYPE_CHECKING:
    from typing_extensions import Self
else:
    try:
        from typing import Self
    except ImportError:  # Python < 3.11
        from typing_extensions import Self

if TYPE_CHECKING:
    from ziplet.cryptography.base import BaseZipEncryptor

from ziplet.compression import ZIP_LZMA, ZIP_STORED, Registry, registry
from ziplet.cryptography import WZ_AES, ZIP_CRYPTO
from ziplet.cryptography.aes import AesZipEncryptor
from ziplet.cryptography.zipcrypto import ZipCryptoEncryptor
from ziplet.exceptions import BadZipFile, LargeZipFile
from ziplet.zipfile.assessment import (
    ArchiveAssessment,
)
from ziplet.zipfile.assessor import (
    assess_archive,
    default_assessment_policy,
)
from ziplet.zipfile.ext import ZipExtFile
from ziplet.zipfile.extract import (
    ExtractionError,
    ExtractMemberResult,
    ExtractPolicy,
    ExtractResult,
    normalized_destination,
)
from ziplet.zipfile.info import ZipInfo
from ziplet.zipfile.inspection import (
    InspectionMember,
    InspectionResult,
    build_inspection_result,
)
from ziplet.zipfile.io_wrappers import (
    ClosableZipStream,
    Tellable,
)
from ziplet.zipfile.materialize import (
    ExtractionQuota,
    MaterializationResult,
    materialize_member,
)
from ziplet.zipfile.policy_extraction import extract_with_policy
from ziplet.zipfile.records import (
    looks_like_zip,
    read_directory,
    read_local_header,
    write_directory,
)
from ziplet.zipfile.shared import (
    MASK_COMPRESS_OPTION_1,
    MASK_ENCRYPTED,
    MASK_USE_DATA_DESCRIPTOR,
    ZIP64_LIMIT,
    ZIP_FILECOUNT_LIMIT,
    ZIP_MAX_COMMENT,
    ReadWriteMode,
    StrPath,
)
from ziplet.zipfile.validators import (
    member_target_name,
)
from ziplet.zipfile.write import ZipWriteFile
from ziplet.zipfile.write_coordinator import WriteCoordinator

__all__ = [
    "ZipFile",
    "is_zipfile",
    "INHERIT_ENCRYPTION",
    "EncryptionOverride",
    "InspectionMember",
    "InspectionResult",
]

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------
_ZipFileMode: TypeAlias = Literal["r", "w", "x", "a"]

# File modes tried in order when opening an archive path: appending falls back
# to creating the file, and a read/write handle falls back to write-only.
_OPEN_MODES = {
    "r": ("rb",),
    "w": ("w+b", "wb"),
    "x": ("x+b", "xb"),
    "a": ("r+b", "w+b", "wb"),
}


def _open_archive_file(path: str, mode: str) -> IO[bytes]:
    *fallbacks, last = _OPEN_MODES[mode]
    for file_mode in fallbacks:
        try:
            return open(path, file_mode)
        except OSError:
            continue
    return open(path, last)


class _InheritEncryption:
    __slots__ = ()

    def __repr__(self) -> str:
        return "INHERIT_ENCRYPTION"


INHERIT_ENCRYPTION = _InheritEncryption()
EncryptionOverride: TypeAlias = str | None | _InheritEncryption


def is_zipfile(filename: StrPath | IO[bytes]) -> bool:
    """Return ``True`` if *filename* is a valid ZIP file based on its magic number.

    Args:
        filename: Path to the file on disk, or an open binary file-like object.
            File-like objects are sought back to their original position after
            inspection.

    Returns:
        ``True`` if the file looks like a ZIP archive, ``False`` otherwise.
    """
    result = False
    try:
        if not isinstance(filename, (str, os.PathLike)):
            pos = filename.tell()
            result = looks_like_zip(filename)
            filename.seek(pos)
        else:
            with open(filename, "rb") as fp:
                result = looks_like_zip(fp)
    except (OSError, BadZipFile):
        pass
    return result


@dataclass(frozen=True)
class ZipFileExtra:
    """Immutable extra options for :class:`ZipFile`.

    Attributes:
        force_wz_aes_version: Override the WinZip AES version written to the
            extra field (``1`` or ``2``). ``None`` selects the metadata-safe
            AES version 2. Version 1 exposes the plaintext CRC and should only
            be selected for compatibility with older tools.
        wz_aes_nbits: AES key size in bits (``128``, ``192``, or ``256``).
            Defaults to ``256``.
    """

    force_wz_aes_version: int | None = None
    wz_aes_nbits: int = 256

    def __post_init__(self) -> None:
        if self.force_wz_aes_version not in (None, 1, 2):
            raise ValueError("force_wz_aes_version must be 1 or 2")


class ZipFile:
    """Read, write, and append ZIP archives.

    Supports standard ZIP compression (stored, deflate, bzip2, lzma, zstd),
    optional WinZip AES (``WZ_AES``) and traditional ZIP encryption
    (``ZIP_CRYPTO``), ZIP64 extensions, and archive comments.

    Attributes:
        fp: The underlying binary file object, or ``None`` when closed.
        debug: Verbosity level for diagnostic output (0–3).
        NameToInfo: Mapping of archive member name to its ZipInfo.
        filelist: Ordered list of ZipInfo entries.
        compression: Default compression method for new entries.
        compresslevel: Default compression level for new entries.
        mode: The mode the archive was opened with (``'r'``, ``'w'``,
            ``'x'``, or ``'a'``).
        pwd: Default decryption password, or ``None``.
        encryption: Encryption scheme (``WZ_AES``, ``ZIP_CRYPTO``, or
            ``None``).
        metadata_encoding: Encoding used to decode non-UTF-8 filenames on
            read. ``None`` defaults to ``'cp437'``.
    """

    fp: IO[bytes] | None = None

    def __init__(
        self,
        file: StrPath | IO[bytes],
        mode: _ZipFileMode = "r",
        compression: int = ZIP_STORED,
        allowZip64: bool = True,
        compresslevel: int | None = None,
        *,
        strict_timestamps: bool = True,
        metadata_encoding: str | None = None,
        encryption: str | None = None,
        extra: ZipFileExtra | None = None,
        compression_registry: Registry | None = None,
    ) -> None:
        """Open a ZIP archive for reading, writing, exclusive creation, or appending.

        Args:
            file: Path to the archive file, or an open binary file-like object.
            mode: ``'r'`` to read, ``'w'`` to create/overwrite, ``'x'`` to
                create exclusively (fail if the file exists), or ``'a'`` to
                append.
            compression: Default compression method for entries added with
                :meth:`write` or :meth:`writestr`. Defaults to ``ZIP_STORED``.
            allowZip64: When ``True`` (the default), emit ZIP64 extensions for
                files or archives that exceed the 4 GiB / 65535-entry limits.
            compresslevel: Default compressor level hint, or ``None`` for the
                compressor's own default.
            strict_timestamps: When ``False``, timestamps outside the range
                1980–2107 are clamped rather than raising an error.
            metadata_encoding: Encoding for non-UTF-8 member names when
                reading. ``None`` defaults to ``'cp437'``. Only valid with
                mode ``'r'``.
            encryption: Encryption scheme to apply when writing (``WZ_AES``
                or ``ZIP_CRYPTO``). Requires :meth:`setpassword` before
                writing.
            extra: Additional settings; see :class:`ZipFileExtra`.

        Raises:
            ValueError: If *mode* is invalid, *metadata_encoding* is supplied
                with a non-read mode, or the compression method is unsupported.
            BadZipFile: If *mode* is ``'r'`` or ``'a'`` and the file is not a
                valid ZIP archive.
        """
        if mode not in ("r", "w", "x", "a"):
            raise ValueError("ZipFile requires mode 'r', 'w', 'x', or 'a'")

        selected_registry = (
            compression_registry.copy() if compression_registry else registry.copy()
        )
        selected_registry.check_compression(compression)

        self._allow_zip64 = allowZip64
        self._did_modify = False
        self.debug = 0
        self.NameToInfo: dict[str, ZipInfo] = {}
        self.filelist: list[ZipInfo] = []
        self.compression = compression
        self.compresslevel = compresslevel
        self.mode = mode
        self.pwd: bytes | None = None
        self.encryption = encryption
        self._wz_aes_nbits = extra.wz_aes_nbits if extra else 256
        self._force_wz_aes_version = extra.force_wz_aes_version if extra else None
        self._comment = b""
        self._strict_timestamps = strict_timestamps
        self.metadata_encoding = metadata_encoding

        if self.metadata_encoding and mode != "r":
            raise ValueError("metadata_encoding is only supported for reading files")

        if isinstance(file, os.PathLike):
            file = os.fspath(file)
        if isinstance(file, str):
            self._file_passed = False
            self.filename: str | None = file
            self.fp = _open_archive_file(file, mode)
        else:
            self._file_passed = True
            self.fp = file
            self.filename = getattr(file, "name", None)
        self._file_ref_cnt = 1
        self._lock = threading.RLock()
        self._write_coordinator = WriteCoordinator(self._lock)
        self._seekable = True
        self._compression_registry = selected_registry

        try:
            if mode == "r":
                self._read_directory()
            elif mode in ("w", "x"):
                self._did_modify = True
                try:
                    self.start_dir = self.fp.tell()
                except (AttributeError, OSError):
                    self.fp = cast(IO[bytes], Tellable(self.fp))
                    self.start_dir = 0
                    self._seekable = False
                else:
                    try:
                        self.fp.seek(self.start_dir)
                    except (AttributeError, OSError):
                        self._seekable = False
            elif mode == "a":
                try:
                    self._read_directory()
                    self.fp.seek(self.start_dir)
                except BadZipFile:
                    self.fp.seek(0, 2)
                    self._did_modify = True
                    self.start_dir = self.fp.tell()
        except BaseException:
            fp = self.fp
            self.fp = None
            assert fp is not None
            self._fpclose(fp)
            raise

    def __enter__(self) -> Self:
        """Enter the runtime context and return this archive."""
        return self

    def __exit__(
        self,
        type: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Exit the runtime context and close the archive.

        Args:
            type: Exception type, if any.
            value: Exception value, if any.
            traceback: Exception traceback, if any.
        """
        self.close()

    def __repr__(self) -> str:
        """Return a developer-friendly string representation.

        Returns:
            A string of the form ``<module.ZipFile filename=... mode=...>``
            or ``<module.ZipFile [closed]>`` when the archive is closed.
        """
        result = ["<%s.%s" % (self.__class__.__module__, self.__class__.__qualname__)]
        if self.fp is not None:
            if self._file_passed:
                result.append(" file=%r" % self.fp)
            elif self.filename is not None:
                result.append(" filename=%r" % self.filename)
            result.append(" mode=%r" % self.mode)
        else:
            result.append(" [closed]")
        result.append(">")
        return "".join(result)

    def _read_directory(self) -> None:
        """Populate :attr:`filelist` and :attr:`NameToInfo` from the archive.

        Raises:
            BadZipFile: If the file is not a ZIP archive or its central
                directory is truncated or corrupt.
        """
        assert self.fp is not None
        directory = read_directory(self.fp, self.metadata_encoding, self.debug)
        self._comment = directory.comment
        self.start_dir = directory.start_dir
        self.filelist.extend(directory.infos)
        self.NameToInfo.update((info.filename, info) for info in directory.infos)

    def namelist(self) -> list[str]:
        """Return a list of archive member names.

        Returns:
            A list of filenames in the order they appear in the central
            directory.
        """
        return [data.filename for data in self.filelist]

    def infolist(self) -> list[ZipInfo]:
        """Return a list of ZipInfo instances for all archive members.

        Returns:
            The internal :attr:`filelist` in central-directory order.
        """
        return self.filelist

    def inspect(
        self,
        path: StrPath | None = None,
        policy: ExtractPolicy | None = None,
    ) -> InspectionResult:
        """Inspect archive metadata without opening or processing payloads.

        No member data is read, decompressed, decrypted, or written.  Policy
        findings are returned in the report and never raise
        :class:`ExtractionError`.
        """
        effective_policy = policy or default_assessment_policy()
        return build_inspection_result(
            self.assess(path, effective_policy), effective_policy
        )

    def assess(
        self,
        path: StrPath | None = None,
        policy: ExtractPolicy | None = None,
    ) -> ArchiveAssessment:
        """Return the metadata assessment shared by policy consumers."""
        return assess_archive(self.filelist, path, policy)

    def printdir(self, file: IO[str] | None = None) -> None:
        """Print a formatted table of contents to *file*.

        Args:
            file: Output stream. Defaults to ``sys.stdout`` when ``None``.
        """
        print("%-46s %19s %12s" % ("File Name", "Modified    ", "Size"), file=file)
        for zinfo in self.filelist:
            date = "%d-%02d-%02d %02d:%02d:%02d" % zinfo.date_time[:6]
            print("%-46s %s %12d" % (zinfo.filename, date, zinfo.file_size), file=file)

    def testzip(self) -> str | None:
        """Verify each archive member by reading it and checking its CRC.

        Returns:
            The filename of the first bad entry, or ``None`` if all entries
            are intact.
        """
        chunk_size = 2**20
        for zinfo in self.filelist:
            try:
                with self.open(zinfo, "r") as f:
                    while f.read(chunk_size):
                        pass
            except BadZipFile:
                return zinfo.filename
        return None

    def getinfo(self, name: str) -> ZipInfo:
        """Return the ZipInfo for the archive member named *name*.

        Args:
            name: Archive member filename.

        Returns:
            The corresponding :class:`~ziplet.zipfile.info.ZipInfo`
            instance.

        Raises:
            KeyError: If no entry with the given name exists.
        """
        info = self.NameToInfo.get(name)
        if info is None:
            raise KeyError("There is no item named %r in the archive" % name)
        return info

    def setpassword(self, pwd: bytes | None) -> None:
        """Set the default decryption password for encrypted archive members.

        Args:
            pwd: Password bytes, or ``None`` to clear the stored password.

        Raises:
            TypeError: If *pwd* is not ``bytes`` or ``None``.
        """
        if pwd and not isinstance(pwd, bytes):
            raise TypeError("pwd: expected bytes, got %s" % type(pwd).__name__)
        if pwd:
            self.pwd = pwd
        else:
            self.pwd = None

    def get_encryptor(
        self,
        encryption: str | None = None,
        password: bytes | None = None,
        *,
        nbits: int | None = None,
        force_wz_aes_version: int | None = None,
    ) -> BaseZipEncryptor:
        """Construct an encryptor, defaulting to this archive's settings.

        Args:
            encryption: Encryption scheme; defaults to :attr:`encryption`.
            password: Encryption password; defaults to :attr:`pwd`.
            nbits: AES key size in bits; defaults to the archive's setting.
            force_wz_aes_version: WinZip AES version override; defaults to the
                archive's setting.

        Returns:
            A :class:`~ziplet.cryptography.base.BaseZipEncryptor` for the
            selected scheme.

        Raises:
            RuntimeError: If no password is available.
            NotImplementedError: If the encryption scheme is unknown.
        """
        method = self.encryption if encryption is None else encryption
        pwd = self.pwd if password is None else password
        if pwd is None:
            raise RuntimeError("Encrypted entries require a password")
        if method == WZ_AES:
            return AesZipEncryptor(
                pwd,
                nbits=self._wz_aes_nbits if nbits is None else nbits,
                force_wz_aes_version=(
                    self._force_wz_aes_version
                    if force_wz_aes_version is None
                    else force_wz_aes_version
                ),
            )
        if method == ZIP_CRYPTO:
            return ZipCryptoEncryptor(pwd)
        raise NotImplementedError("Unknown encryption method: %r" % (method,))

    @property
    def comment(self) -> bytes:
        """The archive-level comment bytes."""
        return self._comment

    @comment.setter
    def comment(self, comment: bytes) -> None:
        if not isinstance(comment, bytes):
            raise TypeError("comment: expected bytes, got %s" % type(comment).__name__)
        if len(comment) > ZIP_MAX_COMMENT:
            warnings.warn(
                "Archive comment is too long; truncating to %d bytes" % ZIP_MAX_COMMENT,
                stacklevel=2,
            )
            comment = comment[:ZIP_MAX_COMMENT]
        self._comment = comment
        self._did_modify = True

    def read(self, name: str | ZipInfo, pwd: bytes | None = None) -> bytes:
        """Return the decompressed bytes for the archive member named *name*.

        Args:
            name: Member filename or a
                :class:`~ziplet.zipfile.info.ZipInfo` instance.
            pwd: Decryption password. Falls back to :attr:`pwd` when ``None``.

        Returns:
            Decompressed file contents as ``bytes``.
        """
        with self.open(name, "r", pwd) as fp:
            return fp.read()

    def open(
        self,
        name: str | ZipInfo,
        mode: ReadWriteMode = "r",
        pwd: bytes | None = None,
        *,
        force_zip64: bool = False,
        encryption: EncryptionOverride = INHERIT_ENCRYPTION,
        password: bytes | None = None,
        extra: ZipFileExtra | None = None,
    ) -> IO[bytes]:
        """Open an archive member for reading or writing.

        Args:
            name: Member filename or a
                :class:`~ziplet.zipfile.info.ZipInfo` instance.
            mode: ``'r'`` to read an existing member, or ``'w'`` to write a
                new one.
            pwd: Decryption password for an encrypted member. Falls back to
                :attr:`pwd` when ``None``.
            force_zip64: When ``True``, always write local header size fields
                as ZIP64 regardless of file size.

        Returns:
            A binary file-like object. For ``mode='r'`` a
            :class:`~ziplet.zipfile.ext.ZipExtFile`; for ``mode='w'`` a
            :class:`~ziplet.zipfile.write.ZipWriteFile`.

        Raises:
            ValueError: If *mode* is invalid, *pwd* is supplied with
                ``mode='w'``, or the archive is closed.
            RuntimeError: If the member is encrypted and no password is
                available.
            NotImplementedError: If the member uses compressed patch data or
                strong encryption.
            BadZipFile: If the local file header is corrupt.
        """
        if mode not in {"r", "w"}:
            raise ValueError('open() requires mode "r" or "w"')
        if pwd and (mode == "w"):
            raise ValueError("pwd is only supported for reading files")
        if not self.fp:
            raise ValueError("Attempt to use ZIP archive that was already closed")

        if isinstance(name, ZipInfo):
            zinfo = name
        elif mode == "w":
            zinfo = ZipInfo(name)
            zinfo.compress_type = self.compression
            zinfo.compress_level = self.compresslevel
        else:
            zinfo = self.getinfo(name)

        if mode == "w":
            return cast(
                IO[bytes],
                self._open_to_write(
                    zinfo,
                    force_zip64=force_zip64,
                    encryption=encryption,
                    password=password,
                    extra=extra,
                ),
            )

        self._write_coordinator.ensure_readable()

        return cast(IO[bytes], self._open_to_read(mode, zinfo, pwd))

    def _open_to_read(
        self, mode: ReadWriteMode, zinfo: ZipInfo, pwd: bytes | None
    ) -> ZipExtFile:
        """Open *zinfo* for reading and return a ZipExtFile.

        Validates the local file header, checks for overlapping entries, sets
        up decryption when the entry is encrypted, and returns a
        :class:`~ziplet.zipfile.ext.ZipExtFile` backed by the archive
        stream.

        Args:
            mode: Read mode (always ``'r'``).
            zinfo: Metadata for the entry to open.
            pwd: Decryption password, or ``None`` for unencrypted entries.

        Returns:
            A :class:`~ziplet.zipfile.ext.ZipExtFile` positioned at the
            start of the compressed data.

        Raises:
            BadZipFile: If the local header is truncated, has a bad signature,
                the filename mismatches the central directory, or entries
                overlap.
            NotImplementedError: If compressed patch data or strong encryption
                are detected.
            RuntimeError: If the entry is encrypted and no password is
                available.
            TypeError: If *pwd* is not ``bytes``.
        """
        assert self.fp is not None
        self._file_ref_cnt += 1
        zef_file = ClosableZipStream(
            self.fp,
            zinfo.header_offset,
            self._fpclose,
            self._lock,
            lambda: self._write_coordinator.active,
        )
        try:
            read_local_header(zef_file, zinfo, self.metadata_encoding)

            if (
                zinfo._end_offset is not None
                and zef_file.tell() + zinfo.compress_size > zinfo._end_offset
            ):
                if zinfo._end_offset == zinfo.header_offset:
                    warnings.warn(
                        f"Overlapped entries: {zinfo.orig_filename!r} "
                        f"(possible zip bomb)",
                        stacklevel=2,
                    )
                else:
                    raise BadZipFile(
                        f"Overlapped entries: {zinfo.orig_filename!r} "
                        f"(possible zip bomb)"
                    )

            is_encrypted = zinfo.flag_bits & MASK_ENCRYPTED
            if is_encrypted:
                if not pwd:
                    pwd = self.pwd
                if pwd and not isinstance(pwd, bytes):
                    raise TypeError("pwd: expected bytes, got %s" % type(pwd).__name__)
                if not pwd:
                    raise RuntimeError(
                        "File %r is encrypted, password "
                        "required for extraction" % zinfo.orig_filename
                    )
            else:
                pwd = None

            return ZipExtFile(
                zef_file, mode, zinfo, True, pwd, self._compression_registry
            )
        except BaseException:
            zef_file.close()
            raise

    def _open_to_write(
        self,
        zinfo: ZipInfo,
        force_zip64: bool = False,
        *,
        encryption: EncryptionOverride = INHERIT_ENCRYPTION,
        password: bytes | None = None,
        extra: ZipFileExtra | None = None,
    ) -> ZipWriteFile:
        """Open *zinfo* for writing and return a ZipWriteFile.

        Initialises CRC and size fields, computes the ZIP64 requirement,
        writes the local file header, sets up encryption if configured, and
        registers the returned handle as the active write handle.

        Args:
            zinfo: Metadata for the new entry. Modified in place (CRC, sizes,
                flags, ``header_offset``).
            force_zip64: When ``True``, force ZIP64 local header fields
                regardless of file size.

        Returns:
            A :class:`~ziplet.zipfile.write.ZipWriteFile` ready to
            accept data.

        Raises:
            ValueError: If *force_zip64* is ``True`` but ZIP64 is not allowed,
                or if a write handle is already open.
            LargeZipFile: If ZIP64 is required but not allowed.
        """
        if force_zip64 and not self._allow_zip64:
            raise ValueError(
                "force_zip64 is True, but allowZip64 was False when opening "
                "the ZIP file."
            )
        reservation = self._write_coordinator.reserve()
        try:
            zinfo.compress_size = 0
            zinfo.CRC = 0

            zinfo.flag_bits = 0x00
            if zinfo.compress_type == ZIP_LZMA:
                zinfo.flag_bits |= MASK_COMPRESS_OPTION_1
            if not self._seekable:
                zinfo.flag_bits |= MASK_USE_DATA_DESCRIPTOR

            if not zinfo.external_attr:
                zinfo.external_attr = 0o600 << 16

            zip64 = force_zip64 or (
                zinfo.file_size + zinfo.file_size // 20 > ZIP64_LIMIT
            )
            if not self._allow_zip64 and zip64:
                raise LargeZipFile("Filesize would require ZIP64 extensions")

            assert self.fp is not None
            if self._seekable:
                self.fp.seek(self.start_dir)
            zinfo.header_offset = self.fp.tell()

            self._check_writable(zinfo)
            self._mark_modified()

            effective_encryption = (
                self.encryption if encryption is INHERIT_ENCRYPTION else encryption
            )
            if effective_encryption is None and password is not None:
                raise ValueError("password cannot be used for an unencrypted entry")
            encryptor = None
            if effective_encryption:
                zinfo.flag_bits |= MASK_ENCRYPTED
                encryptor = self.get_encryptor(
                    cast(str, effective_encryption),
                    password,
                    nbits=extra.wz_aes_nbits if extra else None,
                    force_wz_aes_version=extra.force_wz_aes_version if extra else None,
                )

            return ZipWriteFile(
                self, zinfo, zip64, encryptor, self._compression_registry, reservation
            )
        except BaseException:
            self._write_coordinator.release(reservation)
            raise

    @overload
    def extract(
        self,
        member: str | ZipInfo,
        path: StrPath | None = None,
        pwd: bytes | None = None,
        *,
        policy: None = None,
    ) -> str: ...

    @overload
    def extract(
        self,
        member: str | ZipInfo,
        path: StrPath | None = None,
        pwd: bytes | None = None,
        *,
        policy: ExtractPolicy,
    ) -> ExtractMemberResult: ...

    def extract(
        self,
        member: str | ZipInfo,
        path: StrPath | None = None,
        pwd: bytes | None = None,
        *,
        policy: ExtractPolicy | None = None,
    ) -> str | ExtractMemberResult:
        """Extract a single member to *path* on the filesystem.

        Args:
            member: Archive member filename or
                :class:`~ziplet.zipfile.info.ZipInfo` instance.
            path: Destination directory. Defaults to the current working
                directory when ``None``.
            pwd: Decryption password, or ``None`` to use :attr:`pwd`.

        Returns:
            The normalized path of the extracted file or directory.
        """
        if policy is not None:
            result = self._extract_with_policy(
                [member],
                path,
                pwd,
                policy,
            )
            if result.failed_count:
                raise ExtractionError(result)
            return result.members[0]

        path = os.fspath(os.getcwd() if path is None else path)
        return str(self._extract_member(member, path, pwd).target)

    @overload
    def extractall(
        self,
        path: StrPath | None = None,
        members: Iterable[str | ZipInfo] | None = None,
        pwd: bytes | None = None,
        *,
        policy: None = None,
    ) -> None: ...

    @overload
    def extractall(
        self,
        path: StrPath | None = None,
        members: Iterable[str | ZipInfo] | None = None,
        pwd: bytes | None = None,
        *,
        policy: ExtractPolicy,
    ) -> ExtractResult: ...

    def extractall(
        self,
        path: StrPath | None = None,
        members: Iterable[str | ZipInfo] | None = None,
        pwd: bytes | None = None,
        *,
        policy: ExtractPolicy | None = None,
    ) -> None | ExtractResult:
        """Extract all (or a subset of) members to *path* on the filesystem.

        Args:
            path: Destination directory. Defaults to the current working
                directory when ``None``.
            members: Iterable of member names or
                :class:`~ziplet.zipfile.info.ZipInfo` instances to
                extract. Defaults to all members when ``None``.
            pwd: Decryption password, or ``None`` to use :attr:`pwd`.
        """
        if members is None:
            members = self.namelist()
        if policy is not None:
            result = self._extract_with_policy(list(members), path, pwd, policy)
            if result.failed_count:
                raise ExtractionError(result)
            return result
        path = os.fspath(os.getcwd() if path is None else path)
        for zipinfo in members:
            self._extract_member(zipinfo, path, pwd)
        return None

    def _extract_with_policy(
        self,
        members: list[str | ZipInfo],
        path: StrPath | None,
        pwd: bytes | None,
        policy: ExtractPolicy,
    ) -> ExtractResult:
        destination = normalized_destination(path or os.getcwd())
        policy_root = (
            normalized_destination(policy.destination_root)
            if policy.destination_root is not None
            else destination
        )
        infos = [
            member if isinstance(member, ZipInfo) else self.getinfo(member)
            for member in members
        ]
        return extract_with_policy(
            infos,
            destination,
            policy_root,
            policy,
            lambda info, target, quota: self._extract_member(
                info,
                str(destination),
                pwd,
                target_override=target,
                quota=quota,
                fsync=policy.fsync_files,
            ),
        )

    def _extract_member(
        self,
        member: str | ZipInfo,
        destination: str,
        pwd: bytes | None,
        *,
        target_override: Path | None = None,
        quota: ExtractionQuota | None = None,
        fsync: bool = True,
    ) -> MaterializationResult:
        """Extract *member* to *targetpath* and return the materialization result.

        Resolves the platform path, guards against path traversal, creates
        parent directories as needed, and writes the file content (or creates
        a directory) at the resolved location.

        Args:
            member: Archive member name or
                :class:`~ziplet.zipfile.info.ZipInfo` instance.
            destination: Root directory under which the member is extracted.
            pwd: Decryption password, or ``None``.

        Returns:
            The :class:`~ziplet.zipfile.materialize.MaterializationResult`
            describing what was written.

        Raises:
            ValueError: If the sanitized archive name is empty for a file
                entry.
        """
        if not isinstance(member, ZipInfo):
            member = self.getinfo(member)

        _, parts = member_target_name(member.filename)
        arcname = os.path.sep.join(parts)

        if not arcname and not member.is_dir():
            raise ValueError("Empty filename.")

        if target_override is None:
            targetpath = os.path.normpath(os.path.join(destination, arcname))
        else:
            targetpath = os.fspath(target_override)

        return materialize_member(
            member,
            targetpath,
            lambda: self.open(member, pwd=pwd),
            destination,
            quota,
            fsync=fsync,
        )

    def _mark_modified(self) -> None:
        """Record that the central directory must be rewritten on close."""
        self._did_modify = True

    def _add_entry(self, zinfo: ZipInfo) -> None:
        """Register a fully written entry in the in-memory directory."""
        self.filelist.append(zinfo)
        self.NameToInfo[zinfo.filename] = zinfo

    def _check_writable(self, zinfo: ZipInfo) -> None:
        """Validate that *zinfo* can be written to the archive.

        Issues a warning for duplicate names and raises on invalid archive
        state, unsupported compression, or ZIP64 violations.

        Args:
            zinfo: Metadata for the entry about to be written.

        Raises:
            ValueError: If the archive is not open for writing or is already
                closed.
            LargeZipFile: If a size or count threshold would require ZIP64
                extensions that are not enabled.
        """
        if zinfo.filename in self.NameToInfo:
            warnings.warn("Duplicate name: %r" % zinfo.filename, stacklevel=3)
        if self.mode not in ("w", "x", "a"):
            raise ValueError("write() requires mode 'w', 'x', or 'a'")
        if not self.fp:
            raise ValueError("Attempt to write ZIP archive that was already closed")
        self._compression_registry.check_compression(zinfo.compress_type)
        if not self._allow_zip64:
            requires_zip64 = None
            if len(self.filelist) >= ZIP_FILECOUNT_LIMIT:
                requires_zip64 = "Files count"
            elif zinfo.file_size > ZIP64_LIMIT:
                requires_zip64 = "Filesize"
            elif zinfo.header_offset > ZIP64_LIMIT:
                requires_zip64 = "Zipfile size"
            if requires_zip64:
                raise LargeZipFile(requires_zip64 + " would require ZIP64 extensions")

    def write(
        self,
        filename: StrPath,
        arcname: StrPath | None = None,
        compress_type: int | None = None,
        compresslevel: int | None = None,
        *,
        encryption: EncryptionOverride = INHERIT_ENCRYPTION,
        password: bytes | None = None,
        extra: ZipFileExtra | None = None,
    ) -> None:
        """Add a file from the filesystem to the archive.

        Args:
            filename: Path to the source file or directory on disk.
            arcname: Name to use inside the archive. Defaults to *filename*
                with the drive and leading separators stripped.
            compress_type: Compression method for this entry. Overrides
                :attr:`compression` when provided.
            compresslevel: Compressor level for this entry. Overrides
                :attr:`compresslevel` when provided.

        Raises:
            ValueError: If the archive is closed or a write handle is open.
        """
        if not self.fp:
            raise ValueError("Attempt to write to ZIP archive that was already closed")
        self._write_coordinator.ensure_writable()

        zinfo = ZipInfo.from_file(
            filename, arcname, strict_timestamps=self._strict_timestamps
        )

        if zinfo.is_dir():
            zinfo.compress_size = 0
            zinfo.CRC = 0
            self.mkdir(zinfo)
        else:
            if compress_type is not None:
                zinfo.compress_type = compress_type
            else:
                zinfo.compress_type = self.compression

            if compresslevel is not None:
                zinfo.compress_level = compresslevel
            else:
                zinfo.compress_level = self.compresslevel

            with (
                open(
                    filename,
                    "rb",
                ) as src,
                self.open(
                    zinfo,
                    "w",
                    encryption=encryption,
                    password=password,
                    extra=extra,
                ) as dest,
            ):
                shutil.copyfileobj(src, dest)

    def writestr(
        self,
        zinfo_or_arcname: str | ZipInfo,
        data: str | bytes | bytearray,
        compress_type: int | None = None,
        compresslevel: int | None = None,
        *,
        encryption: EncryptionOverride = INHERIT_ENCRYPTION,
        password: bytes | None = None,
        extra: ZipFileExtra | None = None,
    ) -> None:
        """Write *data* into the archive under the given name or ZipInfo.

        Args:
            zinfo_or_arcname: Destination name inside the archive, or a
                pre-populated
                :class:`~ziplet.zipfile.info.ZipInfo` instance.
            data: File contents as a ``str`` (encoded to UTF-8) or
                ``bytes``/``bytearray``.
            compress_type: Compression method for this entry. Overrides the
                entry's own setting when provided.
            compresslevel: Compressor level for this entry. Overrides the
                entry's own setting when provided.

        Raises:
            ValueError: If the archive is closed or a write handle is open.
        """
        if isinstance(data, str):
            data = data.encode("utf-8")
        if isinstance(zinfo_or_arcname, ZipInfo):
            zinfo = zinfo_or_arcname
        else:
            zinfo = ZipInfo(zinfo_or_arcname)._for_archive(self)

        if not self.fp:
            raise ValueError("Attempt to write to ZIP archive that was already closed")
        self._write_coordinator.ensure_writable()

        if compress_type is not None:
            zinfo.compress_type = compress_type

        if compresslevel is not None:
            zinfo.compress_level = compresslevel

        zinfo.file_size = len(data)
        with self._lock:
            with self.open(
                zinfo,
                mode="w",
                encryption=encryption,
                password=password,
                extra=extra,
            ) as dest:
                dest.write(data)

    def mkdir(self, zinfo_or_directory_name: str | ZipInfo, mode: int = 511) -> None:
        """Add a directory entry to the archive.

        Args:
            zinfo_or_directory_name: Directory path (a trailing ``'/'`` is
                appended if absent) or a
                :class:`~ziplet.zipfile.info.ZipInfo` instance that
                describes a directory.
            mode: Unix permission bits for the directory entry. Defaults to
                ``0o777`` (octal 511).

        Raises:
            ValueError: If a :class:`~ziplet.zipfile.info.ZipInfo`
                instance is supplied that does not describe a directory.
            TypeError: If *zinfo_or_directory_name* is neither a ``str`` nor a
                :class:`~ziplet.zipfile.info.ZipInfo`.
        """
        if isinstance(zinfo_or_directory_name, ZipInfo):
            zinfo = zinfo_or_directory_name
            if not zinfo.is_dir():
                raise ValueError("The given ZipInfo does not describe a directory")
        elif isinstance(zinfo_or_directory_name, str):
            directory_name = zinfo_or_directory_name
            if not directory_name.endswith("/"):
                directory_name += "/"
            zinfo = ZipInfo(directory_name)
            zinfo.compress_size = 0
            zinfo.CRC = 0
            zinfo.external_attr = ((0o40000 | mode) & 0xFFFF) << 16
            zinfo.file_size = 0
            zinfo.external_attr |= 0x10
        else:
            raise TypeError("Expected type str or ZipInfo")

        with self._lock:
            assert self.fp is not None
            if self._seekable:
                self.fp.seek(self.start_dir)
            zinfo.header_offset = self.fp.tell()
            if zinfo.compress_type == ZIP_LZMA:
                zinfo.flag_bits |= MASK_COMPRESS_OPTION_1

            self._check_writable(zinfo)
            self._mark_modified()

            self._add_entry(zinfo)
            self.fp.write(zinfo.FileHeader(False))
            self.start_dir = self.fp.tell()

    def __del__(self) -> None:
        """Ensure the archive is closed when the object is garbage-collected."""
        try:
            self.close()
        except Exception:
            pass

    def close(self) -> None:
        """Flush and close the archive.

        For writable modes (``'w'``, ``'x'``, ``'a'``), writes the central
        directory and end-of-central-directory record before closing the
        underlying file. The underlying file is only closed when it was opened
        by this instance (i.e. *file* was a path, not a file-like object).

        Raises:
            ValueError: If a write handle is still open on the archive.
        """
        if self.fp is None:
            return

        self._write_coordinator.wait_for_finalization()
        if self._write_coordinator.active:
            raise ValueError(
                "Can't close the ZIP file while there is "
                "an open writing handle on it. "
                "Close the writing handle before closing the zip."
            )

        try:
            if self.mode in ("w", "x", "a") and self._did_modify:
                with self._lock:
                    if self._seekable:
                        self.fp.seek(self.start_dir)
                    self._write_end_record()
        finally:
            fp = self.fp
            self.fp = None
            self._fpclose(fp)

    def _write_end_record(self) -> None:
        """Write the central directory and end records, then flush.

        Truncates the file afterwards in append mode, since the new directory
        may be shorter than the one it replaced.

        Raises:
            LargeZipFile: If ZIP64 is required but not allowed.
        """
        assert self.fp is not None
        write_directory(
            self.fp,
            self.filelist,
            self.start_dir,
            self._comment,
            allow_zip64=self._allow_zip64,
        )
        if self.mode == "a":
            self.fp.truncate()
        self.fp.flush()

    def _fpclose(self, fp: IO[bytes]) -> None:
        """Decrement the file reference count and close *fp* when it reaches zero.

        Args:
            fp: The binary file object to (conditionally) close.
        """
        assert self._file_ref_cnt > 0
        self._file_ref_cnt -= 1
        if not self._file_ref_cnt and not self._file_passed:
            fp.close()
