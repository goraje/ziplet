"""ZipFile and PyZipFile classes, plus module-level helper functions."""

from __future__ import annotations

import binascii
import io
import os
import shutil
import stat
import struct
import tempfile
import threading
import warnings
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path
from types import TracebackType
from typing import IO, TYPE_CHECKING, Any, Literal, TypeAlias, cast, overload

if TYPE_CHECKING:
    from typing_extensions import Self
else:
    try:
        from typing import Self
    except ImportError:  # Python < 3.11
        from typing_extensions import Self

if TYPE_CHECKING:
    from ziplet.cryptography.base import BaseZipEncryptor

try:
    import zlib

    crc32 = zlib.crc32
except ImportError:
    crc32 = binascii.crc32

from ziplet.compression import ZIP_LZMA, ZIP_STORED, Registry, registry
from ziplet.cryptography import WZ_AES, ZIP_CRYPTO
from ziplet.cryptography.aes import AesZipEncryptor
from ziplet.cryptography.zipcrypto import ZipCryptoEncryptor
from ziplet.exceptions import BadZipFile, LargeZipFile
from ziplet.zipfile.assessment import (
    ArchiveAssessment,
    ExtractionContext,
    ValidationState,
)
from ziplet.zipfile.exceptions import (
    ExtractionFailure,
    ExtractionMaterializationError,
    ExtractionQuotaExceeded,
    ExtractionSecurityError,
)
from ziplet.zipfile.ext import ZipExtFile
from ziplet.zipfile.extract import (
    ExtractionError,
    ExtractMemberResult,
    ExtractPolicy,
    ExtractResult,
    ExtractViolation,
    MemberAssessment,
    MemberStatus,
    OverwritePolicy,
    ViolationAction,
    normalized_destination,
    resolve_rule,
)
from ziplet.zipfile.info import ZipInfo
from ziplet.zipfile.inspection import InspectionMember, InspectionResult
from ziplet.zipfile.io_wrappers import (
    ClosableZipStream,
    Tellable,
)
from ziplet.zipfile.materialize import MaterializationResult, Materializer
from ziplet.zipfile.secure_fs import SecureExtractionRoot
from ziplet.zipfile.shared import (
    MASK_COMPRESS_OPTION_1,
    MASK_COMPRESSED_PATCH,
    MASK_ENCRYPTED,
    MASK_STRONG_ENCRYPTION,
    MASK_USE_DATA_DESCRIPTOR,
    MASK_UTF_FILENAME,
    MAX_EXTRACT_VERSION,
    ZIP64_LIMIT,
    ZIP_FILECOUNT_LIMIT,
    ZIP_MAX_COMMENT,
    sizeCentralDir,
    sizeEndCentDir,
    sizeEndCentDir64,
    sizeEndCentDir64Locator,
    sizeFileHeader,
    stringCentralDir,
    stringEndArchive,
    stringEndArchive64,
    stringEndArchive64Locator,
    stringFileHeader,
    structCentralDir,
    structEndArchive,
    structEndArchive64,
    structEndArchive64Locator,
    structFileHeader,
)
from ziplet.zipfile.validators import (
    EXTRACT_VALIDATORS,
    ValidatorPipeline,
    _entry_mode,
    _entry_type,
    _member_target_name,
    resolve_extract_target,
)
from ziplet.zipfile.write import WriteState, ZipWriteFile
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
_ReadWriteMode: TypeAlias = Literal["r", "w"]
_StrPath: TypeAlias = str | os.PathLike[str]


class _InheritEncryption:
    __slots__ = ()

    def __repr__(self) -> str:
        return "INHERIT_ENCRYPTION"


INHERIT_ENCRYPTION = _InheritEncryption()
EncryptionOverride: TypeAlias = str | None | _InheritEncryption


class _ExtractionQuotaWriter:
    def __init__(
        self,
        target: IO[bytes],
        *,
        member_limit: int | None,
        total_limit: int | None,
        total_written: int,
    ) -> None:
        self._target = target
        self._member_limit = member_limit
        self._total_limit = total_limit
        self._total_written = total_written
        self.member_written = 0

    def write(self, data: bytes) -> int:
        requested = len(data)
        member_total = self.member_written + requested
        if self._member_limit is not None and member_total > self._member_limit:
            raise ExtractionQuotaExceeded("actual_member_size", self._member_limit)
        if (
            self._total_limit is not None
            and self._total_written + member_total > self._total_limit
        ):
            raise ExtractionQuotaExceeded(
                "actual_total_uncompressed_size", self._total_limit
            )
        written = self._target.write(data)
        self.member_written += written
        return written


# ---------------------------------------------------------------------------
# Local file header field indices
# ---------------------------------------------------------------------------
_FH_SIGNATURE = 0
_FH_EXTRACT_VERSION = 1  # not actually used, but present in the header
_FH_EXTRACT_SYSTEM = 2  # not actually used, but present in the header
_FH_GENERAL_PURPOSE_FLAG_BITS = 3
_FH_COMPRESSION_METHOD = 4  # not actually used, but present in the header
_FH_LAST_MOD_TIME = 5  # not actually used, but present in the header
_FH_LAST_MOD_DATE = 6  # not actually used, but present in the header
_FH_CRC = 7  # not actually used, but present in the header
_FH_COMPRESSED_SIZE = 8  # not actually used, but present in the header
_FH_UNCOMPRESSED_SIZE = 9  # not actually used, but present in the header
_FH_FILENAME_LENGTH = 10
_FH_EXTRA_FIELD_LENGTH = 11

# ---------------------------------------------------------------------------
# End-of-central-directory field indices (local to this module)
# ---------------------------------------------------------------------------
_ECD_SIGNATURE = 0
_ECD_DISK_NUMBER = 1
_ECD_DISK_START = 2
_ECD_ENTRIES_THIS_DISK = 3
_ECD_ENTRIES_TOTAL = 4
_ECD_SIZE = 5
_ECD_OFFSET = 6
_ECD_COMMENT_SIZE = 7
_ECD_COMMENT = 8
_ECD_LOCATION = 9

# ---------------------------------------------------------------------------
# Central directory field indices
# ---------------------------------------------------------------------------
_CD_SIGNATURE = 0
_CD_CREATE_VERSION = 1
_CD_CREATE_SYSTEM = 2
_CD_EXTRACT_VERSION = 3
_CD_EXTRACT_SYSTEM = 4
_CD_FLAG_BITS = 5
_CD_COMPRESS_TYPE = 6
_CD_TIME = 7
_CD_DATE = 8
_CD_CRC = 9
_CD_COMPRESSED_SIZE = 10
_CD_UNCOMPRESSED_SIZE = 11
_CD_FILENAME_LENGTH = 12
_CD_EXTRA_FIELD_LENGTH = 13
_CD_COMMENT_LENGTH = 14
_CD_DISK_NUMBER_START = 15
_CD_INTERNAL_FILE_ATTRIBUTES = 16
_CD_EXTERNAL_FILE_ATTRIBUTES = 17
_CD_LOCAL_HEADER_OFFSET = 18

# ---------------------------------------------------------------------------
# Zip64 central directory field indices
# ---------------------------------------------------------------------------
_CD64_SIGNATURE = 0
_CD64_DIRECTORY_RECSIZE = 1
_CD64_CREATE_VERSION = 2  # not actually used, but present in the record
_CD64_EXTRACT_VERSION = 3  # not actually used, but present in the record
_CD64_DISK_NUMBER = 4
_CD64_DISK_NUMBER_START = 5
_CD64_NUMBER_ENTRIES_THIS_DISK = 6
_CD64_NUMBER_ENTRIES_TOTAL = 7
_CD64_DIRECTORY_SIZE = 8
_CD64_OFFSET_START_CENTDIR = 9


def _handle_prepended_data(endrec: list[Any], debug: int = 0) -> tuple[int, int]:
    """Compute the central directory offset and prepended-data adjustment.

    Args:
        endrec: End-of-central-directory record fields as a list.
        debug: Debug verbosity level; prints diagnostics when greater than 2.

    Returns:
        A tuple of ``(offset_cd, concat)`` where *offset_cd* is the raw
        central directory offset from the record and *concat* is the number
        of prepended bytes before the ZIP data (zero for a normal,
        non-concatenated archive).
    """
    size_cd = endrec[_ECD_SIZE]  # bytes in central directory
    offset_cd = endrec[_ECD_OFFSET]  # offset of central directory

    # "concat" is zero, unless zip was concatenated to another file
    concat = endrec[_ECD_LOCATION] - size_cd - offset_cd

    if debug > 2:
        inferred = concat + offset_cd
        print("given, inferred, offset", offset_cd, inferred, concat)

    return offset_cd, concat


def _EndRecData64(fpin: IO[bytes], offset: int, endrec: list[Any]) -> list[Any]:
    """Read the ZIP64 end-of-archive records and update *endrec*.

    Looks for the ZIP64 end-of-central-directory locator and, if present,
    reads the ZIP64 end-of-central-directory record and overwrites the
    corresponding fields in *endrec* with their 64-bit counterparts.

    Args:
        fpin: Open binary file positioned anywhere; seeks as needed.
        offset: Byte offset of the standard end-of-central-directory record.
        endrec: End-of-central-directory fields as a mutable list, modified
            in place when ZIP64 data is found.

    Returns:
        The (possibly updated) *endrec* list.

    Raises:
        OSError: If a required structure cannot be fully read.
        BadZipFile: If the archive spans multiple disks, the locator or ZIP64
            end record is corrupt, or the ZIP64 end record is not found.
    """
    offset -= sizeEndCentDir64Locator
    if offset < 0:
        return endrec
    fpin.seek(offset)
    data = fpin.read(sizeEndCentDir64Locator)
    if len(data) != sizeEndCentDir64Locator:
        raise OSError("Unknown I/O error")
    sig, diskno, reloff, disks = struct.unpack(structEndArchive64Locator, data)
    if sig != stringEndArchive64Locator:
        return endrec

    if diskno != 0 or disks > 1:
        raise BadZipFile("zipfiles that span multiple disks are not supported")

    offset -= sizeEndCentDir64
    if reloff > offset:
        raise BadZipFile("Corrupt zip64 end of central directory locator")
    fpin.seek(reloff)
    extrasz = offset - reloff
    data = fpin.read(sizeEndCentDir64)
    if len(data) != sizeEndCentDir64:
        raise OSError("Unknown I/O error")
    if not data.startswith(stringEndArchive64) and reloff != offset:
        fpin.seek(offset)
        extrasz = 0
        data = fpin.read(sizeEndCentDir64)
        if len(data) != sizeEndCentDir64:
            raise OSError("Unknown I/O error")
    if not data.startswith(stringEndArchive64):
        raise BadZipFile("Zip64 end of central directory record not found")

    endrec64 = struct.unpack(structEndArchive64, data)
    if (
        endrec64[_CD64_OFFSET_START_CENTDIR] + endrec64[_CD64_DIRECTORY_SIZE] != reloff
        or endrec64[_CD64_DIRECTORY_RECSIZE] + 12 != sizeEndCentDir64 + extrasz
    ):
        raise BadZipFile("Corrupt zip64 end of central directory record")

    endrec[_ECD_SIGNATURE] = endrec64[_CD64_SIGNATURE]
    endrec[_ECD_DISK_NUMBER] = endrec64[_CD64_DISK_NUMBER]
    endrec[_ECD_DISK_START] = endrec64[_CD64_DISK_NUMBER_START]
    endrec[_ECD_ENTRIES_THIS_DISK] = endrec64[_CD64_NUMBER_ENTRIES_THIS_DISK]
    endrec[_ECD_ENTRIES_TOTAL] = endrec64[_CD64_NUMBER_ENTRIES_TOTAL]
    endrec[_ECD_SIZE] = endrec64[_CD64_DIRECTORY_SIZE]
    endrec[_ECD_OFFSET] = endrec64[_CD64_OFFSET_START_CENTDIR]
    endrec[_ECD_LOCATION] = offset - extrasz
    return endrec


def _EndRecData(fpin: IO[bytes]) -> list[Any] | None:
    """Return data from the end-of-central-directory record, or ``None``.

    Searches for the ``PK\x05\x06`` signature at or near the end of *fpin*,
    handles archives with a comment, and delegates to :func:`_EndRecData64`
    to upgrade to ZIP64 values when applicable.

    Args:
        fpin: Open binary file to search.

    Returns:
        A list of end-of-central-directory fields (including the archive
        comment and the file offset of the record), or ``None`` if no valid
        record can be found.
    """
    fpin.seek(0, 2)
    filesize = fpin.tell()

    try:
        fpin.seek(-sizeEndCentDir, 2)
    except OSError:
        return None
    data = fpin.read(sizeEndCentDir)
    if (
        len(data) == sizeEndCentDir
        and data[0:4] == stringEndArchive
        and data[-2:] == b"\000\000"
    ):
        endrec = list(struct.unpack(structEndArchive, data))
        endrec.append(b"")
        endrec.append(filesize - sizeEndCentDir)
        return _EndRecData64(fpin, filesize - sizeEndCentDir, endrec)

    maxCommentStart = max(filesize - ZIP_MAX_COMMENT - sizeEndCentDir, 0)
    fpin.seek(maxCommentStart, 0)
    data = fpin.read(ZIP_MAX_COMMENT + sizeEndCentDir)
    start = data.rfind(stringEndArchive)
    if start >= 0:
        recData = data[start : start + sizeEndCentDir]
        if len(recData) != sizeEndCentDir:
            return None
        endrec = list(struct.unpack(structEndArchive, recData))
        commentSize = endrec[_ECD_COMMENT_SIZE]
        comment = data[start + sizeEndCentDir : start + sizeEndCentDir + commentSize]
        if len(comment) != commentSize or start + sizeEndCentDir + commentSize > len(
            data
        ):
            return None
        endrec.append(comment)
        endrec.append(maxCommentStart + start)
        return _EndRecData64(fpin, maxCommentStart + start, endrec)

    return None


def _check_zipfile(fp: IO[bytes]) -> bool:
    """Return ``True`` if *fp* appears to be a valid ZIP file.

    Reads the end-of-central-directory record and, if present, verifies
    that the first central directory entry carries the expected signature.

    Args:
        fp: Open binary file-like object to inspect.

    Returns:
        ``True`` if a valid ZIP structure is detected, ``False`` otherwise.
    """
    try:
        endrec = _EndRecData(fp)
        if endrec:
            if (
                endrec[_ECD_ENTRIES_TOTAL] == 0
                and endrec[_ECD_SIZE] == 0
                and endrec[_ECD_OFFSET] == 0
            ):
                return True
            elif endrec[_ECD_DISK_NUMBER] == endrec[_ECD_DISK_START]:
                fp.seek(sum(_handle_prepended_data(endrec)))
                if endrec[_ECD_SIZE] >= sizeCentralDir:
                    data = fp.read(sizeCentralDir)
                    if len(data) == sizeCentralDir:
                        centdir = struct.unpack(structCentralDir, data)
                        if centdir[_CD_SIGNATURE] == stringCentralDir:
                            return True
    except OSError:
        pass
    return False


def is_zipfile(filename: _StrPath | IO[bytes]) -> bool:
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
            result = _check_zipfile(fp=filename)
            filename.seek(pos)
        else:
            with open(filename, "rb") as fp:
                result = _check_zipfile(fp)
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

    _HARD_EXTRACTION_VIOLATIONS = frozenset(
        {
            "absolute_path",
            "windows_drive_path",
            "windows_path",
            "parent_traversal",
            "outside_root",
            "symlink",
            "special_file",
            "unsafe_destination",
        }
    )

    _extract_pipeline = ValidatorPipeline(EXTRACT_VALIDATORS)

    @classmethod
    def _apply_hard_violation_floor(
        cls, violations: Iterable[ExtractViolation]
    ) -> list[ExtractViolation]:
        """Escalate WARN to ERROR for codes that can never be soft-failed.

        Runs after per-check violation actions are already resolved (see
        :func:`ziplet.zipfile.extract.resolve_rule`), so this only enforces
        the floor — it does not otherwise touch an already-resolved action.
        """
        return [
            replace(violation, action=ViolationAction.ERROR)
            if (
                violation.code in cls._HARD_EXTRACTION_VIOLATIONS
                and violation.action == ViolationAction.WARN
            )
            else violation
            for violation in violations
        ]

    def _assess_member(
        self,
        info: ZipInfo,
        destination: Path,
        policy_root: Path,
        policy: ExtractPolicy,
        state: ValidationState,
    ) -> MemberAssessment:
        target, _drive, _parts = resolve_extract_target(info, destination)
        context = ExtractionContext(destination, policy_root, None, policy)
        violations = self._extract_pipeline.validate(info, target, context, state)
        violations = self._apply_hard_violation_floor(violations)
        return MemberAssessment(
            info,
            target,
            tuple(violations),
            *_entry_type(info),
        )

    fp: IO[bytes] | None = None

    def __init__(
        self,
        file: _StrPath | IO[bytes],
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

        self._allowZip64 = allowZip64
        self._didModify = False
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
            self._filePassed = False
            self.filename: str | None = file
            modeDict = {
                "r": "rb",
                "w": "w+b",
                "x": "x+b",
                "a": "r+b",
                "r+b": "w+b",
                "w+b": "wb",
                "x+b": "xb",
            }
            filemode = modeDict[mode]
            while True:
                try:
                    self.fp = open(file, filemode)
                except OSError:
                    if filemode in modeDict:
                        filemode = modeDict[filemode]
                        continue
                    raise
                break
        else:
            self._filePassed = True
            self.fp = file
            self.filename = getattr(file, "name", None)
        self._fileRefCnt = 1
        self._lock = threading.RLock()
        self._write_coordinator = WriteCoordinator(self._lock)
        self._write_condition = self._write_coordinator.condition
        self._active_writer: ZipWriteFile | None = None
        self._seekable = True
        self._writing = False
        self._compression_registry = selected_registry

        try:
            if mode == "r":
                self._RealGetContents()
            elif mode in ("w", "x"):
                self._didModify = True
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
                    self._RealGetContents()
                    self.fp.seek(self.start_dir)
                except BadZipFile:
                    self.fp.seek(0, 2)
                    self._didModify = True
                    self.start_dir = self.fp.tell()
            else:
                raise ValueError("Mode must be 'r', 'w', 'x', or 'a'")
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
            if self._filePassed:
                result.append(" file=%r" % self.fp)
            elif self.filename is not None:
                result.append(" filename=%r" % self.filename)
            result.append(" mode=%r" % self.mode)
        else:
            result.append(" [closed]")
        result.append(">")
        return "".join(result)

    def _RealGetContents(self) -> None:
        """Parse the central directory and populate :attr:`filelist`
        and :attr:`NameToInfo`.

        Reads the end-of-central-directory record, locates the central
        directory, decodes every entry, and computes each entry's
        ``_end_offset`` for overlap detection.

        Raises:
            BadZipFile: If the file is not a ZIP archive, the central directory
                is truncated or corrupt, or an unsupported ZIP version is
                encountered.
        """
        fp = self.fp
        assert fp is not None
        try:
            endrec = _EndRecData(fp)
        except OSError:
            raise BadZipFile("File is not a zip file") from None
        if not endrec:
            raise BadZipFile("File is not a zip file")
        if self.debug > 1:
            print(endrec)
        self._comment = endrec[_ECD_COMMENT]

        offset_cd, concat = _handle_prepended_data(endrec, self.debug)

        self.start_dir = offset_cd + concat

        if self.start_dir < 0:
            raise BadZipFile("Bad offset for central directory")
        fp.seek(self.start_dir, 0)
        size_cd = endrec[_ECD_SIZE]
        data = fp.read(size_cd)
        fp = io.BytesIO(data)
        total = 0
        while total < size_cd:
            centdir_raw = fp.read(sizeCentralDir)
            if len(centdir_raw) != sizeCentralDir:
                raise BadZipFile("Truncated central directory")
            centdir = struct.unpack(structCentralDir, centdir_raw)
            if centdir[_CD_SIGNATURE] != stringCentralDir:
                raise BadZipFile("Bad magic number for central directory")
            if self.debug > 2:
                print(centdir)
            filename_bytes = fp.read(centdir[_CD_FILENAME_LENGTH])
            orig_filename_crc = crc32(filename_bytes)
            flags = centdir[_CD_FLAG_BITS]
            if flags & MASK_UTF_FILENAME:
                filename = filename_bytes.decode("utf-8")
            else:
                filename = filename_bytes.decode(self.metadata_encoding or "cp437")
            x = ZipInfo(filename)
            x.extra = fp.read(centdir[_CD_EXTRA_FIELD_LENGTH])
            x.comment = fp.read(centdir[_CD_COMMENT_LENGTH])
            x.header_offset = centdir[_CD_LOCAL_HEADER_OFFSET]
            x.create_version = centdir[_CD_CREATE_VERSION]
            x.create_system = centdir[_CD_CREATE_SYSTEM]
            x.extract_version = centdir[_CD_EXTRACT_VERSION]
            x.reserved = centdir[_CD_EXTRACT_SYSTEM]
            x.flag_bits = centdir[_CD_FLAG_BITS]
            x.compress_type = centdir[_CD_COMPRESS_TYPE]
            t = centdir[_CD_TIME]
            d = centdir[_CD_DATE]
            x.CRC = centdir[_CD_CRC]
            x.compress_size = centdir[_CD_COMPRESSED_SIZE]
            x.file_size = centdir[_CD_UNCOMPRESSED_SIZE]
            if x.extract_version > MAX_EXTRACT_VERSION:
                raise NotImplementedError(
                    "zip file version %.1f" % (x.extract_version / 10)
                )
            x.volume = centdir[_CD_DISK_NUMBER_START]
            x.internal_attr = centdir[_CD_INTERNAL_FILE_ATTRIBUTES]
            x.external_attr = centdir[_CD_EXTERNAL_FILE_ATTRIBUTES]
            x._raw_time = t
            x.date_time = (
                (d >> 9) + 1980,
                (d >> 5) & 0xF,
                d & 0x1F,
                t >> 11,
                (t >> 5) & 0x3F,
                (t & 0x1F) * 2,
            )
            x._decodeExtra(orig_filename_crc)
            x.header_offset = x.header_offset + concat
            self.filelist.append(x)
            self.NameToInfo[x.filename] = x

            total = (
                total
                + sizeCentralDir
                + centdir[_CD_FILENAME_LENGTH]
                + centdir[_CD_EXTRA_FIELD_LENGTH]
                + centdir[_CD_COMMENT_LENGTH]
            )

            if self.debug > 2:
                print("total", total)

        end_offset = self.start_dir
        for zinfo in reversed(
            sorted(self.filelist, key=lambda zinfo: zinfo.header_offset)
        ):
            zinfo._end_offset = end_offset
            end_offset = zinfo.header_offset

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
        path: _StrPath | None = None,
        policy: ExtractPolicy | None = None,
    ) -> InspectionResult:
        """Inspect archive metadata without opening or processing payloads.

        No member data is read, decompressed, decrypted, or written.  Policy
        findings are returned in the report and never raise
        :class:`ExtractionError`.
        """
        effective_policy = (
            policy
            if policy is not None
            else replace(
                ExtractPolicy(),
                allow_overwrite=True,
                overwrite_policy=OverwritePolicy.REPLACE,
                max_member_size=None,
                max_total_uncompressed_size=None,
                max_entries=None,
                max_compression_ratio=None,
            )
        )
        assessment = self.assess(path, effective_policy)
        total_entries = len(assessment.members)

        max_entries_rule = resolve_rule(
            effective_policy.max_entries, effective_policy.on_violation
        )
        count_over = (
            max_entries_rule.value is not None
            and total_entries > max_entries_rule.value
        )
        violations: list[ExtractViolation] = list(assessment.violations)
        if count_over:
            violations.append(
                ExtractViolation(
                    "<archive>",
                    "max_entries",
                    f"archive contains {total_entries} entries, "
                    f"limit is {max_entries_rule.value}",
                    max_entries_rule.action,
                )
            )

        members: list[InspectionMember] = []
        encrypted: list[str] = []
        suspicious: list[str] = []
        large: list[str] = []
        ratio_outliers: list[str] = []
        symlinks: list[str] = []
        special_files: list[str] = []

        for member_assessment in assessment.members:
            info = member_assessment.info
            target = member_assessment.target
            member_violations = member_assessment.violations
            is_link = member_assessment.is_symlink
            is_special = member_assessment.is_special
            ratio = (
                None if info.compress_size == 0 else info.file_size / info.compress_size
            )
            if info.flag_bits & MASK_ENCRYPTED:
                encrypted.append(info.filename)
            if is_link:
                symlinks.append(info.filename)
            if is_special:
                special_files.append(info.filename)
            if any(
                violation.code
                in {
                    "absolute_path",
                    "windows_path",
                    "windows_drive_path",
                    "parent_traversal",
                    "outside_root",
                }
                for violation in member_violations
            ):
                suspicious.append(info.filename)
            if any(v.code == "max_member_size" for v in member_violations):
                large.append(info.filename)
            if any(v.code == "compression_ratio" for v in member_violations):
                ratio_outliers.append(info.filename)
            members.append(
                InspectionMember(
                    info.filename,
                    target,
                    info.is_dir(),
                    info.compress_size,
                    info.file_size,
                    ratio,
                    bool(info.flag_bits & MASK_ENCRYPTED),
                    is_link,
                    is_special,
                    member_violations,
                )
            )

        warnings = tuple(v for v in violations if v.action == ViolationAction.WARN)
        return InspectionResult(
            total_entries,
            assessment.total_compressed_size,
            assessment.total_uncompressed_size,
            tuple(members),
            assessment.duplicate_member_names,
            assessment.duplicate_targets,
            tuple(dict.fromkeys(suspicious)),
            tuple(encrypted),
            tuple(large),
            tuple(ratio_outliers),
            tuple(symlinks),
            tuple(special_files),
            warnings,
            tuple(violations),
            count_over,
        )

    def assess(
        self,
        path: _StrPath | None = None,
        policy: ExtractPolicy | None = None,
    ) -> ArchiveAssessment:
        """Return the metadata assessment shared by policy consumers."""
        effective_policy = policy or replace(
            ExtractPolicy(),
            allow_overwrite=True,
            overwrite_policy=OverwritePolicy.REPLACE,
            max_member_size=None,
            max_total_uncompressed_size=None,
            max_entries=None,
            max_compression_ratio=None,
        )
        destination = normalized_destination(path or os.getcwd())
        root = normalized_destination(effective_policy.destination_root or destination)
        state = ValidationState()
        members: list[MemberAssessment] = []
        violations: list[ExtractViolation] = []
        duplicate_targets: list[Path] = []
        for info in self.filelist:
            state.names[info.filename] = state.names.get(info.filename, 0) + 1
            state.total_declared += info.file_size
            state.total_compressed += info.compress_size
            before = set(state.targets)
            assessment = self._assess_member(
                info, destination, root, effective_policy, state
            )
            state.member_index += 1
            if assessment.target is not None and assessment.target in before:
                duplicate_targets.append(assessment.target)
            members.append(assessment)
            violations.extend(assessment.violations)
        return ArchiveAssessment(
            destination,
            tuple(members),
            tuple(violations),
            state.total_compressed,
            state.total_declared,
            tuple(name for name, count in state.names.items() if count > 1),
            tuple(dict.fromkeys(duplicate_targets)),
        )

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
        """Construct and return an encryptor for the current encryption setting.

        Returns:
            A :class:`~ziplet.cryptography.base.BaseZipEncryptor`
            appropriate for :attr:`encryption`.

        Raises:
            AssertionError: If :attr:`pwd` is ``None``.
            NotImplementedError: If :attr:`encryption` is an unknown scheme.
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
        self._didModify = True

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
        mode: _ReadWriteMode = "r",
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

        if self._writing:
            raise ValueError(
                "Can't read from the ZIP file while there "
                "is an open writing handle on it. "
                "Close the writing handle before trying to read."
            )

        return cast(IO[bytes], self._open_to_read(mode, zinfo, pwd))

    def _open_to_read(
        self, mode: _ReadWriteMode, zinfo: ZipInfo, pwd: bytes | None
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
        self._fileRefCnt += 1
        zef_file = ClosableZipStream(
            self.fp,
            zinfo.header_offset,
            self._fpclose,
            self._lock,
            lambda: self._writing,
        )
        try:
            fheader_raw = zef_file.read(sizeFileHeader)
            if len(fheader_raw) != sizeFileHeader:
                raise BadZipFile("Truncated file header")
            fheader = struct.unpack(structFileHeader, fheader_raw)
            if fheader[_FH_SIGNATURE] != stringFileHeader:
                raise BadZipFile("Bad magic number for file header")

            fname = zef_file.read(fheader[_FH_FILENAME_LENGTH])
            if fheader[_FH_EXTRA_FIELD_LENGTH]:
                zef_file.seek(fheader[_FH_EXTRA_FIELD_LENGTH], whence=1)

            if zinfo.flag_bits & MASK_COMPRESSED_PATCH:
                raise NotImplementedError("compressed patched data (flag bit 5)")

            if zinfo.flag_bits & MASK_STRONG_ENCRYPTION:
                raise NotImplementedError("strong encryption (flag bit 6)")

            if fheader[_FH_GENERAL_PURPOSE_FLAG_BITS] & MASK_UTF_FILENAME:
                fname_str = fname.decode("utf-8")
            else:
                fname_str = fname.decode(self.metadata_encoding or "cp437")

            if fname_str != zinfo.orig_filename:
                raise BadZipFile(
                    "File name in directory %r and header %r differ."
                    % (zinfo.orig_filename, fname)
                )

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
        if force_zip64 and not self._allowZip64:
            raise ValueError(
                "force_zip64 is True, but allowZip64 was False when opening "
                "the ZIP file."
            )
        reservation = self._write_coordinator.reserve()

        zinfo.compress_size = 0
        zinfo.CRC = 0

        zinfo.flag_bits = 0x00
        if zinfo.compress_type == ZIP_LZMA:
            zinfo.flag_bits |= MASK_COMPRESS_OPTION_1
        if not self._seekable:
            zinfo.flag_bits |= MASK_USE_DATA_DESCRIPTOR

        if not zinfo.external_attr:
            zinfo.external_attr = 0o600 << 16

        zip64 = force_zip64 or (zinfo.file_size + zinfo.file_size // 20 > ZIP64_LIMIT)
        if not self._allowZip64 and zip64:
            raise LargeZipFile("Filesize would require ZIP64 extensions")

        assert self.fp is not None
        if self._seekable:
            self.fp.seek(self.start_dir)
        zinfo.header_offset = self.fp.tell()

        self._writecheck(zinfo)
        self._didModify = True

        effective_encryption = (
            self.encryption if encryption is INHERIT_ENCRYPTION else encryption
        )
        if effective_encryption is None and password is not None:
            raise ValueError("password cannot be used for an unencrypted entry")
        encryptor = None
        if effective_encryption:
            zinfo.flag_bits |= MASK_ENCRYPTED
            effective_extra = extra
            if effective_extra is None:
                nbits = self._wz_aes_nbits
                aes_version = self._force_wz_aes_version
            else:
                nbits = effective_extra.wz_aes_nbits
                aes_version = effective_extra.force_wz_aes_version
            encryptor = self.get_encryptor(
                cast(str, effective_encryption),
                password,
                nbits=nbits,
                force_wz_aes_version=aes_version,
            )

        try:
            writer = ZipWriteFile(
                self, zinfo, zip64, encryptor, self._compression_registry, reservation
            )
        except BaseException:
            self._write_coordinator.release(reservation)
            raise
        self._active_writer = writer
        return writer

    @overload
    def extract(
        self,
        member: str | ZipInfo,
        path: _StrPath | None = None,
        pwd: bytes | None = None,
        *,
        policy: None = None,
    ) -> str: ...

    @overload
    def extract(
        self,
        member: str | ZipInfo,
        path: _StrPath | None = None,
        pwd: bytes | None = None,
        *,
        policy: ExtractPolicy,
    ) -> ExtractMemberResult: ...

    def extract(
        self,
        member: str | ZipInfo,
        path: _StrPath | None = None,
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

        if path is None:
            path = os.getcwd()
        else:
            path = os.fspath(path)
        return str(self._extract_member(member, path, pwd).target)

    @overload
    def extractall(
        self,
        path: _StrPath | None = None,
        members: Iterable[str | ZipInfo] | None = None,
        pwd: bytes | None = None,
        *,
        policy: None = None,
    ) -> None: ...

    @overload
    def extractall(
        self,
        path: _StrPath | None = None,
        members: Iterable[str | ZipInfo] | None = None,
        pwd: bytes | None = None,
        *,
        policy: ExtractPolicy,
    ) -> ExtractResult: ...

    def extractall(
        self,
        path: _StrPath | None = None,
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
        if path is None:
            path = os.getcwd()
        else:
            path = os.fspath(path)
        for zipinfo in members:
            self._extract_member(zipinfo, path, pwd)
        return None

    def _extract_with_policy(
        self,
        members: list[str | ZipInfo],
        path: _StrPath | None,
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
        violations: list[ExtractViolation] = []
        results: list[ExtractMemberResult] = []
        state = ValidationState()
        total_written = 0

        max_entries_rule = resolve_rule(policy.max_entries, policy.on_violation)
        if max_entries_rule.value is not None and len(infos) > max_entries_rule.value:
            violation = ExtractViolation(
                "<archive>",
                "max_entries",
                f"archive contains {len(infos)} entries, "
                f"limit is {max_entries_rule.value}",
                max_entries_rule.action,
            )
            violations.append(violation)
        max_total_size_rule = resolve_rule(
            policy.max_total_uncompressed_size, policy.on_violation
        )

        for info in infos:
            state.total_declared += info.file_size
            state.total_compressed += info.compress_size
            assessment = self._assess_member(
                info, destination, policy_root, policy, state
            )
            state.member_index += 1
            target = assessment.target
            member_violations = list(assessment.violations)
            violations.extend(member_violations)

            action = (
                ViolationAction.ERROR
                if any(v.action == ViolationAction.ERROR for v in member_violations)
                else (
                    ViolationAction.SKIP
                    if any(v.action == ViolationAction.SKIP for v in member_violations)
                    else ViolationAction.WARN
                    if member_violations
                    else None
                )
            )
            if action == ViolationAction.ERROR:
                results.append(
                    self._member_result(
                        info,
                        MemberStatus.FAILED,
                        target,
                        0,
                        tuple(member_violations),
                    )
                )
                continue
            if action == ViolationAction.SKIP:
                results.append(
                    self._member_result(
                        info,
                        MemberStatus.SKIPPED,
                        target,
                        0,
                        tuple(member_violations),
                    )
                )
                continue
            for violation in member_violations:
                warnings.warn(violation.message, stacklevel=3)

            if policy.preview_only:
                results.append(
                    self._member_result(
                        info,
                        MemberStatus.PREVIEWED,
                        target,
                        0,
                        tuple(member_violations),
                    )
                )
                continue

            assert target is not None
            target = self._prepare_policy_target(target, info, policy)
            was_existing = target.exists()
            try:
                materialized = self._extract_member(
                    info,
                    str(destination),
                    pwd,
                    target_override=target,
                    quota_member_limit=resolve_rule(
                        policy.max_member_size, policy.on_violation
                    ).value,
                    quota_total_limit=max_total_size_rule.value,
                    quota_total_written=total_written,
                )
                written_target = str(materialized.target)
                written = materialized.bytes_written
                total_written += written
            except ExtractionQuotaExceeded as exc:
                violation = ExtractViolation(
                    info.filename,
                    exc.code,
                    str(exc),
                    ViolationAction.ERROR,
                    target,
                )
                violations.append(violation)
                results.append(
                    self._member_result(
                        info,
                        MemberStatus.FAILED,
                        target,
                        0,
                        tuple(member_violations) + (violation,),
                    )
                )
                continue
            except (
                OSError,
                ValueError,
                BadZipFile,
                RuntimeError,
                ExtractionFailure,
            ) as exc:
                violation = ExtractViolation(
                    info.filename,
                    "extraction_error",
                    str(exc),
                    ViolationAction.ERROR,
                    target,
                )
                violations.append(violation)
                results.append(
                    self._member_result(
                        info,
                        MemberStatus.FAILED,
                        target,
                        0,
                        tuple(member_violations) + (violation,),
                    )
                )
                continue
            results.append(
                self._member_result(
                    info,
                    MemberStatus.EXTRACTED,
                    Path(written_target),
                    written,
                    tuple(member_violations),
                    was_existing,
                )
            )

        extracted = sum(r.status == MemberStatus.EXTRACTED for r in results)
        skipped = sum(
            r.status in (MemberStatus.SKIPPED, MemberStatus.PREVIEWED) for r in results
        )
        failed = sum(r.status == MemberStatus.FAILED for r in results)
        if any(v.action == ViolationAction.ERROR for v in violations):
            failed = max(failed, 1)
        return ExtractResult(
            destination,
            tuple(results),
            tuple(violations),
            extracted,
            skipped,
            failed,
            sum(r.bytes_written for r in results),
            policy.preview_only,
        )

    def _member_result(
        self,
        info: ZipInfo,
        status: MemberStatus,
        target: Path | None,
        written: int,
        violations: tuple[ExtractViolation, ...],
        overwritten: bool = False,
    ) -> ExtractMemberResult:
        ratio = None if info.compress_size == 0 else info.file_size / info.compress_size
        return ExtractMemberResult(
            info.filename,
            status,
            target,
            info.is_dir(),
            info.compress_size,
            info.file_size,
            ratio,
            written,
            violations,
            overwritten,
        )

    @staticmethod
    def _prepare_policy_target(
        target: Path,
        info: ZipInfo,
        policy: ExtractPolicy,
    ) -> Path:
        if target.exists() and policy.overwrite_policy == OverwritePolicy.RENAME:
            stem = target
            counter = 1
            while target.exists():
                target = stem.with_name(f"{stem.name}.{counter}")
                counter += 1
        return target

    def _extract_member(
        self,
        member: str | ZipInfo,
        targetpath: str,
        pwd: bytes | None,
        *,
        target_override: Path | None = None,
        quota_member_limit: int | None = None,
        quota_total_limit: int | None = None,
        quota_total_written: int = 0,
    ) -> MaterializationResult:
        """Extract *member* to *targetpath* and return the materialization result.

        Resolves the platform path, guards against path traversal, creates
        parent directories as needed, and writes the file content (or creates
        a directory) at the resolved location.

        Args:
            member: Archive member name or
                :class:`~ziplet.zipfile.info.ZipInfo` instance.
            targetpath: Root directory under which the member is extracted.
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

        _, parts = _member_target_name(member.filename)
        arcname = os.path.sep.join(parts)

        if not arcname and not member.is_dir():
            raise ValueError("Empty filename.")

        if target_override is None:
            targetpath = os.path.join(targetpath, arcname)
            targetpath = os.path.normpath(targetpath)
        else:
            targetpath = os.fspath(target_override)

        upperdirs = os.path.dirname(targetpath)
        if upperdirs:
            self._secure_mkdirs(upperdirs)

        materializer = self._materializer(member)
        return materializer(
            member,
            targetpath,
            pwd,
            quota_member_limit,
            quota_total_limit,
            quota_total_written,
            upperdirs or ".",
        )

    def _materializer(self, member: ZipInfo) -> Materializer:
        if member.is_dir():
            return self._materialize_directory
        mode = _entry_mode(member)
        if stat.S_ISLNK(mode):
            return self._materialize_symlink
        if mode and not stat.S_ISREG(mode) and not stat.S_ISDIR(mode):
            return self._materialize_special
        return self._materialize_regular_file

    def _materialize_directory(
        self,
        member: ZipInfo,
        targetpath: str,
        pwd: bytes | None,
        quota_member_limit: int | None,
        quota_total_limit: int | None,
        quota_total_written: int,
        directory: str,
    ) -> MaterializationResult:
        del member, pwd, quota_member_limit, quota_total_limit, quota_total_written
        del directory
        if os.path.lexists(targetpath) and os.path.islink(targetpath):
            raise ExtractionSecurityError(
                "Refusing to traverse symlinked extraction directory"
            )
        existed = os.path.isdir(targetpath)
        if not existed:
            try:
                os.mkdir(targetpath)
            except FileExistsError:
                if not os.path.isdir(targetpath):
                    raise
        return MaterializationResult(Path(targetpath), 0, existed)

    def _materialize_symlink(
        self,
        member: ZipInfo,
        targetpath: str,
        pwd: bytes | None,
        quota_member_limit: int | None,
        quota_total_limit: int | None,
        quota_total_written: int,
        directory: str,
    ) -> MaterializationResult:
        del quota_member_limit, quota_total_limit, quota_total_written, directory
        with self.open(member, pwd=pwd) as source:
            link_target = os.fsdecode(source.read())
        if os.path.isabs(link_target) or ".." in link_target.replace("\\", "/").split(
            "/"
        ):
            raise ExtractionSecurityError(
                "Refusing to create symlink outside extraction root"
            )
        existed = os.path.lexists(targetpath)
        if existed:
            os.unlink(targetpath)
        os.symlink(link_target, targetpath)
        return MaterializationResult(Path(targetpath), 0, existed)

    def _materialize_special(
        self,
        member: ZipInfo,
        targetpath: str,
        pwd: bytes | None,
        quota_member_limit: int | None,
        quota_total_limit: int | None,
        quota_total_written: int,
        directory: str,
    ) -> MaterializationResult:
        del pwd, quota_member_limit, quota_total_limit, quota_total_written, directory
        if stat.S_ISFIFO(_entry_mode(member)) and hasattr(os, "mkfifo"):
            existed = os.path.lexists(targetpath)
            if existed:
                os.unlink(targetpath)
            os.mkfifo(targetpath, stat.S_IMODE(member.external_attr >> 16))
            return MaterializationResult(Path(targetpath), 0, existed)
        raise ExtractionMaterializationError("Unsupported special file type")

    def _materialize_regular_file(
        self,
        member: ZipInfo,
        targetpath: str,
        pwd: bytes | None,
        quota_member_limit: int | None,
        quota_total_limit: int | None,
        quota_total_written: int,
        directory: str,
    ) -> MaterializationResult:
        existed = os.path.lexists(targetpath)
        temp_name: str | None = None
        bytes_written = 0
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=directory, prefix=".ziplet-", delete=False
            ) as target:
                temp_name = target.name
                if quota_member_limit is None and quota_total_limit is None:
                    with self.open(member, pwd=pwd) as source:
                        shutil.copyfileobj(source, target)
                else:
                    with self.open(member, pwd=pwd) as source:
                        quota_target = _ExtractionQuotaWriter(
                            target,
                            member_limit=quota_member_limit,
                            total_limit=quota_total_limit,
                            total_written=quota_total_written,
                        )
                        shutil.copyfileobj(source, quota_target)
                target.flush()
                os.fsync(target.fileno())
                bytes_written = target.tell()
            os.replace(temp_name, targetpath)
            temp_name = None
        finally:
            if temp_name is not None:
                try:
                    os.unlink(temp_name)
                except FileNotFoundError:
                    pass

        return MaterializationResult(Path(targetpath), bytes_written, existed)

    @staticmethod
    def _secure_mkdirs(path: str) -> None:
        """Create parents without following pre-existing symlink components."""
        absolute = Path(os.path.abspath(path))
        root = SecureExtractionRoot(Path(absolute.anchor or os.path.sep))
        relative = tuple(part for part in absolute.parts[1:] if part)
        with root:
            root.ensure_parents(relative)

    def _writecheck(self, zinfo: ZipInfo) -> None:
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
        if not self._allowZip64:
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
        filename: _StrPath,
        arcname: _StrPath | None = None,
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
        self._write_coordinator.ensure_readable()
        if self._writing:
            raise ValueError(
                "Can't write to ZIP archive while an open writing handle exists"
            )

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
                shutil.copyfileobj(src, dest, 1024 * 8)

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
        if self._writing:
            raise ValueError(
                "Can't write to ZIP archive while an open writing handle exists."
            )

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

            self._writecheck(zinfo)
            self._didModify = True

            self.filelist.append(zinfo)
            self.NameToInfo[zinfo.filename] = zinfo
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

        if self._writing:
            with self._write_condition:
                writer = self._active_writer
                if writer is not None and writer._state == WriteState.FINALIZING:
                    self._write_condition.wait_for(lambda: not self._writing)
                if self._writing:
                    raise ValueError(
                        "Can't close the ZIP file while there is "
                        "an open writing handle on it. "
                        "Close the writing handle before closing the zip."
                    )

        try:
            if self.mode in ("w", "x", "a") and self._didModify:
                with self._lock:
                    if self._seekable:
                        self.fp.seek(self.start_dir)
                    self._write_end_record()
        finally:
            fp = self.fp
            self.fp = None
            self._fpclose(fp)

    def _write_end_record(self) -> None:
        """Write the central directory and end-of-central-directory record.

        Serialises every :class:`~ziplet.zipfile.info.ZipInfo` in
        :attr:`filelist` into central directory entries, emits a ZIP64 end
        record and locator when required, and finalises with the standard
        end-of-central-directory record and the archive comment. Truncates
        the file afterwards when mode is ``'a'``.

        Raises:
            LargeZipFile: If central directory metrics exceed ZIP64 thresholds
                and ZIP64 is not allowed.
        """
        assert self.fp is not None
        parts: list[bytes] = []
        for zinfo in self.filelist:
            centdir, filename, extra_data = zinfo.central_directory()
            parts.extend((centdir, filename, extra_data, zinfo.comment))
        self.fp.write(b"".join(parts))

        pos2 = self.fp.tell()
        centDirCount = len(self.filelist)
        centDirSize = pos2 - self.start_dir
        centDirOffset = self.start_dir
        requires_zip64 = None
        if centDirCount > ZIP_FILECOUNT_LIMIT:
            requires_zip64 = "Files count"
        elif centDirOffset > ZIP64_LIMIT:
            requires_zip64 = "Central directory offset"
        elif centDirSize > ZIP64_LIMIT:
            requires_zip64 = "Central directory size"
        if requires_zip64:
            if not self._allowZip64:
                raise LargeZipFile(requires_zip64 + " would require ZIP64 extensions")
            zip64endrec = struct.pack(
                structEndArchive64,
                stringEndArchive64,
                sizeEndCentDir64 - 12,
                45,
                45,
                0,
                0,
                centDirCount,
                centDirCount,
                centDirSize,
                centDirOffset,
            )
            self.fp.write(zip64endrec)

            zip64locrec = struct.pack(
                structEndArchive64Locator, stringEndArchive64Locator, 0, pos2, 1
            )
            self.fp.write(zip64locrec)
            centDirCount = min(centDirCount, 0xFFFF)
            centDirSize = min(centDirSize, 0xFFFFFFFF)
            centDirOffset = min(centDirOffset, 0xFFFFFFFF)

        endrec = struct.pack(
            structEndArchive,
            stringEndArchive,
            0,
            0,
            centDirCount,
            centDirCount,
            centDirSize,
            centDirOffset,
            len(self._comment),
        )
        self.fp.write(endrec)
        self.fp.write(self._comment)
        if self.mode == "a":
            self.fp.truncate()
        self.fp.flush()

    def _fpclose(self, fp: IO[bytes]) -> None:
        """Decrement the file reference count and close *fp* when it reaches zero.

        Args:
            fp: The binary file object to (conditionally) close.
        """
        assert self._fileRefCnt > 0
        self._fileRefCnt -= 1
        if not self._fileRefCnt and not self._filePassed:
            fp.close()
