"""Binary ZIP records: end-of-central-directory, central directory, local header.

Everything that knows the on-disk layout of the archive-level records lives
here, so :class:`~ziplet.zipfile.file.ZipFile` only deals with typed values.
"""

from __future__ import annotations

import io
import struct
from dataclasses import dataclass
from typing import IO

from ziplet.exceptions import BadZipFile, LargeZipFile
from ziplet.zipfile.info import ZipInfo
from ziplet.zipfile.io_wrappers import ClosableZipStream
from ziplet.zipfile.shared import (
    CENTRAL_DIR_SIGNATURE,
    CENTRAL_DIR_SIZE,
    CENTRAL_DIR_STRUCT,
    END_ARCHIVE64_LOCATOR_SIGNATURE,
    END_ARCHIVE64_LOCATOR_SIZE,
    END_ARCHIVE64_LOCATOR_STRUCT,
    END_ARCHIVE64_SIGNATURE,
    END_ARCHIVE64_SIZE,
    END_ARCHIVE64_STRUCT,
    END_ARCHIVE_SIGNATURE,
    END_ARCHIVE_SIZE,
    END_ARCHIVE_STRUCT,
    FILE_HEADER_SIGNATURE,
    FILE_HEADER_SIZE,
    FILE_HEADER_STRUCT,
    MASK_COMPRESSED_PATCH,
    MASK_STRONG_ENCRYPTION,
    MASK_UTF_FILENAME,
    MAX_EXTRACT_VERSION,
    ZIP64_LIMIT,
    ZIP64_VERSION,
    ZIP_FILECOUNT_LIMIT,
    ZIP_MAX_COMMENT,
    crc32,
)

# Field positions in the unpacked struct tuples.
_FH_GENERAL_PURPOSE_FLAG_BITS = 3
_FH_FILENAME_LENGTH = 10
_FH_EXTRA_FIELD_LENGTH = 11

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

_UINT16_MAX = 0xFFFF
_UINT32_MAX = 0xFFFFFFFF


@dataclass(frozen=True)
class EndRecord:
    """The end-of-central-directory record, upgraded with ZIP64 values.

    Attributes:
        location: File offset of the record (or of the ZIP64 record, when the
            archive uses ZIP64 and no data is prepended).
    """

    disk_number: int
    disk_start: int
    entries_this_disk: int
    entries_total: int
    size: int
    offset: int
    comment: bytes
    location: int

    @property
    def directory_start(self) -> int:
        """Actual file offset of the central directory.

        Differs from :attr:`offset` when data was prepended to the archive
        (e.g. a self-extracting stub).
        """
        return self.location - self.size

    @property
    def prepended_bytes(self) -> int:
        """Number of bytes preceding the ZIP data (zero for a plain archive)."""
        return self.directory_start - self.offset


@dataclass(frozen=True)
class ArchiveDirectory:
    """Parsed central directory of an existing archive."""

    comment: bytes
    start_dir: int
    infos: list[ZipInfo]


def _read_exactly(fp: IO[bytes], size: int) -> bytes:
    data = fp.read(size)
    if len(data) != size:
        raise OSError("Unknown I/O error")
    return data


def _apply_zip64_end_record(fp: IO[bytes], record: EndRecord) -> EndRecord:
    """Return *record* upgraded with values from the ZIP64 end record, if any."""
    offset = record.location - END_ARCHIVE64_LOCATOR_SIZE
    if offset < 0:
        return record
    fp.seek(offset)
    data = _read_exactly(fp, END_ARCHIVE64_LOCATOR_SIZE)
    signature, disk_number, zip64_offset, disk_count = struct.unpack(
        END_ARCHIVE64_LOCATOR_STRUCT, data
    )
    if signature != END_ARCHIVE64_LOCATOR_SIGNATURE:
        return record

    if disk_number != 0 or disk_count > 1:
        raise BadZipFile("zipfiles that span multiple disks are not supported")

    offset -= END_ARCHIVE64_SIZE
    if zip64_offset > offset:
        raise BadZipFile("Corrupt zip64 end of central directory locator")
    fp.seek(zip64_offset)
    extra_size = offset - zip64_offset
    data = _read_exactly(fp, END_ARCHIVE64_SIZE)
    if not data.startswith(END_ARCHIVE64_SIGNATURE) and zip64_offset != offset:
        fp.seek(offset)
        extra_size = 0
        data = _read_exactly(fp, END_ARCHIVE64_SIZE)
    if not data.startswith(END_ARCHIVE64_SIGNATURE):
        raise BadZipFile("Zip64 end of central directory record not found")

    (
        _signature,
        record_size,
        _create_version,
        _extract_version,
        disk_number,
        disk_start,
        entries_this_disk,
        entries_total,
        directory_size,
        directory_offset,
    ) = struct.unpack(END_ARCHIVE64_STRUCT, data)
    if (
        directory_offset + directory_size != zip64_offset
        or record_size + 12 != END_ARCHIVE64_SIZE + extra_size
    ):
        raise BadZipFile("Corrupt zip64 end of central directory record")

    return EndRecord(
        disk_number=disk_number,
        disk_start=disk_start,
        entries_this_disk=entries_this_disk,
        entries_total=entries_total,
        size=directory_size,
        offset=directory_offset,
        comment=record.comment,
        location=offset - extra_size,
    )


def _unpack_end_record(data: bytes, comment: bytes, location: int) -> EndRecord:
    (
        _signature,
        disk_number,
        disk_start,
        entries_this_disk,
        entries_total,
        size,
        offset,
        _comment_size,
    ) = struct.unpack(END_ARCHIVE_STRUCT, data)
    return EndRecord(
        disk_number=disk_number,
        disk_start=disk_start,
        entries_this_disk=entries_this_disk,
        entries_total=entries_total,
        size=size,
        offset=offset,
        comment=comment,
        location=location,
    )


def read_end_record(fp: IO[bytes]) -> EndRecord | None:
    """Locate and parse the end-of-central-directory record of *fp*.

    Searches the tail of the file (allowing for an archive comment) and
    upgrades the result with ZIP64 values when applicable.

    Returns:
        The record, or ``None`` if *fp* does not end with one.

    Raises:
        OSError: If a required structure cannot be fully read.
        BadZipFile: If the ZIP64 structures are corrupt or the archive spans
            multiple disks.
    """
    fp.seek(0, 2)
    file_size = fp.tell()

    try:
        fp.seek(-END_ARCHIVE_SIZE, 2)
    except OSError:
        return None
    data = fp.read(END_ARCHIVE_SIZE)
    if (
        len(data) == END_ARCHIVE_SIZE
        and data[0:4] == END_ARCHIVE_SIGNATURE
        and data[-2:] == b"\000\000"
    ):
        record = _unpack_end_record(data, b"", file_size - END_ARCHIVE_SIZE)
        return _apply_zip64_end_record(fp, record)

    tail_start = max(file_size - ZIP_MAX_COMMENT - END_ARCHIVE_SIZE, 0)
    fp.seek(tail_start)
    tail = fp.read(ZIP_MAX_COMMENT + END_ARCHIVE_SIZE)
    start = tail.rfind(END_ARCHIVE_SIGNATURE)
    if start < 0:
        return None
    raw = tail[start : start + END_ARCHIVE_SIZE]
    if len(raw) != END_ARCHIVE_SIZE:
        return None
    comment_size = struct.unpack(END_ARCHIVE_STRUCT, raw)[-1]
    comment_start = start + END_ARCHIVE_SIZE
    comment = tail[comment_start : comment_start + comment_size]
    if len(comment) != comment_size:
        return None
    record = _unpack_end_record(raw, comment, tail_start + start)
    return _apply_zip64_end_record(fp, record)


def looks_like_zip(fp: IO[bytes]) -> bool:
    """Return ``True`` if *fp* has a plausible ZIP structure.

    Reads the end-of-central-directory record and, unless the archive is
    empty, checks the signature of the first central directory entry.
    """
    try:
        record = read_end_record(fp)
        if not record:
            return False
        if record.entries_total == 0 and record.size == 0 and record.offset == 0:
            return True
        if record.disk_number == record.disk_start:
            fp.seek(record.directory_start)
            if record.size >= CENTRAL_DIR_SIZE:
                data = fp.read(CENTRAL_DIR_SIZE)
                if len(data) == CENTRAL_DIR_SIZE:
                    header = struct.unpack(CENTRAL_DIR_STRUCT, data)
                    return bool(header[_CD_SIGNATURE] == CENTRAL_DIR_SIGNATURE)
    except OSError:
        pass
    return False


def _read_directory_entry(
    stream: IO[bytes], metadata_encoding: str | None, prepended_bytes: int, debug: int
) -> tuple[ZipInfo, int]:
    """Parse one central directory entry; return it and its declared length."""
    raw = stream.read(CENTRAL_DIR_SIZE)
    if len(raw) != CENTRAL_DIR_SIZE:
        raise BadZipFile("Truncated central directory")
    header = struct.unpack(CENTRAL_DIR_STRUCT, raw)
    if header[_CD_SIGNATURE] != CENTRAL_DIR_SIGNATURE:
        raise BadZipFile("Bad magic number for central directory")
    if debug > 2:
        print(header)
    filename_bytes = stream.read(header[_CD_FILENAME_LENGTH])
    flags = header[_CD_FLAG_BITS]
    if flags & MASK_UTF_FILENAME:
        filename = filename_bytes.decode("utf-8")
    else:
        filename = filename_bytes.decode(metadata_encoding or "cp437")

    info = ZipInfo(filename)
    info.extra = stream.read(header[_CD_EXTRA_FIELD_LENGTH])
    info.comment = stream.read(header[_CD_COMMENT_LENGTH])
    info.header_offset = header[_CD_LOCAL_HEADER_OFFSET]
    info.create_version = header[_CD_CREATE_VERSION]
    info.create_system = header[_CD_CREATE_SYSTEM]
    info.extract_version = header[_CD_EXTRACT_VERSION]
    info.reserved = header[_CD_EXTRACT_SYSTEM]
    info.flag_bits = flags
    info.compress_type = header[_CD_COMPRESS_TYPE]
    dos_time = header[_CD_TIME]
    dos_date = header[_CD_DATE]
    info.CRC = header[_CD_CRC]
    info.compress_size = header[_CD_COMPRESSED_SIZE]
    info.file_size = header[_CD_UNCOMPRESSED_SIZE]
    if info.extract_version > MAX_EXTRACT_VERSION:
        raise NotImplementedError("zip file version %.1f" % (info.extract_version / 10))
    info.volume = header[_CD_DISK_NUMBER_START]
    info.internal_attr = header[_CD_INTERNAL_FILE_ATTRIBUTES]
    info.external_attr = header[_CD_EXTERNAL_FILE_ATTRIBUTES]
    info.raw_time = dos_time
    info.date_time = (
        (dos_date >> 9) + 1980,
        (dos_date >> 5) & 0xF,
        dos_date & 0x1F,
        dos_time >> 11,
        (dos_time >> 5) & 0x3F,
        (dos_time & 0x1F) * 2,
    )
    info._decode_extra(crc32(filename_bytes))
    info.header_offset += prepended_bytes
    declared_length = (
        CENTRAL_DIR_SIZE
        + header[_CD_FILENAME_LENGTH]
        + header[_CD_EXTRA_FIELD_LENGTH]
        + header[_CD_COMMENT_LENGTH]
    )
    return info, declared_length


def read_directory(
    fp: IO[bytes], metadata_encoding: str | None = None, debug: int = 0
) -> ArchiveDirectory:
    """Parse the central directory of the archive in *fp*.

    Each returned :class:`ZipInfo` has ``_end_offset`` set (the start of the
    next local header, or of the central directory) for overlap detection.

    Raises:
        BadZipFile: If *fp* is not a ZIP archive or its central directory is
            truncated or corrupt.
        NotImplementedError: If an entry needs a newer ZIP version than is
            supported.
    """
    try:
        record = read_end_record(fp)
    except OSError:
        raise BadZipFile("File is not a zip file") from None
    if not record:
        raise BadZipFile("File is not a zip file")
    if debug > 1:
        print(record)

    start_dir = record.directory_start
    if start_dir < 0:
        raise BadZipFile("Bad offset for central directory")
    fp.seek(start_dir)
    directory = io.BytesIO(fp.read(record.size))
    infos: list[ZipInfo] = []
    consumed = 0
    while consumed < record.size:
        info, declared_length = _read_directory_entry(
            directory, metadata_encoding, record.prepended_bytes, debug
        )
        infos.append(info)
        consumed += declared_length

    end_offset = start_dir
    for info in reversed(sorted(infos, key=lambda info: info.header_offset)):
        info._end_offset = end_offset
        end_offset = info.header_offset
    return ArchiveDirectory(record.comment, start_dir, infos)


def raise_for_unsupported_flags(info: ZipInfo) -> None:
    """Raise :exc:`NotImplementedError` for flag combinations we cannot read."""
    if info.flag_bits & MASK_COMPRESSED_PATCH:
        raise NotImplementedError("compressed patched data (flag bit 5)")
    if info.flag_bits & MASK_STRONG_ENCRYPTION:
        raise NotImplementedError("strong encryption (flag bit 6)")


def read_local_header(
    stream: ClosableZipStream, info: ZipInfo, metadata_encoding: str | None
) -> None:
    """Validate the local file header of *info* and skip past it.

    On return *stream* is positioned at the start of the entry payload.

    Raises:
        BadZipFile: If the header is truncated, has a bad signature, or its
            file name differs from the central directory.
        NotImplementedError: If the entry uses unsupported flag bits.
    """
    raw = stream.read(FILE_HEADER_SIZE)
    if len(raw) != FILE_HEADER_SIZE:
        raise BadZipFile("Truncated file header")
    header = struct.unpack(FILE_HEADER_STRUCT, raw)
    if header[0] != FILE_HEADER_SIGNATURE:
        raise BadZipFile("Bad magic number for file header")

    name = stream.read(header[_FH_FILENAME_LENGTH])
    if header[_FH_EXTRA_FIELD_LENGTH]:
        stream.seek(header[_FH_EXTRA_FIELD_LENGTH], whence=1)

    raise_for_unsupported_flags(info)

    if header[_FH_GENERAL_PURPOSE_FLAG_BITS] & MASK_UTF_FILENAME:
        header_name = name.decode("utf-8")
    else:
        header_name = name.decode(metadata_encoding or "cp437")
    if header_name != info.orig_filename:
        raise BadZipFile(
            "File name in directory %r and header %r differ."
            % (info.orig_filename, name)
        )


def write_directory(
    fp: IO[bytes],
    infos: list[ZipInfo],
    start_dir: int,
    comment: bytes,
    *,
    allow_zip64: bool,
) -> None:
    """Write the central directory and end records at the current position.

    Emits the ZIP64 end record and locator only when a count, size or offset
    exceeds the classic limits.

    Raises:
        LargeZipFile: If ZIP64 is needed but *allow_zip64* is ``False``.
    """
    parts: list[bytes] = []
    for info in infos:
        header, filename, extra = info.central_directory()
        parts.extend((header, filename, extra, info.comment))
    fp.write(b"".join(parts))

    directory_end = fp.tell()
    count = len(infos)
    size = directory_end - start_dir
    offset = start_dir
    if count > ZIP_FILECOUNT_LIMIT:
        needs_zip64 = "Files count"
    elif offset > ZIP64_LIMIT:
        needs_zip64 = "Central directory offset"
    elif size > ZIP64_LIMIT:
        needs_zip64 = "Central directory size"
    else:
        needs_zip64 = ""
    if needs_zip64:
        if not allow_zip64:
            raise LargeZipFile(needs_zip64 + " would require ZIP64 extensions")
        fp.write(
            struct.pack(
                END_ARCHIVE64_STRUCT,
                END_ARCHIVE64_SIGNATURE,
                END_ARCHIVE64_SIZE - 12,
                ZIP64_VERSION,
                ZIP64_VERSION,
                0,
                0,
                count,
                count,
                size,
                offset,
            )
        )
        fp.write(
            struct.pack(
                END_ARCHIVE64_LOCATOR_STRUCT,
                END_ARCHIVE64_LOCATOR_SIGNATURE,
                0,
                directory_end,
                1,
            )
        )
        count = min(count, _UINT16_MAX)
        size = min(size, _UINT32_MAX)
        offset = min(offset, _UINT32_MAX)

    fp.write(
        struct.pack(
            END_ARCHIVE_STRUCT,
            END_ARCHIVE_SIGNATURE,
            0,
            0,
            count,
            count,
            size,
            offset,
            len(comment),
        )
    )
    fp.write(comment)
