from __future__ import annotations

import os
import stat
import struct
import sys
import time
import warnings
from collections.abc import Callable, Generator, Iterable
from dataclasses import dataclass
from typing import Any

from ziplet.compression import (
    ZIP_BZIP2,
    ZIP_LZMA,
    ZIP_STORED,
    ZIP_ZSTANDARD,
    compressor_names,
)
from ziplet.compression.methods import (
    BZIP2_VERSION,
    LZMA_VERSION,
    ZSTANDARD_VERSION,
)
from ziplet.cryptography import (
    WZ_AES_V1,
    WZ_AES_V2,
)
from ziplet.cryptography.aes import EXTRA_WZ_AES, WZ_AES_COMPRESS_TYPE
from ziplet.exceptions import BadZipFile, LargeZipFile
from ziplet.zipfile.shared import (
    CENTRAL_DIR_SIGNATURE,
    CENTRAL_DIR_STRUCT,
    DEFAULT_VERSION,
    FILE_HEADER_SIGNATURE,
    FILE_HEADER_STRUCT,
    MASK_COMPRESSED_PATCH,
    MASK_ENCRYPTED,
    MASK_STRONG_ENCRYPTION,
    MASK_USE_DATA_DESCRIPTOR,
    MASK_UTF_FILENAME,
    ZIP64_LIMIT,
    ZIP64_VERSION,
)

# ---------------------------------------------------------------------------
# AES extra-field dataclass
# ---------------------------------------------------------------------------


@dataclass
class WzAesExtra:
    """AES extra-field metadata stored on a ``ZipInfo`` instance.

    Populated automatically by ``ZipInfo._decode_extra`` when the 0x9901
    extra field is present, or supplied explicitly via
    ``ZipInfo.__init__(aes_extra=...)``.  All fields default to ``None``
    for non-AES entries.

    Attributes:
        wz_aes_version: AES encryption version (``WZ_AES_V1`` or ``WZ_AES_V2``),
            or ``None`` for non-AES entries.
        wz_aes_vendor_id: Two-byte vendor ID bytes (``b"AE"``), or ``None``
            for non-AES entries.
        wz_aes_strength: AES key strength indicator (1=128-bit, 2=192-bit,
            3=256-bit), or ``None`` for non-AES entries.
    """

    wz_aes_version: int | None = None
    wz_aes_vendor_id: bytes | None = None
    wz_aes_strength: int | None = None


# ---------------------------------------------------------------------------
# Extensible data field codes
# ---------------------------------------------------------------------------
_EXTRA_ZIP64 = 0x0001

# ---------------------------------------------------------------------------
# # Data descriptor signature
# ---------------------------------------------------------------------------
_DD_SIGNATURE = 0x08074B50


def _sanitize_filename(filename: str) -> str:
    """Terminate the file name at the first null byte and normalize separators.

    Strips the filename at the first null byte, then replaces any OS-native
    path separator characters with forward slashes.

    Args:
        filename: Raw filename string from a ZIP archive record or filesystem.

    Returns:
        Sanitized filename using only forward slashes as directory separators.
    """
    null_byte = filename.find("\x00")
    if null_byte >= 0:
        filename = filename[:null_byte]
    if os.sep != "/" and os.sep in filename:
        filename = filename.replace(os.sep, "/")
    if os.altsep and os.altsep != "/" and os.altsep in filename:
        filename = filename.replace(os.altsep, "/")
    return filename


class _Extra:
    """A single ZIP extra-data field (tag + length + body).

    Attributes:
        data: Raw bytes of the complete field including the 4-byte header.
        id: The 2-byte field tag, or ``None`` if the header was malformed.
    """

    FIELD_STRUCT = struct.Struct("<HH")

    def __init__(self, data: bytes | memoryview, field_id: int | None = None) -> None:
        """Initialize an extra field record.

        Args:
            data: Raw bytes of the complete field including the 4-byte
                tag/length header.
            field_id: The 2-byte field tag, or ``None`` for a malformed header.
        """
        self.data: bytes = bytes(data)
        self.id: int | None = field_id

    @classmethod
    def read_one(cls, raw: bytes | memoryview) -> tuple[_Extra, bytes | memoryview]:
        """Parse one extra field from the start of *raw*.

        Args:
            raw: Byte buffer starting at the beginning of an extra field.

        Returns:
            A tuple of the parsed ``_Extra`` instance and the remaining
            unconsumed bytes after the field.
        """
        try:
            xid, xlen = cls.FIELD_STRUCT.unpack(raw[:4])
        except struct.error:
            xid = None
            xlen = 0
        return cls(raw[: 4 + xlen], xid), raw[4 + xlen :]

    @classmethod
    def iter_fields(cls, data: bytes) -> Generator[_Extra, None, None]:
        """Yield each extra field parsed from *data*.

        Uses a zero-copy ``memoryview`` internally for efficient slicing.

        Args:
            data: Raw bytes of a ZIP extra-data block.

        Yields:
            One ``_Extra`` instance per field in the block.
        """
        # use memoryview for zero-copy slices
        rest: bytes | memoryview = memoryview(data)
        while rest:
            if len(rest) < 4:
                raise BadZipFile("Corrupt extra field header")
            _, field_length = cls.FIELD_STRUCT.unpack(rest[:4])
            if len(rest) < 4 + field_length:
                raise BadZipFile("Corrupt extra field data")
            extra, rest = cls.read_one(rest)
            yield extra

    @classmethod
    def strip(cls, data: bytes, xids: Iterable[int | None]) -> bytes:
        """Remove all extra fields whose tag is in *xids*.

        Args:
            data: Raw bytes of a ZIP extra-data block.
            xids: Collection of field tags to remove.

        Returns:
            A new bytes object containing all remaining fields concatenated.
        """
        return b"".join(ex.data for ex in cls.iter_fields(data) if ex.id not in xids)


class ZipInfo:
    """Metadata for a single entry in a ZIP archive.

    Instances are created directly or via ``ZipInfo.from_file``, and are
    populated by ``ZipFile`` when reading an archive. Most attributes are set
    from the central directory record; ``header_offset``, ``CRC``, and
    ``raw_time`` are set externally by ``ZipFile`` after parsing.

    Attributes:
        orig_filename: Filename exactly as stored in the ZIP record.
        filename: Normalized filename (null-byte-stripped, forward slashes).
        date_time: Modification time as ``(year, month, day, hour, min, sec)``.
        compress_type: Compression method code (e.g. ``ZIP_STORED``).
        compress_level: Compressor level hint, or ``None`` for the default.
        comment: Per-file comment bytes.
        extra: Raw bytes of the ZIP extra-data block.
        create_system: OS code for the system that created the entry.
        create_version: ZIP specification version used when creating.
        extract_version: Minimum ZIP version needed to extract.
        reserved: Reserved field; must be zero.
        flag_bits: General-purpose bit flags from the local file header.
        volume: Disk number where the file header resides.
        internal_attr: Internal file attributes.
        external_attr: External file attributes (high 16 bits are Unix mode).
        header_offset: Byte offset of the local file header in the archive.
        CRC: CRC-32 of the uncompressed file data.
        compress_size: Compressed file size in bytes.
        file_size: Uncompressed file size in bytes.
        aes_extra: WinZip AES extra-field metadata; see ``WzAesExtra``.
    """

    # Annotate slots that are set externally (by ZipFile) rather than in __init__
    CRC: int
    header_offset: int
    raw_time: int
    _end_offset: int | None
    aes_extra: WzAesExtra

    __slots__ = (
        "orig_filename",
        "filename",
        "date_time",
        "compress_type",
        "compress_level",
        "comment",
        "extra",
        "create_system",
        "create_version",
        "extract_version",
        "reserved",
        "flag_bits",
        "volume",
        "internal_attr",
        "external_attr",
        "header_offset",
        "CRC",
        "compress_size",
        "file_size",
        "raw_time",
        "_end_offset",
        "aes_extra",
    )

    def __init__(
        self,
        filename: str = "NoName",
        date_time: tuple[int, int, int, int, int, int] = (1980, 1, 1, 0, 0, 0),
        aes_extra: WzAesExtra | None = None,
    ) -> None:
        """Create a ``ZipInfo`` with the given file name and modification time.

        Args:
            filename: Name of the archive entry. Null bytes are stripped and
                OS path separators are replaced with forward slashes.
            date_time: Modification time as ``(year, month, day, hour, min,
                sec)``. The year must be 1980 or later.
            aes_extra: Pre-populated AES metadata. Defaults to a blank
                ``WzAesExtra()`` (no AES encryption).

        Raises:
            ValueError: If ``date_time[0]`` is earlier than 1980.
        """
        self.orig_filename = filename  # Original file name in archive

        # Terminate the file name at the first null byte and
        # ensure paths always use forward slashes as the directory separator.
        filename = _sanitize_filename(filename)

        self.filename = filename  # Normalized file name
        self.date_time = date_time  # year, month, day, hour, min, sec

        if date_time[0] < 1980:
            raise ValueError("ZIP does not support timestamps before 1980")

        # Standard values:
        self.compress_type: int = ZIP_STORED  # Type of compression for the file
        self.compress_level: int | None = None  # Level for the compressor
        self.comment = b""  # Comment for each file
        self.extra = b""  # ZIP extra data
        if sys.platform == "win32":
            self.create_system = 0  # System which created ZIP archive
        else:
            self.create_system = 3  # System which created ZIP archive
        self.create_version = DEFAULT_VERSION  # Version which created ZIP archive
        self.extract_version = DEFAULT_VERSION  # Version needed to extract archive
        self.reserved = 0  # Must be zero
        self.flag_bits = 0  # ZIP flag bits
        self.volume = 0  # Volume number of file header
        self.internal_attr = 0  # Internal attributes
        self.external_attr = 0  # External file attributes
        self.compress_size = 0  # Size of the compressed file
        self.file_size = 0  # Size of the uncompressed file
        self._end_offset = None  # Start of the next local header or central directory
        # Other attributes are set by class ZipFile:
        # header_offset         Byte offset to the file header
        # CRC                   CRC-32 of the uncompressed file
        # AES extra-field metadata; populated by _decode_extra
        # or supplied via aes_extra param
        self.aes_extra: WzAesExtra = (
            aes_extra if aes_extra is not None else WzAesExtra()
        )

    # Maintain backward compatibility with the old protected attribute name.
    @property
    def _compresslevel(self) -> int | None:
        """Alias for ``compress_level``, kept for backward compatibility."""
        return self.compress_level

    @_compresslevel.setter
    def _compresslevel(self, value: int | None) -> None:
        self.compress_level = value

    def __repr__(self) -> str:
        """Return a human-readable representation of the entry.

        Returns:
            A string of the form ``<ZipInfo filename=... [fields...]>``.
        """
        result = ["<%s filename=%r" % (self.__class__.__name__, self.filename)]
        if self.compress_type != ZIP_STORED:
            result.append(
                " compress_type=%s"
                % compressor_names.get(self.compress_type, self.compress_type)
            )
        hi = self.external_attr >> 16
        lo = self.external_attr & 0xFFFF
        if hi:
            result.append(" filemode=%r" % stat.filemode(hi))
        if lo:
            result.append(" external_attr=%#x" % lo)
        isdir = self.is_dir()
        if not isdir or self.file_size:
            result.append(" file_size=%r" % self.file_size)
        if (not isdir or self.compress_size) and (
            self.compress_type != ZIP_STORED or self.file_size != self.compress_size
        ):
            result.append(" compress_size=%r" % self.compress_size)
        result.append(">")
        return "".join(result)

    @property
    def is_encrypted(self) -> bool:
        """Return ``True`` if the encryption flag is set."""
        return bool(self.flag_bits & MASK_ENCRYPTED)

    @property
    def is_utf_filename(self) -> bool:
        """Return ``True`` if filenames are encoded in UTF-8."""
        return bool(self.flag_bits & MASK_UTF_FILENAME)

    @property
    def is_compressed_patch_data(self) -> bool:
        """Return ``True`` if the compressed patch data flag is set."""
        return bool(self.flag_bits & MASK_COMPRESSED_PATCH)

    @property
    def is_strong_encryption(self) -> bool:
        """Return ``True`` if the strong encryption flag is set."""
        return bool(self.flag_bits & MASK_STRONG_ENCRYPTION)

    @property
    def use_data_descriptor(self) -> bool:
        """Return ``True`` if the data descriptor flag is set."""
        return bool(self.flag_bits & MASK_USE_DATA_DESCRIPTOR)

    @property
    def use_datadescripter(self) -> bool:
        """Compatibility alias for the historical misspelled property."""
        return self.use_data_descriptor

    def get_dosdate(self) -> int:
        """Encode the date part of ``date_time`` as a DOS date word.

        Returns:
            16-bit DOS date value packed as
            ``(year - 1980) << 9 | month << 5 | day``.
        """
        dt = self.date_time
        return (dt[0] - 1980) << 9 | dt[1] << 5 | dt[2]

    def get_dostime(self) -> int:
        """Encode the time part of ``date_time`` as a DOS time word.

        Returns:
            16-bit DOS time value packed as
            ``hour << 11 | minute << 5 | (second // 2)``.
        """
        dt = self.date_time
        return dt[3] << 11 | dt[4] << 5 | (dt[5] // 2)

    def encode_data_descriptor(
        self, zip64: bool, crc: int, compress_size: int, file_size: int
    ) -> bytes:
        """Encode a data descriptor record for the given CRC and sizes.

        Args:
            zip64: When ``True``, use 64-bit (Q) fields for the sizes;
                otherwise use 32-bit (L) fields.
            crc: CRC-32 of the uncompressed data.
            compress_size: Compressed size in bytes.
            file_size: Uncompressed size in bytes.

        Returns:
            Packed data descriptor including the ``PK\x07\x08`` signature.
        """
        fmt = "<LLQQ" if zip64 else "<LLLL"
        return struct.pack(fmt, _DD_SIGNATURE, crc, compress_size, file_size)

    def data_descriptor(self, zip64: bool) -> bytes:
        """Encode a data descriptor using this entry's stored CRC and sizes.

        Args:
            zip64: When ``True``, use 64-bit fields for the sizes.

        Returns:
            Packed data descriptor including the ``PK\x07\x08`` signature.
        """
        _, crc, _ = self._encode_extra(self.CRC, self.compress_type)
        return self.encode_data_descriptor(
            zip64, crc, self.compress_size, self.file_size
        )

    def encode_datadescripter(
        self, zip64: bool, crc: int, compress_size: int, file_size: int
    ) -> bytes:
        """Compatibility alias for the historical misspelled method."""
        return self.encode_data_descriptor(zip64, crc, compress_size, file_size)

    def datadescripter(self, zip64: bool) -> bytes:
        """Compatibility alias for the historical misspelled method."""
        return self.data_descriptor(zip64)

    def _zip64_local_extra(
        self, zip64: bool | None, file_size: int, compress_size: int
    ) -> tuple[bytes, int, int, int]:
        """Compute the ZIP64 extra field and placeholder sizes for a local file header.

        Args:
            zip64: Force ZIP64 on (``True``), off (``False``), or auto-detect
                (``None``). Auto-detect enables ZIP64 when either size exceeds
                ``ZIP64_LIMIT``.
            file_size: Uncompressed file size in bytes.
            compress_size: Compressed size in bytes.

        Returns:
            A tuple of ``(extra_bytes, file_size, compress_size, min_version)``
            where sizes are replaced with ``0xFFFFFFFF`` when ZIP64 is active
            and ``min_version`` is ``ZIP64_VERSION`` or 0.

        Raises:
            LargeZipFile: If either size exceeds ``ZIP64_LIMIT`` and *zip64*
                is ``False``.
        """
        min_version = 0
        extra = b""
        requires_zip64 = file_size > ZIP64_LIMIT or compress_size > ZIP64_LIMIT
        if zip64 is None:
            zip64 = requires_zip64
        if zip64:
            extra = struct.pack(
                "<HHQQ",
                _EXTRA_ZIP64,
                8 * 2,  # two Q fields
                file_size,
                compress_size,
            )
        if requires_zip64:
            if not zip64:
                raise LargeZipFile("Filesize would require ZIP64 extensions")
            file_size = 0xFFFFFFFF
            compress_size = 0xFFFFFFFF
            min_version = ZIP64_VERSION
        return extra, file_size, compress_size, min_version

    def _zip64_central_extra(self) -> tuple[bytes, int, int, int, int]:
        """Build the ZIP64 extra field bytes for a central directory entry.

        Any existing extra data on ``self.extra`` is preserved; a stale ZIP64
        field (if present) is stripped and replaced.

        Returns:
            A tuple of
            ``(extra_bytes, file_size, compress_size, header_offset, min_version)``
            where each size/offset is replaced with ``0xFFFFFFFF`` when its
            value exceeds ``ZIP64_LIMIT``, and ``min_version`` is
            ``ZIP64_VERSION`` when any ZIP64 field is emitted.
        """
        zip64_fields = []
        if self.file_size > ZIP64_LIMIT:
            zip64_fields.append(self.file_size)
            file_size = 0xFFFFFFFF
        else:
            file_size = self.file_size

        if self.compress_size > ZIP64_LIMIT:
            zip64_fields.append(self.compress_size)
            compress_size = 0xFFFFFFFF
        else:
            compress_size = self.compress_size

        if self.header_offset > ZIP64_LIMIT:
            zip64_fields.append(self.header_offset)
            header_offset = 0xFFFFFFFF
        else:
            header_offset = self.header_offset

        min_version = 0
        if zip64_fields:
            zip64_extra = struct.pack(
                "<HH" + "Q" * len(zip64_fields),
                _EXTRA_ZIP64,
                8 * len(zip64_fields),
                *zip64_fields,
            )
            min_version = ZIP64_VERSION
        else:
            zip64_extra = b""
        # Preserve existing extra data, stripping any old ZIP64 entry first
        existing_extra = _Extra.strip(self.extra, (_EXTRA_ZIP64,))
        extra_data = zip64_extra + existing_extra
        return extra_data, file_size, compress_size, header_offset, min_version

    def _minimum_version(self, zip64_version: int = 0) -> int:
        """Return the minimum ZIP version required by this entry."""
        versions = {
            ZIP_BZIP2: BZIP2_VERSION,
            ZIP_LZMA: LZMA_VERSION,
            ZIP_ZSTANDARD: ZSTANDARD_VERSION,
        }
        return max(zip64_version, versions.get(self.compress_type, 0))

    def _encode_extra(self, crc: int, compress_type: int) -> tuple[bytes, int, int]:
        """Encode the WinZip AES extra field and adjust CRC and compression type.

        When ``aes_extra.wz_aes_vendor_id`` is ``None`` (non-AES entry) this
        method is a no-op: the extra bytes are empty and *crc* and
        *compress_type* are returned unchanged.

        For AES entries, *compress_type* is overridden to
        ``WZ_AES_COMPRESS_TYPE`` (99). When ``wz_aes_version`` is ``None``,
        ``WZ_AES_V2`` is selected. Version 2 entries have their CRC zeroed;
        version 1 is retained only when explicitly requested for compatibility.

        Args:
            crc: CRC-32 of the uncompressed data.
            compress_type: Compression method code before AES wrapping.

        Returns:
            A tuple of ``(extra_bytes, crc, compress_type)`` containing the
            AES extra field bytes (may be empty), the adjusted CRC, and the
            adjusted compression type.
        """
        wz_aes_extra = b""
        if self.aes_extra.wz_aes_vendor_id is not None:
            compress_type = WZ_AES_COMPRESS_TYPE
            aes_version = self.aes_extra.wz_aes_version
            if aes_version is None:
                aes_version = WZ_AES_V2
            if aes_version not in (WZ_AES_V1, WZ_AES_V2):
                raise ValueError("force_wz_aes_version must be 1 or 2")
            if aes_version == WZ_AES_V2:
                crc = 0
            wz_aes_extra = struct.pack(
                "<3H2sBH",
                EXTRA_WZ_AES,
                7,  # extra block body length: H2sBH
                aes_version,
                self.aes_extra.wz_aes_vendor_id,
                self.aes_extra.wz_aes_strength,
                self.compress_type,
            )
        return wz_aes_extra, crc, compress_type

    def _encode_local_header(
        self,
        *,
        filename: bytes,
        extract_version: int,
        reserved: int,
        flag_bits: int,
        compress_type: int,
        dostime: int,
        dosdate: int,
        crc: int,
        compress_size: int,
        file_size: int,
        extra: bytes,
    ) -> bytes:
        """Serialize a local file header record.

        Appends any WinZip AES extra bytes after the caller-supplied *extra*
        data before packing the header struct.

        Args:
            filename: Encoded filename bytes.
            extract_version: Minimum version needed to extract.
            reserved: Reserved field value (must be 0).
            flag_bits: General-purpose bit flags.
            compress_type: Compression method code.
            dostime: DOS-encoded time word.
            dosdate: DOS-encoded date word.
            crc: CRC-32 of the uncompressed data.
            compress_size: Compressed size in bytes.
            file_size: Uncompressed size in bytes.
            extra: ZIP64 (and any other) extra-data bytes.

        Returns:
            Packed local file header followed by *filename* and *extra* bytes.
        """
        wz_aes_extra, crc, compress_type = self._encode_extra(crc, compress_type)
        extra = extra + wz_aes_extra
        header = struct.pack(
            FILE_HEADER_STRUCT,
            FILE_HEADER_SIGNATURE,
            extract_version,
            reserved,
            flag_bits,
            compress_type,
            dostime,
            dosdate,
            crc,
            compress_size,
            file_size,
            len(filename),
            len(extra),
        )
        return header + filename + extra

    def _encode_central_directory(
        self,
        *,
        filename: bytes,
        create_version: int,
        create_system: int,
        extract_version: int,
        reserved: int,
        flag_bits: int,
        compress_type: int,
        dostime: int,
        dosdate: int,
        crc: int,
        compress_size: int,
        file_size: int,
        disk_start: int,
        internal_attr: int,
        external_attr: int,
        header_offset: int,
        extra_data: bytes,
        comment: bytes,
    ) -> tuple[bytes, bytes, bytes]:
        """Serialize a central directory record for this entry.

        Appends any WinZip AES extra bytes after the caller-supplied
        *extra_data* before packing the central directory struct.

        Args:
            filename: Encoded filename bytes.
            create_version: ZIP spec version used when the entry was created.
            create_system: OS code for the system that created the entry.
            extract_version: Minimum version needed to extract.
            reserved: Reserved field value (must be 0).
            flag_bits: General-purpose bit flags.
            compress_type: Compression method code.
            dostime: DOS-encoded time word.
            dosdate: DOS-encoded date word.
            crc: CRC-32 of the uncompressed data.
            compress_size: Compressed size in bytes.
            file_size: Uncompressed size in bytes.
            disk_start: Disk number where the local header resides.
            internal_attr: Internal file attributes.
            external_attr: External file attributes.
            header_offset: Byte offset of the local file header.
            extra_data: ZIP64 (and any other) extra-data bytes.
            comment: Per-file comment bytes.

        Returns:
            A tuple of ``(centdir_bytes, filename_bytes, extra_data_bytes)``.
        """
        wz_aes_extra, crc, compress_type = self._encode_extra(crc, compress_type)
        extra_data = extra_data + wz_aes_extra
        centdir = struct.pack(
            CENTRAL_DIR_STRUCT,
            CENTRAL_DIR_SIGNATURE,
            create_version,
            create_system,
            extract_version,
            reserved,
            flag_bits,
            compress_type,
            dostime,
            dosdate,
            crc,
            compress_size,
            file_size,
            len(filename),
            len(extra_data),
            len(comment),
            disk_start,
            internal_attr,
            external_attr,
            header_offset,
        )
        return centdir, filename, extra_data

    def central_directory(self) -> tuple[bytes, bytes, bytes]:
        """Serialize this entry's central directory record.

        Computes the minimum required ZIP specification version from the
        compression type and ZIP64 requirements, then delegates to
        ``_encode_central_directory``.

        Returns:
            A tuple of ``(centdir_bytes, filename_bytes, extra_data_bytes)``
            suitable for writing directly into the central directory.
        """
        dosdate = self.get_dosdate()
        dostime = self.get_dostime()
        (
            extra_data,
            file_size,
            compress_size,
            header_offset,
            min_version,
        ) = self._zip64_central_extra()

        min_version = self._minimum_version(min_version)

        extract_version = max(min_version, self.extract_version)
        create_version = max(min_version, self.create_version)
        filename, flag_bits = self._encode_filename_flags()
        # Writing multi-disk archives is not supported so disk_start is always 0
        disk_start = 0
        return self._encode_central_directory(
            filename=filename,
            create_version=create_version,
            create_system=self.create_system,
            extract_version=extract_version,
            reserved=self.reserved,
            flag_bits=flag_bits,
            compress_type=self.compress_type,
            dostime=dostime,
            dosdate=dosdate,
            crc=self.CRC,
            compress_size=compress_size,
            file_size=file_size,
            disk_start=disk_start,
            internal_attr=self.internal_attr,
            external_attr=self.external_attr,
            header_offset=header_offset,
            extra_data=extra_data,
            comment=self.comment,
        )

    def FileHeader(self, zip64: bool | None = None) -> bytes:
        """Serialize the local file header for this entry.

        The effective ``extract_version`` accounts for ZIP64 and the
        compression type but is not written back to ``self``.

        Args:
            zip64: Force ZIP64 on (``True``), off (``False``), or auto-detect
                (``None``). Auto-detect enables ZIP64 when either stored size
                exceeds ``ZIP64_LIMIT``.

        Returns:
            Packed local file header followed by the encoded filename and
            extra-data bytes.
        """
        dosdate = self.get_dosdate()
        dostime = self.get_dostime()
        if self.use_data_descriptor:
            # Set these to zero because we write them after the file data
            CRC = compress_size = file_size = 0
        else:
            CRC = self.CRC
            compress_size = self.compress_size
            file_size = self.file_size

        min_version = 0
        extra, file_size, compress_size, zip64_min_version = self._zip64_local_extra(
            zip64, file_size, compress_size
        )
        min_version = max(min_version, zip64_min_version)

        min_version = self._minimum_version(min_version)

        extract_version = max(min_version, self.extract_version)
        filename, flag_bits = self._encode_filename_flags()
        return self._encode_local_header(
            filename=filename,
            extract_version=extract_version,
            reserved=self.reserved,
            flag_bits=flag_bits,
            compress_type=self.compress_type,
            dostime=dostime,
            dosdate=dosdate,
            crc=CRC,
            compress_size=compress_size,
            file_size=file_size,
            extra=extra,
        )

    def _encode_filename_flags(self) -> tuple[bytes, int]:
        """Encode the filename and determine the UTF-8 flag.

        Attempts ASCII encoding first; falls back to UTF-8 and sets
        ``MASK_UTF_FILENAME`` in the returned flags when the name contains
        non-ASCII characters.

        Returns:
            A tuple of ``(encoded_filename_bytes, flag_bits)``.
        """
        try:
            return self.filename.encode("ascii"), self.flag_bits
        except UnicodeEncodeError:
            return self.filename.encode("utf-8"), self.flag_bits | MASK_UTF_FILENAME

    def _extra_decoders(self) -> dict[int, Callable[..., None]]:
        """Return a mapping of extra-field tag to decoder method.

        Subclasses may override this to register additional decoders for
        vendor-specific or application-defined extra fields.

        Returns:
            A dict mapping each known tag integer to the corresponding bound
            method responsible for decoding that field.
        """
        return {
            _EXTRA_ZIP64: self._decode_zip64_extra,
            EXTRA_WZ_AES: self._decode_wz_aes_extra,
        }

    def _decode_zip64_extra(
        self, ln: int, extra: bytes, is_central_directory: bool = True
    ) -> None:
        """Decode a ZIP64 extended information extra field (tag 0x0001).

        Updates ``file_size``, ``compress_size``, and ``header_offset`` on
        ``self`` when the corresponding sentinel value (``0xFFFFFFFF``) is
        present. Fields are consumed in the order mandated by the ZIP spec:
        file size, then compress size, then header offset.

        Args:
            ln: Length of the extra field body in bytes (excluding the 4-byte
                tag/length header).
            extra: The full extra-data block; the field body is read from
                offset 4.
            is_central_directory: When ``True``, also attempts to decode the
                header offset field (only present in central directory records).

        Raises:
            BadZipFile: If a required 8-byte Q field cannot be unpacked.
        """
        # offset = len(extra block tag) + len(extra block size)
        offset = 4
        data = extra[offset : offset + ln]
        field = "unknown"
        try:
            if self.file_size in (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF):
                field = "File size"
                (self.file_size,) = struct.unpack("<Q", data[:8])
                data = data[8:]

            if self.compress_size == 0xFFFF_FFFF:
                field = "Compress size"
                (self.compress_size,) = struct.unpack("<Q", data[:8])
                data = data[8:]

            if is_central_directory and self.header_offset == 0xFFFF_FFFF:
                field = "Header offset"
                (self.header_offset,) = struct.unpack("<Q", data[:8])
        except struct.error:
            raise BadZipFile(f"Corrupt zip64 extra field. {field} not found.") from None

    def _decode_wz_aes_extra(self, ln: int, extra: bytes) -> None:
        """Decode a WinZip AES extra field (tag 0x9901).

        Populates ``aes_extra.wz_aes_version``, ``aes_extra.wz_aes_vendor_id``,
        ``aes_extra.wz_aes_strength``, and ``compress_type`` from the field body.

        Args:
            ln: Length of the extra field body in bytes; must be exactly 7.
            extra: The full extra-data block; the field body is read from
                offset 4.

        Raises:
            BadZipFile: If *ln* is not 7.
        """
        if ln != 7:
            raise BadZipFile("Corrupt extra field %04x (size=%d)" % (EXTRA_WZ_AES, ln))
        (
            self.aes_extra.wz_aes_version,
            self.aes_extra.wz_aes_vendor_id,
            self.aes_extra.wz_aes_strength,
            self.compress_type,
        ) = struct.unpack("<H2sBH", extra[4 : ln + 4])
        if self.aes_extra.wz_aes_version not in (1, 2):
            raise BadZipFile("Unsupported WinZip AES version")
        if self.aes_extra.wz_aes_vendor_id != b"AE":
            raise BadZipFile("Invalid WinZip AES vendor ID")
        if self.aes_extra.wz_aes_strength not in (1, 2, 3):
            raise BadZipFile("Invalid WinZip AES strength")

    def _decode_extra(self, filename_crc: int) -> None:
        """Parse the extra-data block and update ``self`` with decoded field values.

        Iterates over every extra field in ``self.extra`` and dispatches to the
        appropriate decoder returned by ``_extra_decoders``. The Unicode
        Path extra field (0x7075) is handled inline because it requires the
        *filename_crc* context. Unknown tags are silently ignored.

        Args:
            filename_crc: CRC-32 of the raw (non-Unicode) filename bytes, used
                to validate the Unicode Path extra field.

        Raises:
            BadZipFile: If any field's declared length overflows the buffer, or
                if a known field's payload is structurally invalid.
        """
        # Try to decode the extra field.
        extra = self.extra
        unpack = struct.unpack
        extra_decoders = self._extra_decoders()
        while len(extra) >= 4:
            tp, ln = unpack("<HH", extra[:4])
            if ln + 4 > len(extra):
                raise BadZipFile("Corrupt extra field %04x (size=%d)" % (tp, ln))
            if tp == 0x7075:
                # Unicode Path Extra Field — needs filename_crc, handle inline
                data = extra[4 : ln + 4]
                try:
                    up_version, up_name_crc = unpack("<BL", data[:5])
                    if up_version == 1 and up_name_crc == filename_crc:
                        up_unicode_name = data[5:].decode("utf-8")
                        if up_unicode_name:
                            self.filename = _sanitize_filename(up_unicode_name)
                        else:
                            warnings.warn(
                                "Empty unicode path extra field (0x7075)", stacklevel=2
                            )
                except struct.error as e:
                    raise BadZipFile("Corrupt unicode path extra field (0x7075)") from e
                except UnicodeDecodeError as e:
                    raise BadZipFile(
                        "Corrupt unicode path extra field (0x7075): invalid utf-8 bytes"
                    ) from e
            else:
                try:
                    extra_decoders[tp](ln, extra)
                except KeyError:
                    pass  # Unknown extra field — skip
            extra = extra[ln + 4 :]
        if extra:
            raise BadZipFile("Corrupt trailing extra field data")

    @classmethod
    def from_file(
        cls,
        filename: str | os.PathLike[str],
        arcname: str | os.PathLike[str] | None = None,
        *,
        strict_timestamps: bool = True,
    ) -> ZipInfo:
        """Construct a ``ZipInfo`` from a file or directory on the filesystem.

        Args:
            filename: Path to the file or directory on disk.
            arcname: Name to use inside the archive. Defaults to *filename*
                with the drive letter and leading separators stripped.
            strict_timestamps: When ``False``, timestamps before 1980 are
                clamped to ``1980-01-01`` and timestamps after 2107 are clamped
                to ``2107-12-31`` instead of raising an error.

        Returns:
            A new ``ZipInfo`` instance with ``file_size`` and ``external_attr``
            populated from the file's ``stat`` result.
        """
        if isinstance(filename, os.PathLike):
            filename = os.fspath(filename)
        st = os.stat(filename)
        isdir = stat.S_ISDIR(st.st_mode)
        mtime = time.localtime(st.st_mtime)
        date_time = mtime[0:6]
        if not strict_timestamps and date_time[0] < 1980:
            date_time = (1980, 1, 1, 0, 0, 0)
        elif not strict_timestamps and date_time[0] > 2107:
            date_time = (2107, 12, 31, 23, 59, 59)
        # Create ZipInfo instance to store file information
        if arcname is None:
            arcname = filename
        elif isinstance(arcname, os.PathLike):
            arcname = os.fspath(arcname)
        arcname = os.path.normpath(os.path.splitdrive(arcname)[1])
        while arcname and arcname[0] in (os.sep, os.altsep):
            arcname = arcname[1:]
        if not arcname:
            raise ValueError("Archive name must not be empty")
        if isdir:
            arcname += "/"
        zinfo = cls(arcname, date_time)
        zinfo.external_attr = (st.st_mode & 0xFFFF) << 16  # Unix attributes
        if isdir:
            zinfo.file_size = 0
            zinfo.external_attr |= 0x10  # MS-DOS directory flag
        else:
            zinfo.file_size = st.st_size

        return zinfo

    def _for_archive(self, archive: Any) -> ZipInfo:
        """Populate defaults from *archive* for use with ``ZipFile.writestr``.

        Sets ``date_time`` from the current time (or ``SOURCE_DATE_EPOCH`` when
        defined), copies ``compression`` and ``compresslevel`` from *archive*,
        and assigns appropriate ``external_attr`` permissions.

        Args:
            archive: The ``ZipFile`` instance whose ``compression`` and
                ``compresslevel`` attributes are read.

        Returns:
            ``self``, to allow chained usage.
        """
        # gh-91279: Set the SOURCE_DATE_EPOCH to a specific timestamp
        epoch = os.environ.get("SOURCE_DATE_EPOCH")
        if epoch:
            try:
                get_time = int(epoch)
            except ValueError:
                warnings.warn(
                    f"SOURCE_DATE_EPOCH={epoch!r} is not a valid integer; ignoring",
                    stacklevel=2,
                )
                get_time = int(time.time())
        else:
            get_time = int(time.time())
        self.date_time = time.localtime(get_time)[:6]

        self.compress_type = archive.compression
        self.compress_level = archive.compresslevel
        if self.filename.endswith("/"):  # pragma: no cover
            self.external_attr = 0o40775 << 16  # drwxrwxr-x
            self.external_attr |= 0x10  # MS-DOS directory flag
        else:
            self.external_attr = 0o600 << 16  # ?rw-------
        return self

    def is_dir(self) -> bool:
        """Return True if this archive member is a directory."""
        if self.filename.endswith("/"):
            return True
        # The ZIP format specification requires to use forward slashes
        # as the directory separator, but in practice some ZIP files
        # created on Windows can use backward slashes.  For compatibility
        # with the extraction code which already handles this:
        if os.path.altsep:
            return self.filename.endswith((os.path.sep, os.path.altsep))
        return False


__all__ = ["ZipInfo", "WzAesExtra"]
