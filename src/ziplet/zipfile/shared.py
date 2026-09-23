import os
import struct
from typing import Literal, TypeAlias

try:
    from zlib import crc32
except ImportError:  # pragma: no cover - zlib is optional in some builds
    from binascii import crc32

__all__ = [
    "ReadWriteMode",
    "StrPath",
    "crc32",
    "DEFAULT_VERSION",
    "ZIP64_VERSION",
    "MAX_EXTRACT_VERSION",
    "END_ARCHIVE_STRUCT",
    "END_ARCHIVE_SIGNATURE",
    "END_ARCHIVE_SIZE",
    "CENTRAL_DIR_STRUCT",
    "CENTRAL_DIR_SIGNATURE",
    "CENTRAL_DIR_SIZE",
    "FILE_HEADER_STRUCT",
    "FILE_HEADER_SIGNATURE",
    "FILE_HEADER_SIZE",
    "END_ARCHIVE64_LOCATOR_STRUCT",
    "END_ARCHIVE64_LOCATOR_SIGNATURE",
    "END_ARCHIVE64_LOCATOR_SIZE",
    "END_ARCHIVE64_STRUCT",
    "END_ARCHIVE64_SIGNATURE",
    "END_ARCHIVE64_SIZE",
    "ZIP64_LIMIT",
    "ZIP_FILECOUNT_LIMIT",
    "ZIP_MAX_COMMENT",
    "MASK_ENCRYPTED",
    "MASK_COMPRESS_OPTION_1",
    "MASK_COMPRESSED_PATCH",
    "MASK_STRONG_ENCRYPTION",
    "MASK_UTF_FILENAME",
    "MASK_USE_DATA_DESCRIPTOR",
]

# ---------------------------------------------------------------------------
# Version constants
# ---------------------------------------------------------------------------
DEFAULT_VERSION = 20
ZIP64_VERSION = 45
MAX_EXTRACT_VERSION = 63

# ---------------------------------------------------------------------------
# Struct formats, magic strings and sizes
# ---------------------------------------------------------------------------

# End of central directory
END_ARCHIVE_STRUCT = b"<4s4H2LH"
END_ARCHIVE_SIGNATURE = b"PK\005\006"
END_ARCHIVE_SIZE = struct.calcsize(END_ARCHIVE_STRUCT)

# Central directory
CENTRAL_DIR_STRUCT = "<4s4B4HL2L5H2L"
CENTRAL_DIR_SIGNATURE = b"PK\001\002"
CENTRAL_DIR_SIZE = struct.calcsize(CENTRAL_DIR_STRUCT)

# Local file header
FILE_HEADER_STRUCT = "<4s2B4HL2L2H"
FILE_HEADER_SIGNATURE = b"PK\003\004"
FILE_HEADER_SIZE = struct.calcsize(FILE_HEADER_STRUCT)

# Zip64 end-of-central-directory locator
END_ARCHIVE64_LOCATOR_STRUCT = "<4sLQL"
END_ARCHIVE64_LOCATOR_SIGNATURE = b"PK\x06\x07"
END_ARCHIVE64_LOCATOR_SIZE = struct.calcsize(END_ARCHIVE64_LOCATOR_STRUCT)

# Zip64 end-of-central-directory record
END_ARCHIVE64_STRUCT = "<4sQ2H2L4Q"
END_ARCHIVE64_SIGNATURE = b"PK\x06\x06"
END_ARCHIVE64_SIZE = struct.calcsize(END_ARCHIVE64_STRUCT)

# ---------------------------------------------------------------------------
# Size limits
# ---------------------------------------------------------------------------
ZIP64_LIMIT = (1 << 31) - 1
ZIP_FILECOUNT_LIMIT = (1 << 16) - 1
ZIP_MAX_COMMENT = (1 << 16) - 1

# ---------------------------------------------------------------------------
# General purpose bit flags
# ---------------------------------------------------------------------------
MASK_ENCRYPTED = 1 << 0
MASK_COMPRESS_OPTION_1 = 1 << 1
MASK_COMPRESSED_PATCH = 1 << 5
MASK_STRONG_ENCRYPTION = 1 << 6
MASK_UTF_FILENAME = 1 << 11
MASK_USE_DATA_DESCRIPTOR = 1 << 3

# ---------------------------------------------------------------------------
# Type aliases shared by the public-facing modules
# ---------------------------------------------------------------------------
StrPath: TypeAlias = str | os.PathLike[str]
ReadWriteMode: TypeAlias = Literal["r", "w"]
