from __future__ import annotations

import io
import struct
from typing import Any

import pytest

import ziplet
from ziplet.exceptions import BadZipFile, LargeZipFile
from ziplet.zipfile import records
from ziplet.zipfile.info import ZipInfo
from ziplet.zipfile.records import (
    looks_like_zip,
    raise_for_unsupported_flags,
    read_directory,
    read_end_record,
    write_directory,
)
from ziplet.zipfile.shared import (
    END_ARCHIVE64_LOCATOR_SIGNATURE,
    MASK_COMPRESSED_PATCH,
    MASK_STRONG_ENCRYPTION,
)


def _archive(names: tuple[str, ...] = ("a.txt",), comment: bytes = b"") -> bytes:
    buffer = io.BytesIO()
    with ziplet.ZipFile(buffer, "w") as zf:
        for name in names:
            zf.writestr(name, name.encode())
        zf.comment = comment
    return buffer.getvalue()


def test_end_record_of_empty_archive() -> None:
    record = read_end_record(io.BytesIO(_archive(())))
    assert record is not None
    assert (record.entries_total, record.size, record.offset) == (0, 0, 0)
    assert record.comment == b""
    assert record.prepended_bytes == 0


def test_end_record_reads_archive_comment() -> None:
    data = _archive(comment=b"hello comment")
    record = read_end_record(io.BytesIO(data))
    assert record is not None
    assert record.comment == b"hello comment"
    assert record.entries_total == 1
    assert record.directory_start == record.offset


@pytest.mark.parametrize("data", [b"", b"not a zip file at all", b"PK\x05\x06"])
def test_end_record_missing_returns_none(data: bytes) -> None:
    assert read_end_record(io.BytesIO(data)) is None


def test_truncated_comment_returns_none() -> None:
    data = _archive(comment=b"0123456789")
    assert read_end_record(io.BytesIO(data[:-4])) is None


def test_prepended_data_is_accounted_for() -> None:
    prefix = b"#!/bin/sh\nexit 0\n" * 10
    data = prefix + _archive()
    record = read_end_record(io.BytesIO(data))
    assert record is not None
    assert record.prepended_bytes == len(prefix)
    with ziplet.ZipFile(io.BytesIO(data)) as zf:
        assert zf.read("a.txt") == b"a.txt"


def test_read_directory_sets_end_offsets() -> None:
    directory = read_directory(io.BytesIO(_archive(("a.txt", "b.txt"))))
    first, second = directory.infos
    assert first._end_offset == second.header_offset
    assert second._end_offset == directory.start_dir


def test_read_directory_rejects_non_zip() -> None:
    with pytest.raises(BadZipFile, match="not a zip file"):
        read_directory(io.BytesIO(b"plain text"))


def test_read_directory_rejects_truncated_central_directory() -> None:
    data = bytearray(_archive())
    record = read_end_record(io.BytesIO(bytes(data)))
    assert record is not None
    # Claim a larger directory than the bytes that follow the first entry.
    size_offset = len(data) - 22 + 12
    struct.pack_into("<L", data, size_offset, record.size + 100)
    with pytest.raises(BadZipFile):
        read_directory(io.BytesIO(bytes(data)))


def test_looks_like_zip() -> None:
    assert looks_like_zip(io.BytesIO(_archive()))
    assert looks_like_zip(io.BytesIO(_archive(())))
    assert not looks_like_zip(io.BytesIO(b"definitely not a zip archive"))
    assert not looks_like_zip(io.BytesIO(b""))


@pytest.fixture
def force_zip64(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(records, "ZIP_FILECOUNT_LIMIT", 1)


def test_zip64_end_records_round_trip(force_zip64: None) -> None:
    data = _archive(("a.txt", "b.txt", "c.txt"))
    assert END_ARCHIVE64_LOCATOR_SIGNATURE in data
    record = read_end_record(io.BytesIO(data))
    assert record is not None
    assert record.entries_total == 3
    with ziplet.ZipFile(io.BytesIO(data)) as zf:
        assert zf.namelist() == ["a.txt", "b.txt", "c.txt"]


def test_zip64_required_but_disallowed_raises(force_zip64: None) -> None:
    infos = [ZipInfo("a"), ZipInfo("b")]
    for info in infos:
        info.CRC = 0
        info.header_offset = 0
    with pytest.raises(LargeZipFile, match="Files count"):
        write_directory(io.BytesIO(), infos, 0, b"", allow_zip64=False)


def test_multi_disk_zip64_locator_is_rejected(force_zip64: None) -> None:
    data = bytearray(_archive(("a.txt", "b.txt")))
    locator = data.index(END_ARCHIVE64_LOCATOR_SIGNATURE)
    struct.pack_into("<L", data, locator + 16, 2)  # total number of disks
    with pytest.raises(BadZipFile, match="multiple disks"):
        read_end_record(io.BytesIO(bytes(data)))


@pytest.mark.parametrize(
    ("flag", "message"),
    [
        (MASK_COMPRESSED_PATCH, "compressed patched"),
        (MASK_STRONG_ENCRYPTION, "strong encryption"),
    ],
)
def test_unsupported_flags_raise(flag: int, message: str) -> None:
    info = ZipInfo("f.txt")
    info.flag_bits |= flag
    with pytest.raises(NotImplementedError, match=message):
        raise_for_unsupported_flags(info)


def test_supported_flags_pass() -> None:
    raise_for_unsupported_flags(ZipInfo("f.txt"))


def _corrupt_local_header(offset_in_header: int, value: bytes) -> Any:
    data = bytearray(_archive())
    data[offset_in_header : offset_in_header + len(value)] = value
    return io.BytesIO(bytes(data))


def test_local_header_bad_signature_is_rejected() -> None:
    with ziplet.ZipFile(_corrupt_local_header(0, b"XXXX")) as zf:
        with pytest.raises(BadZipFile, match="Bad magic number"):
            zf.read("a.txt")


def test_local_header_name_mismatch_is_rejected() -> None:
    with ziplet.ZipFile(_corrupt_local_header(30, b"z")) as zf:
        with pytest.raises(BadZipFile, match="differ"):
            zf.read("a.txt")
