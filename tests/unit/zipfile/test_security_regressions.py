from __future__ import annotations

import io
import os
import stat
import struct
from typing import Any, cast

import pytest

import ziplet
from ziplet.compression import lzma, registry
from ziplet.exceptions import BadZipFile
from ziplet.zipfile.exceptions import ExtractionMaterializationError
from ziplet.zipfile.ext import ZipExtFile
from ziplet.zipfile.file import ZipFileExtra
from ziplet.zipfile.info import ZipInfo
from ziplet.zipfile.shared import (
    CENTRAL_DIR_SIGNATURE,
    CENTRAL_DIR_SIZE,
    CENTRAL_DIR_STRUCT,
    FILE_HEADER_SIGNATURE,
    FILE_HEADER_SIZE,
    FILE_HEADER_STRUCT,
)


def test_max_n_is_31_bit_maximum() -> None:
    assert ZipExtFile.MAX_N == (1 << 31) - 1
    assert ZipExtFile.MAX_READ_SIZE == 1 << 20


def test_read2_caps_forged_compressed_size_reads() -> None:
    class CountingStream(io.BytesIO):
        requested: int | None = None

        def read(self, size: int | None = -1) -> bytes:
            requested = -1 if size is None else size
            self.requested = requested
            return b"x" * min(requested, 16)

    stream = CountingStream()
    ext = ZipExtFile.__new__(ZipExtFile)
    ext._fileobj = cast(Any, stream)
    ext._close_fileobj = False
    ext._compress_left = 1 << 40
    ext._decrypter = None

    data = ext._read2(ZipExtFile.MAX_N)

    assert len(data) == 16
    assert stream.requested == ZipExtFile.MAX_READ_SIZE


def test_aes_version_override_is_validated() -> None:
    with pytest.raises(ValueError, match="must be 1 or 2"):
        ZipFileExtra(force_wz_aes_version=3)


def test_lzma_oversized_dictionary_is_rejected() -> None:
    if lzma.compression_entry is None:
        pytest.skip("lzma not available")

    props = bytes([0x5D]) + struct.pack("<I", 1 << 31)
    with pytest.raises(BadZipFile, match="dictionary size"):
        lzma._lzma1_filter_from_props(props)


def test_aes_defaults_to_version_two_and_zero_crc() -> None:
    info = ZipInfo("payload.bin")
    info.aes_extra.wz_aes_vendor_id = b"AE"
    info.aes_extra.wz_aes_strength = 3
    info.file_size = 1024
    info.compress_type = 8

    extra, crc, _ = info._encode_extra(0x12345678, info.compress_type)

    _, _, version = struct.unpack("<HHH", extra[:6])
    assert version == 2
    assert crc == 0


def _find_aes_metadata(archive: bytes) -> tuple[int, int, int, int]:
    local_offset = archive.index(FILE_HEADER_SIGNATURE)
    local = struct.unpack(
        FILE_HEADER_STRUCT,
        archive[local_offset : local_offset + FILE_HEADER_SIZE],
    )
    local_name_len, local_extra_len = local[10:12]
    local_extra_start = local_offset + FILE_HEADER_SIZE + local_name_len
    local_extra = archive[local_extra_start : local_extra_start + local_extra_len]

    central_offset = archive.index(CENTRAL_DIR_SIGNATURE)
    central = struct.unpack(
        CENTRAL_DIR_STRUCT,
        archive[central_offset : central_offset + CENTRAL_DIR_SIZE],
    )
    central_name_len, central_extra_len = central[12:14]
    central_extra_start = central_offset + CENTRAL_DIR_SIZE + central_name_len
    central_extra = archive[
        central_extra_start : central_extra_start + central_extra_len
    ]

    def version(extra: bytes) -> int:
        marker = struct.pack("<HH", 0x9901, 7)
        start = extra.index(marker) + 4
        return int(struct.unpack("<H", extra[start : start + 2])[0])

    return local[7], central[9], version(local_extra), version(central_extra)


@pytest.mark.parametrize(
    ("compression", "payload"),
    [
        (ziplet.ZIP_STORED, b"small payload"),
        (ziplet.ZIP_STORED, b"large payload " * 4096),
        (ziplet.ZIP_DEFLATED, b"small payload"),
        (ziplet.ZIP_DEFLATED, b"large payload " * 4096),
        (ziplet.ZIP_BZIP2, b"large payload " * 4096),
        (ziplet.ZIP_LZMA, b"large payload " * 4096),
        (ziplet.ZIP_ZSTANDARD, b"large payload " * 4096),
    ],
)
def test_read1_is_bounded_and_supports_split_reads(
    tmp_path: Any,
    compression: int,
    payload: bytes,
) -> None:
    if not registry._registry.get(compression):
        pytest.skip("compression method unavailable")

    path = tmp_path / f"bounded-{compression}.zip"
    with ziplet.ZipFile(path, "w", compression=compression) as zf:
        zf.writestr("payload.bin", payload)

    with ziplet.ZipFile(path) as zf:
        with cast(ZipExtFile, zf.open("payload.bin")) as source:
            chunks: list[bytes] = []
            while True:
                chunk = source.read1(17)
                if not chunk:
                    break
                assert len(chunk) <= 17
                chunks.append(chunk)
            assert b"".join(chunks) == payload
            assert source.read1(17) == b""

            source.seek(len(payload) // 2)
            start = len(payload) // 2
            assert source.read(31) == payload[start : start + 31]
            source.seek(0)
            assert source.read() == payload


@pytest.mark.parametrize(
    "compression",
    [ziplet.ZIP_DEFLATED, ziplet.ZIP_BZIP2, ziplet.ZIP_LZMA],
)
def test_truncated_compressed_member_raises(tmp_path: Any, compression: int) -> None:
    if not registry._registry.get(compression):
        pytest.skip("compression method unavailable")

    path = tmp_path / f"truncated-{compression}.zip"
    with ziplet.ZipFile(path, "w", compression=compression) as zf:
        zf.writestr("payload.bin", b"payload " * 1024)
    path.write_bytes(path.read_bytes()[:-30])

    with pytest.raises((BadZipFile, EOFError)):
        with ziplet.ZipFile(path) as zf:
            zf.read("payload.bin")


def test_crc_mismatch_is_detected(tmp_path: Any) -> None:
    path = tmp_path / "crc.zip"
    with ziplet.ZipFile(path, "w") as zf:
        zf.writestr("payload.bin", b"payload")
    archive = bytearray(path.read_bytes())
    central_offset = archive.index(CENTRAL_DIR_SIGNATURE)
    archive[central_offset + 16 : central_offset + 20] = struct.pack("<L", 0)
    path.write_bytes(archive)

    with pytest.raises(BadZipFile, match="Bad CRC-32"):
        with ziplet.ZipFile(path) as zf:
            zf.read("payload.bin")


@pytest.mark.parametrize("compression", [ziplet.ZIP_STORED, ziplet.ZIP_DEFLATED])
@pytest.mark.parametrize("payload", [b"x", b"x" * 8192])
def test_aes_headers_have_consistent_v2_metadata(
    tmp_path: Any,
    compression: int,
    payload: bytes,
) -> None:
    path = tmp_path / f"aes-{compression}-{len(payload)}.zip"
    with ziplet.ZipFile(
        path, "w", compression=compression, encryption=ziplet.WZ_AES
    ) as zf:
        zf.setpassword(b"password")
        zf.writestr("payload.bin", payload)

    local_crc, central_crc, local_version, central_version = _find_aes_metadata(
        path.read_bytes()
    )
    assert local_crc == central_crc == 0
    assert local_version == central_version == ziplet.WZ_AES_V2


def test_aes_v1_headers_preserve_crc(tmp_path: Any) -> None:
    path = tmp_path / "aes-v1.zip"
    payload = b"compatibility payload"
    with ziplet.ZipFile(
        path,
        "w",
        encryption=ziplet.WZ_AES,
        extra=ziplet.ZipFileExtra(force_wz_aes_version=1),
    ) as zf:
        zf.setpassword(b"password")
        zf.writestr("payload.bin", payload)

    local_crc, central_crc, local_version, central_version = _find_aes_metadata(
        path.read_bytes()
    )
    assert local_crc == central_crc
    assert local_crc != 0
    assert local_version == central_version == ziplet.WZ_AES_V1


class _NonSeekableBytesIO(io.BytesIO):
    def seekable(self) -> bool:
        return False

    def seek(self, *args: Any, **kwargs: Any) -> int:
        raise io.UnsupportedOperation("not seekable")


def test_aes_output_works_on_non_seekable_stream() -> None:
    buffer = _NonSeekableBytesIO()
    with ziplet.ZipFile(buffer, "w", encryption=ziplet.WZ_AES) as zf:
        zf.setpassword(b"password")
        zf.writestr("payload.bin", b"payload")

    with ziplet.ZipFile(io.BytesIO(buffer.getvalue())) as zf:
        zf.setpassword(b"password")
        assert zf.read("payload.bin") == b"payload"


def test_aes_v2_data_descriptor_zeroes_crc() -> None:
    buffer = _NonSeekableBytesIO()
    with ziplet.ZipFile(buffer, "w", encryption=ziplet.WZ_AES) as zf:
        zf.setpassword(b"password")
        zf.writestr("payload.bin", b"payload")

    data = buffer.getvalue()
    offset = data.index(b"PK\x07\x08")
    _, crc, _, _ = struct.unpack_from("<LLLL", data, offset)
    assert crc == 0


def _symlink_archive(path: Any, name: str, target: str) -> None:
    info = ZipInfo(name)
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with ziplet.ZipFile(path, "w") as zf:
        zf.writestr(info, target)


@pytest.mark.skipif(os.name != "posix", reason="symlinks")
def test_symlink_member_over_existing_directory_raises_extraction_error(
    tmp_path: Any,
) -> None:
    archive = tmp_path / "link.zip"
    _symlink_archive(archive, "victim", "elsewhere")
    dest = tmp_path / "dest"
    (dest / "victim").mkdir(parents=True)

    with ziplet.ZipFile(archive) as zf:
        with pytest.raises(ExtractionMaterializationError):
            zf.extractall(dest)
    assert (dest / "victim").is_dir()


def test_file_member_over_existing_directory_raises_extraction_error(
    tmp_path: Any,
) -> None:
    archive = tmp_path / "file.zip"
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("victim", b"data")
    dest = tmp_path / "dest"
    (dest / "victim").mkdir(parents=True)

    with ziplet.ZipFile(archive) as zf:
        with pytest.raises(ExtractionMaterializationError):
            zf.extractall(dest)
    assert (dest / "victim").is_dir()


@pytest.mark.skipif(os.name != "posix", reason="symlinks")
def test_extract_refuses_symlinked_intermediate_directory(tmp_path: Any) -> None:
    archive = tmp_path / "nested.zip"
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("sub/inner.txt", b"data")
    dest = tmp_path / "dest"
    outside = tmp_path / "outside"
    dest.mkdir()
    outside.mkdir()
    (dest / "sub").symlink_to(outside, target_is_directory=True)

    with ziplet.ZipFile(archive) as zf:
        with pytest.raises(ValueError, match="unsafe extraction path"):
            zf.extractall(dest)
    assert list(outside.iterdir()) == []


def test_extract_creates_nested_parents(tmp_path: Any) -> None:
    archive = tmp_path / "deep.zip"
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("a/b/c.txt", b"data")
    dest = tmp_path / "dest"

    with ziplet.ZipFile(archive) as zf:
        zf.extractall(dest)
    assert (dest / "a" / "b" / "c.txt").read_bytes() == b"data"


@pytest.mark.skipif(os.name != "posix", reason="symlinks")
@pytest.mark.parametrize("use_policy", [False, True])
def test_extract_into_destination_reached_through_symlink(
    tmp_path: Any, use_policy: bool
) -> None:
    archive = tmp_path / "a.zip"
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("dir/file.txt", b"data")
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    with ziplet.ZipFile(archive) as zf:
        if use_policy:
            zf.extractall(link, policy=ziplet.ExtractPolicy())
        else:
            zf.extractall(link)
    assert (real / "dir" / "file.txt").read_bytes() == b"data"
