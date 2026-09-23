from __future__ import annotations

import struct

import pytest

from ziplet.exceptions import BadZipFile
from ziplet.zipfile.info import (
    WzAesExtra,
    ZipInfo,
    _Extra,
    _sanitize_filename,
)
from ziplet.zipfile.shared import (
    MASK_ENCRYPTED,
    MASK_STRONG_ENCRYPTION,
    MASK_USE_DATA_DESCRIPTOR,
    MASK_UTF_FILENAME,
)

# ---------------------------------------------------------------------------
# WzAesExtra
# ---------------------------------------------------------------------------


class TestWzAesExtra:
    def test_defaults_are_none(self) -> None:
        aes = WzAesExtra()
        assert aes.wz_aes_version is None
        assert aes.wz_aes_vendor_id is None
        assert aes.wz_aes_strength is None

    def test_explicit_values_stored(self) -> None:
        aes = WzAesExtra(wz_aes_version=1, wz_aes_vendor_id=b"AE", wz_aes_strength=3)
        assert aes.wz_aes_version == 1
        assert aes.wz_aes_vendor_id == b"AE"
        assert aes.wz_aes_strength == 3


# ---------------------------------------------------------------------------
# _sanitize_filename
# ---------------------------------------------------------------------------


class TestSanitizeFilename:
    def test_plain_filename_unchanged(self) -> None:
        assert _sanitize_filename("hello.txt") == "hello.txt"

    def test_null_byte_truncates(self) -> None:
        assert _sanitize_filename("file\x00.txt") == "file"

    def test_null_byte_at_start_gives_empty(self) -> None:
        assert _sanitize_filename("\x00rest") == ""

    def test_forward_slash_path_unchanged(self) -> None:
        assert _sanitize_filename("a/b/c.txt") == "a/b/c.txt"


# ---------------------------------------------------------------------------
# _Extra
# ---------------------------------------------------------------------------


def _make_extra_field(tag: int, body: bytes) -> bytes:
    return struct.pack("<HH", tag, len(body)) + body


class TestExtra:
    def test_read_one_parses_tag_and_body(self) -> None:
        raw = _make_extra_field(0x0001, b"\x01\x02\x03\x04\x05\x06\x07\x08")
        field, rest = _Extra.read_one(raw)
        assert field.id == 0x0001
        assert rest == b""

    def test_read_one_returns_remainder(self) -> None:
        f1 = _make_extra_field(0x0001, b"\x00" * 8)
        f2 = _make_extra_field(0x9901, b"\x00" * 7)
        field, rest = _Extra.read_one(f1 + f2)
        assert field.id == 0x0001
        assert rest == f2

    def test_read_one_malformed_gives_none_id(self) -> None:
        field, rest = _Extra.read_one(b"\x01")  # too short for header
        assert field.id is None

    def test_iter_fields_empty_yields_nothing(self) -> None:
        assert list(_Extra.iter_fields(b"")) == []

    def test_iter_fields_yields_all_fields(self) -> None:
        data = _make_extra_field(0x0001, b"\x00" * 8) + _make_extra_field(
            0x9901, b"\x00" * 7
        )
        fields = list(_Extra.iter_fields(data))
        assert len(fields) == 2
        assert fields[0].id == 0x0001
        assert fields[1].id == 0x9901

    def test_strip_removes_matching_tag(self) -> None:
        f1 = _make_extra_field(0x0001, b"\x00" * 8)
        f2 = _make_extra_field(0x9901, b"\x00" * 7)
        result = _Extra.strip(f1 + f2, {0x0001})
        assert result == f2

    def test_strip_keeps_unmatched_fields(self) -> None:
        f1 = _make_extra_field(0x0001, b"\x00" * 8)
        f2 = _make_extra_field(0x9901, b"\x00" * 7)
        result = _Extra.strip(f1 + f2, {0xDEAD})
        assert result == f1 + f2

    def test_strip_empty_input(self) -> None:
        assert _Extra.strip(b"", {0x0001}) == b""


# ---------------------------------------------------------------------------
# ZipInfo
# ---------------------------------------------------------------------------


class TestZipInfoInit:
    def test_default_filename(self) -> None:
        zi = ZipInfo()
        assert zi.filename == "NoName"

    def test_filename_stored_as_orig_filename(self) -> None:
        zi = ZipInfo("test.txt")
        assert zi.orig_filename == "test.txt"

    def test_date_before_1980_raises(self) -> None:
        with pytest.raises(ValueError, match="1980"):
            ZipInfo(date_time=(1979, 1, 1, 0, 0, 0))

    def test_date_exactly_1980_is_valid(self) -> None:
        zi = ZipInfo(date_time=(1980, 1, 1, 0, 0, 0))
        assert zi.date_time[0] == 1980

    def test_default_aes_extra_is_blank(self) -> None:
        zi = ZipInfo()
        assert zi.aes_extra.wz_aes_version is None

    def test_custom_aes_extra_is_stored(self) -> None:
        aes = WzAesExtra(wz_aes_version=2, wz_aes_vendor_id=b"AE", wz_aes_strength=3)
        zi = ZipInfo(aes_extra=aes)
        assert zi.aes_extra is aes

    def test_flag_bits_default_zero(self) -> None:
        assert ZipInfo().flag_bits == 0


class TestZipInfoProperties:
    def test_is_encrypted_false_by_default(self) -> None:
        assert not ZipInfo().is_encrypted

    def test_is_encrypted_true_when_flag_set(self) -> None:
        zi = ZipInfo()
        zi.flag_bits = MASK_ENCRYPTED
        assert zi.is_encrypted

    def test_is_utf_filename_false_by_default(self) -> None:
        assert not ZipInfo().is_utf_filename

    def test_is_utf_filename_true_when_flag_set(self) -> None:
        zi = ZipInfo()
        zi.flag_bits = MASK_UTF_FILENAME
        assert zi.is_utf_filename

    def test_is_strong_encryption_false_by_default(self) -> None:
        assert not ZipInfo().is_strong_encryption

    def test_is_strong_encryption_true_when_flag_set(self) -> None:
        zi = ZipInfo()
        zi.flag_bits = MASK_STRONG_ENCRYPTION
        assert zi.is_strong_encryption

    def test_use_datadescripter_false_by_default(self) -> None:
        assert not ZipInfo().use_datadescripter

    def test_use_datadescripter_true_when_flag_set(self) -> None:
        zi = ZipInfo()
        zi.flag_bits = MASK_USE_DATA_DESCRIPTOR
        assert zi.use_datadescripter
        assert zi.use_data_descriptor

    def test_data_descriptor_aliases_match_legacy_names(self) -> None:
        zi = ZipInfo("payload.bin")
        zi.CRC = 1
        zi.compress_size = 2
        zi.file_size = 3
        assert zi.data_descriptor(False) == zi.datadescripter(False)
        assert zi.encode_data_descriptor(False, 1, 2, 3) == zi.encode_datadescripter(
            False, 1, 2, 3
        )

    def test_compresslevel_alias_roundtrip(self) -> None:
        zi = ZipInfo()
        zi._compresslevel = 9
        assert zi.compress_level == 9
        assert zi._compresslevel == 9


class TestZipInfoDosDateTime:
    def test_get_dosdate_epoch(self) -> None:
        zi = ZipInfo(date_time=(1980, 1, 1, 0, 0, 0))
        assert zi.get_dosdate() == (0 << 9 | 1 << 5 | 1)

    def test_get_dosdate_known_value(self) -> None:
        # 2024-06-15 â†’ (2024-1980)<<9 | 6<<5 | 15 = 44<<9 | 192 | 15
        zi = ZipInfo(date_time=(2024, 6, 15, 0, 0, 0))
        assert zi.get_dosdate() == (44 << 9) | (6 << 5) | 15

    def test_get_dostime_midnight(self) -> None:
        zi = ZipInfo(date_time=(1980, 1, 1, 0, 0, 0))
        assert zi.get_dostime() == 0

    def test_get_dostime_known_value(self) -> None:
        # 13:30:44 â†’ 13<<11 | 30<<5 | 22 (44//2)
        zi = ZipInfo(date_time=(1980, 1, 1, 13, 30, 44))
        assert zi.get_dostime() == (13 << 11) | (30 << 5) | 22

    def test_get_dostime_odd_second_truncated(self) -> None:
        zi_even = ZipInfo(date_time=(1980, 1, 1, 0, 0, 4))
        zi_odd = ZipInfo(date_time=(1980, 1, 1, 0, 0, 5))
        assert zi_even.get_dostime() == zi_odd.get_dostime()


class TestZipInfoEncodeDataDescriptor:
    def test_non_zip64_format(self) -> None:
        zi = ZipInfo()
        result = zi.encode_datadescripter(False, 0xDEADBEEF, 100, 200)
        sig, crc, csz, fsz = struct.unpack("<LLLL", result)
        assert sig == 0x08074B50
        assert crc == 0xDEADBEEF
        assert csz == 100
        assert fsz == 200

    def test_zip64_format_uses_q_fields(self) -> None:
        zi = ZipInfo()
        result = zi.encode_datadescripter(True, 0, 2**32, 2**33)
        sig, crc, csz, fsz = struct.unpack("<LLQQ", result)
        assert sig == 0x08074B50
        assert csz == 2**32
        assert fsz == 2**33

    def test_zip64_record_is_larger_than_non_zip64(self) -> None:
        zi = ZipInfo()
        assert len(zi.encode_datadescripter(True, 0, 0, 0)) > len(
            zi.encode_datadescripter(False, 0, 0, 0)
        )


class TestZipInfoDecodeExtraWzAes:
    def _make_wz_aes_extra(
        self, version: int = 1, strength: int = 3, compress_type: int = 8
    ) -> bytes:
        # tag(H) + size(H) + version(H) + vendor_id(2s) + strength(B) + compress_type(H)
        body = struct.pack("<H2sBH", version, b"AE", strength, compress_type)
        return struct.pack("<HH", 0x9901, len(body)) + body

    def test_valid_field_populates_aes_extra(self) -> None:
        zi = ZipInfo()
        raw = self._make_wz_aes_extra(version=1, strength=3, compress_type=8)
        zi.extra = raw
        zi._decode_extra(0)
        assert zi.aes_extra.wz_aes_version == 1
        assert zi.aes_extra.wz_aes_vendor_id == b"AE"
        assert zi.aes_extra.wz_aes_strength == 3
        assert zi.compress_type == 8

    def test_invalid_length_raises_bad_zip_file(self) -> None:
        zi = ZipInfo()
        body = b"\x00" * 5  # wrong length (must be 7)
        raw = struct.pack("<HH", 0x9901, 5) + body
        zi.extra = raw
        with pytest.raises(BadZipFile):
            zi._decode_extra(0)

    def test_unknown_extra_tag_silently_ignored(self) -> None:
        zi = ZipInfo()
        body = b"\x00" * 4
        zi.extra = struct.pack("<HH", 0xBEEF, 4) + body
        zi._decode_extra(0)  # should not raise
