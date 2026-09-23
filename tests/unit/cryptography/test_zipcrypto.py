from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from ziplet.cryptography.zipcrypto import (
    ZIP_CRYPTO,
    ZipCryptoDecrypter,
    ZipCryptoEncryptor,
    _gen_crc,
    _ZipCryptoState,
)
from ziplet.zipfile.shared import MASK_USE_DATA_DESCRIPTOR

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_enc_header(
    pwd: bytes, dos_time: int = 0x5A3C
) -> tuple[ZipCryptoEncryptor, bytes]:
    """Return a fresh encryptor (after update_zipinfo) and its encryption header."""
    enc = ZipCryptoEncryptor(pwd)
    zinfo = MagicMock()
    zinfo.flag_bits = 0
    zinfo.get_dostime.return_value = dos_time
    enc.update_zipinfo(zinfo)
    return enc, enc.encryption_header()


def _make_dec_zinfo(
    *,
    use_data_descriptor: bool = True,
    raw_time: int = 0x5A3C,
    crc: int = 0,
    filename: str = "test.txt",
) -> MagicMock:
    zinfo = MagicMock()
    zinfo.filename = filename
    zinfo.use_data_descriptor = use_data_descriptor
    zinfo.raw_time = raw_time
    zinfo.CRC = crc
    return zinfo


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------


class TestModuleConstants:
    def test_zip_crypto_string(self) -> None:
        assert ZIP_CRYPTO == "ZipCrypto"


# ---------------------------------------------------------------------------
# _gen_crc
# ---------------------------------------------------------------------------


class TestGenCrc:
    def test_zero_input_returns_zero(self) -> None:
        assert _gen_crc(0) == 0

    def test_known_value_for_one(self) -> None:
        # Standard CRC32 table entry for 1
        assert _gen_crc(1) == 0x77073096

    def test_returns_int(self) -> None:
        assert isinstance(_gen_crc(42), int)

    def test_result_fits_in_32_bits(self) -> None:
        for i in range(256):
            assert 0 <= _gen_crc(i) <= 0xFFFFFFFF

    def test_all_inputs_produce_unique_values(self) -> None:
        results = [_gen_crc(i) for i in range(256)]
        assert len(set(results)) == 256


# ---------------------------------------------------------------------------
# ZipCryptoEncryptor
# ---------------------------------------------------------------------------


class TestZipCryptoEncryptor:
    def test_initial_key_state_with_empty_password(self) -> None:
        enc = ZipCryptoEncryptor(b"")
        assert enc._state.key0 == 305419896
        assert enc._state.key1 == 591751049
        assert enc._state.key2 == 878082192

    def test_password_changes_key_state(self) -> None:
        empty = ZipCryptoEncryptor(b"")
        with_pwd = ZipCryptoEncryptor(b"password")
        # At least one key must differ
        assert (
            empty._state.key0 != with_pwd._state.key0
            or empty._state.key1 != with_pwd._state.key1
            or empty._state.key2 != with_pwd._state.key2
        )

    def test_same_passwords_produce_same_key_state(self) -> None:
        enc1 = ZipCryptoEncryptor(b"same")
        enc2 = ZipCryptoEncryptor(b"same")
        assert enc1._state.key0 == enc2._state.key0
        assert enc1._state.key1 == enc2._state.key1
        assert enc1._state.key2 == enc2._state.key2

    def test_crc32_returns_int(self) -> None:
        enc = ZipCryptoEncryptor(b"pw")
        assert isinstance(enc._state.crc32(0x41, 0x12345678), int)

    def test_crc32_result_fits_32_bits(self) -> None:
        enc = ZipCryptoEncryptor(b"pw")
        result = enc._state.crc32(0xFF, 0xFFFFFFFF)
        assert 0 <= result <= 0xFFFFFFFF

    def test_encrypt_returns_bytes(self) -> None:
        enc = ZipCryptoEncryptor(b"pw")
        assert isinstance(enc.encrypt(b"hello"), bytes)

    def test_encrypt_preserves_length(self) -> None:
        enc = ZipCryptoEncryptor(b"pw")
        data = b"hello world"
        assert len(enc.encrypt(data)) == len(data)

    def test_encrypt_empty_returns_empty(self) -> None:
        assert ZipCryptoEncryptor(b"pw").encrypt(b"") == b""

    def test_flush_returns_empty_bytes(self) -> None:
        assert ZipCryptoEncryptor(b"pw").flush() == b""

    def test_update_zipinfo_sets_data_descriptor_flag(self) -> None:
        enc = ZipCryptoEncryptor(b"pw")
        zinfo = MagicMock()
        zinfo.flag_bits = 0
        enc.update_zipinfo(zinfo)
        assert zinfo.flag_bits & MASK_USE_DATA_DESCRIPTOR

    def test_update_zipinfo_preserves_other_flags(self) -> None:
        enc = ZipCryptoEncryptor(b"pw")
        zinfo = MagicMock()
        zinfo.flag_bits = 0x0001
        enc.update_zipinfo(zinfo)
        assert zinfo.flag_bits & 0x0001

    def test_encryption_header_before_update_zipinfo_raises(self) -> None:
        enc = ZipCryptoEncryptor(b"pw")
        with pytest.raises(AssertionError):
            enc.encryption_header()

    def test_encryption_header_is_twelve_bytes(self) -> None:
        _, header = _make_enc_header(b"pw")
        assert len(header) == 12

    def test_encryption_header_returns_bytes(self) -> None:
        _, header = _make_enc_header(b"pw")
        assert isinstance(header, bytes)

    def test_different_calls_produce_different_headers(self) -> None:
        # Headers contain random bytes so two fresh calls should differ
        _, h1 = _make_enc_header(b"pw", dos_time=0x1234)
        _, h2 = _make_enc_header(b"pw", dos_time=0x1234)
        assert h1 != h2


# ---------------------------------------------------------------------------
# ZipCryptoDecrypter
# ---------------------------------------------------------------------------


class TestZipCryptoDecrypter:
    def test_encryption_header_length_class_attribute(self) -> None:
        assert ZipCryptoDecrypter.encryption_header_length == 12

    def test_valid_password_via_datadescriptor(self) -> None:
        dos_time = 0x5A3C
        _, header = _make_enc_header(b"correct", dos_time)
        zinfo = _make_dec_zinfo(use_data_descriptor=True, raw_time=dos_time)
        dec = ZipCryptoDecrypter(zinfo, b"correct", header)
        assert dec._state.key0 is not None

    def test_wrong_password_raises_runtime_error(self) -> None:
        dos_time = 0x5A3C
        # Patch os.urandom so the encryption header is deterministic across runs.
        # Without this, h[11] with a wrong password is a random byte and there is
        # a 1/256 chance it accidentally matches the check byte, silently passing.
        with patch(
            "ziplet.cryptography.zipcrypto.os.urandom", return_value=b"\x00" * 11
        ):
            _, header = _make_enc_header(b"correct", dos_time)
        zinfo = _make_dec_zinfo(use_data_descriptor=True, raw_time=dos_time)
        with pytest.raises(RuntimeError, match="Bad password"):
            ZipCryptoDecrypter(zinfo, b"wrong", header)

    def test_valid_password_via_crc(self) -> None:
        """Password check using the CRC MSB (use_data_descriptor=False)."""
        pwd = b"crctest"
        crc = 0xAB000000
        check_byte = (crc >> 24) & 0xFF  # 0xAB

        # Build a 12-byte plaintext whose last byte is the check_byte, then
        # encrypt it with the same password so the decrypter can verify it.
        enc = ZipCryptoEncryptor(pwd)
        raw_header = bytes(range(11)) + bytes([check_byte])
        encrypted_header = enc.encrypt(raw_header)

        zinfo = _make_dec_zinfo(use_data_descriptor=False, crc=crc)
        # Must not raise
        ZipCryptoDecrypter(zinfo, pwd, encrypted_header)

    def test_crc32_returns_int(self) -> None:
        dos_time = 0x3C00
        _, header = _make_enc_header(b"pw", dos_time)
        zinfo = _make_dec_zinfo(raw_time=dos_time)
        dec = ZipCryptoDecrypter(zinfo, b"pw", header)
        assert isinstance(dec._state.crc32(0x41, 0x12345678), int)

    def test_decrypt_returns_bytes(self) -> None:
        dos_time = 0x3C00
        _, header = _make_enc_header(b"pw", dos_time)
        zinfo = _make_dec_zinfo(raw_time=dos_time)
        dec = ZipCryptoDecrypter(zinfo, b"pw", header)
        assert isinstance(dec.decrypt(b"hello"), bytes)

    def test_decrypt_preserves_length(self) -> None:
        dos_time = 0x3C00
        _, header = _make_enc_header(b"pw", dos_time)
        zinfo = _make_dec_zinfo(raw_time=dos_time)
        dec = ZipCryptoDecrypter(zinfo, b"pw", header)
        data = b"hello world"
        assert len(dec.decrypt(data)) == len(data)

    def test_decrypt_empty_returns_empty(self) -> None:
        dos_time = 0x3C00
        _, header = _make_enc_header(b"pw", dos_time)
        zinfo = _make_dec_zinfo(raw_time=dos_time)
        dec = ZipCryptoDecrypter(zinfo, b"pw", header)
        assert dec.decrypt(b"") == b""

    def test_round_trip(self) -> None:
        dos_time = 0x3C00
        plaintext = b"the quick brown fox jumps over the lazy dog"
        enc = ZipCryptoEncryptor(b"hunter2")
        enc_zinfo = MagicMock()
        enc_zinfo.flag_bits = 0
        enc_zinfo.get_dostime.return_value = dos_time
        enc.update_zipinfo(enc_zinfo)
        header = enc.encryption_header()
        ciphertext = enc.encrypt(plaintext)

        dec_zinfo = _make_dec_zinfo(raw_time=dos_time)
        dec = ZipCryptoDecrypter(dec_zinfo, b"hunter2", header)
        assert dec.decrypt(ciphertext) == plaintext

    @pytest.mark.parametrize("plaintext", [b"a", b"x" * 16, b"y" * 100])
    def test_round_trip_various_lengths(self, plaintext: bytes) -> None:
        dos_time = 0x1A2B
        enc = ZipCryptoEncryptor(b"multitest")
        enc_zinfo = MagicMock()
        enc_zinfo.flag_bits = 0
        enc_zinfo.get_dostime.return_value = dos_time
        enc.update_zipinfo(enc_zinfo)
        header = enc.encryption_header()
        ciphertext = enc.encrypt(plaintext)

        dec_zinfo = _make_dec_zinfo(raw_time=dos_time)
        dec = ZipCryptoDecrypter(dec_zinfo, b"multitest", header)
        assert dec.decrypt(ciphertext) == plaintext


# ---------------------------------------------------------------------------
# Inlined key schedule must match the straightforward per-byte definition
# ---------------------------------------------------------------------------


def _reference_encrypt(pwd: bytes, data: bytes) -> bytes:
    state = _ZipCryptoState(pwd)
    out = bytearray()
    for value in data:
        key = state.key2 | 2
        stream_byte = ((key * (key ^ 1)) >> 8) & 0xFF
        state.update_keys(value)
        out.append(value ^ stream_byte)
    return bytes(out)


def test_encrypt_matches_reference_and_decrypt_inverts_it() -> None:
    data = bytes(range(256)) * 5
    ciphertext = _ZipCryptoState(b"secret").encrypt(data)
    assert ciphertext == _reference_encrypt(b"secret", data)
    assert _ZipCryptoState(b"secret").decrypt(ciphertext) == data


def test_state_carries_over_between_chunks() -> None:
    data = os.urandom(1000)
    whole = _ZipCryptoState(b"pw").encrypt(data)
    chunked = _ZipCryptoState(b"pw")
    assert (
        chunked.encrypt(data[:1])
        + chunked.encrypt(data[1:700])
        + chunked.encrypt(data[700:])
        == whole
    )
