from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ziplet.cryptography.aes import (
    EXTRA_WZ_AES,
    WZ_AES,
    WZ_AES_COMPRESS_TYPE,
    WZ_AES_V1,
    WZ_AES_V2,
    AesZipDecrypter,
    AesZipEncryptor,
    _AesCtrWithLittleEndian,
    _counter_blocks,
)
from ziplet.exceptions import BadZipFile
from ziplet.zipfile.info import WzAesExtra


def _make_zinfo(strength: int | None = 3, filename: str = "test.txt") -> MagicMock:
    zinfo = MagicMock()
    zinfo.filename = filename
    zinfo.aes_extra = WzAesExtra(wz_aes_strength=strength)
    return zinfo


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------


class TestModuleConstants:
    def test_wz_aes_string(self) -> None:
        assert WZ_AES == "WZ_AES"

    def test_wz_aes_v1(self) -> None:
        assert WZ_AES_V1 == 0x0001

    def test_wz_aes_v2(self) -> None:
        assert WZ_AES_V2 == 0x0002

    def test_extra_wz_aes(self) -> None:
        assert EXTRA_WZ_AES == 0x9901

    def test_wz_aes_compress_type(self) -> None:
        assert WZ_AES_COMPRESS_TYPE == 99


# ---------------------------------------------------------------------------
# _AesCtrWithLittleEndian
# ---------------------------------------------------------------------------


class TestAesCtrWithLittleEndian:
    def _make(self, key: bytes | None = None) -> _AesCtrWithLittleEndian:
        if key is None:
            key = b"\x00" * 16
        return _AesCtrWithLittleEndian(key)

    def test_initial_counter_is_one(self) -> None:
        assert self._make().counter == 1

    def test_initial_keystream_buffer_is_empty(self) -> None:
        assert self._make().keystream_buffer == b""

    def test_encrypt_returns_bytes(self) -> None:
        assert isinstance(self._make().encrypt(b"hello"), bytes)

    def test_encrypt_preserves_length(self) -> None:
        data = b"hello world"
        assert len(self._make().encrypt(data)) == len(data)

    def test_encrypt_empty_returns_empty(self) -> None:
        assert self._make().encrypt(b"") == b""

    def test_decrypt_is_inverse_of_encrypt(self) -> None:
        key = b"\x42" * 16
        plaintext = b"the quick brown fox jumps over the lazy dog"
        enc = _AesCtrWithLittleEndian(key)
        dec = _AesCtrWithLittleEndian(key)
        assert dec.decrypt(enc.encrypt(plaintext)) == plaintext

    def test_round_trip_across_block_boundary(self) -> None:
        # 17 bytes straddles a 16-byte AES block
        key = b"\x11" * 16
        plaintext = b"A" * 17
        enc = _AesCtrWithLittleEndian(key)
        dec = _AesCtrWithLittleEndian(key)
        assert dec.decrypt(enc.encrypt(plaintext)) == plaintext

    def test_streaming_matches_single_call(self) -> None:
        key = b"\x33" * 16
        data = b"hello world"
        single_enc = _AesCtrWithLittleEndian(key)
        stream_enc = _AesCtrWithLittleEndian(key)
        single = single_enc.encrypt(data)
        chunked = stream_enc.encrypt(data[:5]) + stream_enc.encrypt(data[5:])
        assert chunked == single

    def test_counter_increments_after_full_block(self) -> None:
        cipher = self._make()
        cipher.encrypt(b"\x00" * 16)
        assert cipher.counter == 2

    def test_partial_block_populates_keystream_buffer(self) -> None:
        cipher = self._make()
        cipher.encrypt(b"\x00" * 3)
        assert len(cipher.keystream_buffer) == 13

    def test_keystream_buffer_consumed_on_next_call(self) -> None:
        cipher = self._make()
        cipher.encrypt(b"\x00" * 3)
        cipher.encrypt(b"\x00" * 3)
        assert len(cipher.keystream_buffer) == 10

    def test_256_bit_key_works(self) -> None:
        cipher = _AesCtrWithLittleEndian(b"\x00" * 32)
        result = cipher.encrypt(b"test")
        assert len(result) == 4

    def test_192_bit_key_works(self) -> None:
        cipher = _AesCtrWithLittleEndian(b"\x00" * 24)
        result = cipher.encrypt(b"test")
        assert len(result) == 4

    def test_ciphertext_differs_from_plaintext(self) -> None:
        key = b"\x01" * 16
        plaintext = b"\xff" * 16
        cipher = _AesCtrWithLittleEndian(key)
        assert cipher.encrypt(plaintext) != plaintext

    def test_different_keys_produce_different_ciphertext(self) -> None:
        pt = b"same plaintext!!"
        ct1 = _AesCtrWithLittleEndian(b"\x00" * 16).encrypt(pt)
        ct2 = _AesCtrWithLittleEndian(b"\x01" * 16).encrypt(pt)
        assert ct1 != ct2

    @pytest.mark.parametrize("size", [1, 15, 16, 17, 32, 33, 100])
    def test_round_trip_various_sizes(self, size: int) -> None:
        key = b"\xab" * 16
        plaintext = bytes(range(size % 256)) * (size // 256 + 1)
        plaintext = plaintext[:size]
        enc = _AesCtrWithLittleEndian(key)
        dec = _AesCtrWithLittleEndian(key)
        assert dec.decrypt(enc.encrypt(plaintext)) == plaintext


# ---------------------------------------------------------------------------
# AesZipEncryptor
# ---------------------------------------------------------------------------


class TestAesZipEncryptor:
    @pytest.mark.parametrize(
        ("nbits", "expected_strength", "expected_salt_len"),
        [
            (128, 1, 8),
            (192, 2, 12),
            (256, 3, 16),
        ],
    )
    def test_strength_and_salt_length_per_nbits(
        self, nbits: int, expected_strength: int, expected_salt_len: int
    ) -> None:
        enc = AesZipEncryptor(b"password", nbits=nbits)
        assert enc.aes_strength == expected_strength
        assert enc.salt_length == expected_salt_len
        assert len(enc.salt) == expected_salt_len

    def test_encpwdverify_is_two_bytes(self) -> None:
        assert len(AesZipEncryptor(b"secret").encpwdverify) == 2

    def test_hmac_size_class_attribute(self) -> None:
        assert AesZipEncryptor.hmac_size == 10

    def test_string_password_accepted(self) -> None:
        enc = AesZipEncryptor("password")
        assert len(enc.salt) == 16

    def test_empty_bytes_password_raises(self) -> None:
        with pytest.raises(RuntimeError, match="encryption requires a password"):
            AesZipEncryptor(b"")

    def test_empty_string_password_raises(self) -> None:
        with pytest.raises(RuntimeError, match="encryption requires a password"):
            AesZipEncryptor("")

    def test_invalid_nbits_64_raises(self) -> None:
        with pytest.raises(RuntimeError, match="nbits"):
            AesZipEncryptor(b"pass", nbits=64)

    def test_invalid_nbits_512_raises(self) -> None:
        with pytest.raises(RuntimeError, match="nbits"):
            AesZipEncryptor(b"pass", nbits=512)

    def test_encrypt_returns_bytes(self) -> None:
        assert isinstance(AesZipEncryptor(b"pass").encrypt(b"data"), bytes)

    def test_encrypt_preserves_length(self) -> None:
        enc = AesZipEncryptor(b"pass")
        data = b"hello world"
        assert len(enc.encrypt(data)) == len(data)

    def test_encrypt_empty_returns_empty(self) -> None:
        assert AesZipEncryptor(b"pass").encrypt(b"") == b""

    def test_flush_returns_ten_bytes(self) -> None:
        enc = AesZipEncryptor(b"pass")
        enc.encrypt(b"some data")
        result = enc.flush()
        assert isinstance(result, bytes)
        assert len(result) == 10

    def test_flush_without_encrypt_returns_ten_bytes(self) -> None:
        result = AesZipEncryptor(b"pass").flush()
        assert len(result) == 10

    def test_encryption_header_is_salt_plus_verify(self) -> None:
        enc = AesZipEncryptor(b"pass", nbits=256)
        header = enc.encryption_header()
        assert header == enc.salt + enc.encpwdverify
        assert len(header) == 18  # 16 (salt) + 2 (verify)

    def test_encryption_header_128(self) -> None:
        enc = AesZipEncryptor(b"pass", nbits=128)
        assert len(enc.encryption_header()) == 10  # 8 + 2

    def test_encryption_header_192(self) -> None:
        enc = AesZipEncryptor(b"pass", nbits=192)
        assert len(enc.encryption_header()) == 14  # 12 + 2

    def test_update_zipinfo_sets_vendor_id(self) -> None:
        enc = AesZipEncryptor(b"pass")
        zinfo = MagicMock()
        zinfo.aes_extra = WzAesExtra()
        enc.update_zipinfo(zinfo)
        assert zinfo.aes_extra.wz_aes_vendor_id == b"AE"

    def test_update_zipinfo_sets_strength(self) -> None:
        enc = AesZipEncryptor(b"pass", nbits=128)
        zinfo = MagicMock()
        zinfo.aes_extra = WzAesExtra()
        enc.update_zipinfo(zinfo)
        assert zinfo.aes_extra.wz_aes_strength == 1

    def test_update_zipinfo_forced_version_applied(self) -> None:
        enc = AesZipEncryptor(b"pass", force_wz_aes_version=WZ_AES_V1)
        zinfo = MagicMock()
        zinfo.aes_extra = WzAesExtra()
        enc.update_zipinfo(zinfo)
        assert zinfo.aes_extra.wz_aes_version == WZ_AES_V1

    def test_update_zipinfo_no_forced_version_leaves_version_untouched(self) -> None:
        enc = AesZipEncryptor(b"pass", force_wz_aes_version=None)
        zinfo = MagicMock()
        zinfo.aes_extra = WzAesExtra(wz_aes_version=WZ_AES_V2)
        enc.update_zipinfo(zinfo)
        assert zinfo.aes_extra.wz_aes_version == WZ_AES_V2

    def test_different_instances_have_different_salts(self) -> None:
        enc1 = AesZipEncryptor(b"pass")
        enc2 = AesZipEncryptor(b"pass")
        # Two random 16-byte values will differ with overwhelming probability
        assert enc1.salt != enc2.salt


# ---------------------------------------------------------------------------
# AesZipDecrypter
# ---------------------------------------------------------------------------


class TestAesZipDecrypter:
    def _make_pair(
        self, pwd: bytes, nbits: int = 256
    ) -> tuple[AesZipEncryptor, MagicMock]:
        enc = AesZipEncryptor(pwd, nbits=nbits)
        zinfo = _make_zinfo(strength=enc.aes_strength)
        return enc, zinfo

    def test_valid_password_accepts_bytes(self) -> None:
        enc, zinfo = self._make_pair(b"secret")
        dec = AesZipDecrypter(zinfo, b"secret", enc.encryption_header())
        assert dec.filename == "test.txt"

    def test_valid_password_accepts_str(self) -> None:
        enc, zinfo = self._make_pair(b"secret")
        dec = AesZipDecrypter(zinfo, "secret", enc.encryption_header())
        assert dec.filename == "test.txt"

    def test_wrong_password_raises_runtime_error(self) -> None:
        enc, zinfo = self._make_pair(b"correct")
        with pytest.raises(RuntimeError, match="Bad password"):
            AesZipDecrypter(zinfo, b"wrong", enc.encryption_header())

    def test_missing_aes_strength_raises_bad_zip_file(self) -> None:
        zinfo = _make_zinfo(strength=None)
        with pytest.raises(BadZipFile, match="Missing AES strength"):
            AesZipDecrypter(zinfo, b"pass", b"\x00" * 18)

    def test_hmac_size_class_attribute(self) -> None:
        assert AesZipDecrypter.hmac_size == 10

    @pytest.mark.parametrize(
        ("nbits", "expected_header_len"),
        [
            (128, 10),  # 8 + 2
            (192, 14),  # 12 + 2
            (256, 18),  # 16 + 2
        ],
    )
    def test_encryption_header_length(
        self, nbits: int, expected_header_len: int
    ) -> None:
        enc = AesZipEncryptor(b"pw", nbits=nbits)
        zinfo = _make_zinfo(strength=enc.aes_strength)
        assert AesZipDecrypter.encryption_header_length(zinfo) == expected_header_len

    def test_encryption_header_length_missing_strength_raises(self) -> None:
        with pytest.raises(BadZipFile):
            AesZipDecrypter.encryption_header_length(_make_zinfo(strength=None))

    def test_decrypt_returns_bytes(self) -> None:
        enc, zinfo = self._make_pair(b"pw")
        header = enc.encryption_header()
        dec = AesZipDecrypter(zinfo, b"pw", header)
        assert isinstance(dec.decrypt(b"data"), bytes)

    def test_decrypt_empty_returns_empty(self) -> None:
        enc, zinfo = self._make_pair(b"pw")
        dec = AesZipDecrypter(zinfo, b"pw", enc.encryption_header())
        assert dec.decrypt(b"") == b""

    def test_decrypt_round_trip(self) -> None:
        plaintext = b"the quick brown fox jumps over the lazy dog"
        enc, zinfo = self._make_pair(b"hunter2")
        header = enc.encryption_header()
        ciphertext = enc.encrypt(plaintext)
        dec = AesZipDecrypter(zinfo, b"hunter2", header)
        assert dec.decrypt(ciphertext) == plaintext

    def test_check_hmac_passes_for_valid_tag(self) -> None:
        plaintext = b"sample data"
        enc, zinfo = self._make_pair(b"pw")
        header = enc.encryption_header()
        ciphertext = enc.encrypt(plaintext)
        hmac_tag = enc.flush()
        dec = AesZipDecrypter(zinfo, b"pw", header)
        dec.decrypt(ciphertext)
        dec.check_hmac(hmac_tag)  # must not raise

    def test_check_hmac_raises_for_wrong_tag(self) -> None:
        enc, zinfo = self._make_pair(b"pw")
        header = enc.encryption_header()
        ciphertext = enc.encrypt(b"data")
        enc.flush()
        dec = AesZipDecrypter(zinfo, b"pw", header)
        dec.decrypt(ciphertext)
        with pytest.raises(BadZipFile, match="Bad HMAC"):
            dec.check_hmac(b"\x00" * 10)

    def test_check_hmac_raises_for_truncated_tag(self) -> None:
        enc, zinfo = self._make_pair(b"pw")
        header = enc.encryption_header()
        ciphertext = enc.encrypt(b"data")
        hmac_tag = enc.flush()
        dec = AesZipDecrypter(zinfo, b"pw", header)
        dec.decrypt(ciphertext)
        with pytest.raises(BadZipFile, match="Bad HMAC"):
            dec.check_hmac(bytes([b ^ 0xFF for b in hmac_tag]))

    @pytest.mark.parametrize("nbits", [128, 192, 256])
    def test_full_round_trip_all_key_sizes(self, nbits: int) -> None:
        plaintext = b"Hello, AES!" * 10
        enc = AesZipEncryptor(b"testpass", nbits=nbits)
        zinfo = _make_zinfo(strength=enc.aes_strength)
        header = enc.encryption_header()
        ciphertext = enc.encrypt(plaintext)
        hmac_tag = enc.flush()
        dec = AesZipDecrypter(zinfo, b"testpass", header)
        assert dec.decrypt(ciphertext) == plaintext
        dec.check_hmac(hmac_tag)  # must not raise


# ---------------------------------------------------------------------------
# WinZip little-endian CTR: known answers and reference equivalence
# ---------------------------------------------------------------------------

_KAT_PLAINTEXT = bytes((i * 7 + 3) & 0xFF for i in range(100))
# Generated from the original per-block implementation (WinZip-compatible).
_KAT_CIPHERTEXT = {
    16: "e076c27bc25aaa94a1bd476e37bef9ee88f062932a4d01093c84f447e51aa6fa6f5268ec7019a5eb8a10f9db229773bea3d6ec6cfc649743e41d39f0dfb93f1dbb5716b414b423e8c6bb07db2264d322d804a91909475a9aa900ee32fd5b70ffa9fe725e",  # noqa: E501
    24: "0a406324f5d1da8309a212c08405e99ddb87d0e5739f561d18393ce738eb6e3810bf482440e719cb4bee03101ed3f51f8b8be750c43197df9180ca6c2cefe3cd8ed9f46c4949994db29c6bd8d0c9e8342a303539c1e6347d89bab720c101e099776fd231",  # noqa: E501
    32: "c4bf089c75376c28edee4e9b54a664c43d8e39036443d4f768cd4336a9341fa76329f086708fa62545fc1b812976ee1c862208685c3dc729ba3af16a9b8797a75a211d18ce9fa4399d3e4dd07d027d9c6e90965b60d6c559c5fa957949ffdf87c3aea01c",  # noqa: E501
}


def _reference_ctr(key: bytes, data: bytes) -> bytes:
    """Straightforward WinZip CTR: one AES block per little-endian counter."""
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    out = bytearray()
    for block, offset in enumerate(range(0, len(data), 16), start=1):
        keystream = encryptor.update(block.to_bytes(16, "little"))
        chunk = data[offset : offset + 16]
        out.extend(a ^ b for a, b in zip(chunk, keystream, strict=False))
    return bytes(out)


@pytest.mark.parametrize("key_length", [16, 24, 32])
def test_known_answer_split_across_calls(key_length: int) -> None:
    cipher = _AesCtrWithLittleEndian(bytes(range(key_length)))
    ciphertext = cipher.encrypt(_KAT_PLAINTEXT[:37]) + cipher.encrypt(
        _KAT_PLAINTEXT[37:]
    )
    assert ciphertext.hex() == _KAT_CIPHERTEXT[key_length]


@pytest.mark.parametrize(
    "sizes",
    [
        [0],
        [1],
        [15, 1],
        [16],
        [17, 15],
        [1] * 40,
        [3, 0, 29, 16, 1, 100],
        [65536 + 5, 7],
    ],
)
def test_chunking_never_changes_the_stream(sizes: list[int]) -> None:
    key = os.urandom(32)
    data = os.urandom(sum(sizes))
    cipher = _AesCtrWithLittleEndian(key)
    produced = bytearray()
    offset = 0
    for size in sizes:
        produced += cipher.encrypt(data[offset : offset + size])
        offset += size
    assert bytes(produced) == _reference_ctr(key, data)


def test_counter_blocks_are_little_endian() -> None:
    blocks = _counter_blocks(255, 3)
    assert blocks[0:16] == (255).to_bytes(16, "little")
    assert blocks[16:32] == (256).to_bytes(16, "little")
    assert blocks[32:48] == (257).to_bytes(16, "little")
