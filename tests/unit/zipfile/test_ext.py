from __future__ import annotations

import io
from typing import Any, cast

import pytest

from ziplet.cryptography.aes import AesZipDecrypter
from ziplet.cryptography.zipcrypto import ZipCryptoDecrypter
from ziplet.zipfile.ext import ZipExtFile
from ziplet.zipfile.info import WzAesExtra, ZipInfo


def _make_ext() -> ZipExtFile:
    ext = ZipExtFile.__new__(ZipExtFile)
    ext._close_fileobj = False
    ext._fileobj = cast(Any, io.BytesIO())
    return ext


class TestZipExtFileSetupDecrypter:
    def test_aes_missing_password_raises(self) -> None:
        ext = _make_ext()
        zinfo = ZipInfo("secret.txt")
        zinfo.aes_extra = WzAesExtra(wz_aes_version=2, wz_aes_strength=3)
        ext._zinfo = zinfo
        ext._pwd = None
        ext.name = "secret.txt"

        with pytest.raises(RuntimeError, match="requires a password"):
            ext._setup_decrypter()

    def test_zipcrypto_missing_password_raises(self) -> None:
        ext = _make_ext()
        zinfo = ZipInfo("secret.txt")
        zinfo.aes_extra = WzAesExtra()
        ext._zinfo = zinfo
        ext._pwd = None
        ext.name = "secret.txt"

        with pytest.raises(RuntimeError, match="password required"):
            ext._setup_decrypter()

    def test_aes_branch_reads_header_and_subtracts_hmac(self) -> None:
        ext = _make_ext()
        zinfo = ZipInfo("secret.txt")
        zinfo.aes_extra = WzAesExtra(wz_aes_version=2, wz_aes_strength=3)
        ext._zinfo = zinfo
        ext._pwd = b"pw"
        ext.name = "secret.txt"
        ext._fileobj = cast(Any, io.BytesIO(b"x" * 128))
        ext._orig_compress_left = 100

        cls = ext._setup_decrypter()

        header_len = AesZipDecrypter.encryption_header_length(ext._zinfo)
        assert cls is AesZipDecrypter
        assert len(ext.encryption_header) == header_len
        assert ext._orig_compress_left == (100 - header_len - AesZipDecrypter.hmac_size)

    def test_zipcrypto_branch_reads_header(self) -> None:
        ext = _make_ext()
        zinfo = ZipInfo("secret.txt")
        zinfo.aes_extra = WzAesExtra()
        ext._zinfo = zinfo
        ext._pwd = b"pw"
        ext.name = "secret.txt"
        ext._fileobj = cast(Any, io.BytesIO(b"x" * 64))
        ext._orig_compress_left = 80

        cls = ext._setup_decrypter()

        assert cls is ZipCryptoDecrypter
        assert len(ext.encryption_header) == ZipCryptoDecrypter.encryption_header_length
        assert ext._orig_compress_left == (
            80 - ZipCryptoDecrypter.encryption_header_length
        )

    def test_get_decrypter_kwargs_returns_pwd_and_header(self) -> None:
        ext = _make_ext()
        ext._pwd = b"pw"
        ext.encryption_header = b"header"

        kwargs = ext._decrypter_kwargs()

        assert kwargs == {"pwd": b"pw", "encryption_header": b"header"}
