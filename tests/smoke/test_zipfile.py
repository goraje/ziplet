"""Smoke tests for ZipFile round-trips.

Covers write/read behavior across encryption and compression combinations.
"""

from __future__ import annotations

import sys
import zipfile as _stdlib_zipfile
from pathlib import Path
from unittest import mock

import pytest

import ziplet

PASSWORD = b"Cefzuj-hetveg-xifve5"
CONTENT = "This is a test file."

COMPRESSIONS = [
    pytest.param(ziplet.ZIP_STORED, id="ZIP_STORED"),
    pytest.param(ziplet.ZIP_DEFLATED, id="ZIP_DEFLATED"),
    pytest.param(ziplet.ZIP_BZIP2, id="ZIP_BZIP2"),
    pytest.param(ziplet.ZIP_LZMA, id="ZIP_LZMA"),
    pytest.param(
        ziplet.ZIP_ZSTANDARD,
        id="ZIP_ZSTANDARD",
        marks=pytest.mark.skipif(
            sys.version_info < (3, 14),
            reason="zstandard tests require Python >= 3.14",
        ),
    ),
]

# (enc_write, enc_read, needs_password)
ENCRYPTIONS = [
    pytest.param(None, None, False, id="None"),
    pytest.param(ziplet.WZ_AES, ziplet.WZ_AES, True, id="WZ_AES"),
    pytest.param(ziplet.ZIP_CRYPTO, None, True, id="ZipCrypto"),
]


@pytest.mark.parametrize("compression", COMPRESSIONS)
@pytest.mark.parametrize(("enc_write", "enc_read", "needs_pwd"), ENCRYPTIONS)
def test_round_trip(
    tmp_path: Path,
    compression: int,
    enc_write: str | None,
    enc_read: str | None,
    needs_pwd: bool,
) -> None:
    path = tmp_path / "test.zip"

    with ziplet.ZipFile(
        path,
        "w",
        compression=compression,
        encryption=enc_write,
    ) as zf:
        if needs_pwd:
            zf.setpassword(PASSWORD)
        zf.writestr("test.txt", CONTENT)

    with ziplet.ZipFile(path, "r", encryption=enc_read) as zf:
        if needs_pwd:
            zf.setpassword(PASSWORD)
        result = zf.read("test.txt").decode()

    assert result == CONTENT


def test_zip64_eocd_round_trip(tmp_path: Path) -> None:
    """Create a ZIP64 archive with stdlib (via patched ZIP64_LIMIT) and read it."""
    path = tmp_path / "zip64.zip"
    with mock.patch.object(_stdlib_zipfile, "ZIP64_LIMIT", -1):
        with _stdlib_zipfile.ZipFile(path, "w", allowZip64=True) as zf:
            zf.writestr("test.txt", CONTENT)

    with ziplet.ZipFile(path, "r") as zf:
        assert zf.read("test.txt").decode() == CONTENT


_TOTALLY_UNKNOWN = 999  # never in the registry or _required_modules


def test_zipfile_open_with_unknown_compression_raises(tmp_path: Path) -> None:
    """ZipFile.open should surface the error when writing with an unsupported method."""
    path = tmp_path / "bad.zip"
    with pytest.raises((NotImplementedError, RuntimeError)):
        with ziplet.ZipFile(path, "w", compression=_TOTALLY_UNKNOWN) as zf:
            zf.writestr("f.txt", "data")
