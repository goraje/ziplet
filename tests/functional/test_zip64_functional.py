"""Functional ZIP64 tests with tiny payloads via patched ZIP64 thresholds.

These tests avoid giant files by monkeypatching ZIP64 limits in runtime modules.
They validate ZIP64 behavior end-to-end (ziplet, stdlib, and 7-Zip).
"""

from __future__ import annotations

import struct
import subprocess
import zipfile as _stdlib_zipfile
from pathlib import Path
from unittest import mock

import pytest

from ziplet import ZipFile
from ziplet.exceptions import LargeZipFile
from ziplet.zipfile import file as file_mod
from ziplet.zipfile import info as info_mod
from ziplet.zipfile.shared import (
    CENTRAL_DIR_SIGNATURE,
    CENTRAL_DIR_SIZE,
    CENTRAL_DIR_STRUCT,
    END_ARCHIVE64_LOCATOR_SIGNATURE,
    END_ARCHIVE64_SIGNATURE,
    FILE_HEADER_SIGNATURE,
    FILE_HEADER_SIZE,
    FILE_HEADER_STRUCT,
)

SZ_EXE = Path(r"C:\Program Files\7-Zip\7z.exe")

pytestmark = pytest.mark.skipif(
    not SZ_EXE.exists(),
    reason="7-Zip not found at C:\\Program Files\\7-Zip\\7z.exe",
)


def _sz(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(SZ_EXE), *args], capture_output=True, text=True)


def _sz_test(archive: Path) -> int:
    return _sz("t", str(archive)).returncode


def _parse_extra_has_zip64(extra: bytes) -> bool:
    """Return True when extra-data bytes contain ZIP64 tag 0x0001."""
    pos = 0
    while pos + 4 <= len(extra):
        xid, xlen = struct.unpack("<HH", extra[pos : pos + 4])
        if xid == 0x0001:
            return True
        pos += 4 + xlen
    return False


def _first_local_extra(path: Path) -> bytes:
    data = path.read_bytes()
    off = data.find(FILE_HEADER_SIGNATURE)
    assert off >= 0, "local header not found"
    header = struct.unpack(FILE_HEADER_STRUCT, data[off : off + FILE_HEADER_SIZE])
    fname_len = header[10]
    extra_len = header[11]
    start = off + FILE_HEADER_SIZE + fname_len
    return data[start : start + extra_len]


def _first_central_extra(path: Path) -> bytes:
    data = path.read_bytes()
    off = data.find(CENTRAL_DIR_SIGNATURE)
    assert off >= 0, "central directory not found"
    cent = struct.unpack(CENTRAL_DIR_STRUCT, data[off : off + CENTRAL_DIR_SIZE])
    fname_len = cent[12]
    extra_len = cent[13]
    start = off + CENTRAL_DIR_SIZE + fname_len
    return data[start : start + extra_len]


class TestZip64Functional:
    def test_force_zip64_writes_local_zip64_extra(self, tmp_path: Path) -> None:
        """force_zip64=True should emit ZIP64 extra.

        Even for small data, the local header should include the ZIP64 extra field.
        """
        path = tmp_path / "force-local.zip"
        with ZipFile(path, "w") as zf:
            with zf.open("tiny.txt", "w", force_zip64=True) as fp:
                fp.write(b"tiny")

        local_extra = _first_local_extra(path)
        assert _parse_extra_has_zip64(local_extra)
        assert _sz_test(path) == 0

    def test_force_zip64_with_allowzip64_false_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "force-denied.zip"
        with ZipFile(path, "w", allowZip64=False) as zf:
            with pytest.raises(ValueError, match="force_zip64"):
                zf.open("x.txt", "w", force_zip64=True)

    def test_patched_limit_triggers_local_and_central_zip64_extra(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Patched low ZIP64 limit should produce ZIP64 extra.

        This must appear in both local and central headers.
        """
        monkeypatch.setattr(file_mod, "ZIP64_LIMIT", 64)
        monkeypatch.setattr(info_mod, "ZIP64_LIMIT", 64)

        path = tmp_path / "zip64-both-extra.zip"
        with ZipFile(path, "w") as zf:
            zf.writestr("big.bin", b"A" * 200)

        local_extra = _first_local_extra(path)
        central_extra = _first_central_extra(path)
        assert _parse_extra_has_zip64(local_extra)
        assert _parse_extra_has_zip64(central_extra)
        assert _sz_test(path) == 0

    def test_allowzip64_false_raises_when_threshold_exceeded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(file_mod, "ZIP64_LIMIT", 64)

        path = tmp_path / "nozip64.zip"
        with ZipFile(path, "w", allowZip64=False) as zf:
            with pytest.raises(LargeZipFile, match="ZIP64"):
                zf.writestr("too-big.bin", b"B" * 200)

    def test_stdlib_forced_zip64_is_readable_and_7z_validates(
        self, tmp_path: Path
    ) -> None:
        """Cross-tool check for forced ZIP64 interoperability.

        stdlib writes, ziplet reads, and 7z validates.
        """
        path = tmp_path / "stdlib-zip64.zip"
        with mock.patch.object(_stdlib_zipfile, "ZIP64_LIMIT", -1):
            with _stdlib_zipfile.ZipFile(path, "w", allowZip64=True) as zf:
                zf.writestr("s.txt", "stdlib zip64")

        with ZipFile(path, "r") as zf:
            assert zf.read("s.txt") == b"stdlib zip64"

        assert _sz_test(path) == 0

    def test_patched_filecount_limit_emits_zip64_eocd_records(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Low file-count limit forces ZIP64 EOCD/locator for multi-file archives."""
        monkeypatch.setattr(file_mod, "ZIP_FILECOUNT_LIMIT", 2)

        path = tmp_path / "zip64-count.zip"
        with ZipFile(path, "w") as zf:
            zf.writestr("a.txt", b"a")
            zf.writestr("b.txt", b"b")
            zf.writestr("c.txt", b"c")

        raw = path.read_bytes()
        assert END_ARCHIVE64_SIGNATURE in raw
        assert END_ARCHIVE64_LOCATOR_SIGNATURE in raw

        with ZipFile(path, "r") as zf:
            assert zf.namelist() == ["a.txt", "b.txt", "c.txt"]

        assert _sz_test(path) == 0
