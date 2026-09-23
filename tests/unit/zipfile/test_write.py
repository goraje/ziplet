from __future__ import annotations

import io
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import ziplet
from ziplet.compression import ZIP_STORED
from ziplet.zipfile import write as write_mod
from ziplet.zipfile.info import ZipInfo
from ziplet.zipfile.shared import MASK_USE_DATA_DESCRIPTOR
from ziplet.zipfile.write import ZipWriteFile


class _FakeEncryptor:
    def __init__(self, header: bytes = b"hdr", flush_tail: bytes = b"tag") -> None:
        self._header = header
        self._flush_tail = flush_tail

    def update_zipinfo(self, zipinfo: ZipInfo) -> None:
        self._zinfo = zipinfo

    def encryption_header(self) -> bytes:
        return self._header

    def encrypt(self, data: bytes) -> bytes:
        return data

    def flush(self) -> bytes:
        return self._flush_tail


def _make_parent() -> SimpleNamespace:
    return SimpleNamespace(
        fp=io.BytesIO(),
        _didModify=False,
        start_dir=0,
        filelist=[],
        NameToInfo={},
    )


def _make_zinfo(name: str) -> ZipInfo:
    zinfo = ZipInfo(name)
    zinfo.compress_type = ZIP_STORED
    zinfo.compress_level = None
    zinfo.CRC = 0
    zinfo.file_size = 0
    zinfo.compress_size = 0
    zinfo.flag_bits = 0
    zinfo.header_offset = 0
    return zinfo


class TestZipWriteFile:
    def test_encryption_header_counts_toward_compress_size(self) -> None:
        parent = _make_parent()
        zinfo = _make_zinfo("a.txt")

        zwf = ZipWriteFile(
            cast(Any, parent),
            zinfo,
            zip64=False,
            encryptor=cast(Any, _FakeEncryptor(header=b"abc")),
        )

        assert zwf._compress_size == 3
        zwf.close()

    def test_close_registers_entry_and_commits_state(self) -> None:
        parent = _make_parent()
        zinfo = _make_zinfo("b.txt")

        with ZipWriteFile(cast(Any, parent), zinfo, zip64=False) as zwf:
            zwf.write(b"hello")

        assert zwf._state == write_mod.WriteState.COMMITTED
        assert zinfo in parent.filelist
        assert parent.NameToInfo["b.txt"] is zinfo

    def test_non_zip64_file_size_over_limit_raises(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(write_mod, "ZIP64_LIMIT", 1)
        parent = _make_parent()
        zinfo = _make_zinfo("big.txt")

        zwf = ZipWriteFile(cast(Any, parent), zinfo, zip64=False)
        zwf.write(b"abcd")

        with pytest.raises(
            RuntimeError,
            match="File size unexpectedly exceeded ZIP64 limit",
        ):
            zwf.close()
        assert zwf._state.value == "failed"

    def test_non_zip64_compress_size_over_limit_raises(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(write_mod, "ZIP64_LIMIT", 10)
        parent = _make_parent()
        zinfo = _make_zinfo("big-compress.txt")

        zwf = ZipWriteFile(
            cast(Any, parent),
            zinfo,
            zip64=False,
            encryptor=cast(Any, _FakeEncryptor(header=b"", flush_tail=b"x" * 16)),
        )
        zwf.write(b"a")

        with pytest.raises(
            RuntimeError,
            match="Compressed size unexpectedly exceeded ZIP64 limit",
        ):
            zwf.close()

    def test_close_uses_data_descriptor_when_flag_set(self) -> None:
        parent = _make_parent()
        zinfo = _make_zinfo("dd.txt")
        zinfo.flag_bits |= MASK_USE_DATA_DESCRIPTOR

        with ZipWriteFile(cast(Any, parent), zinfo, zip64=False) as zwf:
            zwf.write(b"abc")

        assert parent.start_dir > 0

    def test_finalization_failure_marks_writer_failed(self) -> None:
        parent = _make_parent()
        zinfo = _make_zinfo("failed.txt")
        zwf = ZipWriteFile(
            cast(Any, parent),
            zinfo,
            zip64=False,
            encryptor=cast(Any, _FakeEncryptor(flush_tail=b"x" * 20)),
        )
        write_module = cast(Any, write_mod)
        original = write_module.ZIP64_LIMIT
        write_module.ZIP64_LIMIT = 1
        try:
            with pytest.raises(RuntimeError):
                zwf.close()
        finally:
            write_module.ZIP64_LIMIT = original
        assert zwf._state == write_mod.WriteState.FAILED
        assert zinfo not in parent.filelist


class TestWriteCoordinatorRecovery:
    def test_zipfile_usable_after_failed_write(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failed write must not permanently lock the archive.

        Regression test: WriteCoordinator.fail() leaves the coordinator in
        WriterArchiveState.FAILED, a terminal state distinct from IDLE.
        `active` must treat FAILED as "not active" — otherwise every
        subsequent read, write, or close on this ZipFile raises forever.
        """
        original_limit = cast(Any, write_mod).ZIP64_LIMIT
        monkeypatch.setattr(write_mod, "ZIP64_LIMIT", 1)
        archive = tmp_path / "recover.zip"
        zf = ziplet.ZipFile(archive, "w")
        writer = zf.open("big.bin", "w")
        writer.write(b"abcd")
        with pytest.raises(RuntimeError, match="ZIP64 limit"):
            writer.close()

        assert not zf._write_coordinator.active

        monkeypatch.setattr(write_mod, "ZIP64_LIMIT", original_limit)
        zf.writestr("small.txt", b"ok")
        zf.close()

        with ziplet.ZipFile(archive) as zf2:
            assert zf2.read("small.txt") == b"ok"
