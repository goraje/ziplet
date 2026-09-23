from __future__ import annotations

import pytest

from ziplet.compression import zstd
from ziplet.compression.methods import (
    ZIP_ZSTANDARD,
    CompressionEntry,
    CompressorBase,
    DecompressorBase,
)

pytestmark = pytest.mark.skipif(
    zstd.compression_entry is None,
    reason="zstandard tests require compression.zstd or backports.zstd",
)

SAMPLE_DATA = b"Hello, Zstandard world! " * 100


def _entry() -> CompressionEntry:
    assert zstd.compression_entry is not None
    return zstd.compression_entry


class TestZstdCompressionEntry:
    def test_entry_is_compression_entry(self) -> None:
        assert isinstance(_entry(), CompressionEntry)

    def test_compression_method_is_zip_zstandard(self) -> None:
        assert _entry().compression_method == ZIP_ZSTANDARD

    def test_compressor_factory_returns_compressor_base(self) -> None:
        compressor = _entry().compressor_factory(None)
        assert isinstance(compressor, CompressorBase)

    def test_decompressor_factory_returns_decompressor_base(self) -> None:
        decompressor = _entry().decompressor_factory()
        assert isinstance(decompressor, DecompressorBase)


class TestZstdCompressor:
    def _make_compressor(self, level: int | None = None) -> CompressorBase:
        compressor = _entry().compressor_factory(level)
        assert compressor is not None
        return compressor

    def test_compress_returns_bytes(self) -> None:
        c = self._make_compressor()
        assert isinstance(c.compress(SAMPLE_DATA), bytes)

    def test_flush_returns_bytes(self) -> None:
        c = self._make_compressor()
        c.compress(SAMPLE_DATA)
        assert isinstance(c.flush(), bytes)

    def test_round_trip_default_level(self) -> None:
        c = self._make_compressor()
        compressed = c.compress(SAMPLE_DATA) + c.flush()
        d = _entry().decompressor_factory()
        assert d is not None
        assert d.decompress(compressed) == SAMPLE_DATA

    def test_round_trip_with_level(self) -> None:
        c = self._make_compressor(level=3)
        compressed = c.compress(SAMPLE_DATA) + c.flush()
        d = _entry().decompressor_factory()
        assert d is not None
        assert d.decompress(compressed) == SAMPLE_DATA

    def test_compress_produces_smaller_output_for_repetitive_data(self) -> None:
        c = self._make_compressor()
        compressed = c.compress(SAMPLE_DATA) + c.flush()
        assert len(compressed) < len(SAMPLE_DATA)


class TestZstdDecompressor:
    def _make_decompressor(self) -> DecompressorBase:
        decompressor = _entry().decompressor_factory()
        assert decompressor is not None
        return decompressor

    def _make_compressed(self, data: bytes = SAMPLE_DATA) -> bytes:
        c = _entry().compressor_factory(None)
        assert c is not None
        return c.compress(data) + c.flush()

    def test_eof_starts_false(self) -> None:
        d = self._make_decompressor()
        assert d.eof is False

    def test_decompress_returns_bytes(self) -> None:
        d = self._make_decompressor()
        compressed = self._make_compressed()
        assert isinstance(d.decompress(compressed), bytes)

    def test_round_trip(self) -> None:
        d = self._make_decompressor()
        compressed = self._make_compressed()
        assert d.decompress(compressed) == SAMPLE_DATA

    def test_eof_after_full_stream(self) -> None:
        d = self._make_decompressor()
        compressed = self._make_compressed()
        d.decompress(compressed)
        assert d.eof is True

    def test_decompress_respects_max_length(self) -> None:
        data = SAMPLE_DATA * 100
        d = self._make_decompressor()
        compressed = self._make_compressed(data)

        output = b""
        chunk = compressed
        while not d.eof:
            part = d.decompress(chunk, 17)
            assert len(part) <= 17
            output += part
            chunk = b""
        assert output == data
