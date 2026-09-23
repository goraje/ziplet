from __future__ import annotations

from ziplet.compression import bz2 as bz2
from ziplet.compression import deflate as deflate
from ziplet.compression import lzma as lzma
from ziplet.compression import stored as stored
from ziplet.compression import zstd as zstd
from ziplet.compression.methods import (
    BZIP2_VERSION,
    LZMA_VERSION,
    ZIP_BZIP2,
    ZIP_DEFLATED,
    ZIP_LZMA,
    ZIP_STORED,
    ZIP_ZSTANDARD,
    ZSTANDARD_VERSION,
    CompressionEntry,
    CompressorBase,
    DecompressorBase,
    NoopCompressor,
    NoopDecompressor,
    StreamingDecompressor,
)

__all__ = [
    "BZIP2_VERSION",
    "LZMA_VERSION",
    "ZSTANDARD_VERSION",
    "ZIP_STORED",
    "ZIP_DEFLATED",
    "ZIP_BZIP2",
    "ZIP_LZMA",
    "ZIP_ZSTANDARD",
    "CompressorBase",
    "DecompressorBase",
    "NoopCompressor",
    "NoopDecompressor",
    "StreamingDecompressor",
    "CompressionEntry",
    "Registry",
    "registry",
    "compressor_names",
]

compressor_names: dict[int, str] = {
    0: "store",
    1: "shrink",
    2: "reduce",
    3: "reduce",
    4: "reduce",
    5: "reduce",
    6: "implode",
    7: "tokenize",
    8: "deflate",
    9: "deflate64",
    10: "implode",
    12: "bzip2",
    14: "lzma",
    18: "terse",
    19: "lz77",
    93: "zstd",
    97: "wavpack",
    98: "ppmd",
}


class Registry:
    _required_modules: dict[int, str] = {
        ZIP_DEFLATED: "zlib",
        ZIP_BZIP2: "bz2",
        ZIP_LZMA: "lzma",
        ZIP_ZSTANDARD: "compression.zstd (or backports.zstd)",
    }

    def __init__(self) -> None:
        self._registry: dict[int, CompressionEntry] = {}
        for mod in (stored, deflate, bz2, lzma, zstd):
            if mod.compression_entry is not None:
                self._registry[mod.compression_entry.compression_method] = (
                    mod.compression_entry
                )

    def register(self, method: int, entry: CompressionEntry) -> None:
        if method != entry.compression_method:
            raise ValueError("Registry key does not match compression method")
        self._registry[method] = entry

    def copy(self) -> Registry:
        """Return an independent registry for one archive instance."""
        cloned = object.__new__(Registry)
        cloned._registry = self._registry.copy()
        return cloned

    def check_compression(self, compression: int) -> None:
        if compression in self._registry:
            return
        if compression in self._required_modules:
            raise RuntimeError(
                "Compression requires the (missing) %s module"
                % self._required_modules[compression]
            )
        raise NotImplementedError("That compression method is not supported")

    def get_compressor(
        self, compress_type: int, compresslevel: int | None = None
    ) -> CompressorBase:
        self.check_compression(compress_type)
        entry = self._registry.get(compress_type)
        assert entry is not None
        compressor = entry.compressor_factory(compresslevel)
        if compressor is None:
            raise RuntimeError("Compression entry did not provide a compressor")
        return compressor

    def get_decompressor(self, compress_type: int) -> DecompressorBase:
        self.check_compression(compress_type)
        entry = self._registry.get(compress_type)
        assert entry is not None
        decompressor = entry.decompressor_factory()
        if decompressor is None:
            raise RuntimeError("Compression entry did not provide a decompressor")
        return decompressor


registry = Registry()
