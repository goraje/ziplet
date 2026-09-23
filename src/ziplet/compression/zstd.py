from __future__ import annotations

from typing import TYPE_CHECKING

from ziplet.compression.methods import (
    ZIP_ZSTANDARD,
    CompressionEntry,
    CompressorBase,
    DecompressorBase,
)

if TYPE_CHECKING:
    from compression import (  # ty: ignore[unresolved-import]
        zstd,  # type: ignore[import-not-found,unused-ignore]
    )
else:
    try:
        from compression import zstd
    except ImportError:  # Python < 3.14
        try:
            from backports import zstd  # ty: ignore[unresolved-import]
        except ImportError:
            zstd = None

compression_entry: CompressionEntry | None = None

if zstd is not None:

    class _ZstdCompressor(CompressorBase):
        """Wraps zstd.ZstdCompressor to satisfy CompressorBase.

        Attributes:
            _c: The underlying zstd.ZstdCompressor instance.
        """

        def __init__(self, level: int | None) -> None:
            """Initializes the compressor with an optional compression level.

            Args:
                level: The Zstandard compression level. If None, the default
                    compression level is used.
            """
            self._c = zstd.ZstdCompressor(level=level)

        def compress(self, data: bytes) -> bytes:
            """Compresses a chunk of data.

            Args:
                data: The raw bytes to compress.

            Returns:
                Compressed bytes. May be empty if data is buffered internally.
            """
            return self._c.compress(data)

        def flush(self) -> bytes:
            """Flushes any remaining buffered data and finalizes the stream.

            Returns:
                The remaining compressed bytes.
            """
            return self._c.flush()

    class _ZstdDecompressor(DecompressorBase):
        """Wraps zstd.ZstdDecompressor to satisfy DecompressorBase.

        Attributes:
            _d: The underlying zstd.ZstdDecompressor instance.
        """

        def __init__(self) -> None:
            """Initializes the decompressor."""
            self._d = zstd.ZstdDecompressor()

        @property
        def eof(self) -> bool:
            """Whether the end of the compressed stream has been reached.

            Returns:
                True if the decompressor has reached the end of stream,
                False otherwise.
            """
            return self._d.eof

        @property
        def needs_input(self) -> bool:
            return self._d.needs_input

        def decompress(self, data: bytes, max_length: int = -1) -> bytes:
            """Decompresses a chunk of data.

            Args:
                data: The compressed bytes to decompress.

            Returns:
                Decompressed bytes.
            """
            return self._d.decompress(data, max_length)

    compression_entry = CompressionEntry(
        compression_method=ZIP_ZSTANDARD,
        compressor_factory=_ZstdCompressor,
        decompressor_factory=_ZstdDecompressor,
    )
