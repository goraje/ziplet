from __future__ import annotations

import io
import os
from collections.abc import Callable
from typing import Any

from ziplet.compression import (
    ZIP_DEFLATED,
    ZIP_LZMA,
    ZIP_STORED,
    Registry,
    compressor_names,
    registry,
)
from ziplet.compression.methods import (
    DecompressorBase,
    StreamingDecompressor,
)
from ziplet.cryptography.aes import AesZipDecrypter
from ziplet.cryptography.zipcrypto import ZipCryptoDecrypter
from ziplet.exceptions import BadZipFile
from ziplet.zipfile.info import ZipInfo
from ziplet.zipfile.io_wrappers import ClosableZipStream
from ziplet.zipfile.records import raise_for_unsupported_flags
from ziplet.zipfile.shared import ReadWriteMode, crc32

__all__ = [
    "ZipExtFile",
]


class ZipExtFile(io.BufferedIOBase):
    """Readable file-like object for a single ZIP entry.

    Wraps a :class:`~ziplet.zipfile.io_wrappers.ClosableZipStream` and
    transparently decrypts (ZipCrypto or WZ-AES) and decompresses data on
    demand.  Supports :meth:`read`, :meth:`readline`, :meth:`peek`,
    :meth:`read1`, and — for uncompressed or seekable streams — :meth:`seek`
    and :meth:`tell`.

    Attributes:
        MAX_N (int): Maximum byte count passed to a single decompressor call.
        MIN_READ_SIZE (int): Minimum read from the underlying stream (4 KiB).
        MAX_SEEK_READ (int): Maximum bytes consumed per seek-forward step (16 MiB).
        encryption_header (bytes): Raw encryption header read from the stream.
            Set by :meth:`_setup_decrypter`; only present on encrypted entries.
        mode (str): Opening mode, always ``'r'``.
        name (str): Filename of the ZIP entry.
        newlines (None): Unused compatibility attribute for the ``io`` layer.
    """

    # Max size supported by decompressor.
    MAX_N: int = (1 << 31) - 1

    # Read from compressed files in 4k blocks.
    MIN_READ_SIZE: int = 4096

    # Keep a forged compressed-size field from turning one logical read into
    # an oversized allocation.  Large entries are still streamed over calls.
    MAX_READ_SIZE: int = 1 << 20

    # Chunk size to read during seek
    MAX_SEEK_READ: int = 1 << 24

    # Set by _setup_decrypter before _decrypter_kwargs
    encryption_header: bytes

    def __init__(
        self,
        fileobj: ClosableZipStream,
        mode: ReadWriteMode,
        zipinfo: ZipInfo,
        close_fileobj: bool = False,
        pwd: bytes | None = None,
        compression_registry: Registry = registry,
    ) -> None:
        """Initialise a :class:`ZipExtFile` for reading a single ZIP entry.

        Reads and validates any encryption header, then initialises all
        reading state ready for the first :meth:`read` call.

        Args:
            fileobj (ClosableZipStream): Stream positioned at the start of this
                entry's data (immediately after the local file header).
            mode (str): Opening mode.  Only ``'r'`` is supported by this class.
            zipinfo (ZipInfo): Metadata for the entry being read.
            close_fileobj (bool): If ``True``, *fileobj* is closed when this
                object is closed.  Defaults to ``False``.
            pwd (bytes | None): Decryption password.  Required when the entry
                is encrypted; ignored otherwise.  Defaults to ``None``.

        Raises:
            RuntimeError: If the entry is encrypted but *pwd* is ``None`` or
                empty.
            NotImplementedError: If the entry uses compressed-patch data
                (flag bit 5) or strong encryption (flag bit 6).
        """
        self._fileobj = fileobj
        self._zinfo: ZipInfo = zipinfo
        self._close_fileobj = close_fileobj
        self._pwd = pwd
        self._compression_registry = compression_registry

        raise_for_unsupported_flags(zipinfo)

        self._compress_type = zipinfo.compress_type
        self._orig_compress_left = zipinfo.compress_size
        self.newlines: None = None

        self.mode = mode
        self.name = zipinfo.filename

        self._expected_crc: int | None
        self._orig_start_crc: int | None
        if hasattr(zipinfo, "CRC"):
            self._expected_crc = zipinfo.CRC
            self._orig_start_crc = crc32(b"")
        else:
            self._expected_crc = None
            self._orig_start_crc = None

        self._seekable: bool = False
        try:
            if fileobj.seekable():
                self._seekable = True
        except AttributeError:
            pass

        self._decrypter_cls: Callable[..., ZipCryptoDecrypter | AesZipDecrypter] | None
        if self._zinfo.is_encrypted:
            self._decrypter_cls = self._setup_decrypter()
        else:
            self._decrypter_cls = None

        # _compress_start is the file position after any encryption header.
        # Used for seek-backwards resets.
        self._compress_start: int = fileobj.tell()
        self._init_read_state()

    def _setup_decrypter(self) -> type[ZipCryptoDecrypter] | type[AesZipDecrypter]:
        """Read the encryption header and return the appropriate decrypter class.

        Reads the encryption header bytes from the stream, stores them in
        :attr:`encryption_header`, and subtracts their length (plus the
        HMAC trailer for WZ-AES) from ``_orig_compress_left``.

        Returns:
            type[ZipCryptoDecrypter] | type[AesZipDecrypter]: The decrypter
            class to use for this entry.

        Raises:
            RuntimeError: If the entry is encrypted but no password was
                supplied.
        """
        decrypter_cls = self._decrypter_class_for_entry()
        if decrypter_cls is AesZipDecrypter:
            if not self._pwd:
                raise RuntimeError(
                    f"File {self.name!r} is encrypted with WZ_AES encryption and "
                    "requires a password."
                )
            encryption_header_length = decrypter_cls.header_length(self._zinfo)
            self.encryption_header = self._fileobj.read(encryption_header_length)
            if len(self.encryption_header) != encryption_header_length:
                raise BadZipFile("Truncated AES encryption header")
            self._orig_compress_left -= encryption_header_length
            self._orig_compress_left -= decrypter_cls.authentication_trailer_length
            if self._orig_compress_left < 0:
                raise BadZipFile("AES entry is shorter than its encryption overhead")
            return decrypter_cls
        else:
            if not self._pwd:
                raise RuntimeError(
                    f"File {self.name!r} is encrypted, password required for extraction"
                )
            self.encryption_header = self._fileobj.read(
                ZipCryptoDecrypter.encryption_header_length
            )
            if (
                len(self.encryption_header)
                != ZipCryptoDecrypter.encryption_header_length
            ):
                raise BadZipFile("Truncated ZipCrypto encryption header")
            self._orig_compress_left -= decrypter_cls.header_length(self._zinfo)
            if self._orig_compress_left < 0:
                raise BadZipFile(
                    "ZipCrypto entry is shorter than its encryption header"
                )
            return decrypter_cls

    def _decrypter_class_for_entry(
        self,
    ) -> type[ZipCryptoDecrypter] | type[AesZipDecrypter]:
        if self._zinfo.aes_extra.wz_aes_version is not None:
            return AesZipDecrypter
        return ZipCryptoDecrypter

    def _decrypter_kwargs(self) -> dict[str, Any]:
        """Return keyword arguments for the decrypter constructor.

        Returns:
            dict[str, Any]: Mapping containing ``pwd`` and
            ``encryption_header`` to be passed to the decrypter class.
        """
        return {
            "pwd": self._pwd,
            "encryption_header": self.encryption_header,
        }

    def _get_decrypter(self) -> ZipCryptoDecrypter | AesZipDecrypter | None:
        """Instantiate and return the decrypter for this entry.

        Returns:
            ZipCryptoDecrypter | AesZipDecrypter | None: A ready-to-use
            decrypter instance, or ``None`` if the entry is not encrypted.

        Raises:
            RuntimeError: If the password check inside
                :class:`~ziplet.cryptography.zipcrypto.ZipCryptoDecrypter`
                fails (wrong password).
        """
        if self._decrypter_cls is not None:
            return self._decrypter_cls(self._zinfo, **self._decrypter_kwargs())
        return None

    def _init_read_state(self) -> None:
        """(Re-)initialise all reading state.

        Called at construction time and whenever a backwards seek resets the
        stream to :attr:`_compress_start`.  Resets the CRC accumulator, byte
        counters, read buffer, EOF flag, and creates fresh decrypter and
        decompressor instances.
        """
        self._running_crc: int | None = self._orig_start_crc
        self._compress_left: int = self._orig_compress_left
        self._left: int = self._zinfo.file_size
        self._readbuffer: bytes = b""
        self._offset: int = 0
        self._eof: bool = False
        self._decrypter: ZipCryptoDecrypter | AesZipDecrypter | None = (
            self._get_decrypter()
        )
        self._decompressor: DecompressorBase = (
            self._compression_registry.get_decompressor(self._compress_type)
        )

    def _check_integrity(self) -> None:
        """Verify the integrity of a fully-read entry.

        Called automatically by :meth:`_read1` once EOF is reached.
        Delegates to the active decrypter's
        :meth:`~ziplet.cryptography.base.BaseZipDecrypter.finalize`, which
        validates the HMAC tag for WZ-AES V2 or the CRC-32 otherwise.
        Unencrypted entries check the CRC-32 directly.

        For LZMA entries inside a WZ-AES stream any trailing end-of-stream
        marker or padding bytes are consumed so that the HMAC covers the
        complete compressed data.

        Raises:
            BadZipFile: If the HMAC tag does not match, or if the CRC-32 of
                the decompressed data does not equal the expected value.
        """
        if (
            self._zinfo.aes_extra.wz_aes_version is not None
            and self._zinfo.compress_type == ZIP_LZMA
        ):
            # LZMA may have an end-of-stream marker or padding.  Read it
            # all so the HMAC covers the full compressed byte stream.
            while self._compress_left > 0:
                data = self._read2(self.MIN_READ_SIZE)
                assert self._decompressor is not None
                data = self._decompressor.decompress(data)
                if data:
                    raise BadZipFile(
                        f"More data found than indicated by uncompressed size "
                        f"for '{self.name}'"
                    )
        if self._decrypter is not None:
            self._decrypter.finalize(
                self._expected_crc,
                self._running_crc if self._eof else None,
                self._fileobj,
            )
        elif (
            self._eof
            and self._expected_crc is not None
            and self._running_crc != self._expected_crc
        ):
            raise BadZipFile(f"Bad CRC-32 for file {self.name!r}")

    def __repr__(self) -> str:
        """Return a developer-friendly string representation.

        Returns:
            str: A string of the form
            ``<package.ZipExtFile name='...' compress_type=deflate>``
            while open, or ``<package.ZipExtFile [closed]>`` after closing.
        """
        result = [f"<{self.__class__.__module__}.{self.__class__.__qualname__}"]
        if not self.closed:
            result.append(f" name={self.name!r}")
            if self._compress_type != ZIP_STORED:
                compressor_type = compressor_names.get(
                    self._compress_type,
                    self._compress_type,
                )
                result.append(f" compress_type={compressor_type}")
        else:
            result.append(" [closed]")
        result.append(">")
        return "".join(result)

    def readline(self, limit: int | None = -1) -> bytes:
        """Read and return one line from the stream.

        Args:
            limit (int | None): Maximum number of bytes to read.  A negative
                value or ``None`` means no limit.

        Returns:
            bytes: Bytes up to and including the next ``b'\\n'``, or until
            EOF if no newline is found.  Returns ``b''`` at EOF.
        """
        if limit is None:
            limit = -1
        if limit < 0:
            # Shortcut common case - newline found in buffer.
            i = self._readbuffer.find(b"\n", self._offset) + 1
            if i > 0:
                line = self._readbuffer[self._offset : i]
                self._offset = i
                return line

        return io.BufferedIOBase.readline(self, limit)

    def peek(self, n: int = 1) -> bytes:
        """Return buffered bytes without advancing the position.

        If fewer than *n* bytes are buffered a read is attempted to fill the
        buffer, but the stream position is not advanced.

        Args:
            n (int): Hint for the minimum number of bytes to buffer.
                Defaults to ``1``.

        Returns:
            bytes: Up to 512 bytes from the current position.  May return
            fewer bytes than *n* if near EOF.
        """
        if n > len(self._readbuffer) - self._offset:
            chunk = self.read(n)
            if len(chunk) > self._offset:
                self._readbuffer = chunk + self._readbuffer[self._offset :]
                self._offset = 0
            else:
                self._offset -= len(chunk)

        # Return up to 512 bytes to reduce allocation overhead for tight loops.
        return self._readbuffer[self._offset : self._offset + 512]

    def readable(self) -> bool:
        """Return ``True`` since this stream is always readable.

        Returns:
            bool: Always ``True``.

        Raises:
            ValueError: If the file has already been closed.
        """
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return True

    def read(self, n: int | None = -1) -> bytes:
        """Read and return up to *n* bytes.

        Args:
            n (int | None): Number of bytes to read.  If omitted, ``None``,
                or negative, reads and returns all remaining data until EOF.

        Returns:
            bytes: The requested bytes, or fewer if EOF is reached first.

        Raises:
            ValueError: If the file has already been closed.
        """
        if self.closed:
            raise ValueError("read from closed file.")
        if n is None or n < 0:
            buf = self._readbuffer[self._offset :]
            self._readbuffer = b""
            self._offset = 0
            while not self._eof:
                buf += self._read1(self.MAX_N)
            return buf

        end = n + self._offset
        if end < len(self._readbuffer):
            buf = self._readbuffer[self._offset : end]
            self._offset = end
            return buf

        n = end - len(self._readbuffer)
        buf = self._readbuffer[self._offset :]
        self._readbuffer = b""
        self._offset = 0
        while n > 0 and not self._eof:
            data = self._read1(n)
            if n < len(data):
                self._readbuffer = data
                self._offset = n
                buf += data[:n]
                break
            buf += data
            n -= len(data)
        return buf

    def _update_crc(self, newdata: bytes) -> None:
        """Accumulate *newdata* into the running CRC-32 checksum.

        Does nothing if no expected CRC was recorded (i.e. the entry had no
        ``CRC`` field, or CRC checking was disabled by a seek operation).

        Args:
            newdata (bytes): Freshly decompressed bytes to include in the
                checksum.
        """
        if self._expected_crc is None:
            # No need to compute the CRC if we don't have a reference value
            return
        assert self._running_crc is not None
        self._running_crc = crc32(newdata, self._running_crc)

    def read1(self, n: int | None = -1) -> bytes:
        """Read up to *n* bytes with at most one read() system call.

        Args:
            n (int | None): Maximum number of bytes to return.  A negative
                value or ``None`` reads all remaining data, draining any
                buffered bytes first before issuing a single further read.

        Returns:
            bytes: Decompressed bytes, possibly fewer than *n*.
        """
        if n is None or n < 0:
            buf = self._readbuffer[self._offset :]
            self._readbuffer = b""
            self._offset = 0
            while not self._eof:
                data = self._read1(self.MAX_N)
                if data:
                    buf += data
                    break
            return buf

        end = n + self._offset
        if end < len(self._readbuffer):
            buf = self._readbuffer[self._offset : end]
            self._offset = end
            return buf

        n = end - len(self._readbuffer)
        buf = self._readbuffer[self._offset :]
        self._readbuffer = b""
        self._offset = 0
        if n > 0:
            while not self._eof:
                data = self._read1(n)
                if n < len(data):
                    self._readbuffer = data
                    self._offset = n
                    buf += data[:n]
                    break
                if data:
                    buf += data
                    break
        return buf

    def _read1(self, n: int) -> bytes:
        """Read, decrypt, and decompress up to *n* bytes.

        Reads raw compressed bytes via :meth:`_read2`, optionally decrypts
        them, decompresses them according to :attr:`_compress_type`, updates
        the running CRC, and calls :meth:`_check_integrity` once EOF is
        detected.

        Args:
            n (int): Target number of decompressed bytes to return.

        Returns:
            bytes: Decompressed plaintext bytes.  Returns ``b''`` if already
            at EOF or *n* is non-positive.
        """
        if self._eof or n <= 0:
            return b""

        # Read from file. Bounded decompressors may have output buffered
        # internally, so drain that output before consuming more input.
        if self._compress_type == ZIP_DEFLATED:
            assert self._decompressor is not None
            assert isinstance(self._decompressor, StreamingDecompressor)
            # Handle unconsumed data.
            data = self._decompressor.unconsumed_tail
            if n > len(data):
                data += self._read2(n - len(data))
        elif self._compress_type == ZIP_STORED:
            data = self._read2(n)
        else:
            assert self._decompressor is not None
            if getattr(self._decompressor, "needs_input", True):
                data = self._read2(n)
            else:
                data = b""

        if self._compress_type == ZIP_STORED:
            self._eof = self._compress_left <= 0
        elif self._compress_type == ZIP_DEFLATED:
            assert self._decompressor is not None
            assert isinstance(self._decompressor, StreamingDecompressor)
            data = self._decompressor.decompress(data, n)
            self._eof = self._decompressor.eof or (
                self._compress_left <= 0 and not self._decompressor.unconsumed_tail
            )
            if self._eof:
                data += self._decompressor.flush()
        else:
            assert self._decompressor is not None
            data = self._decompressor.decompress(data, n)
            # A bounded decompressor may still have output buffered after the
            # compressed input has been consumed.  Only the decompressor can
            # establish EOF; treating ``_compress_left == 0`` as EOF would
            # truncate split-output reads and produce false CRC failures.
            self._eof = self._decompressor.eof

        if len(data) > self._left:
            raise BadZipFile(
                f"More data found than indicated by uncompressed size for '{self.name}'"
            )
        self._left -= len(data)
        if self._compress_type == ZIP_STORED and self._left <= 0:
            self._eof = True
        elif (
            self._compress_type != ZIP_STORED
            and self._compress_left <= 0
            and not self._eof
            and not data
        ):
            raise BadZipFile(f"Truncated compressed stream for '{self.name}'")
        self._update_crc(data)
        if self._eof:
            self._check_integrity()
        return data

    def _read2(self, n: int) -> bytes:
        """Read up to *n* raw (compressed and encrypted) bytes from the stream.

        Enforces :attr:`MIN_READ_SIZE` as a lower bound and
        ``_compress_left`` as an upper bound, then decrypts the data if a
        decrypter is active.

        Args:
            n (int): Maximum number of compressed bytes to read.

        Returns:
            bytes: Raw decrypted (but still compressed) bytes.  Returns
            ``b''`` when no compressed data remains.

        Raises:
            EOFError: If the underlying stream returns empty bytes before
                ``_compress_left`` reaches zero.
        """
        if self._compress_left <= 0:
            return b""

        n = min(max(n, self.MIN_READ_SIZE), self.MAX_READ_SIZE)
        n = min(n, self._compress_left)

        data = self._fileobj.read(n)
        self._compress_left -= len(data)
        if not data:
            raise EOFError

        if self._decrypter is not None:
            data = self._decrypter.decrypt(data)
        return data

    def close(self) -> None:
        """Close this file object.

        Also closes the underlying
        :class:`~ziplet.zipfile.io_wrappers.ClosableZipStream` if
        ``close_fileobj`` was ``True`` at construction time.
        """
        try:
            if self._close_fileobj:
                self._fileobj.close()
        finally:
            super().close()

    def seekable(self) -> bool:
        """Return whether this stream supports random access.

        Returns:
            bool: ``True`` if the underlying stream is seekable.

        Raises:
            ValueError: If the file has already been closed.
        """
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return self._seekable

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Set the stream position to *offset*.

        Seeking forward is always supported (by consuming and discarding
        data).  Seeking backward resets and replays the stream from
        :attr:`_compress_start`.  Uncompressed, unencrypted streams also
        support direct forward seeks via the underlying file object without
        decompressing data.

        Args:
            offset (int): Target position expressed as decompressed byte
                offset.
            whence (int): How *offset* is interpreted: ``os.SEEK_SET`` (0),
                ``os.SEEK_CUR`` (1), or ``os.SEEK_END`` (2).  Defaults to
                ``os.SEEK_SET``.

        Returns:
            int: New stream position as a byte offset from the start of the
            decompressed entry data.

        Raises:
            ValueError: If the file has already been closed, or if *whence*
                is not one of the three recognised values.
            io.UnsupportedOperation: If the underlying stream is not seekable.
        """
        if self.closed:
            raise ValueError("seek on closed file.")
        if not self._seekable:
            raise io.UnsupportedOperation("underlying stream is not seekable")
        curr_pos = self.tell()
        if whence == os.SEEK_SET:
            new_pos = offset
        elif whence == os.SEEK_CUR:
            new_pos = curr_pos + offset
        elif whence == os.SEEK_END:
            new_pos = self._zinfo.file_size + offset
        else:
            raise ValueError(
                "whence must be os.SEEK_SET (0), os.SEEK_CUR (1), or os.SEEK_END (2)"
            )

        if new_pos > self._zinfo.file_size:
            new_pos = self._zinfo.file_size

        if new_pos < 0:
            new_pos = 0

        read_offset = new_pos - curr_pos
        buff_offset = read_offset + self._offset

        if buff_offset >= 0 and buff_offset < len(self._readbuffer):
            # Just move the _offset index if the new position is in the _readbuffer
            self._offset = buff_offset
            read_offset = 0
        # Fast seek for uncompressed unencrypted files
        elif (
            self._compress_type == ZIP_STORED
            and self._decrypter is None
            and read_offset != 0
        ):
            # Disable CRC checking after first seeking - it would be invalid
            self._expected_crc = None
            # Seek actual file taking already buffered data into account
            read_offset -= len(self._readbuffer) - self._offset
            self._fileobj.seek(read_offset, os.SEEK_CUR)
            self._left -= read_offset
            self._compress_left -= read_offset
            self._eof = self._left <= 0
            read_offset = 0
            # Flush read buffer
            self._readbuffer = b""
            self._offset = 0
        elif read_offset < 0:
            # Position is before the current position. Reset state.
            self._fileobj.seek(self._compress_start)
            self._init_read_state()
            read_offset = new_pos

        while read_offset > 0:
            read_len = min(self.MAX_SEEK_READ, read_offset)
            self.read(read_len)
            read_offset -= read_len

        return self.tell()

    def tell(self) -> int:
        """Return the current stream position.

        The position is computed as the number of decompressed bytes
        delivered to the caller, accounting for data still held in the
        internal read buffer.

        Returns:
            int: Byte offset from the start of the decompressed entry data.

        Raises:
            ValueError: If the file has already been closed.
            io.UnsupportedOperation: If the underlying stream is not seekable.
        """
        if self.closed:
            raise ValueError("tell on closed file.")
        if not self._seekable:
            raise io.UnsupportedOperation("underlying stream is not seekable")
        filepos = (
            self._zinfo.file_size - self._left - len(self._readbuffer) + self._offset
        )
        return filepos
