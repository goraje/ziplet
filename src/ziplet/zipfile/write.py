"""Writable file-like object for streaming data into a ZIP archive entry."""

from __future__ import annotations

import io
from enum import Enum
from typing import IO, TYPE_CHECKING, cast

from ziplet.compression import Registry, registry
from ziplet.compression.methods import CompressorBase

if TYPE_CHECKING:
    from _typeshed import ReadableBuffer

    from ziplet.zipfile.file import ZipFile

from ziplet.cryptography.base import BaseZipEncryptor
from ziplet.zipfile.info import ZipInfo
from ziplet.zipfile.shared import ZIP64_LIMIT, crc32
from ziplet.zipfile.write_coordinator import WriterReservation

__all__ = ["ZipWriteFile"]


class WriteState(str, Enum):
    ACTIVE = "active"
    FINALIZING = "finalizing"
    COMMITTED = "committed"
    FAILED = "failed"
    CLOSED = "closed"


class ZipWriteFile(io.BufferedIOBase):
    """Writable, file-like object returned by :meth:`ZipFile.open` in write mode.

    Streams data through an optional compressor and encryptor before writing
    it to the underlying ZIP archive.  The local file header is emitted
    during construction; CRC-32, compressed size, and uncompressed size are
    finalised when :meth:`close` is called.

    Do not instantiate this class directly — use :meth:`ZipFile.open` or
    :meth:`ZipFile.writestr`.
    """

    def __init__(
        self,
        zf: ZipFile,
        zinfo: ZipInfo,
        zip64: bool,
        encryptor: BaseZipEncryptor | None = None,
        compression_registry: Registry = registry,
        reservation: WriterReservation | None = None,
    ) -> None:
        """Initialise the write-file, emit the local header, and (if requested)
        the encryption header.

        Args:
            zf: The parent :class:`ZipFile` instance.
            zinfo: Metadata for the entry being written.
            zip64: Whether to use ZIP64 extensions for this entry.
            encryptor: Optional encryptor.  When provided,
                :meth:`BaseZipEncryptor.update_zipinfo` is called to patch
                *zinfo* before the local header is written, and the
                encryption header is written immediately afterwards.
        """
        self._zinfo: ZipInfo = zinfo
        self._zip64: bool = zip64
        self._zipfile: ZipFile = zf
        self._compressor: CompressorBase = compression_registry.get_compressor(
            zinfo.compress_type, zinfo.compress_level
        )
        self._encryptor: BaseZipEncryptor | None = encryptor
        self._file_size: int = 0
        self._compress_size: int = 0
        self._crc: int = 0
        self._state = WriteState.ACTIVE
        self._error: BaseException | None = None
        self._reservation = reservation

        if self._encryptor is not None:
            self._encryptor.update_zipinfo(self._zinfo)

        self._write_local_header()

        if self._encryptor:
            self._write_encryption_header()

    @property
    def _fileobj(self) -> IO[bytes]:
        """The underlying raw file object of the parent :class:`ZipFile`."""
        assert self._zipfile.fp is not None
        return self._zipfile.fp

    @property
    def name(self) -> str:
        """The filename of the ZIP entry being written."""
        return self._zinfo.filename

    @property
    def mode(self) -> str:
        """Always ``'wb'`` for a write-mode entry."""
        return "wb"

    def writable(self) -> bool:
        """Return ``True``; this stream is always writable."""
        return True

    def _write_local_header(self) -> None:
        """Serialise and write the local file header to the archive.

        Also marks the parent :class:`ZipFile` as modified. Concurrent
        opens are rejected via the parent's ``_write_coordinator``, whose
        reservation is already active by the time this runs.
        """
        header = self._zinfo.FileHeader(self._zip64)
        # From this point onwards, we have modified the archive.
        self._zipfile._mark_modified()
        _write_all(self._fileobj, header)

    def _write_encryption_header(self) -> None:
        """Request the encryption header from the encryptor and write it.

        The encryption header bytes are counted toward :attr:`_compress_size`
        because they appear before the compressed ciphertext in the stream.
        """
        assert self._encryptor is not None
        buf = self._encryptor.encryption_header()
        self._compress_size += len(buf)
        _write_all(self._fileobj, buf)

    def write(self, data: ReadableBuffer, /) -> int:
        """Write *data* to the ZIP entry, compressing and encrypting as needed.

        Accepts any object that supports the buffer protocol (``bytes``,
        ``bytearray``, ``memoryview``, ``array.array``, or any object
        implementing ``__buffer__``).

        Args:
            data: The plaintext bytes to write.

        Returns:
            The number of uncompressed bytes consumed from *data*.

        Raises:
            ValueError: If the file has already been closed.
        """
        if self.closed:
            raise ValueError("I/O operation on closed file.")

        # Accept any data that supports the buffer protocol
        if isinstance(data, (bytes, bytearray)):
            nbytes = len(data)
        elif isinstance(data, memoryview):
            nbytes = data.nbytes
        else:
            data = memoryview(data)
            nbytes = data.nbytes
        self._file_size += nbytes

        self._crc = crc32(data, self._crc)
        raw = data if isinstance(data, bytes) else bytes(data)
        raw = self._compressor.compress(raw)
        if self._encryptor:
            raw = self._encryptor.encrypt(raw)
        self._compress_size += len(raw)
        self._fileobj.write(raw)
        return nbytes

    def close(self) -> None:
        """Flush, finalise, and close the entry.

        Flushes any remaining bytes from the compressor and encryptor,
        updates :attr:`ZipInfo.compress_size`, :attr:`ZipInfo.CRC`, and
        :attr:`ZipInfo.file_size`, then writes either a data descriptor or
        an updated local file header back into the archive.  Also registers
        the entry in the parent :class:`ZipFile`'s internal caches.

        Raises:
            RuntimeError: If a non-ZIP64 entry exceeds the 4 GiB ZIP64 limit
                for either the uncompressed or compressed size.
        """
        coordinator = getattr(self._zipfile, "_write_coordinator", None)
        condition = coordinator.condition if coordinator is not None else None
        if condition is not None:
            with condition:
                if self._state in (WriteState.COMMITTED, WriteState.CLOSED):
                    return
                if self._state == WriteState.FAILED:
                    assert self._error is not None
                    raise self._error
                if self._state == WriteState.FINALIZING:
                    condition.wait_for(
                        lambda: self._state in (WriteState.COMMITTED, WriteState.FAILED)
                    )
                    state = cast(WriteState, self._state)
                    if state == WriteState.FAILED:
                        assert self._error is not None
                        raise self._error
                    return
        self._state = WriteState.FINALIZING
        if self._reservation is not None:
            self._zipfile._write_coordinator.begin_finalization(self._reservation)
        elif self.closed:
            return
        try:
            self._write_final_payload()
            self._update_metadata()
            self._validate_sizes()
            self._write_entry_trailer()
            self._register_entry()
            self._state = WriteState.COMMITTED
            if self._reservation is not None:
                self._zipfile._write_coordinator.commit(self._reservation)
        except BaseException as exc:
            self._error = exc
            self._state = WriteState.FAILED
            if self._reservation is not None:
                self._zipfile._write_coordinator.fail(self._reservation)
            raise
        finally:
            super().close()

    def _write_final_payload(self) -> None:
        """Flush compression/encryption and write the final payload bytes."""
        data = self._compressor.flush()
        if self._encryptor:
            data = self._encryptor.encrypt(data) + self._encryptor.flush()
        self._compress_size += len(data)
        _write_all(self._fileobj, data)

    def _update_metadata(self) -> None:
        self._zinfo.compress_size = self._compress_size
        self._zinfo.CRC = self._crc
        self._zinfo.file_size = self._file_size

    def _validate_sizes(self) -> None:
        if not self._zip64 and self._file_size > ZIP64_LIMIT:
            raise RuntimeError("File size unexpectedly exceeded ZIP64 limit")
        if not self._zip64 and self._compress_size > ZIP64_LIMIT:
            raise RuntimeError("Compressed size unexpectedly exceeded ZIP64 limit")

    def _write_entry_trailer(self) -> None:
        if self._zinfo.use_data_descriptor:
            _write_all(self._fileobj, self._zinfo.data_descriptor(self._zip64))
            self._zipfile.start_dir = self._fileobj.tell()
            return
        self._zipfile.start_dir = self._fileobj.tell()
        self._fileobj.seek(self._zinfo.header_offset)
        _write_all(self._fileobj, self._zinfo.FileHeader(self._zip64))
        self._fileobj.seek(self._zipfile.start_dir)

    def _register_entry(self) -> None:
        self._zipfile._add_entry(self._zinfo)


def _write_all(fileobj: IO[bytes], data: bytes) -> None:
    """Write all bytes or fail instead of silently truncating a ZIP record."""
    view = memoryview(data)
    while view:
        written = fileobj.write(view)
        if written is None or written <= 0:
            raise io.BlockingIOError(0, "short write", len(view))
        view = view[written:]
