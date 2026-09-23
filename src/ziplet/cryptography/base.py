"""Abstract base classes for ZIP encryption and decryption.

Provides the interfaces that all encryptor and decrypter implementations
must satisfy.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Protocol

from ziplet.exceptions import BadZipFile

if TYPE_CHECKING:
    from ziplet.zipfile.info import ZipInfo


__all__ = [
    "BaseZipDecrypter",
    "BaseZipEncryptor",
]


class _ReadableStream(Protocol):
    """The minimal stream interface :meth:`BaseZipDecrypter.finalize` needs."""

    def read(self, n: int = -1, /) -> bytes: ...


class BaseZipDecrypter(ABC):
    """Abstract base class for ZIP entry decrypters.

    Subclasses must implement :meth:`decrypt` and :meth:`header_length` to
    provide the decryption logic for a specific algorithm. :meth:`finalize`
    has a CRC-32 default (correct for ZipCrypto and WZ-AES V1); WZ-AES V2
    overrides it to also verify the HMAC authentication tag.
    """

    authentication_trailer_length: int = 0
    filename: str = "?"

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        """Decrypt a chunk of ciphertext.

        Args:
            data (bytes): Ciphertext bytes to decrypt.

        Returns:
            bytes: Decrypted plaintext of the same length as *data*.
        """
        raise NotImplementedError(
            "BaseZipDecrypter implementations must implement `decrypt`."
        )

    @classmethod
    @abstractmethod
    def header_length(cls, zinfo: "ZipInfo") -> int:
        """Return the length in bytes of this algorithm's encryption header.

        Args:
            zinfo (ZipInfo): Metadata for the entry being read.

        Returns:
            int: Number of header bytes to read before the ciphertext.
        """
        raise NotImplementedError(
            "BaseZipDecrypter implementations must implement `header_length`."
        )

    def finalize(
        self,
        expected_crc: int | None,
        running_crc: int | None,
        fileobj: _ReadableStream,
    ) -> None:
        """Verify integrity once the entry has been fully read.

        The default checks CRC-32, which is correct for ZipCrypto and
        WZ-AES V1. WZ-AES V2 overrides this to verify the HMAC tag instead.

        Args:
            expected_crc (int | None): The CRC-32 recorded for the entry,
                or ``None`` if unavailable.
            running_crc (int | None): The CRC-32 accumulated while reading,
                or ``None`` before EOF is reached.
            fileobj (_ReadableStream): The underlying stream, positioned
                right after the ciphertext, for reading any trailing
                authentication bytes.

        Raises:
            BadZipFile: If the CRC-32 does not match.
        """
        del fileobj
        if (
            expected_crc is not None
            and running_crc is not None
            and running_crc != expected_crc
        ):
            raise BadZipFile(f"Bad CRC-32 for file {self.filename!r}")


class BaseZipEncryptor(ABC):
    """Abstract base class for ZIP entry encryptors.

    Subclasses must implement :meth:`update_zipinfo`, :meth:`encrypt`,
    :meth:`encryption_header`, and :meth:`flush` to provide the encryption
    logic for a specific algorithm.
    """

    @abstractmethod
    def update_zipinfo(self, zipinfo: "ZipInfo") -> None:
        """Write algorithm-specific fields into a ZipInfo extra-data structure.

        Args:
            zipinfo (ZipInfo): The entry metadata to update in-place.
        """
        raise NotImplementedError(
            "BaseZipEncryptor implementations must implement `update_zipinfo`."
        )

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt a chunk of plaintext.

        Args:
            data (bytes): Plaintext bytes to encrypt.

        Returns:
            bytes: Ciphertext of the same length as *data*.
        """
        raise NotImplementedError(
            "BaseZipEncryptor implementations must implement `encrypt`."
        )

    @abstractmethod
    def encryption_header(self) -> bytes:
        """Build the encryption header to prepend to the ciphertext.

        Returns:
            bytes: Algorithm-specific header bytes (e.g. salt and password
            verification bytes for AES, or the initialisation value for
            ZipCrypto).
        """
        raise NotImplementedError(
            "BaseZipEncryptor implementations must implement `encryption_header`."
        )

    @abstractmethod
    def flush(self) -> bytes:
        """Finalise encryption and return any trailing authentication bytes.

        Called once after all plaintext has been encrypted. Implementations
        that append an authentication tag (e.g. HMAC) return it here;
        others may return an empty bytes object.

        Returns:
            bytes: Trailing bytes to append after the ciphertext, or
            ``b""`` if none.
        """
        raise NotImplementedError(
            "BaseZipEncryptor implementations must implement `flush`."
        )
