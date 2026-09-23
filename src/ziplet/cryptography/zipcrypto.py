"""Traditional ZipCrypto (PKWARE) encryption and decryption for ZIP archives.

Implements the original ZIP stream cipher described in the PKWARE Application
Note. The algorithm maintains three 32-bit keys updated with each byte
processed, derived from a CRC32-based key schedule.

Note:
    ZipCrypto provides only weak security. Prefer WZ-AES for new archives.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from ziplet.cryptography.base import BaseZipDecrypter, BaseZipEncryptor
from ziplet.exceptions import BadZipFile
from ziplet.zipfile.shared import MASK_USE_DATA_DESCRIPTOR

if TYPE_CHECKING:
    from ziplet.zipfile.info import ZipInfo

__all__ = [
    "ZIP_CRYPTO",
    "ZipCryptoDecrypter",
    "ZipCryptoEncryptor",
]

ZIP_CRYPTO = "ZipCrypto"


def _gen_crc(crc: int) -> int:
    """Compute one entry of the CRC32 lookup table.

    Args:
        crc (int): Seed value (0–255) for the table entry.

    Returns:
        int: The 32-bit CRC table value for *crc*.
    """
    for _ in range(8):
        if crc & 1:
            crc = (crc >> 1) ^ 0xEDB88320
        else:
            crc >>= 1
    return crc


_crctable: list[int] = list(map(_gen_crc, range(256)))


class _ZipCryptoState:
    """Shared ZipCrypto key schedule used by encryption and decryption."""

    def __init__(self, password: bytes) -> None:
        self.key0 = 305419896
        self.key1 = 591751049
        self.key2 = 878082192
        for value in password:
            self.update_keys(value)

    def crc32(self, value: int, crc: int) -> int:
        return (crc >> 8) ^ _crctable[(crc ^ value) & 0xFF]

    def update_keys(self, value: int) -> None:
        self.key0 = self.crc32(value, self.key0)
        self.key1 = (self.key1 + (self.key0 & 0xFF)) & 0xFFFFFFFF
        self.key1 = (self.key1 * 134775813 + 1) & 0xFFFFFFFF
        self.key2 = self.crc32(self.key1 >> 24, self.key2)

    def decrypt(self, data: bytes) -> bytes:
        result = bytearray()
        for value in data:
            key = self.key2 | 2
            value ^= ((key * (key ^ 1)) >> 8) & 0xFF
            self.update_keys(value)
            result.append(value)
        return bytes(result)

    def encrypt(self, data: bytes) -> bytes:
        result = bytearray()
        for value in data:
            key = self.key2 | 2
            stream_byte = ((key * (key ^ 1)) >> 8) & 0xFF
            self.update_keys(value)
            result.append(value ^ stream_byte)
        return bytes(result)


def _state_property(name: str) -> property:
    return property(lambda self: getattr(self._state, name))


class ZipCryptoDecrypter(BaseZipDecrypter):
    """Decrypter for traditionally ZipCrypto-encrypted ZIP entries.

    Initialises the three-key state from the password, then verifies
    the password by checking the 12th byte of the encryption header
    against either the CRC MSB (stored entries) or the file-time MSB
    (entries using a data descriptor).

    Attributes:
        encryption_header_length (int): Always 12 bytes.
    """

    encryption_header_length = 12
    authentication_trailer_length = 0
    key0 = _state_property("key0")
    key1 = _state_property("key1")
    key2 = _state_property("key2")
    crctable = _crctable

    def __init__(self, zinfo: ZipInfo, pwd: bytes, encryption_header: bytes) -> None:
        """Initialise the decrypter for a ZIP entry.

        Args:
            zinfo (ZipInfo): Metadata for the ZIP entry to decrypt.
            pwd (bytes): Decryption password as raw bytes.
            encryption_header (bytes): The 12-byte encryption header read
                from the beginning of the entry data.

        Raises:
            RuntimeError: If *pwd* does not match the check byte in
                *encryption_header*.
        """
        if len(encryption_header) != self.encryption_header_length:
            raise BadZipFile("Truncated ZipCrypto encryption header")
        self.filename = zinfo.filename
        self._state = _ZipCryptoState(pwd)

        # The first 12 bytes in the cypher stream is an encryption header
        # used to strengthen the algorithm. The first 11 bytes are completely
        # random, while the 12th contains the MSB of the CRC, or the MSB of
        # the file time depending on the header type and is used to check
        # the correctness of the password.
        h = self.decrypt(encryption_header)
        if zinfo.use_datadescripter:
            # compare against the file time from extended local headers
            check_byte = (zinfo._raw_time >> 8) & 0xFF
        else:
            # compare against the CRC otherwise
            check_byte = (zinfo.CRC >> 24) & 0xFF
        if h[11] != check_byte:
            raise RuntimeError("Bad password for file %r" % zinfo.filename)

    @classmethod
    def header_length(cls, zinfo: ZipInfo) -> int:
        """Return the encryption header length. Always 12 bytes for ZipCrypto."""
        del zinfo
        return cls.encryption_header_length

    def crc32(self, ch: int, crc: int) -> int:
        """Compute the CRC32 primitive on one byte.

        Args:
            ch (int): The input byte value (0–255).
            crc (int): The current 32-bit CRC accumulator.

        Returns:
            int: Updated 32-bit CRC value.
        """
        return self._state.crc32(ch, crc)

    def update_keys(self, c: int) -> None:
        """Update the three internal keys with a plaintext byte.

        Args:
            c (int): The plaintext byte value (0–255) used to advance
                the key schedule.
        """
        self._state.update_keys(c)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt a chunk of ciphertext.

        Args:
            data (bytes): Ciphertext bytes to decrypt.

        Returns:
            bytes: Decrypted plaintext of the same length as *data*.
        """
        return self._state.decrypt(data)


class ZipCryptoEncryptor(BaseZipEncryptor):
    """Encryptor for ZipCrypto ZIP entries.

    Initialises the three-key state from the password and produces an
    11-byte random header plus a check byte derived from the DOS time
    field, relying on a data descriptor for the CRC.

    Attributes:
        key0 (int): First 32-bit key in the ZipCrypto key schedule.
        key1 (int): Second 32-bit key in the ZipCrypto key schedule.
        key2 (int): Third 32-bit key in the ZipCrypto key schedule.
    """

    def __init__(self, pwd: bytes) -> None:
        """Initialise the encryptor with a password.

        Args:
            pwd (bytes): Encryption password as raw bytes.
        """
        self._state = _ZipCryptoState(pwd)

        self._zinfo: ZipInfo | None = None

    key0 = _state_property("key0")
    key1 = _state_property("key1")
    key2 = _state_property("key2")
    crctable = _crctable

    def crc32(self, ch: int, crc: int) -> int:
        """Compute the CRC32 primitive on one byte.

        Args:
            ch (int): The input byte value (0–255).
            crc (int): The current 32-bit CRC accumulator.

        Returns:
            int: Updated 32-bit CRC value.
        """
        return self._state.crc32(ch, crc)

    def update_keys(self, c: int) -> None:
        """Update the three internal keys with a plaintext byte.

        Args:
            c (int): The plaintext byte value (0–255) used to advance
                the key schedule.
        """
        self._state.update_keys(c)

    def update_zipinfo(self, zipinfo: ZipInfo) -> None:
        """Set the data-descriptor flag and store the ZipInfo reference.

        Forces the data descriptor flag so that the check byte is derived
        from the file time rather than the CRC (which is unknown when the
        encryption header is written).

        Args:
            zipinfo (ZipInfo): The entry metadata to update in-place.
        """
        # Force data descriptor flag so the check byte uses file time
        # (CRC is unknown at the time the encryption header is written)
        zipinfo.flag_bits |= MASK_USE_DATA_DESCRIPTOR
        self._zinfo = zipinfo

    def encryption_header(self) -> bytes:
        """Build the 12-byte ZipCrypto encryption header.

        Generates 11 random bytes followed by the MSB of the DOS time
        field, then encrypts the whole header with the key schedule.

        Returns:
            bytes: The 12-byte encrypted header to prepend to the
            ciphertext.

        Raises:
            AssertionError: If :meth:`update_zipinfo` has not been called
                before this method.
        """
        assert self._zinfo is not None, (
            "update_zipinfo must be called before encryption_header"
        )
        # check byte is the MSB of the DOS time field
        check_byte = (self._zinfo.get_dostime() >> 8) & 0xFF
        header = os.urandom(11) + bytes([check_byte])
        return self.encrypt(header)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt a chunk of plaintext.

        Args:
            data (bytes): Plaintext bytes to encrypt.

        Returns:
            bytes: Ciphertext of the same length as *data*.
        """
        return self._state.encrypt(data)

    def flush(self) -> bytes:
        """Finalise encryption.

        ZipCrypto has no trailing authentication tag.

        Returns:
            bytes: Always ``b""``.
        """
        return b""
