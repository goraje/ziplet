"""WZ-AES (AES-CTR + HMAC-SHA1) encryption and decryption for ZIP archives.

Implements the WinZip AES encryption specification using PBKDF2 key derivation,
AES in CTR mode with a little-endian counter, and HMAC-SHA1 authentication.
"""

from __future__ import annotations

import hmac as stdlib_hmac
import os
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ziplet.cryptography.base import BaseZipDecrypter, BaseZipEncryptor, _ReadableStream
from ziplet.exceptions import BadZipFile

if TYPE_CHECKING:
    from ziplet.zipfile.info import ZipInfo

__all__ = [
    "WZ_AES",
    "WZ_AES_V1",
    "WZ_AES_V2",
    "EXTRA_WZ_AES",
    "AesZipDecrypter",
    "AesZipEncryptor",
]

WZ_AES = "WZ_AES"
WZ_AES_COMPRESS_TYPE = 99
WZ_AES_V1 = 0x0001
WZ_AES_V2 = 0x0002

EXTRA_WZ_AES = 0x9901

_WZ_AES_VENDOR_ID = b"AE"

_WZ_SALT_LENGTHS: dict[int, int] = {
    1: 8,  # 128-bit key
    2: 12,  # 192-bit key
    3: 16,  # 256-bit key
}
_WZ_KEY_LENGTHS: dict[int, int] = {
    1: 16,  # 128-bit key
    2: 24,  # 192-bit key
    3: 32,  # 256-bit key
}

_PWD_VERIFY_LENGTH = 2
_NBITS_TO_STRENGTH: dict[int, int] = {128: 1, 192: 2, 256: 3}


class _AesCtrWithLittleEndian:
    """AES-CTR cipher with a little-endian counter.

    Implements AES-CTR with little-endian counter increments to match
    pycryptodome's behavior. The cryptography library's CTR mode uses
    big-endian, so little-endian is implemented manually.

    Maintains a keystream buffer to handle partial blocks correctly across
    multiple encrypt/decrypt calls.

    Attributes:
        counter (int): Current CTR counter value (starts at 1).
        keystream_buffer (bytes): Remaining unused bytes from the last keystream block.
    """

    def __init__(self, key: bytes) -> None:
        """Initialise the cipher with an AES key.

        Args:
            key (bytes): AES encryption key. Must be 16, 24, or 32 bytes
                (128, 192, or 256 bits).
        """
        self.counter = 1  # Start at 1, matching pycryptodome's default
        self.keystream_buffer = b""
        self._encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()

    def _get_keystream_block(self) -> bytes:
        """Generate the next 16-byte keystream block.

        Encrypts the current counter value (little-endian) with AES-ECB
        and increments the counter.

        Returns:
            bytes: 16-byte keystream block.
        """
        counter_bytes = self.counter.to_bytes(16, byteorder="little")
        self.counter += 1
        return self._encryptor.update(counter_bytes)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using AES-CTR with a little-endian counter.

        Args:
            data (bytes): Plaintext bytes to encrypt.

        Returns:
            bytes: Ciphertext of the same length as *data*.
        """
        ciphertext = bytearray()
        data_idx = 0
        n = len(data)

        if self.keystream_buffer:
            use = min(len(self.keystream_buffer), n)
            ciphertext.extend(
                a ^ b
                for a, b in zip(data[:use], self.keystream_buffer[:use], strict=False)
            )
            self.keystream_buffer = self.keystream_buffer[use:]
            data_idx = use

        while data_idx < n:
            keystream = self._get_keystream_block()
            chunk = data[data_idx : data_idx + 16]
            chunk_len = len(chunk)
            ciphertext.extend(a ^ b for a, b in zip(chunk, keystream, strict=False))
            if chunk_len < 16:
                self.keystream_buffer = keystream[chunk_len:]
            data_idx += chunk_len

        return bytes(ciphertext)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data using AES-CTR (identical to encryption in CTR mode).

        Args:
            data (bytes): Ciphertext bytes to decrypt.

        Returns:
            bytes: Plaintext of the same length as *data*.
        """
        return self.encrypt(data)


class AesZipDecrypter(BaseZipDecrypter):
    """Decrypter for WZ-AES encrypted ZIP entries.

    Derives the AES and HMAC keys from a password and salt using PBKDF2,
    then decrypts entry data with AES-CTR and verifies integrity with
    HMAC-SHA1.

    Attributes:
        hmac_size (int): Number of bytes of the HMAC digest appended to
            the ciphertext (always 10).
        filename (str): Name of the ZIP entry being decrypted.
    """

    hmac_size: int = 10
    authentication_trailer_length: int = hmac_size

    def __init__(
        self,
        zinfo: ZipInfo,
        pwd: bytes | str,
        encryption_header: bytes,
    ) -> None:
        """Initialise the decrypter for a ZIP entry.

        Args:
            zinfo (ZipInfo): Metadata for the ZIP entry to decrypt.
            pwd (bytes | str): Decryption password. Strings are encoded
                as UTF-8.
            encryption_header (bytes): Salt and password-verification bytes
                read from the beginning of the entry data.

        Raises:
            BadZipFile: If *zinfo* has no AES strength field.
            RuntimeError: If *pwd* does not match the password-verification
                bytes in *encryption_header*.
        """
        self.filename = zinfo.filename
        self._wz_aes_version = zinfo.aes_extra.wz_aes_version

        if isinstance(pwd, str):
            pwd = pwd.encode("utf-8")

        if zinfo.aes_extra.wz_aes_strength is None:
            raise BadZipFile("Missing AES strength for file %r" % zinfo.filename)

        try:
            key_length = _WZ_KEY_LENGTHS[zinfo.aes_extra.wz_aes_strength]
            salt_length = _WZ_SALT_LENGTHS[zinfo.aes_extra.wz_aes_strength]
        except KeyError:
            raise BadZipFile("Invalid AES strength") from None
        if len(encryption_header) != salt_length + _PWD_VERIFY_LENGTH:
            raise BadZipFile("Truncated AES encryption header")

        salt = encryption_header[:salt_length]
        pwd_verify = encryption_header[salt_length : salt_length + _PWD_VERIFY_LENGTH]
        dk_len = 2 * key_length + _PWD_VERIFY_LENGTH

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=dk_len,
            salt=salt,
            iterations=1000,
        )
        keymaterial = kdf.derive(pwd)

        if not stdlib_hmac.compare_digest(keymaterial[2 * key_length :], pwd_verify):
            raise RuntimeError("Bad password for file %r" % zinfo.filename)

        self.decrypter = _AesCtrWithLittleEndian(keymaterial[:key_length])
        self.hmac = hmac.HMAC(
            keymaterial[key_length : 2 * key_length],
            hashes.SHA1(),
        )

    @staticmethod
    def encryption_header_length(zinfo: ZipInfo) -> int:
        """Return the number of bytes in the encryption header for an entry.

        Args:
            zinfo (ZipInfo): Metadata for the ZIP entry.

        Returns:
            int: Salt length plus password-verification length in bytes.

        Raises:
            BadZipFile: If *zinfo* has no AES strength field.
        """
        if zinfo.aes_extra.wz_aes_strength is None:
            raise BadZipFile("Missing AES strength for file %r" % zinfo.filename)
        try:
            return (
                _WZ_SALT_LENGTHS[zinfo.aes_extra.wz_aes_strength] + _PWD_VERIFY_LENGTH
            )
        except KeyError:
            raise BadZipFile("Invalid AES strength") from None

    @classmethod
    def header_length(cls, zinfo: ZipInfo) -> int:
        """Return the encryption header length for an entry.

        Delegates to :meth:`encryption_header_length`.
        """
        return cls.encryption_header_length(zinfo)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt a chunk of ciphertext and update the running HMAC.

        Args:
            data (bytes): Ciphertext bytes to decrypt.

        Returns:
            bytes: Decrypted plaintext of the same length as *data*.
        """
        self.hmac.update(data)
        return self.decrypter.decrypt(data)

    def check_hmac(self, hmac_check: bytes) -> None:
        """Verify the HMAC-SHA1 authentication tag for the decrypted entry.

        Args:
            hmac_check (bytes): The 10-byte HMAC digest appended to the
                ciphertext.

        Raises:
            BadZipFile: If the computed HMAC does not match *hmac_check*.
        """
        if len(hmac_check) != self.hmac_size:
            raise BadZipFile("Truncated HMAC check for file %r" % self.filename)
        hmac_copy = self.hmac.copy()
        if not stdlib_hmac.compare_digest(
            hmac_copy.finalize()[: self.hmac_size], hmac_check
        ):
            raise BadZipFile("Bad HMAC check for file %r" % self.filename)

    def finalize(
        self,
        expected_crc: int | None,
        running_crc: int | None,
        fileobj: _ReadableStream,
    ) -> None:
        """Verify the HMAC tag, and for WZ-AES V1 also the CRC-32.

        WZ-AES V2 relies on the HMAC alone; V1 predates that guarantee and
        also carries a CRC-32, which the base implementation checks.
        """
        hmac_check = fileobj.read(self.hmac_size)
        self.check_hmac(hmac_check)
        if self._wz_aes_version == WZ_AES_V1:
            super().finalize(expected_crc, running_crc, fileobj)


class AesZipEncryptor(BaseZipEncryptor):
    """Encryptor for WZ-AES ZIP entries.

    Generates a random salt, derives AES and HMAC keys from the password
    using PBKDF2, encrypts entry data with AES-CTR, and produces a
    10-byte HMAC-SHA1 authentication tag.

    Attributes:
        hmac_size (int): Number of HMAC bytes appended after the ciphertext
            (always 10).
        aes_strength (int): WZ-AES strength value (1=128-bit, 2=192-bit,
            3=256-bit).
        salt_length (int): Length of the random salt in bytes.
        salt (bytes): Randomly generated salt used for key derivation.
        encpwdverify (bytes): Password-verification bytes included in the
            encryption header.
    """

    hmac_size: int = 10

    def __init__(
        self,
        pwd: bytes | str,
        nbits: int = 256,
        force_wz_aes_version: int | None = None,
    ) -> None:
        """Initialise the encryptor with a password and key size.

        Args:
            pwd (bytes | str): Encryption password. Strings are encoded
                as UTF-8.
            nbits (int): AES key size in bits. Must be 128, 192, or 256.
                Defaults to 256.
            force_wz_aes_version (int | None): Override the WZ-AES version
                written to the ZIP extra field. ``None`` uses the default
                version negotiation. Defaults to ``None``.

        Raises:
            RuntimeError: If *pwd* is empty.
            RuntimeError: If *nbits* is not 128, 192, or 256.
        """
        if isinstance(pwd, str):
            pwd = pwd.encode("utf-8")

        if not pwd:
            raise RuntimeError("%s encryption requires a password." % WZ_AES)

        if nbits not in (128, 192, 256):
            raise RuntimeError("`nbits` must be one of 128, 192, 256. Got '%s'" % nbits)
        if force_wz_aes_version not in (None, WZ_AES_V1, WZ_AES_V2):
            raise ValueError("force_wz_aes_version must be 1 or 2")

        self.force_wz_aes_version = force_wz_aes_version
        self.aes_strength = _NBITS_TO_STRENGTH[nbits]
        self.salt_length = _WZ_SALT_LENGTHS[self.aes_strength]
        key_length = _WZ_KEY_LENGTHS[self.aes_strength]

        self.salt = os.urandom(self.salt_length)
        dk_len = 2 * key_length + _PWD_VERIFY_LENGTH

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=dk_len,
            salt=self.salt,
            iterations=1000,
        )
        keymaterial = kdf.derive(pwd)

        self.encpwdverify = keymaterial[2 * key_length :]
        self.encryptor = _AesCtrWithLittleEndian(keymaterial[:key_length])
        self.hmac = hmac.HMAC(
            keymaterial[key_length : 2 * key_length],
            hashes.SHA1(),
        )

    def update_zipinfo(self, zipinfo: ZipInfo) -> None:
        """Write AES-related fields into a ZipInfo extra-data structure.

        Args:
            zipinfo (ZipInfo): The entry metadata to update in-place.
        """
        zipinfo.aes_extra.wz_aes_vendor_id = _WZ_AES_VENDOR_ID
        zipinfo.aes_extra.wz_aes_strength = self.aes_strength
        if self.force_wz_aes_version is not None:
            zipinfo.aes_extra.wz_aes_version = self.force_wz_aes_version

    def encryption_header(self) -> bytes:
        """Build the encryption header to prepend to the ciphertext.

        Returns:
            bytes: Concatenation of the random salt and the
            password-verification bytes.
        """
        return self.salt + self.encpwdverify

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt a chunk of plaintext and update the running HMAC.

        Args:
            data (bytes): Plaintext bytes to encrypt.

        Returns:
            bytes: Ciphertext of the same length as *data*.
        """
        data = self.encryptor.encrypt(data)
        self.hmac.update(data)
        return data

    def flush(self) -> bytes:
        """Finalise encryption and return the HMAC authentication tag.

        Returns:
            bytes: First :attr:`hmac_size` (10) bytes of the HMAC-SHA1
            digest, to be appended after the ciphertext.
        """
        return self.hmac.copy().finalize()[: self.hmac_size]
