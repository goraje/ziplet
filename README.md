<!-- # ziplet -->

<p align="center">
	<img src="https://raw.githubusercontent.com/goraje/ziplet/main/assets/ziplet-logo.svg" alt="ziplet logo" width="260">
</p>

<p align="center">
	<img src="https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-6ca79e?style=flat-square&logo=python&logoColor=white" alt="Supported Python versions: 3.10, 3.11, 3.12, 3.13, 3.14">
	<img src="https://img.shields.io/badge/license-MIT-6ca79e?style=flat-square" alt="License: MIT">
</p>

`ziplet` is a standalone ZIP library derived from CPython's `zipfile`
module, extended with WinZip AES support adapted from pyzipper.

The project aims to provide a `zipfile`-style API for applications that need
to read and write standard ZIP archives, WinZip AES-encrypted archives and
traditional ZipCrypto archives.

## Why this project exists

`ziplet` started as a split-off from pyzipper for deployments that need to
use the `cryptography` package with a FIPS-configured OpenSSL provider.
Pyzipper uses PyCryptodomeX for its cryptographic primitives, which is outside
the FIPS-validated cryptographic boundary used by those deployments.

This project is not itself FIPS-validated and using `cryptography` does not
make an application FIPS-compliant. A deployment must use a FIPS-validated
cryptographic module and a FIPS-configured Python/OpenSSL environment, and
must follow the applicable operational controls. For a FIPS-constrained
deployment, use WinZip AES only after confirming that the selected provider
permits the algorithms and modes required by the WinZip AES format. Do not use
the legacy ZipCrypto option for FIPS-constrained data; it is a compatibility
feature and is not a FIPS-approved encryption algorithm.

WinZip AES output uses AES version 2 by default. Version 2 omits the plaintext
CRC-32 from ZIP metadata, reducing offline candidate-guessing disclosure.
Select `ZipFileExtra(force_wz_aes_version=1)` only when compatibility with a
consumer that requires AES version 1 is more important than that metadata
protection; version 1 stores the plaintext CRC-32 in both ZIP headers.

## What it provides?

- a familiar `ZipFile` API.
- read and write support for plain ZIP archives
- write support for WinZip AES and ZipCrypto encryption
- read support that auto-detects AES vs. ZipCrypto for encrypted members
- support for `ZIP_STORED`, `ZIP_DEFLATED`, `ZIP_BZIP2`, `ZIP_LZMA` and
  `ZIP_ZSTANDARD` compression

ZIP LZMA archives declare their dictionary size in the member stream. ziplet
rejects dictionaries larger than 1 GiB before constructing a decompressor.
This bounds attacker-controlled allocation while retaining compatibility with
normal ZIP LZMA archives; applications handling untrusted archives should also
apply extraction size and compression-ratio limits.

## Installation

```bash
pip install ziplet
```

## Intended usage

The intended usage is the same as `zipfile`'s: use `ziplet.ZipFile` to create your archive, optionally choose a compression and/or encryption methods and
set a password for encrypted archives if applicable.

### Creating a plain ZIP archive

```python
from ziplet import ZipFile, ZIP_DEFLATED

with ZipFile("example.zip", "w", compression=ZIP_DEFLATED) as zf:
    zf.writestr("hello.txt", "hello world")
```

### Reading a plain ZIP archive

```python
from ziplet import ZipFile

with ZipFile("example.zip", "r") as zf:
    data = zf.read("hello.txt")
```

### Writing an AES-encrypted archive

```python
from ziplet import ZipFile, WZ_AES, ZIP_DEFLATED

password = b"correct horse battery staple"

with ZipFile(
    "secret-aes.zip",
    "w",
    compression=ZIP_DEFLATED,
    encryption=WZ_AES,
) as zf:
    zf.setpassword(password)
    zf.writestr("secret.txt", b"sensitive payload")
```

### Reading an encrypted ZIP archive

```python
from ziplet import ZipFile

password = b"correct horse battery staple"

with ZipFile("secret-aes.zip", "r") as zf:
    zf.setpassword(password)
    data = zf.read("secret.txt")
```

> **NOTE**:
When reading, encryption is normally detected automatically from the archive
metadata, so you typically do not need to specify an encryption mode.

### Customizing AES settings with `ZipFileExtra`

`ZipFileExtra` is the write-time configuration object for AES-specific ZIP
output. It lets you override the WinZip AES version written into the extra
field and choose the AES key size.

```python
from ziplet import ZipFile, ZipFileExtra, WZ_AES, ZIP_DEFLATED

password = b"correct horse battery staple"
extra = ZipFileExtra(force_wz_aes_version=1, wz_aes_nbits=256)

with ZipFile(
    "secret-aes-v1.zip",
    "w",
    compression=ZIP_DEFLATED,
    encryption=WZ_AES,
    extra=extra,
) as zf:
    zf.setpassword(password)
    zf.writestr("secret.txt", b"payload")
```

### Writing AES-encrypted archive with a different key size

```python
from ziplet import ZipFile, ZipFileExtra, WZ_AES

password = b"correct horse battery staple"
extra = ZipFileExtra(wz_aes_nbits=128)

with ZipFile("secret-aes-128.zip", "w", encryption=WZ_AES, extra=extra) as zf:
    zf.setpassword(password)
    zf.writestr("secret.txt", b"payload")
```

### Writing a ZipCrypto-encrypted archive

```python
from ziplet import ZipFile, ZIP_CRYPTO, ZIP_DEFLATED

password = b"correct horse battery staple"

with ZipFile(
    "secret-zipcrypto.zip",
    "w",
    compression=ZIP_DEFLATED,
    encryption=ZIP_CRYPTO,
) as zf:
    zf.setpassword(password)
    zf.writestr("secret.txt", b"legacy compatible payload")
```

ZipCrypto is retained for legacy interoperability only. It is not a modern
confidentiality mechanism and is unsuitable for FIPS-constrained or otherwise
security-sensitive new archives; use WinZip AES instead.

### Using in-memory buffers

```python
import io

from ziplet import ZipFile, WZ_AES

password = b"correct horse battery staple"
buffer = io.BytesIO()

with ZipFile(buffer, "w", encryption=WZ_AES) as zf:
    zf.setpassword(password)
    zf.writestr("data.txt", b"payload")

buffer.seek(0)

with ZipFile(buffer, "r") as zf:
    zf.setpassword(password)
    data = zf.read("data.txt")
```

### Per-entry encryption

Archive-level encryption remains the default for newly written members, but
individual entries can override it. Use `INHERIT_ENCRYPTION` to make
inheritance explicit, `None` for a plaintext member, or an encryption method
for a protected member.

```python
from ziplet import INHERIT_ENCRYPTION, ZIP_CRYPTO, WZ_AES

with ZipFile("mixed.zip", "w", encryption=WZ_AES) as zf:
    zf.setpassword(b"default-password")
    zf.writestr("secret.txt", b"secret")
    zf.writestr("public.txt", b"public", encryption=None)
    zf.writestr(
        "legacy.txt",
        b"legacy",
        encryption=ZIP_CRYPTO,
        password=b"legacy-password",
    )
    zf.writestr("inherited.txt", b"inherited", encryption=INHERIT_ENCRYPTION)
```

An entry-level password overrides the archive default password. Per-entry
encryption is part of the ZIP format, but consumers vary in their support for
mixed algorithms or multiple passwords in one archive.

### Opt-in extraction policy

The legacy `extract()` and `extractall()` behavior remains unchanged when no
policy is supplied. For untrusted archives, pass an `ExtractPolicy`; policy
enabled calls return structured results describing every member.

```python
from ziplet import ExtractPolicy, ViolationAction

with ZipFile("input.zip") as zf:
    result = zf.extractall(
        "out",
        policy=ExtractPolicy(
            on_violation=ViolationAction.SKIP,
            max_compression_ratio=100.0,
        ),
    )

for member in result.members:
    print(member.member, member.status, member.violations)
```

`ExtractPolicy` can enforce path, overwrite, file-size, archive-size,
entry-count, compression-ratio, extension, duplicate-target, and file-type
limits. Set `preview_only=True` for a dry run. Policy violations configured as
errors raise `ExtractionError`, whose `result` attribute contains the partial
structured result. Size limits are enforced both from archive metadata before
extraction and against actual bytes written during extraction; an actual-size
quota breach aborts that member and removes its partial output.

### Metadata-only inspection

Use `ZipFile.inspect()` to produce a structured report before extraction.
Inspection reads the central directory and member metadata only: it never
opens, decompresses, decrypts, or writes a payload, and policy findings never
raise `ExtractionError`.

```python
from ziplet import ExtractPolicy, ZipFile

with ZipFile("input.zip") as zf:
    report = zf.inspect(policy=ExtractPolicy(max_compression_ratio=100.0))

print(report.total_entries, report.total_uncompressed_size)
print(report.suspicious_paths, report.encrypted_members)
print(report.duplicate_member_names, report.duplicate_targets)
for member in report.members:
    print(member.member, member.violations)
```

The report separately identifies duplicate member names and duplicate
filesystem targets, suspicious paths, encrypted members, symlinks and special
files, large members, compression-ratio outliers, and entry/size policy
findings. `path=` controls the destination used for non-mutating target
resolution; it does not create or modify that path.

## Public API

The package exports these primary entry points:

- `ZipFile`
- `is_zipfile`
- `INHERIT_ENCRYPTION`
- `ExtractPolicy`, `ExtractResult`, `ExtractMemberResult`, `ExtractionError`
- `InspectionMember`, `InspectionResult`
- `ZipFileExtra`
- `WZ_AES`, `WZ_AES_V1`, `WZ_AES_V2`
- `ZIP_CRYPTO`
- `ZIP_STORED`, `ZIP_DEFLATED`, `ZIP_BZIP2`, `ZIP_LZMA`, `ZIP_ZSTANDARD`
- `WzAesExtra`

### Assessment And Extraction

Policy-enabled extraction is a two-stage operation. Metadata is assessed first;
only members whose effective policy action permits it are materialized. The
assessment stage does not open, decrypt, decompress, or write member payloads.
`ZipFile.inspect()` exposes this metadata-only behavior through an
`InspectionResult`. `MemberAssessment` describes the normalized target, entry
type, and violations for one member; `ArchiveAssessment` is available for
applications that need to build security tooling around the shared assessment
model.

For callers that need the shared lower-level model directly, use
`ZipFile.assess()`:

```python
with ZipFile("input.zip") as zf:
    assessment = zf.assess(
        "out",
        ExtractPolicy(max_compression_ratio=100.0),
    )

for member in assessment.members:
    print(member.info.filename, member.target, member.violations)
```

`ViolationAction.ERROR`, `WARN`, and `SKIP` control ordinary policy findings.
`max_entries` applies to the archive as a whole and is reported once: `ERROR`
extracts nothing, `SKIP` extracts only the first `max_entries` members, and
`WARN` warns and extracts everything.
Security-critical path and file-type findings remain errors when `WARN` is
selected. `preview_only=True` performs assessment and returns member results
without creating or modifying the destination. An `ExtractionError` contains
the partial `ExtractResult` in its `result` attribute.

Regular files are written to a temporary file in the destination directory and
atomically committed only after the member has been fully read and quota checks
have succeeded. Existing files are therefore preserved when a member fails.
Each file is fsynced before it is moved into place; pass
`ExtractPolicy(fsync_files=False)` to skip that when extraction throughput matters
more than durability across power loss.
Symlinks and special files are rejected by default. Allowed symlinks are
materialized without following their targets, and supported FIFOs can be
materialized on platforms that provide `os.mkfifo`. Descriptor-backed
no-follow checks are used where the platform exposes the required APIs; other
platforms use the strongest path-based checks available.

### Compression Registries

Each `ZipFile` receives an archive-local snapshot of the compression registry.
Applications can provide a custom `Registry` with the `compression_registry=`
constructor option. Registering or replacing a method in one archive does not
change other archives or the module-level default registry. Stored entries use
the same no-op compressor/decompressor strategy as other compression methods.
The snapshot is taken when the archive is constructed, so later changes to the
module-level registry do not affect an existing `ZipFile`.

### ZipInfo Compatibility Names

ZIP header serialization is side-effect-free: calling `ZipInfo.FileHeader()` or
`ZipInfo.central_directory()` calculates effective ZIP versions without
rewriting the `ZipInfo` object's `create_version` or `extract_version` fields.
Prefer these correctly spelled data-descriptor APIs:

- `use_data_descriptor`
- `encode_data_descriptor()`
- `data_descriptor()`

The historical CPython-derived spellings remain supported as compatibility
aliases: `use_datadescripter`, `encode_datadescripter()`, and
`datadescripter()`. The `_compresslevel` alias likewise remains available for
compatibility with code using the CPython-style metadata attribute.

## Notes

- `ZIP_ZSTANDARD` compression uses stdlib `compression.zstd` (Python 3.14+); on
  Python 3.10-3.13 install the optional extra (`pip install "ziplet[zstd]"`,
  which pulls in `backports.zstd`), otherwise using it raises `RuntimeError`
- ZIP archives that span multiple disks are not supported (same as the standard
  library) and are rejected with `BadZipFile`
- only one write handle may be open per archive at a time; opening a second
  one, or reading while a writer is active, raises `ValueError`
- use WinZip AES for modern encrypted ZIP workflows (ZipCrypto is mainly for compatibility with older tools)
- passwords must be byte strings
- decompression is streamed and bounded per read, but callers should still
  enforce application-level limits on total extracted bytes and archive member
  counts when processing untrusted archives

## Interoperability

The project is intended to interoperate with common ZIP tooling while exposing
an API that feels like the standard library.

- the functional test suite includes 7-Zip interoperability checks in both
	directions: archives written by `ziplet` are validated by 7-Zip, and
	AES- and ZipCrypto-encrypted archives written by 7-Zip are read by
	`ziplet`
- WinZip AES is the primary encrypted format to use for modern workflows
- ZipCrypto is included for compatibility with older ZIP consumers and tools
- plain ZIP archives remain readable through the same `ZipFile` API

This is not a claim of universal compatibility with every ZIP tool and every
feature combination. If interoperability matters for your environment, verify
the exact compression and encryption combinations you plan to ship.

## License

This project is licensed under the MIT License. Additional upstream licensing
and attribution files are included for the CPython- and pyzipper-derived
portions of the codebase:

- `LICENSE`
- `NOTICE`
- `licenses/CPYTHON-3.14.3.txt`
- `licenses/pyzipper-MIT.txt`
