# 256 Bits on Paper, 32 Bits in Practice

## Breaking r543t/ok75 Ransomware Through a CryptoAPI Implementation Flaw

This repository contains the research and recovery tooling for the `.r543t` / `.ok75` AutoIt ransomware lineage.

The analyzed samples use AES-256 through the legacy Windows CryptoAPI. The cryptographic primitive itself is not broken. Instead, a key-handling mistake in the ransomware causes an `HCRYPTKEY` value to be passed back into the AutoIt Crypto UDF as fresh key-derivation input.

For the analyzed 32-bit samples, this makes the final file-encryption key reproducible from a 32-bit handle representation, reducing practical key recovery to at most `2^32` candidate inputs rather than requiring recovery of the original password material or enumeration of the AES-256 key space.

A standalone recovery tool was developed and validated against files encrypted by both analyzed ransomware generations.

## Research Summary

The investigation covers a ransomware lineage observed in public reports since at least 2023.

The earlier generation appends the `.r543t` extension, while a newer sample analyzed in 2025 appends `.ok75`. Comparison of the recovered AutoIt sources shows strong code-level continuity between the two generations:

- the same general encryption workflow;
- the same AutoIt Crypto UDF usage;
- the same key-generation logic;
- the same partial-file encryption design for large files;
- the same CryptoAPI key-handling flaw.

The newer generation adds more robust handling for small files, but the underlying cryptographic mistake remains unchanged.

### Analyzed Samples

| Generation | Filename | SHA-256 | Ransom Extension |
|---|---|---|---|
| 2023 | `rel.exe` | `c3bb43f63238cda44481f33a3a594c9b368f472f41bcf35748c1a840efad7311` | `.r543t` |
| 2025 | `relfixed3.exe` | `5AF82A82CA5A827E525F0BB5C7D2639ACCCA65C608C0CB1B0A7F561C597C78F0` | `.ok75` |

Both analyzed executables are 32-bit PE files containing compiled AutoIt code.

## The Cryptographic Flaw

The ransomware first generates pseudo-random password material and derives an AES-256 CryptoAPI key object:

```text
password material
      ↓
_Crypt_DeriveKey(..., CALG_AES_256)
      ↓
HCRYPTKEY
```

`_Crypt_DeriveKey()` returns an `HCRYPTKEY`, which is an opaque handle identifying a key object managed by the CryptoAPI provider. It is not the raw AES key material.

The ransomware later calls `_Crypt_EncryptData()` with that existing handle, but passes `CALG_AES_256` instead of `CALG_USERKEY`.

The relevant AutoIt UDF behavior is:

```text
if algorithm != CALG_USERKEY
    derive a new key from the supplied value
```

As a result, the numeric `HCRYPTKEY` value is treated as fresh input to a second derivation.

For the analyzed 32-bit samples:

```text
LE32(HCRYPTKEY)
      ↓
     MD5
      ↓
CryptoAPI AES-256 MD5 expansion
      ↓
AES-256 file-encryption key
```

The final encryption key remains a valid 256-bit AES key. The weakness is in how the ransomware derives it.

The effective recovery problem is therefore bounded by:

```text
2^32 = 4,294,967,296 candidate handle values
```

During testing, observed handle values were consistently aligned on four-byte boundaries. This allows an optional stride-of-four optimization, reducing the empirical search to approximately `2^30` candidates.

This alignment is an observed property, not a documented CryptoAPI guarantee.

## Reconstructing the CryptoAPI Derivation

The AutoIt Crypto UDF uses `CALG_MD5` by default.

For the vulnerable second derivation:

```text
H = MD5(input)
```

When deriving AES-256 from a non-SHA-2 hash, legacy CryptoAPI expands the digest using two 64-byte buffers based on `0x36` and `0x5C`:

```text
ipad = 0x36 repeated 64 times
opad = 0x5c repeated 64 times

for i = 0..15:
    ipad[i] ^= H[i]
    opad[i] ^= H[i]

A = MD5(ipad)
B = MD5(opad)

AES256_KEY = A || B
```

The recovery implementation reproduces this behavior directly rather than attempting to export the original CryptoAPI key object.

For the analyzed samples, file encryption can then be reproduced as AES-256-CBC using the CryptoAPI default zero initialization vector.

## File Encryption Layout

Large files use a partial-encryption scheme.

For an original file of size `N`:

```text
A = original[0 : 10000]
B = original[10000 : 10016]
M = original[10016 : N-10016]
C = original[N-10016 : N-16]
D = original[N-16 : N]
```

The encrypted output is:

```text
AES(A) || M || AES(C) || B || D
```

Each 10,000-byte encrypted region expands to 10,016 bytes because the final CryptoAPI encryption call adds a complete AES padding block.

The resulting encrypted file is therefore 32 bytes larger than the original file.

The middle region remains plaintext.

### Small Files

The two analyzed generations differ in their treatment of small inputs:

- `.r543t` uses the partial-encryption routine without equivalent size validation, producing an observed legacy edge-case layout for sufficiently small files.
- `.ok75` introduces explicit size checks and falls back to whole-file AES encryption when the partial layout cannot be used safely.

The recovery tool supports both behaviors.

## Practical Key Recovery

Once the second derivation is reproduced, key recovery becomes a candidate-enumeration problem.

The recovery process is:

```text
candidate HCRYPTKEY
      ↓
little-endian 32-bit representation
      ↓
CryptoAPI-compatible derivation
      ↓
candidate AES-256 key
      ↓
decrypt candidate block
      ↓
validate expected plaintext
```

Known file headers provide a practical validation oracle.

Examples include:

```text
PE      4D 5A
PNG     89 50 4E 47 0D 0A 1A 0A
JPEG    FF D8 FF
PDF     25 50 44 46
ZIP     50 4B 03 04
```

This is not a known-plaintext attack against AES. The predictable header is only used to identify the correct candidate from the already-reduced derivation-input space.

For partially encrypted files, validation can also use the expected final AES padding block.

## Direct Recovery with `sslog.txt`

Before processing target files, the analyzed ransomware writes the CryptoAPI key-handle value to:

```text
sslog.txt
```

If this artifact survives an incident, brute force may not be required.

Recovery becomes:

```text
sslog.txt
      ↓
extract HCRYPTKEY
      ↓
reproduce second derivation
      ↓
recover AES-256 file key
      ↓
decrypt files
```

For incident response, preserving `sslog.txt` can therefore be extremely valuable.

## Recovery Tool

The repository includes a standalone C recovery utility for Windows and Linux.

It supports:

- automatic key discovery using built-in file signatures;
- custom known plaintext with `--magic`;
- direct recovery using a known `HCRYPTKEY`;
- direct recovery using `sslog.txt`;
- recursive directory recovery;
- preservation of the original directory hierarchy;
- multi-key recovery for datasets containing files from separate ransomware executions;
- `.r543t` legacy small-file recovery;
- `.r543t` partial-encryption recovery;
- `.ok75` whole-file recovery;
- `.ok75` partial-encryption recovery;
- padding and layout validation;
- detection of ransomware-suffixed files that were not actually encrypted;
- recovery reporting;
- built-in cryptographic self-tests.

The recovery utility does not modify encrypted input files in place.

See the decryptor-specific README for build instructions, CLI examples, supported file signatures, and operational details.

## Validation

The recovery workflow was validated in isolated test environments using both analyzed ransomware generations.

Testing covered:

- `.r543t` legacy small-file behavior;
- `.r543t` partial encryption;
- `.ok75` whole-file encryption;
- `.ok75` partial encryption;
- automatic known-file-header key discovery;
- direct handle recovery;
- `sslog.txt` recovery;
- recursive recovery;
- multiple encryption keys.

Recovered outputs were compared against their corresponding pre-encryption files using cryptographic hashes and confirmed to be byte-for-byte identical.

## Detection and Incident Response Notes

The analyzed samples expose several useful host-level artifacts and behaviors:

- `y.txt`, used as an externally supplied list of target paths;
- `sslog.txt`, containing the key-handle value used by the vulnerable derivation;
- `.r543t` and `.ok75` ransomware extensions;
- execution of an AutoIt-compiled PE followed by large-scale file modification and renaming;
- use of legacy CryptoAPI primitives including `CryptCreateHash`, `CryptHashData`, `CryptDeriveKey`, and `CryptEncrypt`;
- partial encryption affecting selected regions of large files while leaving substantial middle regions unchanged.

No single indicator should be treated as unique to this ransomware family. Detection should combine multiple artifacts and behaviors.

During incident response, preserve the ransomware working directory and any available copy of `sslog.txt` before cleanup.

## Limitations

- The practical `2^32` recovery bound described here applies to the analyzed 32-bit ransomware samples.
- A hypothetical 64-bit implementation may exhibit different `HCRYPTKEY` behavior and has not been characterized by this research.
- The observed four-byte handle alignment is empirical and is not guaranteed by CryptoAPI.
- Automatic key discovery requires recognizable plaintext structure or another suitable validation oracle.
- Files encrypted by modified or unsupported variants may require additional manual analysis.
- Public evidence supports strong code lineage between the analyzed `.r543t` and `.ok75` samples, but does not establish the identity, number, or complete intrusion methodology of the operators.

## Repository Contents

```text
.
├── report/
│   └── research report
├── decryptor/
│   ├── r543t_recover.c
│   ├── README.md
│   ├── build_linux.sh
│   └── build_windows_vs.bat
└── README.md
```

## Research Paper

**256 Bits on Paper, 32 Bits in Practice: Breaking r543t/ok75 Ransomware Through a CryptoAPI Implementation Flaw**

The full report contains the complete threat-intelligence timeline, sample comparison, AutoIt analysis, encryption layouts, CryptoAPI reconstruction, practical key-recovery methodology, validation evidence, detection opportunities, and limitations.

**Full report:** `https://github.com/ShadowOpCode/r543t-ok75-ransomware-recovery/blob/main/report/256%20Bits%20on%20Paper%2C%2032%20Bits%20in%20Practice.pdf`

## Disclaimer

This repository is intended for defensive security research, incident response, and legitimate data recovery.

AES-256 itself is not broken by this research. The recovery technique exploits a ransomware-specific implementation mistake in the handling of CryptoAPI key objects.

Always preserve original encrypted data before attempting recovery.
