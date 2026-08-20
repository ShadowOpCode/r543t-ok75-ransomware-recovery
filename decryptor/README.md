# r543t / ok75 Ransomware Recovery Tool

Standalone recovery utility for the `.r543t` / `.ok75` AutoIt ransomware lineage analyzed in the accompanying research.

The ransomware contains a CryptoAPI implementation flaw that causes an `HCRYPTKEY` value to be reused as input to a second key derivation.

For the analyzed 32-bit samples, the effective file-key derivation can be reproduced as:

```text
LE32(HCRYPTKEY)
      ↓
     MD5
      ↓
CryptoAPI AES-256 MD5 expansion
      ↓
AES-256 file-encryption key
```

This reduces practical key recovery to enumeration of the 32-bit handle representation rather than the AES-256 key space itself.

The tool implements the relevant MD5 processing, CryptoAPI-compatible key derivation, and AES-256 decryption logic directly in C and does not require third-party cryptographic libraries.

## Research

This tool accompanies the research:

**256 Bits on Paper, 32 Bits in Practice: Breaking r543t/ok75 Ransomware Through a CryptoAPI Implementation Flaw**

Full technical analysis: `https://github.com/ShadowOpCode/r543t-ok75-ransomware-recovery/blob/main/report/256%20Bits%20on%20Paper%2C%2032%20Bits%20in%20Practice.pdf`

The paper documents the ransomware lineage, encryption layouts, AutoIt Crypto UDF misuse, CryptoAPI key derivation, key-recovery methodology, and validation of the recovery process.

## Features

- Automatic key recovery using built-in file signatures.
- Manual known-plaintext matching with `--magic` and `--magic-offset`.
- Direct recovery using a known `HCRYPTKEY`.
- Direct recovery from `sslog.txt`.
- Recursive directory recovery.
- Preservation of the original directory hierarchy.
- Multi-key recovery for datasets containing files encrypted by different ransomware executions.
- Support for the `.r543t` legacy small-file behavior.
- Support for `.r543t` / `.ok75` partial-encryption layouts.
- Support for `.ok75` whole-file encryption.
- Padding and layout validation to reduce false positives.
- Detection of ransomware-suffixed files that were not actually encrypted.
- Recovery report generation in automatic mode.
- Windows x64 and Linux x64 support.
- Built-in cryptographic self-test.

Encrypted input files are never modified in place.

## Quick Start

Before processing evidence, verify the build.

### Windows

```powershell
.\r543t_recover_windows_x64.exe --self-test
```

### Linux

```bash
./r543t_recover_linux_x64 --self-test
```

A successful self-test validates the internal CryptoAPI-compatible key derivation and AES-256 implementation.

## Recovering a Single File

When the original file type can be inferred from its extension, the tool can select an appropriate built-in signature automatically.

### Windows

```powershell
.\r543t_recover_windows_x64.exe .\photo.jpg.ok75 `
    --output .\photo.jpg
```

### Linux

```bash
./r543t_recover_linux_x64 ./photo.jpg.ok75 \
    --output ./photo.jpg
```

The tool will:

1. Infer the expected file format.
2. Enumerate candidate `HCRYPTKEY` values.
3. Reconstruct the corresponding AES-256 key.
4. Validate candidate plaintext.
5. Recover the file when a valid key is identified.

## Manual Known-Plaintext Recovery

A custom expected plaintext sequence can be supplied as hexadecimal bytes.

Example using the PNG signature:

### Windows

```powershell
.\r543t_recover_windows_x64.exe .\unknown.ok75 `
    --magic 89504E470D0A1A0A `
    --output .\recovered.png
```

### Linux

```bash
./r543t_recover_linux_x64 ./unknown.ok75 \
    --magic 89504E470D0A1A0A \
    --output ./recovered.png
```

An optional offset can also be supplied:

```text
--magic-offset N
```

This is useful for formats whose known plaintext does not begin at offset zero.

## Recursive Automatic Recovery

Automatic mode recursively scans a directory and its subdirectories for supported ransomware-suffixed files.

### Windows

```powershell
.\r543t_recover_windows_x64.exe `
    --auto "C:\encrypted" `
    --output-dir "C:\recovered"
```

### Linux

```bash
./r543t_recover_linux_x64 \
    --auto ./encrypted \
    --output-dir ./recovered
```

Recovered files are written under the output directory while preserving their original relative paths.

For example:

```text
encrypted/
├── documents/
│   └── report.pdf.ok75
└── images/
    └── photo.jpg.ok75
```

becomes:

```text
recovered/
├── documents/
│   └── report.pdf
└── images/
    └── photo.jpg
```

Automatic mode also creates:

```text
_r543t_recovery_report.tsv
```

containing the recovery status for each processed file.

## Multiple Encryption Keys

A single ransomware execution normally reuses the same effective encryption key across the files it processes.

Datasets containing files from multiple ransomware executions may therefore require more than one key.

Use:

```text
--multi-key
```

Example:

### Windows

```powershell
.\r543t_recover_windows_x64.exe `
    --auto "C:\encrypted" `
    --output-dir "C:\recovered" `
    --multi-key
```

### Linux

```bash
./r543t_recover_linux_x64 \
    --auto ./encrypted \
    --output-dir ./recovered \
    --multi-key
```

When enabled, unresolved files can be selected as additional recovery probes and separate keys can be discovered independently.

## Recovery Using `sslog.txt`

The analyzed ransomware samples write the CryptoAPI key-handle value to `sslog.txt`.

When this artifact is available, brute force may be unnecessary.

### Windows

```powershell
.\r543t_recover_windows_x64.exe .\encrypted.jpg.ok75 `
    --sslog .\sslog.txt `
    --output .\recovered.jpg
```

### Linux

```bash
./r543t_recover_linux_x64 ./encrypted.jpg.ok75 \
    --sslog ./sslog.txt \
    --output ./recovered.jpg
```

The stored handle is used to reconstruct the AES-256 file-encryption key directly.

Incident responders should therefore preserve any available `sslog.txt` artifact before remediation or system cleanup.

## Recovery Using a Known Handle

A previously recovered `HCRYPTKEY` value can be supplied directly.

### Windows

```powershell
.\r543t_recover_windows_x64.exe .\encrypted.jpg.ok75 `
    --handle 0x01234568 `
    --output .\recovered.jpg
```

### Linux

```bash
./r543t_recover_linux_x64 ./encrypted.jpg.ok75 \
    --handle 0x01234568 \
    --output ./recovered.jpg
```

This skips candidate enumeration.

## Candidate Search Space

For the analyzed 32-bit ransomware samples, the vulnerable second derivation uses the four-byte representation of the `HCRYPTKEY` value.

The complete candidate space is therefore bounded by:

```text
2^32 = 4,294,967,296 candidates
```

During testing, observed handle values were consistently aligned on four-byte boundaries. The default search therefore uses a stride of four, reducing the typical search to approximately:

```text
2^30 = 1,073,741,824 candidates
```

This alignment is an empirical observation and is **not** a documented CryptoAPI guarantee.

For an exhaustive search of the complete 32-bit candidate space, use:

```text
--step 1
```

Search performance depends on CPU performance, thread count, and the numerical position of the matching handle within the selected range.

## Supported Recovery Layouts

The tool supports the encryption layouts observed during the accompanying research:

```text
.r543t  legacy small-file edge case
.r543t  partial encryption
.ok75   whole-file encryption
.ok75   partial encryption
```

For large partially encrypted files, only selected regions of the original file are encrypted while the middle region remains unchanged.

The exact file layout and reconstruction procedure are documented in the research paper.

## Built-in File Signatures

Automatic key discovery includes matchers for common formats including:

- PE
- JPEG
- PNG
- PDF
- GIF
- BMP
- ZIP / OOXML
- OLE
- 7-Zip
- RAR
- gzip
- bzip2
- SQLite
- ELF
- LNK
- EVTX
- VHDX
- QCOW2
- TIFF
- MP4 / MOV
- PCAP / PCAPNG
- common text, configuration, and log files

Unsupported formats can still be tested using a manually supplied known plaintext sequence.

## Building on Windows

Requirements:

- Microsoft Visual Studio or Visual Studio Build Tools
- Desktop development with C++ workload
- Windows SDK

Open an **x64 Native Tools Command Prompt for Visual Studio** and run:

```cmd
cl /nologo /std:c17 /O2 /W3 /MT /TC ^
    r543t_recover.c ^
    /Fe:r543t_recover_windows_x64.exe
```

Then verify the build:

```cmd
r543t_recover_windows_x64.exe --self-test
```

The included build script can also be used:

```cmd
build_windows_vs.bat
```

## Building on Linux

A static x64 build can be produced with:

```bash
cc -std=c11 -O3 -Wall -Wextra -Wpedantic -pthread -static \
    -D_FILE_OFFSET_BITS=64 \
    r543t_recover.c \
    -o r543t_recover_linux_x64
```

Verify the build:

```bash
./r543t_recover_linux_x64 --self-test
```

The included build script performs the same operation:

```bash
./build_linux.sh
```

## Validation

The recovery implementation was validated in isolated environments against files encrypted by both analyzed ransomware generations.

Tested recovery paths included:

- `.r543t` legacy small-file recovery;
- `.r543t` partial-encryption recovery;
- `.ok75` whole-file recovery;
- `.ok75` partial-encryption recovery;
- automatic file-signature key discovery;
- manually supplied known plaintext;
- direct handle recovery;
- `sslog.txt` recovery;
- recursive multi-key recovery;
- nested directory reconstruction.

Successful recovery outputs were compared against their corresponding pre-encryption files using SHA-256 and confirmed to be byte-for-byte identical.

## Evidence Handling

The tool never modifies encrypted input files in place.

Nevertheless, original encrypted data should always be preserved before attempting recovery. During incident response, operate on copies whenever possible and retain original ransomware artifacts for forensic analysis.

In particular, preserve:

```text
sslog.txt
y.txt
ransom notes
encrypted files
the ransomware executable
```

before remediation or cleanup.

## Limitations

- The 32-bit candidate-space reduction described here applies to the analyzed 32-bit ransomware samples.
- A hypothetical 64-bit implementation may exhibit different `HCRYPTKEY` behavior and has not been characterized by this research.
- The default `--step 4` optimization is based on observed handle alignment and is not guaranteed by CryptoAPI.
- Automatic key discovery requires recognizable plaintext structure or another suitable validation oracle.
- Files encrypted by modified or unsupported ransomware variants may require additional manual analysis.
- Recovery cannot be guaranteed for samples whose encryption implementation differs from the variants analyzed in the accompanying research.

## Disclaimer

This software is intended for defensive incident response, malware research, and legitimate data recovery.

It is provided without warranty.

Always preserve original encrypted data before attempting recovery.
