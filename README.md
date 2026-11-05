# POSIX Signed & Timestamped Asset Manifest (`mk-web-manifest.sh`)

A 100% POSIX-compliant (`#!/bin/sh`, IEEE Std 1003.1) command-line tool for generating and verifying cryptographically signed, RFC 3161 trusted-timestamped SHA-256 asset manifests.

Designed for static websites, software release directories, and archival bundles, `mk-web-manifest.sh` binds every file in a target directory into a verifiable three-layer chain of trust:

1. **Asset Integrity (`SHA256SUMS`)** — A locale-independent, deterministically sorted SHA-256 checksum manifest of all regular files in the target directory.
2. **Authenticity & Non-Repudiation (`SHA256SUMS.asc`)** — An ASCII-armored GnuPG cryptographic signature over `SHA256SUMS`.
3. **Trusted Temporal Proof (`SHA256SUMS.asc.tsq` & `SHA256SUMS.asc.tsr`)** — An IETF RFC 3161 timestamp query (`.tsq`) and signed response token (`.tsr`) issued by an independent Time Stamping Authority (TSA) over `SHA256SUMS.asc`, proving that the signature existed prior to the attested UTC timestamp (even if the signing GPG key later expires or is rotated).

---

## Cryptographic Chain of Trust

```
+-------------------------------------------------------------------+
| Target Directory Assets (./index.html, ./assets/app.js, ...)      |
+-------------------------------------------------------------------+
                                  |
                                  |  SHA-256 (LC_ALL=C deterministic sort)
                                  v
+-------------------------------------------------------------------+
| SHA256SUMS              (Canonical SHA-256 checksum manifest)     |
+-------------------------------------------------------------------+
                                  |
                                  |  GnuPG Sign (--detach-sign --armor)
                                  v
+-------------------------------------------------------------------+
| SHA256SUMS.asc          (ASCII-armored OpenPGP signature)         |
+-------------------------------------------------------------------+
                                  |
                                  |  OpenSSL RFC 3161 (SHA-256 + 64-bit Nonce)
                                  v
+-------------------------------------------------------------------+
| SHA256SUMS.asc.tsq      (ASN.1 DER TimeStampReq query)            |
+-------------------------------------------------------------------+
                                  |
                                  |  HTTPS POST (application/timestamp-query)
                                  v
+-------------------------------------------------------------------+
| SHA256SUMS.asc.tsr      (ASN.1 DER TimeStampResp signed by TSA)   |
+-------------------------------------------------------------------+
```

---

## Key Features

- **100% POSIX Compliant**: Written in strict POSIX `sh` (`IEEE Std 1003.1-2017` / `1003.1-2024`) with zero bashisms. Tested across `/bin/sh`, `dash`, `ksh`, `bash --posix`, and `zsh`.
- **Cross-Platform SHA-256 Normalization**: Automatically detects and normalizes output across GNU/Linux `sha256sum`, macOS/Perl `shasum -a 256`, FreeBSD/OpenBSD/NetBSD `sha256 -r`, and `openssl dgst -sha256 -r` to produce byte-for-byte identical `SHA256SUMS` files on every OS.
- **Built-in Generation & Three-Layer Verification (`-V` / `--verify`)**: Both creates attestation bundles and verifies them in strict outer-to-inner (*Verify-Then-Parse*) cryptographic order.
- **Selectable Time Stamping Authorities (`-t` / `--tsa`)**: Includes built-in presets for well-known public RFC 3161 TSAs (`freetsa`, `digicert`, `sectigo`, `globalsign`, `entrust`, `apple`, `identrust`) and accepts any custom `https://` or `http://` TSA endpoint URL.
- **Atomic Staging & Rollback**: Builds and self-verifies all artifacts inside a private (`0700`) temporary staging directory before atomically moving them into the target directory. If signing or TSA timestamping fails, pre-existing valid artifacts are never corrupted or deleted.
- **Defense-in-Depth Security**:
  - Rejects filenames containing newlines, carriage returns, backslashes, or ASCII control / ANSI terminal escape sequences (`[[:cntrl:]]`).
  - Sanitize all untrusted strings written to `stderr` to prevent terminal escape injection.
  - Rejects unexpected symbolic links (unless `-L` / `--follow-symlinks` is explicitly passed).
  - Blocks path traversal (`../`, leading `/`) and duplicate filename entries in `SHA256SUMS`.
  - Detects untracked extra files planted in the target directory during `--verify`.
  - Validates RFC 3161 `Granted` status, SHA-256 message imprint, 64-bit replay nonce, and X.509 certificate chain.

---

## Requirements

- A POSIX-compliant shell (`/bin/sh`, `dash`, `ksh`, `ash`, `bash`, or `zsh`)
- Standard POSIX utilities (`find`, `sort`, `awk`, `sed`, `grep`, `comm`, `cmp`, `tr`, `wc`, `mv`, `rm`, `mkdir`, `chmod`)
- **GnuPG** (`gpg`) — for signing and signature verification
- **OpenSSL** (`openssl` with `ts` command support) — for RFC 3161 query creation and token verification
- **cURL** (`curl`) — required during generation mode to query the TSA over HTTP/HTTPS
- Any one of: `sha256sum`, `shasum`, `sha256`, or `openssl`

---

## Quick Start

### 1. Generate an Attestation Bundle

Generate `SHA256SUMS`, `SHA256SUMS.asc`, `SHA256SUMS.asc.tsq`, and `SHA256SUMS.asc.tsr` in the current directory (using the default `freetsa` TSA preset):

```sh
./mk-web-manifest.sh
```

Generate an attestation bundle for `./dist` using the **DigiCert** TSA and a specific GPG key:

```sh
./mk-web-manifest.sh -t digicert -k 0xDEADBEEF12345678 ./dist
```

Exclude `.map` and `.tmp` files during generation:

```sh
./mk-web-manifest.sh -t sectigo -x '*.map' -x '*.tmp' ./public
```

### 2. List Available TSA Presets

```sh
./mk-web-manifest.sh --list-tsa
```

| Preset | Endpoint URL | Notes |
| :--- | :--- | :--- |
| `freetsa` | `https://freetsa.org/tsr` | Default; requires FreeTSA Root CA (`cacert.pem`) for X.509 chain verification |
| `digicert` | `https://timestamp.digicert.com` | Chains to DigiCert root CA in standard OS trust stores |
| `sectigo` | `https://timestamp.sectigo.com` | Chains to Sectigo/USERTrust root CA in standard OS trust stores |
| `globalsign` | `http://timestamp.globalsign.com/tsa/r6advanced1` | Chains to GlobalSign root CA in standard OS trust stores |
| `entrust` | `http://timestamp.entrust.net/TSS/RFC3161sha2TS` | Chains to Entrust root CA in standard OS trust stores |
| `apple` | `http://timestamp.apple.com/ts01` | Chains to Apple root CA |
| `identrust` | `http://timestamp.identrust.com` | Chains to IdenTrust root CA in standard OS trust stores |

You can also pass any custom URL directly via `-t https://tsa.example.com` or set `TSA_URL=https://tsa.example.com`.

### 3. Verify an Attestation Bundle

Verify all three layers (RFC 3161 timestamp, GPG signature, and SHA-256 asset checksums + directory bijection):

```sh
# Using system CA bundle (works out-of-the-box for digicert, sectigo, globalsign, entrust, etc.):
./mk-web-manifest.sh -V ./dist

# Or specifying an explicit TSA Root CA certificate (e.g., for FreeTSA):
./mk-web-manifest.sh -V -C /path/to/freetsa-cacert.pem ./dist

# Verify timestamp imprint & nonce without X.509 CA root validation:
./mk-web-manifest.sh -V --no-ts-cert-verify ./dist
```

---

## Command-Line Reference

```text
Usage:
  mk-web-manifest.sh [OPTIONS] [TARGET_DIR]
  mk-web-manifest.sh -V [OPTIONS] [TARGET_DIR]
  mk-web-manifest.sh --list-tsa

Modes:
  (default)              Generate manifest, GPG signature, and RFC 3161 timestamp
  -V, --verify           Verify existing manifest, signature, and timestamp
      --list-tsa         List built-in RFC 3161 TSA presets and exit
  -h, --help             Display this help message and exit
  -v, --version          Display version information and exit

Options:
  -d, --dir DIR          Target directory (default: positional TARGET_DIR or '.')
  -m, --manifest NAME    Manifest filename (default: SHA256SUMS)
  -k, --gpg-key KEY      GPG key ID, fingerprint, or email for signing
      --gpg-homedir DIR  Custom GnuPG home directory
      --keyring FILE     Additional GPG keyring file for verification
      --clearsign        Create a clearsigned signature instead of detached
  -t, --tsa TSA          TSA preset name (e.g. freetsa, digicert, sectigo)
                         or full http(s):// URL (default: freetsa)
      --timeout SECS     TSA HTTP request timeout in seconds (default: 30)
      --keep-tsq         Keep the .tsq query file alongside .tsr (default)
      --no-keep-tsq      Remove the .tsq query file after generation
  -C, --ca-file FILE     Trusted CA certificate PEM bundle for TSA verification
      --ca-path DIR      Trusted CA certificate directory for TSA verification
      --untrusted FILE   Untrusted intermediate certificates PEM for TSA verify
      --no-ts-cert-verify
                         Verify timestamp token imprint/nonce without X.509 CA
                         chain validation during --verify
  -x, --exclude PATTERN  Exclude files/directories matching glob PATTERN
                         (may be specified multiple times)
      --include-vcs      Do not exclude .git, .hg, and .svn directories
  -L, --follow-symlinks  Follow symbolic links when scanning and verifying
      --allow-untracked  Warn instead of failing on untracked files in --verify
  -q, --quiet            Suppress informational progress output
```

### Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `TSA_URL` | Default TSA preset name or `http(s)://` endpoint URL | `freetsa` |
| `GPG_KEY` | Default GPG key ID, fingerprint, or email for signing | *(GPG default key)* |
| `GPG_HOMEDIR` | Custom GnuPG home directory | *(GPG default)* |
| `GPG_KEYRING` | Additional GnuPG keyring file for verification | *(none)* |
| `TSA_CA_FILE` | Trusted CA PEM bundle for RFC 3161 verification | *(system CA store)* |
| `TSA_CA_PATH` | Trusted CA directory for RFC 3161 verification | *(none)* |
| `TSA_UNTRUSTED_FILE` | Untrusted intermediate certificates PEM file | *(none)* |
| `TSA_TIMEOUT` | HTTP request timeout in seconds | `30` |
| `MANIFEST_NAME` | Manifest filename | `SHA256SUMS` |
| `KEEP_TSQ` | Retain `.tsq` file (`1`) or remove after generation (`0`) | `1` |
| `POSIX_MANIFEST_SHA256_BACKEND` | Force specific hash tool (`sha256sum`, `shasum`, `sha256`, `openssl`) | *(auto-detected)* |

---

## Independent Manual Verification (Without `mk-web-manifest.sh`)

All generated artifacts use standard formats (`SHA256SUMS`, OpenPGP RFC 4880, and IETF RFC 3161 ASN.1 DER) so any third party can verify them using stock command-line tools:

```sh
# 1. Verify the RFC 3161 timestamp token against the GPG signature and TSA Root CA:
openssl ts -verify \
    -data SHA256SUMS.asc \
    -queryfile SHA256SUMS.asc.tsq \
    -in SHA256SUMS.asc.tsr \
    -CAfile /path/to/ca-bundle.pem

# Inspect the human-readable timestamp details (UTC time, TSA signer, nonce):
openssl ts -reply -in SHA256SUMS.asc.tsr -text

# 2. Verify the detached GPG signature over SHA256SUMS:
gpg --verify SHA256SUMS.asc SHA256SUMS

# 3. Verify all file SHA-256 checksums:
sha256sum -c SHA256SUMS
# Or on macOS / Perl:
shasum -a 256 -c SHA256SUMS
```

---

## Exit Codes

| Exit Code | Constant | Meaning |
| :---: | :--- | :--- |
| `0` | `EXIT_OK` | Success (generation or verification passed completely) |
| `1` | `EXIT_ERR` | General runtime or filesystem error |
| `2` | `EXIT_USAGE` | Invalid CLI option, argument, or configuration |
| `3` | `EXIT_DEP` | Missing required external dependency (`gpg`, `openssl`, `curl`, or SHA-256 utility) |
| `4` | `EXIT_MANIFEST` | Asset or manifest integrity error (checksum mismatch, missing file, untracked file, symlink, unsafe filename, path traversal, or duplicate entry) |
| `5` | `EXIT_GPG` | GPG signing or signature verification failure (or weak digest algorithm) |
| `6` | `EXIT_TSA` | RFC 3161 timestamp query, TSA network request, or token verification failure |

---

## Manual Page & Test Suite

### View the POSIX Man Page

```sh
man ./mk-web-manifest.1
```

### Run the Automated Test Suite

The test suite (`tests/run-tests.sh`) is 100% POSIX-compliant, sets up a local ephemeral X.509 Root CA and RFC 3161 TSA responder via `openssl ts -reply`, and runs 51 functional, cross-shell, cross-backend, and security tamper-detection tests offline:

```sh
./tests/run-tests.sh
```
