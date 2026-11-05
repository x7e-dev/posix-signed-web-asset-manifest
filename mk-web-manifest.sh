#!/bin/sh
#
# mk-web-manifest.sh - Generate and verify a deterministic SHA-256 asset
#                      manifest, GPG signature, and RFC 3161 trusted timestamp.
#
# Standards: POSIX.1-2017 / POSIX.1-2024 (IEEE Std 1003.1) compliant.
# License:   MIT
#

set -eu

# Enforce deterministic C locale for sorting, character classes, and parsing.
LC_ALL=C
export LC_ALL

# Reset IFS to standard space, tab, newline.
DEFAULT_IFS=$(printf ' \t\n')
IFS="$DEFAULT_IFS"
NL='
'
CR=$(printf '\r')

PROGNAME="${0##*/}"
VERSION="2.0.0"

# Exit codes
EXIT_OK=0
EXIT_ERR=1
EXIT_USAGE=2
EXIT_DEP=3
EXIT_MANIFEST=4
EXIT_GPG=5
EXIT_TSA=6

# Default configuration (overridable via environment or CLI flags)
MODE="generate"
TARGET_DIR=""
TSA_SPEC="${TSA_URL:-freetsa}"
TSA_RESOLVED_URL=""
GPG_KEY="${GPG_KEY:-}"
GPG_HOMEDIR="${GPG_HOMEDIR:-}"
GPG_KEYRING="${GPG_KEYRING:-}"
GPG_SIGN_MODE="detached"
MANIFEST_NAME="${MANIFEST_NAME:-SHA256SUMS}"
KEEP_TSQ="${KEEP_TSQ:-1}"
TSA_CA_FILE="${TSA_CA_FILE:-}"
TSA_CA_PATH="${TSA_CA_PATH:-}"
TSA_UNTRUSTED_FILE="${TSA_UNTRUSTED_FILE:-}"
VERIFY_TS_CERT=1
FOLLOW_SYMLINKS=0
EXCLUDE_VCS=1
ALLOW_UNTRACKED=0
EXCLUDE_LIST=""
TSA_TIMEOUT="${TSA_TIMEOUT:-30}"
QUIET=0

# Temporary workspace directory (populated in setup_tmpdir)
WORK_TMPDIR=""

# ---------------------------------------------------------------------------
# Output & Logging Helpers (with control-character sanitization)
# ---------------------------------------------------------------------------

# Sanitize untrusted strings before terminal output to prevent ANSI escape injection.
sanitize_text() {
    printf '%s' "$1" | tr '[:cntrl:]' '?'
}

log_info() {
    if [ "$QUIET" -eq 0 ]; then
        printf '==> %s\n' "$1"
    fi
}

log_detail() {
    if [ "$QUIET" -eq 0 ]; then
        printf '    %s\n' "$1"
    fi
}

log_warn() {
    printf '%s: warning: %s\n' "$PROGNAME" "$1" >&2
}

log_error() {
    printf '%s: error: %s\n' "$PROGNAME" "$1" >&2
}

die() {
    die_code="$1"
    shift
    log_error "$*"
    exit "$die_code"
}

# ---------------------------------------------------------------------------
# Temporary Workspace & Signal Cleanup
# ---------------------------------------------------------------------------

cleanup() {
    trap - EXIT HUP INT QUIT TERM
    if [ -n "$WORK_TMPDIR" ] && [ -d "$WORK_TMPDIR" ]; then
        rm -rf -- "$WORK_TMPDIR"
    fi
}

setup_tmpdir() {
    old_umask=$(umask)
    umask 077
    base_tmp="${TMPDIR:-/tmp}"
    # Remove trailing slash if not root
    case "$base_tmp" in
        /) ;;
        */) base_tmp="${base_tmp%/}" ;;
    esac

    if [ ! -d "$base_tmp" ] || [ ! -w "$base_tmp" ]; then
        base_tmp="/tmp"
    fi

    if command -v mktemp >/dev/null 2>&1; then
        WORK_TMPDIR=$(mktemp -d "${base_tmp}/mk-web-manifest.XXXXXXXXXX" 2>/dev/null || true)
    fi

    if [ -z "$WORK_TMPDIR" ] || [ ! -d "$WORK_TMPDIR" ]; then
        try_count=0
        while [ "$try_count" -lt 100 ]; do
            try_count=$((try_count + 1))
            candidate="${base_tmp}/mk-web-manifest.$$.${try_count}"
            if (umask 077 && mkdir -- "$candidate") 2>/dev/null; then
                WORK_TMPDIR="$candidate"
                break
            fi
        done
    fi

    umask "$old_umask"

    if [ -z "$WORK_TMPDIR" ] || [ ! -d "$WORK_TMPDIR" ]; then
        die "$EXIT_ERR" "Failed to create secure temporary directory in ${base_tmp}."
    fi

    chmod -- 0700 "$WORK_TMPDIR" || die "$EXIT_ERR" "Failed to set permissions on temporary directory."
}

trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
trap 'cleanup; exit 129' HUP
trap 'cleanup; exit 131' QUIT
trap 'cleanup' EXIT

# ---------------------------------------------------------------------------
# TSA Presets & Resolution
# ---------------------------------------------------------------------------

list_tsa_presets() {
    cat <<'EOF'
Available RFC 3161 Time Stamping Authority (TSA) presets:

  Preset       Endpoint URL
  -----------  -----------------------------------------------------------
  freetsa      https://freetsa.org/tsr                      (default)
  digicert     https://timestamp.digicert.com
  sectigo      https://timestamp.sectigo.com
  globalsign   http://timestamp.globalsign.com/tsa/r6advanced1
  entrust      http://timestamp.entrust.net/TSS/RFC3161sha2TS
  apple        http://timestamp.apple.com/ts01
  identrust    http://timestamp.identrust.com

You may pass any preset name above or a full https:// / http:// TSA URL
via -t / --tsa <tsa> or the TSA_URL environment variable.
EOF
}

resolve_tsa_url() {
    tsa_input="$1"
    case "$tsa_input" in
        freetsa)
            TSA_RESOLVED_URL="https://freetsa.org/tsr"
            ;;
        digicert)
            TSA_RESOLVED_URL="https://timestamp.digicert.com"
            ;;
        sectigo)
            TSA_RESOLVED_URL="https://timestamp.sectigo.com"
            ;;
        globalsign)
            TSA_RESOLVED_URL="http://timestamp.globalsign.com/tsa/r6advanced1"
            ;;
        entrust)
            TSA_RESOLVED_URL="http://timestamp.entrust.net/TSS/RFC3161sha2TS"
            ;;
        apple)
            TSA_RESOLVED_URL="http://timestamp.apple.com/ts01"
            ;;
        identrust)
            TSA_RESOLVED_URL="http://timestamp.identrust.com"
            ;;
        https://?* | http://?*)
            # Reject whitespace or control characters in URL
            case "$tsa_input" in
                *[[:space:][:cntrl:]]*)
                    die "$EXIT_USAGE" "Invalid TSA URL (contains whitespace or control characters)."
                    ;;
            esac
            TSA_RESOLVED_URL="$tsa_input"
            ;;
        *)
            die "$EXIT_USAGE" "Unknown TSA preset or invalid URL: '$(sanitize_text "$tsa_input")'. Use --list-tsa to view presets, or provide an https:// or http:// URL."
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Usage & Help
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage:
  $PROGNAME [OPTIONS] [TARGET_DIR]
  $PROGNAME -V [OPTIONS] [TARGET_DIR]
  $PROGNAME --list-tsa

Generate or verify a deterministic SHA-256 asset manifest (SHA256SUMS),
GPG cryptographic signature (SHA256SUMS.asc), and RFC 3161 trusted timestamp
(SHA256SUMS.asc.tsq and SHA256SUMS.asc.tsr).

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

Environment Variables:
  TSA_URL                Default TSA preset or URL (overridden by -t / --tsa)
  GPG_KEY                Default GPG signing key (overridden by -k / --gpg-key)
  GPG_HOMEDIR            Default GnuPG home directory
  GPG_KEYRING            Default GPG keyring for verification
  TSA_CA_FILE            Default trusted CA bundle for RFC 3161 verification
  TSA_CA_PATH            Default trusted CA directory for RFC 3161 verification
  TSA_UNTRUSTED_FILE     Default untrusted cert file for RFC 3161 verification
  TSA_TIMEOUT            Default TSA HTTP timeout in seconds (default: 30)
  MANIFEST_NAME          Default manifest filename (default: SHA256SUMS)
  KEEP_TSQ               Set to 1 to keep .tsq (default) or 0 to remove it

Exit Status:
  0  Success
  1  General runtime error
  2  Invalid command-line option or configuration
  3  Missing required dependency (sha256 tool, gpg, openssl, curl)
  4  Manifest or asset integrity error (mismatch, untracked file, unsafe path)
  5  GPG signing or signature verification failure
  6  RFC 3161 timestamp creation, TSA request, or verification failure
EOF
}

# ---------------------------------------------------------------------------
# Dependency & Portable Hashing Helpers
# ---------------------------------------------------------------------------

SHA256_BACKEND=""

detect_sha256_backend() {
    if [ -n "${POSIX_MANIFEST_SHA256_BACKEND:-}" ]; then
        case "$POSIX_MANIFEST_SHA256_BACKEND" in
            sha256sum|shasum|sha256|openssl)
                if command -v "$POSIX_MANIFEST_SHA256_BACKEND" >/dev/null 2>&1; then
                    SHA256_BACKEND="$POSIX_MANIFEST_SHA256_BACKEND"
                    return 0
                fi
                die "$EXIT_DEP" "Requested SHA-256 backend '$POSIX_MANIFEST_SHA256_BACKEND' not found in PATH."
                ;;
            *)
                die "$EXIT_USAGE" "Unsupported POSIX_MANIFEST_SHA256_BACKEND: '$POSIX_MANIFEST_SHA256_BACKEND'."
                ;;
        esac
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        SHA256_BACKEND="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        SHA256_BACKEND="shasum"
    elif command -v sha256 >/dev/null 2>&1; then
        SHA256_BACKEND="sha256"
    elif command -v openssl >/dev/null 2>&1; then
        SHA256_BACKEND="openssl"
    else
        die "$EXIT_DEP" "No SHA-256 utility found in PATH (tried: sha256sum, shasum, sha256, openssl)."
    fi
}

check_dependencies() {
    detect_sha256_backend
    for req_cmd in gpg openssl; do
        if ! command -v "$req_cmd" >/dev/null 2>&1; then
            die "$EXIT_DEP" "Required command '$req_cmd' not found in PATH."
        fi
    done
    if [ "$MODE" = "generate" ]; then
        if ! command -v curl >/dev/null 2>&1; then
            die "$EXIT_DEP" "Required command 'curl' not found in PATH."
        fi
    fi
}

# Compute normalized "<64-lowercase-hex>  <filepath>" lines for given file arguments.
# All file paths passed MUST start with "./" or "/" so leading dashes are safe.
hash_files_batch() {
    batch_raw="$WORK_TMPDIR/hash_batch_raw.txt"
    batch_err="$WORK_TMPDIR/hash_batch_err.txt"
    case "$SHA256_BACKEND" in
        sha256sum)
            if ! sha256sum -- "$@" >"$batch_raw" 2>"$batch_err"; then
                h_err=$(cat "$batch_err" 2>/dev/null || true)
                die "$EXIT_MANIFEST" "sha256sum failed: $(sanitize_text "$h_err")"
            fi
            awk '{ printf "%s  %s\n", tolower(substr($0, 1, 64)), substr($0, 67) }' "$batch_raw"
            ;;
        shasum)
            if ! shasum -a 256 -- "$@" >"$batch_raw" 2>"$batch_err"; then
                h_err=$(cat "$batch_err" 2>/dev/null || true)
                die "$EXIT_MANIFEST" "shasum failed: $(sanitize_text "$h_err")"
            fi
            awk '{ printf "%s  %s\n", tolower(substr($0, 1, 64)), substr($0, 67) }' "$batch_raw"
            ;;
        sha256)
            if ! sha256 -r -- "$@" >"$batch_raw" 2>"$batch_err"; then
                h_err=$(cat "$batch_err" 2>/dev/null || true)
                die "$EXIT_MANIFEST" "sha256 failed: $(sanitize_text "$h_err")"
            fi
            awk '{ printf "%s  %s\n", tolower(substr($0, 1, 64)), substr($0, 66) }' "$batch_raw"
            ;;
        openssl)
            if ! openssl dgst -sha256 -r -- "$@" >"$batch_raw" 2>"$batch_err"; then
                h_err=$(cat "$batch_err" 2>/dev/null || true)
                die "$EXIT_MANIFEST" "openssl dgst failed: $(sanitize_text "$h_err")"
            fi
            awk '{ printf "%s  %s\n", tolower(substr($0, 1, 64)), substr($0, 67) }' "$batch_raw"
            ;;
    esac
}

# Compute just the 64-character lowercase hex SHA-256 digest of a single file.
hash_single_file() {
    target_file="$1"
    # Ensure safe path prefix if relative and starting with '-'
    case "$target_file" in
        -*) target_file="./$target_file" ;;
    esac
    line=$(hash_files_batch "$target_file")
    digest="${line%% *}"
    case "$digest" in
        [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*)
            if [ "${#digest}" -eq 64 ]; then
                printf '%s\n' "$digest"
                return 0
            fi
            ;;
    esac
    die "$EXIT_MANIFEST" "Failed to compute valid SHA-256 digest for '$(sanitize_text "$1")'."
}

# ---------------------------------------------------------------------------
# Directory Scanning & Security Validation
# ---------------------------------------------------------------------------

# Check for files or directories containing unsafe characters:
# - Backslash (\)
# - Control characters ([[:cntrl:]]), including newline (\n), CR (\r), tab, ESC (\033)
check_unsafe_filenames() {
    set --
    if [ "$FOLLOW_SYMLINKS" -eq 1 ]; then
        set -- "$@" -L
    fi
    set -- "$@" .
    if [ "$EXCLUDE_VCS" -eq 1 ]; then
        set -- "$@" "(" -name .git -o -name .hg -o -name .svn ")" -prune -o
    fi
    if [ -n "$EXCLUDE_LIST" ]; then
        IFS="$NL"
        set -f
        for pat in $EXCLUDE_LIST; do
            set -- "$@" "(" -name "$pat" -o -path "./$pat" ")" -prune -o
        done
        set +f
        IFS="$DEFAULT_IFS"
    fi
    set -- "$@" "(" -name "*\\\\*" -o -name "*[[:cntrl:]]*" -o -name "*${NL}*" -o -name "*${CR}*" ")" -print

    unsafe_found=$(find "$@")
    if [ -n "$unsafe_found" ]; then
        safe_display=$(sanitize_text "$unsafe_found")
        die "$EXIT_MANIFEST" "Unsafe filename(s) containing backslashes or control characters (newlines/CR/escape sequences) detected: ${safe_display}"
    fi
}

# Check for unexpected symbolic links when --follow-symlinks (-L) is not enabled.
check_unexpected_symlinks() {
    if [ "$FOLLOW_SYMLINKS" -eq 1 ]; then
        return 0
    fi
    set -- .
    if [ "$EXCLUDE_VCS" -eq 1 ]; then
        set -- "$@" "(" -name .git -o -name .hg -o -name .svn ")" -prune -o
    fi
    if [ -n "$EXCLUDE_LIST" ]; then
        IFS="$NL"
        set -f
        for pat in $EXCLUDE_LIST; do
            set -- "$@" "(" -name "$pat" -o -path "./$pat" ")" -prune -o
        done
        set +f
        IFS="$DEFAULT_IFS"
    fi
    set -- "$@" -type l -print

    symlinks_found=$(find "$@")
    if [ -n "$symlinks_found" ]; then
        safe_display=$(sanitize_text "$symlinks_found")
        die "$EXIT_MANIFEST" "Symbolic link(s) detected in target directory: ${safe_display} (use -L/--follow-symlinks to follow or -x/--exclude to ignore)."
    fi
}

# Run find in current directory and either list files ("list") or hash them ("hash").
run_asset_find() {
    find_action="$1"
    set --
    if [ "$FOLLOW_SYMLINKS" -eq 1 ]; then
        set -- "$@" -L
    fi
    set -- "$@" .
    if [ "$EXCLUDE_VCS" -eq 1 ]; then
        set -- "$@" "(" -name .git -o -name .hg -o -name .svn ")" -prune -o
    fi
    # Always exclude macOS metadata file .DS_Store unless explicitly included
    set -- "$@" -name .DS_Store -prune -o
    if [ -n "$EXCLUDE_LIST" ]; then
        IFS="$NL"
        set -f
        for pat in $EXCLUDE_LIST; do
            set -- "$@" "(" -name "$pat" -o -path "./$pat" ")" -prune -o
        done
        set +f
        IFS="$DEFAULT_IFS"
    fi

    set -- "$@" -type f \
        ! -name "$MANIFEST_NAME" \
        ! -name "${MANIFEST_NAME}.asc" \
        ! -name "${MANIFEST_NAME}.gpg" \
        ! -name "${MANIFEST_NAME}.tsq" \
        ! -name "${MANIFEST_NAME}.tsr" \
        ! -name "${MANIFEST_NAME}.asc.tsq" \
        ! -name "${MANIFEST_NAME}.asc.tsr" \
        ! -name "*.tsq" \
        ! -name "*.tsr"

    if [ "$find_action" = "list" ]; then
        set -- "$@" -print
        find "$@"
    else
        # List files and hash in batches
        find "$@" -print
    fi
}

# Validate that every line in a manifest file conforms strictly to:
# "<64-lowercase-hex>  ./<safe-relative-path>" (or "<64-lowercase-hex>  <safe-relative-path>")
# and contains no path traversal (".."), leading slash, control characters, or duplicates.
validate_manifest_structure() {
    manifest_file="$1"
    normalized_out="$2"

    if [ ! -s "$manifest_file" ]; then
        die "$EXIT_MANIFEST" "Manifest file '$MANIFEST_NAME' is empty."
    fi

    awk_err=$(awk -v out_file="$normalized_out" '
    BEGIN {
        err = ""
        count = 0
    }
    {
        count++
        line = $0
        if (line ~ /[[:cntrl:]]/ || index(line, "\\") > 0) {
            err = sprintf("Line %d contains control characters or backslashes.", count)
            exit 1
        }
        if (length(line) < 67) {
            err = sprintf("Line %d is too short to be a valid SHA-256 entry.", count)
            exit 1
        }
        hash = substr(line, 1, 64)
        sep = substr(line, 65, 2)
        path = substr(line, 67)

        if (hash !~ /^[0-9a-fA-F]{64}$/) {
            err = sprintf("Line %d has an invalid SHA-256 hex digest.", count)
            exit 1
        }
        if (sep != "  " && sep !~ /^ [ *]$/) {
            err = sprintf("Line %d does not use standard two-space separator.", count)
            exit 1
        }
        if (path == "" || substr(path, 1, 1) == "/") {
            err = sprintf("Line %d contains an empty or absolute file path: %s", count, path)
            exit 1
        }
        # Normalize path to start with ./
        if (substr(path, 1, 2) != "./") {
            norm_path = "./" path
        } else {
            norm_path = path
        }
        # Reject any "." or ".." path traversal segments
        n = split(norm_path, parts, "/")
        for (i = 2; i <= n; i++) {
            if (parts[i] == "" || parts[i] == "." || parts[i] == "..") {
                err = sprintf("Line %d contains unsafe path segment in: %s", count, path)
                exit 1
            }
        }
        if (seen[norm_path]++) {
            err = sprintf("Line %d contains duplicate file path entry: %s", count, norm_path)
            exit 1
        }
        printf "%s  %s\n", tolower(hash), norm_path > out_file
    }
    END {
        if (err != "") {
            print err
            exit 1
        }
        if (count == 0) {
            print "Manifest contains zero entries."
            exit 1
        }
    }
    ' "$manifest_file" 2>&1) || die "$EXIT_MANIFEST" "Malformed manifest '$MANIFEST_NAME': $(sanitize_text "$awk_err")"
}

# ---------------------------------------------------------------------------
# OpenSSL RFC 3161 Parsing & Verification Helpers
# ---------------------------------------------------------------------------

# Parse openssl ts -query -text output into key=value lines:
# hash_alg, msg_data, nonce
parse_tsq_info() {
    tsq_path="$1"
    tsq_text_out="$WORK_TMPDIR/tsq_text.txt"
    if ! openssl ts -query -in "$tsq_path" -text >"$tsq_text_out" 2>"$WORK_TMPDIR/tsq_err.txt"; then
        err_msg=$(cat "$WORK_TMPDIR/tsq_err.txt" 2>/dev/null || true)
        die "$EXIT_TSA" "Failed to parse RFC 3161 timestamp query '$tsq_path': $(sanitize_text "$err_msg")"
    fi

    awk '
    /^Hash Algorithm:/ {
        sub(/^Hash Algorithm:[[:space:]]*/, "")
        gsub(/[[:space:]]+$/, "")
        hash_alg = tolower($0)
    }
    /^Message data:/ { in_msg = 1; next }
    in_msg && /^[[:space:]]+[0-9a-fA-F]+ - / {
        line = $0
        sub(/^[[:space:]]+[0-9a-fA-F]+ - /, "", line)
        sub(/  .*$/, "", line)
        gsub(/[^0-9a-fA-F]/, "", line)
        msg = msg tolower(line)
        next
    }
    in_msg { in_msg = 0 }
    /^Nonce:/ {
        sub(/^Nonce:[[:space:]]*/, "")
        gsub(/[[:space:]]+$/, "")
        nonce = tolower($0)
    }
    END {
        printf "TSQ_HASH_ALG=%s\nTSQ_MSG_DATA=%s\nTSQ_NONCE=%s\n", hash_alg, msg, nonce
    }
    ' "$tsq_text_out"
}

# Parse openssl ts -reply -text output into key=value lines:
# status, hash_alg, msg_data, nonce, timestamp, serial, tsa_name
parse_tsr_info() {
    tsr_path="$1"
    tsr_text_out="$WORK_TMPDIR/tsr_text.txt"
    if ! openssl ts -reply -in "$tsr_path" -text >"$tsr_text_out" 2>"$WORK_TMPDIR/tsr_err.txt"; then
        err_msg=$(cat "$WORK_TMPDIR/tsr_err.txt" 2>/dev/null || true)
        die "$EXIT_TSA" "Invalid RFC 3161 timestamp response '$tsr_path' (not a valid DER TimeStampResp): $(sanitize_text "$err_msg")"
    fi

    awk '
    /^Status:/ {
        sub(/^Status:[[:space:]]*/, "")
        gsub(/[[:space:]]+$/, "")
        status = $0
    }
    /^Status description:/ {
        sub(/^Status description:[[:space:]]*/, "")
        gsub(/[[:space:]]+$/, "")
        status_desc = $0
    }
    /^Failure info:/ {
        sub(/^Failure info:[[:space:]]*/, "")
        gsub(/[[:space:]]+$/, "")
        fail_info = $0
    }
    /^Hash Algorithm:/ {
        sub(/^Hash Algorithm:[[:space:]]*/, "")
        gsub(/[[:space:]]+$/, "")
        hash_alg = tolower($0)
    }
    /^Message data:/ { in_msg = 1; next }
    in_msg && /^[[:space:]]+[0-9a-fA-F]+ - / {
        line = $0
        sub(/^[[:space:]]+[0-9a-fA-F]+ - /, "", line)
        sub(/  .*$/, "", line)
        gsub(/[^0-9a-fA-F]/, "", line)
        msg = msg tolower(line)
        next
    }
    in_msg { in_msg = 0 }
    /^Serial number:/ {
        sub(/^Serial number:[[:space:]]*/, "")
        gsub(/[[:space:]]+$/, "")
        serial = $0
    }
    /^Time stamp:/ {
        sub(/^Time stamp:[[:space:]]*/, "")
        gsub(/[[:space:]]+$/, "")
        ts_time = $0
    }
    /^Nonce:/ {
        sub(/^Nonce:[[:space:]]*/, "")
        gsub(/[[:space:]]+$/, "")
        nonce = tolower($0)
    }
    /^TSA:/ {
        sub(/^TSA:[[:space:]]*/, "")
        gsub(/[[:space:]]+$/, "")
        tsa_name = $0
    }
    END {
        printf "TSR_STATUS=%s\nTSR_STATUS_DESC=%s\nTSR_FAIL_INFO=%s\nTSR_HASH_ALG=%s\nTSR_MSG_DATA=%s\nTSR_SERIAL=%s\nTSR_TIME=%s\nTSR_NONCE=%s\nTSR_TSA_NAME=%s\n",
            status, status_desc, fail_info, hash_alg, msg, serial, ts_time, nonce, tsa_name
    }
    ' "$tsr_text_out"
}

get_kv_field() {
    kv_blob="$1"
    kv_key="$2"
    printf '%s\n' "$kv_blob" | sed -n "s/^${kv_key}=//p" | head -n 1
}

# Validate RFC 3161 response token against signature file and optional query file.
verify_rfc3161_token() {
    v_sig_file="$1"
    v_tsr_file="$2"
    v_tsq_file="$3"
    v_require_cert_chain="$4"

    expected_sig_hash=$(hash_single_file "$v_sig_file")

    tsr_kv=$(parse_tsr_info "$v_tsr_file")
    tsr_status=$(get_kv_field "$tsr_kv" "TSR_STATUS")
    tsr_status_desc=$(get_kv_field "$tsr_kv" "TSR_STATUS_DESC")
    tsr_fail_info=$(get_kv_field "$tsr_kv" "TSR_FAIL_INFO")
    tsr_hash_alg=$(get_kv_field "$tsr_kv" "TSR_HASH_ALG")
    tsr_msg_data=$(get_kv_field "$tsr_kv" "TSR_MSG_DATA")
    tsr_nonce=$(get_kv_field "$tsr_kv" "TSR_NONCE")
    tsr_time=$(get_kv_field "$tsr_kv" "TSR_TIME")
    tsr_serial=$(get_kv_field "$tsr_kv" "TSR_SERIAL")
    tsr_tsa_name=$(get_kv_field "$tsr_kv" "TSR_TSA_NAME")

    case "$tsr_status" in
        "Granted." | "Granted with modifications.")
            ;;
        *)
            die "$EXIT_TSA" "TSA rejected timestamp request (Status: '$(sanitize_text "$tsr_status")', Description: '$(sanitize_text "$tsr_status_desc")', Failure: '$(sanitize_text "$tsr_fail_info")')."
            ;;
    esac

    if [ "$tsr_hash_alg" != "sha256" ] && [ "$tsr_hash_alg" != "sha-256" ]; then
        die "$EXIT_TSA" "Unexpected or weak hash algorithm in timestamp token: '$(sanitize_text "$tsr_hash_alg")' (expected sha256)."
    fi

    if [ "$tsr_msg_data" != "$expected_sig_hash" ]; then
        die "$EXIT_TSA" "Timestamp token message imprint ($tsr_msg_data) does NOT match SHA-256 of signature file ($expected_sig_hash)."
    fi

    if [ -n "$v_tsq_file" ] && [ -f "$v_tsq_file" ]; then
        tsq_kv=$(parse_tsq_info "$v_tsq_file")
        tsq_hash_alg=$(get_kv_field "$tsq_kv" "TSQ_HASH_ALG")
        tsq_msg_data=$(get_kv_field "$tsq_kv" "TSQ_MSG_DATA")
        tsq_nonce=$(get_kv_field "$tsq_kv" "TSQ_NONCE")

        if [ "$tsq_hash_alg" != "sha256" ] && [ "$tsq_hash_alg" != "sha-256" ]; then
            die "$EXIT_TSA" "Unexpected hash algorithm in timestamp query (.tsq): '$(sanitize_text "$tsq_hash_alg")'."
        fi
        if [ "$tsq_msg_data" != "$expected_sig_hash" ]; then
            die "$EXIT_TSA" "Timestamp query (.tsq) message imprint ($tsq_msg_data) does NOT match SHA-256 of signature file ($expected_sig_hash)."
        fi
        if [ -n "$tsq_nonce" ] && [ "$tsq_nonce" != "unspecified" ]; then
            if [ "$tsr_nonce" != "$tsq_nonce" ]; then
                die "$EXIT_TSA" "Timestamp response nonce ($tsr_nonce) does NOT match query nonce ($tsq_nonce). Possible replay or substitution attack!"
            fi
        fi
    fi

    # Perform cryptographic X.509 signature verification via openssl ts -verify if requested
    if [ "$v_require_cert_chain" -eq 1 ]; then
        ca_file_to_use="$TSA_CA_FILE"
        ca_path_to_use="$TSA_CA_PATH"

        # Auto-detect system CA bundle if neither -CAfile nor -CApath was explicitly given
        if [ -z "$ca_file_to_use" ] && [ -z "$ca_path_to_use" ]; then
            for sys_ca in \
                /etc/ssl/cert.pem \
                /etc/ssl/certs/ca-certificates.crt \
                /etc/pki/tls/certs/ca-bundle.crt \
                /etc/ssl/ca-bundle.pem \
                /opt/homebrew/etc/ca-certificates/cert.pem \
                /usr/local/etc/openssl/cert.pem; do
                if [ -f "$sys_ca" ]; then
                    ca_file_to_use="$sys_ca"
                    break
                fi
            done
        fi

        set -- ts -verify -data "$v_sig_file" -in "$v_tsr_file"
        if [ -n "$ca_file_to_use" ]; then
            set -- "$@" -CAfile "$ca_file_to_use"
        fi
        if [ -n "$ca_path_to_use" ]; then
            set -- "$@" -CApath "$ca_path_to_use"
        fi
        if [ -n "$TSA_UNTRUSTED_FILE" ]; then
            set -- "$@" -untrusted "$TSA_UNTRUSTED_FILE"
        fi

        if ! openssl "$@" >"$WORK_TMPDIR/ts_verify_out.txt" 2>"$WORK_TMPDIR/ts_verify_err.txt"; then
            ts_v_err=$(cat "$WORK_TMPDIR/ts_verify_err.txt" 2>/dev/null || true)
            die "$EXIT_TSA" "RFC 3161 X.509 certificate chain verification failed: $(sanitize_text "$ts_v_err") (Provide the TSA root CA via -C / --ca-file <cacert.pem>, or pass --no-ts-cert-verify to verify imprint/nonce only)."
        fi

        # If .tsq exists, also verify against -queryfile
        if [ -n "$v_tsq_file" ] && [ -f "$v_tsq_file" ]; then
            set -- ts -verify -queryfile "$v_tsq_file" -in "$v_tsr_file"
            if [ -n "$ca_file_to_use" ]; then
                set -- "$@" -CAfile "$ca_file_to_use"
            fi
            if [ -n "$ca_path_to_use" ]; then
                set -- "$@" -CApath "$ca_path_to_use"
            fi
            if [ -n "$TSA_UNTRUSTED_FILE" ]; then
                set -- "$@" -untrusted "$TSA_UNTRUSTED_FILE"
            fi
            if ! openssl "$@" >/dev/null 2>"$WORK_TMPDIR/ts_verify_q_err.txt"; then
                ts_vq_err=$(cat "$WORK_TMPDIR/ts_verify_q_err.txt" 2>/dev/null || true)
                die "$EXIT_TSA" "RFC 3161 queryfile verification failed: $(sanitize_text "$ts_vq_err")."
            fi
        fi
    fi

    log_detail "Timestamp Time : $(sanitize_text "${tsr_time:-unspecified}")"
    if [ -n "$tsr_tsa_name" ]; then
        log_detail "TSA Signer     : $(sanitize_text "$tsr_tsa_name")"
    fi
    if [ -n "$tsr_serial" ]; then
        log_detail "Token Serial   : $(sanitize_text "$tsr_serial")"
    fi
    if [ -n "$tsr_nonce" ]; then
        log_detail "Token Nonce    : $(sanitize_text "$tsr_nonce")"
    fi
}

# ---------------------------------------------------------------------------
# GPG Signing & Verification Helpers
# ---------------------------------------------------------------------------

verify_gpg_signature() {
    v_manifest="$1"
    v_sig="$2"

    gpg_status_file="$WORK_TMPDIR/gpg_status.txt"
    gpg_err_file="$WORK_TMPDIR/gpg_err.txt"

    # Detect whether signature is clearsigned or detached
    first_line=$( sed -n '1p' "$v_sig" 2>/dev/null || true )

    set -- --batch --no-tty --status-fd 1
    if [ -n "$GPG_HOMEDIR" ]; then
        set -- "$@" --homedir "$GPG_HOMEDIR"
    fi
    if [ -n "$GPG_KEYRING" ]; then
        set -- "$@" --keyring "$GPG_KEYRING"
    fi

    case "$first_line" in
        "-----BEGIN PGP SIGNED MESSAGE-----"*)
            extracted_manifest="$WORK_TMPDIR/extracted_manifest.txt"
            if ! gpg "$@" --output "$extracted_manifest" --decrypt -- "$v_sig" >"$gpg_status_file" 2>"$gpg_err_file"; then
                gpg_err=$(cat "$gpg_err_file" 2>/dev/null || true)
                die "$EXIT_GPG" "GPG clearsigned signature verification failed: $(sanitize_text "$gpg_err")"
            fi
            if ! cmp -s -- "$v_manifest" "$extracted_manifest"; then
                die "$EXIT_GPG" "Clearsigned payload inside '${v_sig##*/}' does NOT match '$MANIFEST_NAME' on disk!"
            fi
            ;;
        *)
            if ! gpg "$@" --verify -- "$v_sig" "$v_manifest" >"$gpg_status_file" 2>"$gpg_err_file"; then
                gpg_err=$(cat "$gpg_err_file" 2>/dev/null || true)
                die "$EXIT_GPG" "GPG detached signature verification failed: $(sanitize_text "$gpg_err")"
            fi
            ;;
    esac

    # Require explicit GOODSIG and VALIDSIG status tokens from GnuPG
    if ! grep -q '^\[GNUPG:\] GOODSIG ' "$gpg_status_file" || ! grep -q '^\[GNUPG:\] VALIDSIG ' "$gpg_status_file"; then
        die "$EXIT_GPG" "GPG did not report a valid GOODSIG/VALIDSIG status for '${v_sig##*/}'."
    fi

    # Check digest algorithm in VALIDSIG (field 9 in line: [GNUPG:] VALIDSIG <fpr> <date> <ts> <exp> <ver> <res> <pk_algo> <hash_algo> ...)
    # Reject MD5 (1), SHA-1 (2), RIPEMD160 (3)
    validsig_line=$(grep '^\[GNUPG:\] VALIDSIG ' "$gpg_status_file" | head -n 1)
    hash_algo_id=$(printf '%s\n' "$validsig_line" | awk '{print $10}')
    signer_fpr=$(printf '%s\n' "$validsig_line" | awk '{print $3}')
    case "$hash_algo_id" in
        1|2|3)
            die "$EXIT_GPG" "GPG signature uses weak/deprecated digest algorithm ID ($hash_algo_id). SHA-256 or stronger is required."
            ;;
    esac

    goodsig_uid=$(sed -n 's/^\[GNUPG:\] GOODSIG [0-9A-Fa-f]* //p' "$gpg_status_file" | head -n 1)
    log_detail "Signer Key     : $(sanitize_text "$signer_fpr")"
    if [ -n "$goodsig_uid" ]; then
        log_detail "Signer Identity: $(sanitize_text "$goodsig_uid")"
    fi
}

# ---------------------------------------------------------------------------
# Generate Mode
# ---------------------------------------------------------------------------

do_generate() {
    resolve_tsa_url "$TSA_SPEC"

    if [ ! -d "$TARGET_DIR" ]; then
        die "$EXIT_USAGE" "Target directory does not exist: '$(sanitize_text "$TARGET_DIR")'."
    fi

    setup_tmpdir

    # Stage all output files inside the secure temporary workspace first
    STAGE_MANIFEST="$WORK_TMPDIR/$MANIFEST_NAME"
    STAGE_SIG="$WORK_TMPDIR/${MANIFEST_NAME}.asc"
    STAGE_TSQ="$WORK_TMPDIR/${MANIFEST_NAME}.asc.tsq"
    STAGE_TSR="$WORK_TMPDIR/${MANIFEST_NAME}.asc.tsr"
    RAW_HASHES="$WORK_TMPDIR/raw_hashes.txt"
    FILE_LIST="$WORK_TMPDIR/file_list.txt"

    cd -- "$TARGET_DIR" || die "$EXIT_ERR" "Cannot enter target directory: '$(sanitize_text "$TARGET_DIR")'."
    ABS_TARGET_DIR=$(pwd)

    # 1. Security scan & deterministic SHA-256 checksum generation
    log_info "Hashing files in $(sanitize_text "$ABS_TARGET_DIR") (backend: $SHA256_BACKEND)..."
    check_unsafe_filenames
    check_unexpected_symlinks

    run_asset_find "list" > "$FILE_LIST"
    if [ ! -s "$FILE_LIST" ]; then
        die "$EXIT_MANIFEST" "No eligible files found to hash in '$(sanitize_text "$ABS_TARGET_DIR")'."
    fi

    # Hash found files safely via positional parameters in batches
    : > "$RAW_HASHES"
    # Since check_unsafe_filenames verified no newlines or backslashes exist in paths,
    # reading line-by-line with IFS= is 100% exact.
    set --
    batch_count=0
    while IFS= read -r rel_file; do
        [ -z "$rel_file" ] && continue
        set -- "$@" "$rel_file"
        batch_count=$((batch_count + 1))
        if [ "$batch_count" -ge 100 ]; then
            hash_files_batch "$@" >> "$RAW_HASHES"
            set --
            batch_count=0
        fi
    done < "$FILE_LIST"
    if [ "$#" -gt 0 ]; then
        hash_files_batch "$@" >> "$RAW_HASHES"
    fi

    # Sort deterministically by file path (column 67 onwards) under LC_ALL=C
    sort -k 1.67 -- "$RAW_HASHES" > "$STAGE_MANIFEST"

    # Self-validate manifest structure & entry count
    validate_manifest_structure "$STAGE_MANIFEST" "$WORK_TMPDIR/validated_manifest.txt"
    expected_count=$(wc -l < "$FILE_LIST" | tr -d '[:space:]')
    actual_count=$(wc -l < "$STAGE_MANIFEST" | tr -d '[:space:]')
    if [ "$expected_count" != "$actual_count" ]; then
        die "$EXIT_MANIFEST" "File count mismatch during manifest generation (expected $expected_count, got $actual_count)."
    fi

    log_detail "Hashed $actual_count file(s) -> $MANIFEST_NAME"

    # 2. Cryptographic GPG signature over the manifest
    log_info "Signing manifest with GPG ($GPG_SIGN_MODE mode)..."
    set -- --batch --yes --no-tty --armor --digest-algo SHA256
    if [ -n "$GPG_HOMEDIR" ]; then
        set -- "$@" --homedir "$GPG_HOMEDIR"
    fi
    if [ -n "$GPG_KEY" ]; then
        set -- "$@" --default-key "$GPG_KEY"
    fi
    if [ "$GPG_SIGN_MODE" = "clearsign" ]; then
        set -- "$@" --clearsign
    else
        set -- "$@" --detach-sign
    fi
    set -- "$@" --output "$STAGE_SIG" -- "$STAGE_MANIFEST"

    if ! gpg "$@" 2>"$WORK_TMPDIR/gpg_sign_err.txt"; then
        gpg_s_err=$(cat "$WORK_TMPDIR/gpg_sign_err.txt" 2>/dev/null || true)
        die "$EXIT_GPG" "GPG signing failed: $(sanitize_text "$gpg_s_err")"
    fi

    # Immediately self-verify the generated GPG signature
    verify_gpg_signature "$STAGE_MANIFEST" "$STAGE_SIG"

    # 3. Create RFC 3161 timestamp query (.tsq) over the signature file
    log_info "Creating RFC 3161 timestamp query..."
    if ! openssl ts -query \
        -data "$STAGE_SIG" \
        -sha256 \
        -cert \
        -out "$STAGE_TSQ" 2>"$WORK_TMPDIR/tsq_gen_err.txt"; then
        tsq_g_err=$(cat "$WORK_TMPDIR/tsq_gen_err.txt" 2>/dev/null || true)
        die "$EXIT_TSA" "Failed to generate RFC 3161 query: $(sanitize_text "$tsq_g_err")"
    fi

    # 4. Request RFC 3161 timestamp response token (.tsr) from TSA
    log_info "Requesting RFC 3161 timestamp from $(sanitize_text "$TSA_RESOLVED_URL")..."
    curl_err_file="$WORK_TMPDIR/curl_err.txt"
    http_status=$(curl -s -S \
        --proto '=https,http' \
        --connect-timeout "$TSA_TIMEOUT" \
        --max-time "$TSA_TIMEOUT" \
        -w '%{http_code}' \
        -H 'Content-Type: application/timestamp-query' \
        -H 'Accept: application/timestamp-reply' \
        --data-binary "@$STAGE_TSQ" \
        -o "$STAGE_TSR" \
        -- "$TSA_RESOLVED_URL" 2>"$curl_err_file") || {
        curl_err=$(cat "$curl_err_file" 2>/dev/null || true)
        die "$EXIT_TSA" "Network request to TSA '$(sanitize_text "$TSA_RESOLVED_URL")' failed: $(sanitize_text "$curl_err")"
    }

    if [ "$http_status" != "200" ]; then
        die "$EXIT_TSA" "TSA server '$(sanitize_text "$TSA_RESOLVED_URL")' returned HTTP status $http_status."
    fi

    if [ ! -s "$STAGE_TSR" ]; then
        die "$EXIT_TSA" "TSA server returned an empty response body."
    fi

    # 5. Validate the RFC 3161 response token (status, hash algorithm, message imprint, nonce, and optional CA chain)
    check_ca_on_gen=0
    if [ -n "$TSA_CA_FILE" ] || [ -n "$TSA_CA_PATH" ]; then
        check_ca_on_gen=1
    fi
    verify_rfc3161_token "$STAGE_SIG" "$STAGE_TSR" "$STAGE_TSQ" "$check_ca_on_gen"

    # 6. Atomically move verified artifacts into target directory
    chmod -- 0644 "$STAGE_MANIFEST" "$STAGE_SIG" "$STAGE_TSQ" "$STAGE_TSR"
    mv -f -- "$STAGE_MANIFEST" "./$MANIFEST_NAME"
    mv -f -- "$STAGE_SIG" "./${MANIFEST_NAME}.asc"
    mv -f -- "$STAGE_TSR" "./${MANIFEST_NAME}.asc.tsr"

    if [ "$KEEP_TSQ" -eq 1 ]; then
        mv -f -- "$STAGE_TSQ" "./${MANIFEST_NAME}.asc.tsq"
    else
        rm -f -- "./${MANIFEST_NAME}.asc.tsq"
    fi

    if [ "$QUIET" -eq 0 ]; then
        printf '\nAttestation artifacts successfully generated:\n'
        if [ "$KEEP_TSQ" -eq 1 ]; then
            ls -la -- "./$MANIFEST_NAME" "./${MANIFEST_NAME}.asc" "./${MANIFEST_NAME}.asc.tsq" "./${MANIFEST_NAME}.asc.tsr"
        else
            ls -la -- "./$MANIFEST_NAME" "./${MANIFEST_NAME}.asc" "./${MANIFEST_NAME}.asc.tsr"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Verify Mode
# ---------------------------------------------------------------------------

do_verify() {
    if [ ! -d "$TARGET_DIR" ]; then
        die "$EXIT_USAGE" "Target directory does not exist: '$(sanitize_text "$TARGET_DIR")'."
    fi

    setup_tmpdir

    cd -- "$TARGET_DIR" || die "$EXIT_ERR" "Cannot enter target directory: '$(sanitize_text "$TARGET_DIR")'."
    ABS_TARGET_DIR=$(pwd)

    V_MANIFEST="./$MANIFEST_NAME"
    V_SIG="./${MANIFEST_NAME}.asc"
    V_TSQ="./${MANIFEST_NAME}.asc.tsq"
    V_TSR="./${MANIFEST_NAME}.asc.tsr"

    log_info "Verifying attestation artifacts in $(sanitize_text "$ABS_TARGET_DIR")..."

    # Ensure core attestation artifacts exist and are regular files
    for req_artifact in "$V_MANIFEST" "$V_SIG" "$V_TSR"; do
        if [ "$FOLLOW_SYMLINKS" -eq 0 ] && [ -L "$req_artifact" ]; then
            die "$EXIT_MANIFEST" "Attestation artifact '${req_artifact#./}' is a symbolic link (rejected for security)."
        fi
        if [ ! -f "$req_artifact" ]; then
            die "$EXIT_MANIFEST" "Required attestation artifact not found: '${req_artifact#./}'."
        fi
        if [ ! -s "$req_artifact" ]; then
            die "$EXIT_MANIFEST" "Attestation artifact is empty: '${req_artifact#./}'."
        fi
    done

    if [ -e "$V_TSQ" ] && [ "$FOLLOW_SYMLINKS" -eq 0 ] && [ -L "$V_TSQ" ]; then
        die "$EXIT_MANIFEST" "Timestamp query artifact '${V_TSQ#./}' is a symbolic link (rejected for security)."
    fi

    # Layer 1: Verify RFC 3161 Timestamp over Signature
    log_info "[1/3] Verifying RFC 3161 timestamp (${V_TSR#./})..."
    tsq_arg=""
    if [ -f "$V_TSQ" ]; then
        tsq_arg="$V_TSQ"
    fi
    verify_rfc3161_token "$V_SIG" "$V_TSR" "$tsq_arg" "$VERIFY_TS_CERT"

    # Layer 2: Verify GPG Cryptographic Signature over Manifest
    log_info "[2/3] Verifying GPG signature (${V_SIG#./})..."
    verify_gpg_signature "$V_MANIFEST" "$V_SIG"

    # Layer 3: Verify Manifest Structure, Path Safety, and Asset Checksums
    log_info "[3/3] Verifying asset checksums (${V_MANIFEST#./})..."
    check_unsafe_filenames
    check_unexpected_symlinks

    NORM_MANIFEST="$WORK_TMPDIR/norm_manifest.txt"
    validate_manifest_structure "$V_MANIFEST" "$NORM_MANIFEST"

    MANIFEST_PATHS="$WORK_TMPDIR/manifest_paths.txt"
    sed 's/^[0-9a-f]\{64\}  //' "$NORM_MANIFEST" > "$MANIFEST_PATHS"

    # Verify each listed file exists, is a regular file (and not a symlink unless -L)
    missing_count=0
    while IFS= read -r m_path; do
        [ -z "$m_path" ] && continue
        if [ "$FOLLOW_SYMLINKS" -eq 0 ] && [ -L "$m_path" ]; then
            log_error "Asset is a symbolic link: $(sanitize_text "$m_path")"
            missing_count=$((missing_count + 1))
        elif [ ! -f "$m_path" ]; then
            log_error "Missing asset file: $(sanitize_text "$m_path")"
            missing_count=$((missing_count + 1))
        fi
    done < "$MANIFEST_PATHS"

    if [ "$missing_count" -gt 0 ]; then
        die "$EXIT_MANIFEST" "$missing_count asset file(s) missing or invalid."
    fi

    # Compute actual SHA-256 digests of all files listed in the manifest
    COMPUTED_HASHES="$WORK_TMPDIR/computed_hashes.txt"
    : > "$COMPUTED_HASHES"
    set --
    batch_count=0
    while IFS= read -r m_path; do
        [ -z "$m_path" ] && continue
        set -- "$@" "$m_path"
        batch_count=$((batch_count + 1))
        if [ "$batch_count" -ge 100 ]; then
            hash_files_batch "$@" >> "$COMPUTED_HASHES"
            set --
            batch_count=0
        fi
    done < "$MANIFEST_PATHS"
    if [ "$#" -gt 0 ]; then
        hash_files_batch "$@" >> "$COMPUTED_HASHES"
    fi

    SORTED_EXPECTED="$WORK_TMPDIR/sorted_expected.txt"
    SORTED_COMPUTED="$WORK_TMPDIR/sorted_computed.txt"
    sort -k 1.67 -- "$NORM_MANIFEST" > "$SORTED_EXPECTED"
    sort -k 1.67 -- "$COMPUTED_HASHES" > "$SORTED_COMPUTED"

    if ! cmp -s -- "$SORTED_EXPECTED" "$SORTED_COMPUTED"; then
        # Identify specific mismatched files
        awk '
        NR == FNR {
            h = substr($0, 1, 64)
            p = substr($0, 67)
            expected[p] = h
            next
        }
        {
            h = substr($0, 1, 64)
            p = substr($0, 67)
            if (expected[p] != h) {
                printf "MISMATCH: %s (expected %s, got %s)\n", p, expected[p], h
            }
        }
        ' "$SORTED_EXPECTED" "$SORTED_COMPUTED" >&2
        die "$EXIT_MANIFEST" "SHA-256 checksum verification FAILED for one or more files."
    fi

    verified_count=$(wc -l < "$SORTED_EXPECTED" | tr -d '[:space:]')
    log_detail "Verified $verified_count asset file(s) match $MANIFEST_NAME"

    # Check for untracked files on disk that are not listed in the manifest
    DISK_FILES_RAW="$WORK_TMPDIR/disk_files_raw.txt"
    DISK_FILES_SORTED="$WORK_TMPDIR/disk_files_sorted.txt"
    MANIFEST_PATHS_SORTED="$WORK_TMPDIR/manifest_paths_sorted.txt"
    run_asset_find "list" > "$DISK_FILES_RAW"
    sort -- "$DISK_FILES_RAW" > "$DISK_FILES_SORTED"
    sort -- "$MANIFEST_PATHS" > "$MANIFEST_PATHS_SORTED"

    UNTRACKED_FILES="$WORK_TMPDIR/untracked_files.txt"
    comm -23 -- "$DISK_FILES_SORTED" "$MANIFEST_PATHS_SORTED" > "$UNTRACKED_FILES"

    if [ -s "$UNTRACKED_FILES" ]; then
        untracked_count=$(wc -l < "$UNTRACKED_FILES" | tr -d '[:space:]')
        untracked_list=$(tr '\n' ' ' < "$UNTRACKED_FILES")
        if [ "$ALLOW_UNTRACKED" -eq 1 ]; then
            log_warn "$untracked_count untracked file(s) present in directory: $(sanitize_text "$untracked_list")"
        else
            die "$EXIT_MANIFEST" "$untracked_count untracked file(s) found in directory (not in $MANIFEST_NAME): $(sanitize_text "$untracked_list")(use --allow-untracked to ignore)."
        fi
    fi

    log_info "Verification PASSED: All $verified_count file(s), GPG signature, and RFC 3161 timestamp are valid."
}

# ---------------------------------------------------------------------------
# Command-Line Argument Parsing (POSIX sh)
# ---------------------------------------------------------------------------

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -h|--help)
                usage
                exit "$EXIT_OK"
                ;;
            -v|--version)
                printf '%s %s\n' "$PROGNAME" "$VERSION"
                exit "$EXIT_OK"
                ;;
            --list-tsa)
                list_tsa_presets
                exit "$EXIT_OK"
                ;;
            -V|--verify)
                MODE="verify"
                shift
                ;;
            -d|--dir)
                [ "$#" -ge 2 ] || die "$EXIT_USAGE" "Option '$1' requires a directory argument."
                TARGET_DIR="$2"
                shift 2
                ;;
            --dir=*)
                TARGET_DIR="${1#*=}"
                shift
                ;;
            -m|--manifest)
                [ "$#" -ge 2 ] || die "$EXIT_USAGE" "Option '$1' requires a filename argument."
                MANIFEST_NAME="$2"
                shift 2
                ;;
            --manifest=*)
                MANIFEST_NAME="${1#*=}"
                shift
                ;;
            -k|--gpg-key)
                [ "$#" -ge 2 ] || die "$EXIT_USAGE" "Option '$1' requires a GPG key argument."
                GPG_KEY="$2"
                shift 2
                ;;
            --gpg-key=*)
                GPG_KEY="${1#*=}"
                shift
                ;;
            --gpg-homedir)
                [ "$#" -ge 2 ] || die "$EXIT_USAGE" "Option '$1' requires a directory argument."
                GPG_HOMEDIR="$2"
                shift 2
                ;;
            --gpg-homedir=*)
                GPG_HOMEDIR="${1#*=}"
                shift
                ;;
            --keyring)
                [ "$#" -ge 2 ] || die "$EXIT_USAGE" "Option '$1' requires a file argument."
                GPG_KEYRING="$2"
                shift 2
                ;;
            --keyring=*)
                GPG_KEYRING="${1#*=}"
                shift
                ;;
            --clearsign)
                GPG_SIGN_MODE="clearsign"
                shift
                ;;
            -t|--tsa)
                [ "$#" -ge 2 ] || die "$EXIT_USAGE" "Option '$1' requires a TSA preset or URL argument."
                TSA_SPEC="$2"
                shift 2
                ;;
            --tsa=*)
                TSA_SPEC="${1#*=}"
                shift
                ;;
            --timeout)
                [ "$#" -ge 2 ] || die "$EXIT_USAGE" "Option '$1' requires a timeout in seconds."
                TSA_TIMEOUT="$2"
                shift 2
                ;;
            --timeout=*)
                TSA_TIMEOUT="${1#*=}"
                shift
                ;;
            --keep-tsq)
                KEEP_TSQ=1
                shift
                ;;
            --no-keep-tsq)
                KEEP_TSQ=0
                shift
                ;;
            -C|--ca-file)
                [ "$#" -ge 2 ] || die "$EXIT_USAGE" "Option '$1' requires a CA certificate file path."
                TSA_CA_FILE="$2"
                shift 2
                ;;
            --ca-file=*)
                TSA_CA_FILE="${1#*=}"
                shift
                ;;
            --ca-path)
                [ "$#" -ge 2 ] || die "$EXIT_USAGE" "Option '$1' requires a CA directory path."
                TSA_CA_PATH="$2"
                shift 2
                ;;
            --ca-path=*)
                TSA_CA_PATH="${1#*=}"
                shift
                ;;
            --untrusted)
                [ "$#" -ge 2 ] || die "$EXIT_USAGE" "Option '$1' requires a certificate file path."
                TSA_UNTRUSTED_FILE="$2"
                shift 2
                ;;
            --untrusted=*)
                TSA_UNTRUSTED_FILE="${1#*=}"
                shift
                ;;
            --no-ts-cert-verify)
                VERIFY_TS_CERT=0
                shift
                ;;
            -x|--exclude)
                [ "$#" -ge 2 ] || die "$EXIT_USAGE" "Option '$1' requires a glob pattern argument."
                case "$2" in
                    *"$NL"* | *"$CR"*)
                        die "$EXIT_USAGE" "Exclude pattern cannot contain newlines."
                        ;;
                esac
                if [ -z "$EXCLUDE_LIST" ]; then
                    EXCLUDE_LIST="$2"
                else
                    EXCLUDE_LIST="${EXCLUDE_LIST}${NL}$2"
                fi
                shift 2
                ;;
            --exclude=*)
                ex_pat="${1#*=}"
                case "$ex_pat" in
                    *"$NL"* | *"$CR"*)
                        die "$EXIT_USAGE" "Exclude pattern cannot contain newlines."
                        ;;
                esac
                if [ -z "$EXCLUDE_LIST" ]; then
                    EXCLUDE_LIST="$ex_pat"
                else
                    EXCLUDE_LIST="${EXCLUDE_LIST}${NL}${ex_pat}"
                fi
                shift
                ;;
            --include-vcs)
                EXCLUDE_VCS=0
                shift
                ;;
            -L|--follow-symlinks)
                FOLLOW_SYMLINKS=1
                shift
                ;;
            --allow-untracked)
                ALLOW_UNTRACKED=1
                shift
                ;;
            -q|--quiet)
                QUIET=1
                shift
                ;;
            --)
                shift
                break
                ;;
            -*)
                die "$EXIT_USAGE" "Unknown option: '$(sanitize_text "$1")'. Use --help for usage."
                ;;
            *)
                if [ -z "$TARGET_DIR" ]; then
                    TARGET_DIR="$1"
                else
                    die "$EXIT_USAGE" "Unexpected positional argument: '$(sanitize_text "$1")'."
                fi
                shift
                ;;
        esac
    done

    # Handle remaining positional argument after --
    if [ "$#" -gt 0 ]; then
        if [ -z "$TARGET_DIR" ] && [ "$#" -eq 1 ]; then
            TARGET_DIR="$1"
        else
            die "$EXIT_USAGE" "Too many positional arguments."
        fi
    fi

    if [ -z "$TARGET_DIR" ]; then
        TARGET_DIR="."
    fi

    # Validate MANIFEST_NAME is a simple filename without path separators or control chars
    case "$MANIFEST_NAME" in
        "" | .* | */* | *"\\"* | *[[:cntrl:]]*)
            die "$EXIT_USAGE" "Invalid manifest filename: '$(sanitize_text "$MANIFEST_NAME")' (must be a simple filename not starting with '.' or containing '/')."
            ;;
    esac

    # Validate KEEP_TSQ is 0 or 1
    case "$KEEP_TSQ" in
        0|1) ;;
        *) die "$EXIT_USAGE" "KEEP_TSQ must be 0 or 1 (got '$(sanitize_text "$KEEP_TSQ")')." ;;
    esac

    # Validate TSA_TIMEOUT is a positive integer
    case "$TSA_TIMEOUT" in
        ''|*[!0-9]*|0)
            die "$EXIT_USAGE" "Timeout must be a positive integer in seconds (got '$(sanitize_text "$TSA_TIMEOUT")')."
            ;;
    esac

    # Convert relative certificate/keyring paths to absolute paths before cd "$TARGET_DIR"
    orig_pwd=$(pwd)
    if [ -n "$TSA_CA_FILE" ]; then
        [ -f "$TSA_CA_FILE" ] || die "$EXIT_USAGE" "CA file not found: '$(sanitize_text "$TSA_CA_FILE")'."
        case "$TSA_CA_FILE" in
            /*) ;;
            *) TSA_CA_FILE="${orig_pwd}/${TSA_CA_FILE}" ;;
        esac
    fi
    if [ -n "$TSA_CA_PATH" ]; then
        [ -d "$TSA_CA_PATH" ] || die "$EXIT_USAGE" "CA directory not found: '$(sanitize_text "$TSA_CA_PATH")'."
        case "$TSA_CA_PATH" in
            /*) ;;
            *) TSA_CA_PATH="${orig_pwd}/${TSA_CA_PATH}" ;;
        esac
    fi
    if [ -n "$TSA_UNTRUSTED_FILE" ]; then
        [ -f "$TSA_UNTRUSTED_FILE" ] || die "$EXIT_USAGE" "Untrusted cert file not found: '$(sanitize_text "$TSA_UNTRUSTED_FILE")'."
        case "$TSA_UNTRUSTED_FILE" in
            /*) ;;
            *) TSA_UNTRUSTED_FILE="${orig_pwd}/${TSA_UNTRUSTED_FILE}" ;;
        esac
    fi
    if [ -n "$GPG_HOMEDIR" ]; then
        [ -d "$GPG_HOMEDIR" ] || die "$EXIT_USAGE" "GPG homedir not found: '$(sanitize_text "$GPG_HOMEDIR")'."
        case "$GPG_HOMEDIR" in
            /*) ;;
            *) GPG_HOMEDIR="${orig_pwd}/${GPG_HOMEDIR}" ;;
        esac
    fi
    if [ -n "$GPG_KEYRING" ]; then
        [ -f "$GPG_KEYRING" ] || die "$EXIT_USAGE" "GPG keyring not found: '$(sanitize_text "$GPG_KEYRING")'."
        case "$GPG_KEYRING" in
            /*) ;;
            *) GPG_KEYRING="${orig_pwd}/${GPG_KEYRING}" ;;
        esac
    fi
}

# ---------------------------------------------------------------------------
# Main Entrypoint
# ---------------------------------------------------------------------------

main() {
    parse_args "$@"
    check_dependencies

    case "$MODE" in
        generate)
            do_generate
            ;;
        verify)
            do_verify
            ;;
    esac
}

main "$@"
