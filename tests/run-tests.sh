#!/bin/sh
#
# tests/run-tests.sh - Automated POSIX compliance, functional, and security
#                      test suite for mk-web-manifest.sh.
#
# Standards: POSIX.1-2017 / POSIX.1-2024 (IEEE Std 1003.1) compliant.
#

set -eu

LC_ALL=C
export LC_ALL

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
TARGET_SCRIPT="${PROJECT_ROOT}/mk-web-manifest.sh"

TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/posix-manifest-tests.XXXXXXXXXX")
chmod -- 0700 "$TEST_TMP"

cleanup_tests() {
    trap - EXIT HUP INT QUIT TERM
    if [ -n "$TEST_TMP" ] && [ -d "$TEST_TMP" ]; then
        rm -rf -- "$TEST_TMP"
    fi
}

trap 'cleanup_tests; exit 130' INT
trap 'cleanup_tests; exit 143' TERM
trap 'cleanup_tests; exit 129' HUP
trap 'cleanup_tests; exit 131' QUIT
trap 'cleanup_tests' EXIT

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_COUNT=0

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    printf '  [PASS] %s\n' "$1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    printf '  [FAIL] %s\n' "$1" >&2
    if [ "${2:-}" != "" ]; then
        printf '         Detail: %s\n' "$2" >&2
    fi
}

assert_eq() {
    expected="$1"
    actual="$2"
    label="$3"
    if [ "$expected" = "$actual" ]; then
        pass "$label"
    else
        fail "$label" "expected '$expected', got '$actual'"
    fi
}

assert_contains() {
    haystack="$1"
    needle="$2"
    label="$3"
    case "$haystack" in
        *"$needle"*)
            pass "$label"
            ;;
        *)
            fail "$label" "output did not contain '$needle' (got: '$haystack')"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Set up Local Cryptographic Test PKI (Real OpenSSL RFC 3161 TSA + Signer Keys)
# ---------------------------------------------------------------------------

PKI_DIR="${TEST_TMP}/pki"
MOCK_BIN="${TEST_TMP}/bin"
mkdir -p -- "$PKI_DIR" "$MOCK_BIN"

cat > "${PKI_DIR}/tsa.cnf" <<EOF
[ tsa ]
default_tsa = tsa_config1

[ tsa_config1 ]
dir = ${PKI_DIR}
serial = \$dir/tsaserial
crypto_device = builtin
signer_cert = \$dir/tsa.crt
certs = \$dir/tsa.crt
signer_key = \$dir/tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256, sha384, sha512
accuracy = secs:1, millisecs:500, microsecs:100
ordering = yes
tsa_name = yes
ess_cert_id_alg = sha256

[ v3_tsa ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,nonRepudiation
extendedKeyUsage = critical,timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

printf '01\n' > "${PKI_DIR}/tsaserial"

# Generate Root CA and RFC 3161 TSA Leaf Certificate
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${PKI_DIR}/ca.key" \
    -out "${PKI_DIR}/ca.crt" \
    -subj "/CN=POSIX Test Root CA" \
    -days 1 \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

openssl req -newkey rsa:2048 -nodes \
    -keyout "${PKI_DIR}/tsa.key" \
    -out "${PKI_DIR}/tsa.csr" \
    -subj "/CN=POSIX Test TSA Signer" 2>/dev/null

openssl x509 -req \
    -in "${PKI_DIR}/tsa.csr" \
    -CA "${PKI_DIR}/ca.crt" \
    -CAkey "${PKI_DIR}/ca.key" \
    -CAcreateserial \
    -out "${PKI_DIR}/tsa.crt" \
    -days 1 \
    -extfile "${PKI_DIR}/tsa.cnf" \
    -extensions v3_tsa 2>/dev/null

# Generate RSA keypair for deterministic offline GPG harness
openssl genpkey -algorithm RSA -out "${PKI_DIR}/gpg_sim.key" -pkeyopt rsa_keygen_bits:2048 2>/dev/null
openssl pkey -in "${PKI_DIR}/gpg_sim.key" -pubout -out "${PKI_DIR}/gpg_sim.pub" 2>/dev/null

# Create local curl shim that routes RFC 3161 HTTP requests to real `openssl ts -reply`
cat > "${MOCK_BIN}/curl" <<EOF
#!/bin/sh
set -eu
out_file=""
data_file=""
url=""
while [ "\$#" -gt 0 ]; do
    case "\$1" in
        -o) out_file="\$2"; shift 2 ;;
        --data-binary)
            data_file="\${2#@}"
            shift 2
            ;;
        --connect-timeout|--max-time|-w|-H|--proto)
            shift 2
            ;;
        -s|-S)
            shift
            ;;
        --)
            shift
            url="\$1"
            break
            ;;
        http://*|https://*)
            url="\$1"
            shift
            ;;
        *)
            shift
            ;;
    esac
done

case "\${MOCK_TSA_MODE:-ok}" in
    http500)
        printf 'Internal Server Error\n' > "\$out_file"
        printf '500'
        exit 0
        ;;
    netfail)
        printf 'curl: (6) Could not resolve host\n' >&2
        exit 6
        ;;
    corrupt_der)
        printf '<html>Not a DER token</html>\n' > "\$out_file"
        printf '200'
        exit 0
        ;;
    wrong_imprint)
        printf 'wrong-data\n' > "${PKI_DIR}/wrong_data.txt"
        openssl ts -query -data "${PKI_DIR}/wrong_data.txt" -sha256 -cert -out "${PKI_DIR}/wrong.tsq" 2>/dev/null
        openssl ts -reply -config "${PKI_DIR}/tsa.cnf" -queryfile "${PKI_DIR}/wrong.tsq" -out "\$out_file" 2>/dev/null
        printf '200'
        exit 0
        ;;
    ok|*)
        openssl ts -reply -config "${PKI_DIR}/tsa.cnf" -queryfile "\$data_file" -out "\$out_file" 2>/dev/null
        printf '200'
        exit 0
        ;;
esac
EOF
chmod +x "${MOCK_BIN}/curl"

# Create OpenSSL-backed GnuPG harness so tests run reliably even in sandboxes
# that restrict gpg-agent UNIX domain socket bind().
cat > "${MOCK_BIN}/gpg" <<EOF
#!/bin/sh
set -eu
mode=""
sig_type="detached"
out_file=""
status_fd=""
pos1=""
pos2=""

while [ "\$#" -gt 0 ]; do
    case "\$1" in
        --version)
            printf 'gpg (GnuPG-Test-Harness) 2.5.0\n'
            exit 0
            ;;
        --detach-sign)
            mode="sign"
            sig_type="detached"
            shift
            ;;
        --clearsign)
            mode="sign"
            sig_type="clearsign"
            shift
            ;;
        --verify)
            mode="verify"
            shift
            ;;
        --decrypt)
            mode="decrypt"
            shift
            ;;
        --output|-o)
            out_file="\$2"
            shift 2
            ;;
        --status-fd)
            status_fd="\$2"
            shift 2
            ;;
        --default-key|--homedir|--keyring|--digest-algo)
            shift 2
            ;;
        --batch|--yes|--no-tty|--armor)
            shift
            ;;
        --)
            shift
            while [ "\$#" -gt 0 ]; do
                if [ -z "\$pos1" ]; then
                    pos1="\$1"
                else
                    pos2="\$1"
                fi
                shift
            done
            break
            ;;
        -*)
            shift
            ;;
        *)
            if [ -z "\$pos1" ]; then
                pos1="\$1"
            else
                pos2="\$1"
            fi
            shift
            ;;
    esac
done

FPR="A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
ALGO_ID="\${MOCK_GPG_HASH_ALGO_ID:-8}"

if [ "\$mode" = "sign" ]; then
    if [ "\${MOCK_GPG_FAIL_SIGN:-0}" = "1" ]; then
        printf 'gpg: signing failed: secret key not available\n' >&2
        exit 2
    fi
    raw_sig=\$(openssl dgst -sha256 -sign "${PKI_DIR}/gpg_sim.key" "\$pos1" | base64 | tr -d '\n')
    if [ "\$sig_type" = "clearsign" ]; then
        {
            printf -- '-----BEGIN PGP SIGNED MESSAGE-----\n'
            printf -- 'Hash: SHA256\n\n'
            cat -- "\$pos1"
            printf -- '-----BEGIN PGP SIGNATURE-----\n\n'
            printf '%s\n' "\$raw_sig"
            printf -- '-----END PGP SIGNATURE-----\n'
        } > "\$out_file"
    else
        {
            printf -- '-----BEGIN PGP SIGNATURE-----\n\n'
            printf '%s\n' "\$raw_sig"
            printf -- '-----END PGP SIGNATURE-----\n'
        } > "\$out_file"
    fi
    exit 0
fi

if [ "\$mode" = "decrypt" ]; then
    # Extract clearsigned body and verify signature
    sig_file="\$pos1"
    awk '
        /^-----BEGIN PGP SIGNED MESSAGE-----/ { in_hdr = 1; next }
        in_hdr && /^$/ { in_hdr = 0; in_body = 1; next }
        in_hdr { next }
        /^-----BEGIN PGP SIGNATURE-----/ { in_body = 0; in_sig = 1; next }
        /^-----END PGP SIGNATURE-----/ { in_sig = 0; next }
        in_body { print > "'"${PKI_DIR}/dec_body.txt"'" }
        in_sig && NF > 0 { print > "'"${PKI_DIR}/dec_sig.b64"'" }
    ' "\$sig_file"
    base64 -d < "${PKI_DIR}/dec_sig.b64" > "${PKI_DIR}/dec_sig.bin" 2>/dev/null || base64 -D < "${PKI_DIR}/dec_sig.b64" > "${PKI_DIR}/dec_sig.bin" 2>/dev/null
    if ! openssl dgst -sha256 -verify "${PKI_DIR}/gpg_sim.pub" -signature "${PKI_DIR}/dec_sig.bin" "${PKI_DIR}/dec_body.txt" >/dev/null 2>&1; then
        printf 'gpg: BAD signature\n' >&2
        exit 1
    fi
    cp -- "${PKI_DIR}/dec_body.txt" "\$out_file"
    printf '[GNUPG:] GOODSIG %s Test Signer <signer@example.com>\n' "\$FPR"
    printf '[GNUPG:] VALIDSIG %s 2026-11-04 1762290000 0 4 0 1 %s 01 %s\n' "\$FPR" "\$ALGO_ID" "\$FPR"
    exit 0
fi

if [ "\$mode" = "verify" ]; then
    sig_file="\$pos1"
    data_file="\$pos2"
    sed -n '/^-----BEGIN PGP SIGNATURE-----/,/^-----END PGP SIGNATURE-----/{
        /^-----/d
        /^$/d
        p
    }' "\$sig_file" > "${PKI_DIR}/ver_sig.b64"
    if [ ! -s "${PKI_DIR}/ver_sig.b64" ]; then
        printf 'gpg: no valid OpenPGP data found.\n' >&2
        exit 2
    fi
    base64 -d < "${PKI_DIR}/ver_sig.b64" > "${PKI_DIR}/ver_sig.bin" 2>/dev/null || base64 -D < "${PKI_DIR}/ver_sig.b64" > "${PKI_DIR}/ver_sig.bin" 2>/dev/null
    if ! openssl dgst -sha256 -verify "${PKI_DIR}/gpg_sim.pub" -signature "${PKI_DIR}/ver_sig.bin" "\$data_file" >/dev/null 2>&1; then
        printf 'gpg: BAD signature from Test Signer\n' >&2
        exit 1
    fi
    printf '[GNUPG:] GOODSIG %s Test Signer <signer@example.com>\n' "\$FPR"
    printf '[GNUPG:] VALIDSIG %s 2026-11-04 1762290000 0 4 0 1 %s 01 %s\n' "\$FPR" "\$ALGO_ID" "\$FPR"
    exit 0
fi
EOF
chmod +x "${MOCK_BIN}/gpg"

PATH="${MOCK_BIN}:${PATH}"
export PATH

# ---------------------------------------------------------------------------
# 1. POSIX Shell Syntax & Standards Audit
# ---------------------------------------------------------------------------
printf '\n=== 1. POSIX Shell Syntax & Non-POSIX Construct Audit ===\n'

for sh_bin in /bin/sh /bin/dash /bin/ksh /bin/bash /bin/zsh; do
    if [ -x "$sh_bin" ]; then
        if "$sh_bin" -n "$TARGET_SCRIPT" 2>/dev/null; then
            pass "Syntax valid under $sh_bin -n"
        else
            fail "Syntax valid under $sh_bin -n"
        fi
    fi
done

# Ensure zero non-POSIX 'local ' declarations or '[[' bashisms exist in code lines
if grep -v '^[[:space:]]*#' "$TARGET_SCRIPT" | grep -Eq '(^|[[:space:];])local[[:space:]]+|(^|[[:space:];(])\[\[[[:space:]]|echo[[:space:]]+-[ne]'; then
    fail "Zero bashisms (local, [[, echo -n/-e) in mk-web-manifest.sh"
else
    pass "Zero bashisms (local, [[, echo -n/-e) in mk-web-manifest.sh"
fi

if command -v mandoc >/dev/null 2>&1; then
    if mandoc -T lint -W warning "${PROJECT_ROOT}/mk-web-manifest.1" >/dev/null 2>&1; then
        pass "POSIX man page (mk-web-manifest.1) passes mandoc -T lint -W warning"
    else
        fail "POSIX man page (mk-web-manifest.1) passes mandoc -T lint -W warning"
    fi
fi

# ---------------------------------------------------------------------------
# 2. CLI Options, Help, Version & TSA Presets
# ---------------------------------------------------------------------------
printf '\n=== 2. CLI Options, Help, Version & TSA Presets ===\n'

help_out=$("$TARGET_SCRIPT" --help)
assert_contains "$help_out" "Usage:" "--help prints usage"

ver_out=$("$TARGET_SCRIPT" --version)
assert_contains "$ver_out" "mk-web-manifest.sh 2.0.0" "--version prints version string"

tsa_out=$("$TARGET_SCRIPT" --list-tsa)
assert_contains "$tsa_out" "freetsa" "--list-tsa includes freetsa"
assert_contains "$tsa_out" "digicert" "--list-tsa includes digicert"
assert_contains "$tsa_out" "sectigo" "--list-tsa includes sectigo"
assert_contains "$tsa_out" "globalsign" "--list-tsa includes globalsign"
assert_contains "$tsa_out" "entrust" "--list-tsa includes entrust"

# Invalid flag should exit with EXIT_USAGE (2)
rc=0
"$TARGET_SCRIPT" --no-such-flag >/dev/null 2>&1 || rc=$?
assert_eq "2" "$rc" "Unknown CLI flag exits with code 2 (EXIT_USAGE)"

# Invalid TSA URL/preset should exit with EXIT_USAGE (2)
rc=0
"$TARGET_SCRIPT" -t "ftp://bad.example.com" "$TEST_TMP" >/dev/null 2>&1 || rc=$?
assert_eq "2" "$rc" "Invalid TSA scheme (ftp://) exits with code 2 (EXIT_USAGE)"

# Invalid manifest name with slash should exit with EXIT_USAGE (2)
rc=0
"$TARGET_SCRIPT" -m "../evil" "$TEST_TMP" >/dev/null 2>&1 || rc=$?
assert_eq "2" "$rc" "Path traversal in -m manifest name exits with code 2 (EXIT_USAGE)"

# ---------------------------------------------------------------------------
# 3. Cross-Backend SHA-256 Determinism & Edge-Case Filenames
# ---------------------------------------------------------------------------
printf '\n=== 3. Cross-Backend SHA-256 Determinism & Edge-Case Filenames ===\n'

ASSET_DIR="${TEST_TMP}/assets_determinism"
mkdir -p -- "${ASSET_DIR}/sub/nested" "${ASSET_DIR}/.git"
printf '<!doctype html><title>Hello</title>\n' > "${ASSET_DIR}/index.html"
printf 'body { color: #123456; }\n' > "${ASSET_DIR}/sub/style.css"
printf 'console.log("hi");\n' > "${ASSET_DIR}/sub/nested/App_ABCDEF.js"
printf 'dash-leading-content\n' > "${ASSET_DIR}/-leading-dash.txt"
printf 'spaces-content\n' > "${ASSET_DIR}/file with  two spaces.txt"
printf 'git-internal\n' > "${ASSET_DIR}/.git/config"

REF_MANIFEST="${TEST_TMP}/ref_SHA256SUMS"

for backend in sha256sum shasum sha256 openssl; do
    if command -v "$backend" >/dev/null 2>&1; then
        POSIX_MANIFEST_SHA256_BACKEND="$backend" "$TARGET_SCRIPT" -q -t digicert -C "${PKI_DIR}/ca.crt" "$ASSET_DIR"
        if [ ! -f "$REF_MANIFEST" ]; then
            cp -- "${ASSET_DIR}/SHA256SUMS" "$REF_MANIFEST"
        fi
        if cmp -s -- "$REF_MANIFEST" "${ASSET_DIR}/SHA256SUMS"; then
            pass "Identical deterministic SHA256SUMS with backend '$backend'"
        else
            fail "Identical deterministic SHA256SUMS with backend '$backend'"
        fi
    fi
done

# Ensure .git was excluded by default
if grep -q '\.git' "$REF_MANIFEST"; then
    fail ".git directory excluded by default"
else
    pass ".git directory excluded by default"
fi

# Ensure uppercase characters in filenames (App_ABCDEF.js) were preserved
if grep -q 'App_ABCDEF\.js' "$REF_MANIFEST"; then
    pass "Uppercase hex letters A-F in filenames preserved intact"
else
    fail "Uppercase hex letters A-F in filenames preserved intact"
fi

# ---------------------------------------------------------------------------
# 4. End-to-End Generation & Three-Layer Verification
# ---------------------------------------------------------------------------
printf '\n=== 4. End-to-End Generation & Three-Layer Verification ===\n'

E2E_DIR="${TEST_TMP}/e2e_site"
mkdir -p -- "${E2E_DIR}/js"
printf '<h1>Signed Site</h1>\n' > "${E2E_DIR}/index.html"
printf 'export const v = 1;\n' > "${E2E_DIR}/js/main.js"
printf 'ignore-me\n' > "${E2E_DIR}/secret.bak"

"$TARGET_SCRIPT" -t sectigo -C "${PKI_DIR}/ca.crt" -x "*.bak" "$E2E_DIR" >/dev/null

for art in SHA256SUMS SHA256SUMS.asc SHA256SUMS.asc.tsq SHA256SUMS.asc.tsr; do
    if [ -s "${E2E_DIR}/${art}" ]; then
        pass "Artifact ${art} created and non-empty"
    else
        fail "Artifact ${art} created and non-empty"
    fi
done

# Verify with -V and -C ca.crt (and same exclusion -x "*.bak")
if "$TARGET_SCRIPT" -V -C "${PKI_DIR}/ca.crt" -x "*.bak" "$E2E_DIR" >/dev/null; then
    pass "Three-layer verification (-V) succeeds on valid bundle"
else
    fail "Three-layer verification (-V) succeeds on valid bundle"
fi

# Test --no-keep-tsq mode and verification without .tsq
"$TARGET_SCRIPT" -q --no-keep-tsq -t freetsa -C "${PKI_DIR}/ca.crt" -x "*.bak" "$E2E_DIR"
if [ ! -e "${E2E_DIR}/SHA256SUMS.asc.tsq" ]; then
    pass "--no-keep-tsq removes SHA256SUMS.asc.tsq"
else
    fail "--no-keep-tsq removes SHA256SUMS.asc.tsq"
fi

if "$TARGET_SCRIPT" -V -q -C "${PKI_DIR}/ca.crt" -x "*.bak" "$E2E_DIR"; then
    pass "Verification succeeds when .tsq is omitted"
else
    fail "Verification succeeds when .tsq is omitted"
fi

# Test --clearsign mode and verification
"$TARGET_SCRIPT" -q --clearsign -t entrust -C "${PKI_DIR}/ca.crt" -x "*.bak" "$E2E_DIR"
if "$TARGET_SCRIPT" -V -q -C "${PKI_DIR}/ca.crt" -x "*.bak" "$E2E_DIR"; then
    pass "--clearsign generation and verification succeed"
else
    fail "--clearsign generation and verification succeed"
fi

# Test clearsign desynchronization attack (modifying SHA256SUMS while keeping valid clearsigned SHA256SUMS.asc)
printf '0000000000000000000000000000000000000000000000000000000000000000  ./injected.txt\n' >> "${E2E_DIR}/SHA256SUMS"
rc=0
"$TARGET_SCRIPT" -V -q -C "${PKI_DIR}/ca.crt" -x "*.bak" "$E2E_DIR" 2>/dev/null || rc=$?
assert_eq "5" "$rc" "Clearsign payload mismatch against modified SHA256SUMS is rejected (exit 5)"

# Regenerate clean detached bundle for security tests
"$TARGET_SCRIPT" -q -t freetsa -C "${PKI_DIR}/ca.crt" -x "*.bak" "$E2E_DIR"

# ---------------------------------------------------------------------------
# 5. Security & Tamper Detection Tests
# ---------------------------------------------------------------------------
printf '\n=== 5. Security & Tamper Detection Tests ===\n'

# 5a. Tampered asset file
printf '<!-- backdoor -->\n' >> "${E2E_DIR}/index.html"
rc=0
"$TARGET_SCRIPT" -V -q -C "${PKI_DIR}/ca.crt" -x "*.bak" "$E2E_DIR" 2>/dev/null || rc=$?
assert_eq "4" "$rc" "Tampered asset file detected and rejected (exit 4)"
# Restore index.html
printf '<h1>Signed Site</h1>\n' > "${E2E_DIR}/index.html"

# 5b. Untracked file planted in directory
printf 'malicious payload\n' > "${E2E_DIR}/untracked_evil.js"
rc=0
"$TARGET_SCRIPT" -V -q -C "${PKI_DIR}/ca.crt" -x "*.bak" "$E2E_DIR" 2>/dev/null || rc=$?
assert_eq "4" "$rc" "Untracked file planted in directory detected and rejected (exit 4)"

# Verify --allow-untracked permits untracked file with warning
if "$TARGET_SCRIPT" -V -q --allow-untracked -C "${PKI_DIR}/ca.crt" -x "*.bak" "$E2E_DIR" 2>/dev/null; then
    pass "--allow-untracked allows untracked file with warning"
else
    fail "--allow-untracked allows untracked file with warning"
fi
rm -f -- "${E2E_DIR}/untracked_evil.js"

# 5c. Missing asset file
mv -- "${E2E_DIR}/js/main.js" "${TEST_TMP}/main.js.saved"
rc=0
"$TARGET_SCRIPT" -V -q -C "${PKI_DIR}/ca.crt" -x "*.bak" "$E2E_DIR" 2>/dev/null || rc=$?
assert_eq "4" "$rc" "Missing asset file detected and rejected (exit 4)"
mv -- "${TEST_TMP}/main.js.saved" "${E2E_DIR}/js/main.js"

# 5d. Symlink replacement attack
ln -s /etc/hosts "${E2E_DIR}/evil_link"
rc=0
"$TARGET_SCRIPT" -V -q -C "${PKI_DIR}/ca.crt" -x "*.bak" "$E2E_DIR" 2>/dev/null || rc=$?
assert_eq "4" "$rc" "Unexpected symbolic link rejected during verification (exit 4)"
rc=0
"$TARGET_SCRIPT" -q -C "${PKI_DIR}/ca.crt" -x "*.bak" "$E2E_DIR" 2>/dev/null || rc=$?
assert_eq "4" "$rc" "Unexpected symbolic link rejected during generation (exit 4)"
rm -f -- "${E2E_DIR}/evil_link"

# 5e. Unsafe filenames (newline, backslash, ANSI escape control char)
ESC_CHAR=$(printf '\033')
touch "${E2E_DIR}/bad\\backslash.txt"
rc=0
"$TARGET_SCRIPT" -q -C "${PKI_DIR}/ca.crt" -x "*.bak" "$E2E_DIR" 2>/dev/null || rc=$?
assert_eq "4" "$rc" "Filename with backslash rejected (exit 4)"
rm -f -- "${E2E_DIR}/bad\\backslash.txt"

touch "${E2E_DIR}/bad${ESC_CHAR}ansi.txt"
rc=0
"$TARGET_SCRIPT" -q -C "${PKI_DIR}/ca.crt" -x "*.bak" "$E2E_DIR" 2>/dev/null || rc=$?
assert_eq "4" "$rc" "Filename with ANSI escape control character rejected (exit 4)"
rm -f -- "${E2E_DIR}/bad${ESC_CHAR}ansi.txt"

# 5f. Path traversal ("../") and duplicate entries in signed manifest
TRAV_DIR="${TEST_TMP}/trav_test"
mkdir -p -- "$TRAV_DIR"
printf 'hello\n' > "${TRAV_DIR}/a.txt"
"$TARGET_SCRIPT" -q -C "${PKI_DIR}/ca.crt" "$TRAV_DIR"

# Create a signed & timestamped manifest containing a ../ traversal entry
cat > "${TRAV_DIR}/SHA256SUMS" <<EOF
5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  ./../a.txt
EOF
"${MOCK_BIN}/gpg" --detach-sign --output "${TRAV_DIR}/SHA256SUMS.asc" -- "${TRAV_DIR}/SHA256SUMS"
openssl ts -query -data "${TRAV_DIR}/SHA256SUMS.asc" -sha256 -cert -out "${TRAV_DIR}/SHA256SUMS.asc.tsq" 2>/dev/null
openssl ts -reply -config "${PKI_DIR}/tsa.cnf" -queryfile "${TRAV_DIR}/SHA256SUMS.asc.tsq" -out "${TRAV_DIR}/SHA256SUMS.asc.tsr" 2>/dev/null
rc=0
"$TARGET_SCRIPT" -V -q -C "${PKI_DIR}/ca.crt" "$TRAV_DIR" 2>/dev/null || rc=$?
assert_eq "4" "$rc" "Path traversal (./../) inside manifest rejected (exit 4)"

# Create a signed & timestamped manifest containing duplicate file entries
cat > "${TRAV_DIR}/SHA256SUMS" <<EOF
5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  ./a.txt
5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  ./a.txt
EOF
"${MOCK_BIN}/gpg" --detach-sign --output "${TRAV_DIR}/SHA256SUMS.asc" -- "${TRAV_DIR}/SHA256SUMS"
openssl ts -query -data "${TRAV_DIR}/SHA256SUMS.asc" -sha256 -cert -out "${TRAV_DIR}/SHA256SUMS.asc.tsq" 2>/dev/null
openssl ts -reply -config "${PKI_DIR}/tsa.cnf" -queryfile "${TRAV_DIR}/SHA256SUMS.asc.tsq" -out "${TRAV_DIR}/SHA256SUMS.asc.tsr" 2>/dev/null
rc=0
"$TARGET_SCRIPT" -V -q -C "${PKI_DIR}/ca.crt" "$TRAV_DIR" 2>/dev/null || rc=$?
assert_eq "4" "$rc" "Duplicate file entry inside manifest rejected (exit 4)"

# 5g. Weak GPG digest algorithm (SHA-1 = algorithm ID 2) rejected
"$TARGET_SCRIPT" -q -C "${PKI_DIR}/ca.crt" "$TRAV_DIR"
rc=0
MOCK_GPG_HASH_ALGO_ID=2 "$TARGET_SCRIPT" -V -q -C "${PKI_DIR}/ca.crt" "$TRAV_DIR" 2>/dev/null || rc=$?
assert_eq "5" "$rc" "Weak GPG digest algorithm (SHA-1) rejected during verification (exit 5)"

# 5h. Tampered GPG signature
printf 'tampered\n' >> "${E2E_DIR}/SHA256SUMS.asc"
rc=0
"$TARGET_SCRIPT" -V -q -C "${PKI_DIR}/ca.crt" -x "*.bak" "$E2E_DIR" 2>/dev/null || rc=$?
assert_eq "6" "$rc" "Tampered SHA256SUMS.asc caught at Layer 1 RFC 3161 imprint check (exit 6)"

# 5i. Atomic staging rollback on TSA failure (existing valid artifacts must survive!)
"$TARGET_SCRIPT" -q -C "${PKI_DIR}/ca.crt" "$TRAV_DIR"
orig_tsr_hash=$(openssl dgst -sha256 -r "${TRAV_DIR}/SHA256SUMS.asc.tsr" | awk '{print $1}')

rc=0
MOCK_TSA_MODE="http500" "$TARGET_SCRIPT" -q -C "${PKI_DIR}/ca.crt" "$TRAV_DIR" 2>/dev/null || rc=$?
assert_eq "6" "$rc" "TSA HTTP 500 error fails with exit code 6 (EXIT_TSA)"

rc=0
MOCK_TSA_MODE="corrupt_der" "$TARGET_SCRIPT" -q -C "${PKI_DIR}/ca.crt" "$TRAV_DIR" 2>/dev/null || rc=$?
assert_eq "6" "$rc" "TSA HTTP 200 with invalid DER body fails with exit code 6 (EXIT_TSA)"

rc=0
MOCK_TSA_MODE="wrong_imprint" "$TARGET_SCRIPT" -q -C "${PKI_DIR}/ca.crt" "$TRAV_DIR" 2>/dev/null || rc=$?
assert_eq "6" "$rc" "TSA token with mismatched message imprint fails with exit code 6 (EXIT_TSA)"

after_tsr_hash=$(openssl dgst -sha256 -r "${TRAV_DIR}/SHA256SUMS.asc.tsr" | awk '{print $1}')
assert_eq "$orig_tsr_hash" "$after_tsr_hash" "Atomic staging preserves pre-existing valid artifacts when TSA fails"

# ---------------------------------------------------------------------------
# 6. Archive Rotation (-a) & Original Publication Date Proof (-P)
# ---------------------------------------------------------------------------
printf '\n=== 6. Archive Rotation (-a) & Original Publication Date Proof (-P) ===\n'

PUB_DIR="${TEST_TMP}/pub_site"
mkdir -p -- "${PUB_DIR}/articles"
printf '<h1>Home v1</h1>\n' > "${PUB_DIR}/index.html"
printf 'Original whitepaper v1 content\n' > "${PUB_DIR}/articles/first-post.pdf"

# Initial publication with -a
"$TARGET_SCRIPT" -q -a -t digicert -C "${PKI_DIR}/ca.crt" "$PUB_DIR"
first_tsr_hash=$(openssl dgst -sha256 -r "${PUB_DIR}/SHA256SUMS.asc.tsr" | awk '{print $1}')

# Re-running with -a when no files changed should skip regeneration and keep the original .tsr
# (Even with MOCK_TSA_MODE=http500, it must succeed because no TSA request is made)
if MOCK_TSA_MODE="http500" "$TARGET_SCRIPT" -q -a -t digicert -C "${PKI_DIR}/ca.crt" "$PUB_DIR"; then
    pass "-a skips TSA request and exits 0 when no tracked files changed"
else
    fail "-a skips TSA request and exits 0 when no tracked files changed"
fi

unchanged_tsr_hash=$(openssl dgst -sha256 -r "${PUB_DIR}/SHA256SUMS.asc.tsr" | awk '{print $1}')
assert_eq "$first_tsr_hash" "$unchanged_tsr_hash" "-a preserves original .tsr token when site is unchanged"

# If TSA fails during an update with -a, no partial proofs/ directory should be created
printf '<h1>Home v2</h1>\n' > "${PUB_DIR}/index.html"
rc=0
MOCK_TSA_MODE="http500" "$TARGET_SCRIPT" -q -a -t digicert -C "${PKI_DIR}/ca.crt" "$PUB_DIR" 2>/dev/null || rc=$?
assert_eq "6" "$rc" "TSA failure during -a exits with code 6"
if [ ! -d "${PUB_DIR}/proofs" ]; then
    pass "Atomic staging with -a leaves no partial proofs/ directory on TSA failure"
else
    fail "Atomic staging with -a leaves no partial proofs/ directory on TSA failure"
fi

# Now succeed on site update (index.html modified + second-post.pdf added; first-post.pdf untouched)
printf 'Second article content\n' > "${PUB_DIR}/articles/second-post.pdf"
"$TARGET_SCRIPT" -q -a -t digicert -C "${PKI_DIR}/ca.crt" "$PUB_DIR"

if [ -d "${PUB_DIR}/proofs" ]; then
    pass "-a creates proofs/<timestamp>/ archive directory on site update"
else
    fail "-a creates proofs/<timestamp>/ archive directory on site update"
fi

if grep -q '^\([0-9a-f]\{64\}\)  \./proofs/.*/SHA256SUMS\.asc\.tsr$' "${PUB_DIR}/SHA256SUMS"; then
    pass "New root SHA256SUMS cryptographically chains archived proofs/<timestamp>/ artifacts"
else
    fail "New root SHA256SUMS cryptographically chains archived proofs/<timestamp>/ artifacts"
fi

if "$TARGET_SCRIPT" -V -q -C "${PKI_DIR}/ca.crt" "$PUB_DIR"; then
    pass "Full site verification (-V) passes with chained proofs/ archive"
else
    fail "Full site verification (-V) passes with chained proofs/ archive"
fi

# Prove original publication date of ./articles/first-post.pdf via -P
prove_out=$("$TARGET_SCRIPT" -P "articles/first-post.pdf" -C "${PKI_DIR}/ca.crt" "$PUB_DIR")
assert_contains "$prove_out" "Verified Proofs: 2 bundle(s)" "-P verifies both archived and live proof bundles for unchanged file"
assert_contains "$prove_out" "./proofs/" "-P identifies earliest proof inside ./proofs/<timestamp>/"

# Prove publication date of newly added ./articles/second-post.pdf (only in latest bundle)
prove_new_out=$("$TARGET_SCRIPT" -P "articles/second-post.pdf" -C "${PKI_DIR}/ca.crt" "$PUB_DIR")
assert_contains "$prove_new_out" "Verified Proofs: 1 bundle(s)" "-P verifies single proof bundle for newly added file"

# Tampering with first-post.pdf causes -P to fail with exit code 4
printf 'tampered content\n' >> "${PUB_DIR}/articles/first-post.pdf"
rc=0
"$TARGET_SCRIPT" -P "articles/first-post.pdf" -q -C "${PKI_DIR}/ca.crt" "$PUB_DIR" 2>/dev/null || rc=$?
assert_eq "4" "$rc" "-P rejects modified file whose SHA-256 matches no signed proof (exit 4)"

# ---------------------------------------------------------------------------
# 7. Cross-Shell Execution Test (/bin/sh, /bin/dash, /bin/ksh)
# ---------------------------------------------------------------------------
printf '\n=== 7. Cross-Shell Full Execution (/bin/sh, /bin/dash, /bin/ksh) ===\n'

for shell_bin in /bin/sh /bin/dash /bin/ksh; do
    if [ -x "$shell_bin" ]; then
        SHELL_TEST_DIR="${TEST_TMP}/shell_${shell_bin##*/}"
        mkdir -p -- "$SHELL_TEST_DIR"
        printf 'test content for %s\n' "$shell_bin" > "${SHELL_TEST_DIR}/asset.txt"
        if "$shell_bin" "$TARGET_SCRIPT" -q -t apple -C "${PKI_DIR}/ca.crt" "$SHELL_TEST_DIR" && \
           "$shell_bin" "$TARGET_SCRIPT" -V -q -C "${PKI_DIR}/ca.crt" "$SHELL_TEST_DIR"; then
            pass "Full generate + verify lifecycle under $shell_bin"
        else
            fail "Full generate + verify lifecycle under $shell_bin"
        fi
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf -- '\n------------------------------------------------------------\n'
printf 'Test Summary: %d/%d passed (%d failed)\n' "$PASS_COUNT" "$TOTAL_COUNT" "$FAIL_COUNT"
printf -- '------------------------------------------------------------\n'

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
exit 0
