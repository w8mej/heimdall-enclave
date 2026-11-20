#!/usr/bin/env bash
# ==============================================================================
# depot Workstation Bootstrap — v1.0-Legacy Python Architectural Simulation
# Target: Apple Silicon macOS 14.0+ (hardware mode) or any POSIX host (--ci-vm mode)
#
# Remediates F-011 / F-007 / F-031:
#   * umask 077 is set BEFORE any key material is generated.
#   * Default install root is /opt/enterprise/enclave (matches envoy-local.yaml and
#     spire-agent-macos.conf). Use --prefix DIR for unprivileged local/CI testing.
#   * ECDSA P-256 local CA + gateway certificate with X.509v3 subjectAltName
#     (IP:127.0.0.1, URI:spiffe://<trust_domain>/ns/enclave/gateway).
#   * --ci-vm skips the SEP and FileVault gates (reported as SKIPPED, never PASSED)
#     because GitHub-hosted macOS runners are Virtualization.framework guests.
#   * Installs scripts/break-glass.sh into <prefix>/bin.
#
# This script does NOT load pf rules; loading is an explicit operator step (printed below).
# It makes no compliance claim (no HIPAA / SOC 2 / GDPR attestation is implied).
# ==============================================================================

set -euo pipefail
umask 077

PREFIX="/opt/enterprise/enclave"
CI_VM=0
TRUST_DOMAIN="${depot_TRUST_DOMAIN:-corporate.internal}"

usage() {
	echo "Usage: $0 [--prefix DIR] [--ci-vm] [--trust-domain NAME]"
	echo "  --prefix DIR        install root (default /opt/enterprise/enclave; requires root)"
	echo "  --ci-vm             VM/CI mode: skip SEP + FileVault hardware gates (reported as SKIPPED)"
	echo "  --trust-domain NAME SPIFFE trust domain for the gateway SAN (default corporate.internal)"
}

while [ $# -gt 0 ]; do
	case "$1" in
	--prefix)
		PREFIX="${2:?--prefix requires a directory}"
		shift 2
		;;
	--ci-vm)
		CI_VM=1
		shift
		;;
	--trust-domain)
		TRUST_DOMAIN="${2:?--trust-domain requires a value}"
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "Unknown argument: $1"
		usage
		exit 2
		;;
	esac
done

if ! [[ "$TRUST_DOMAIN" =~ ^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$ ]]; then
	echo "[FAIL] invalid trust domain: $TRUST_DOMAIN"
	exit 2
fi

BOLD="\033[1m"
GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"
log_info() { echo -e "${BLUE}[INFO]${RESET} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${RESET} $1"; }
log_skip() { echo -e "${YELLOW}[SKIP]${RESET} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${RESET} $1"; }
log_fail() { echo -e "${RED}[FAIL]${RESET} $1"; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo -e "${BOLD}================================================================="
echo " depot Workstation Bootstrap (v1.0-Legacy Python Simulation)"
echo " Mode: $([ $CI_VM -eq 1 ] && echo 'CI-VM (hardware gates skipped)' || echo 'HARDWARE')   Prefix: $PREFIX"
echo -e "=================================================================${RESET}\n"

# 1. Host architecture
ARCH=$(uname -m)
if [ "$(uname -s)" = "Darwin" ] && [ "$ARCH" = "arm64" ]; then
	log_pass "Apple Silicon host: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo arm64)"
elif [ $CI_VM -eq 1 ]; then
	log_skip "Non-Apple-Silicon host ($(uname -s)/$ARCH) accepted in --ci-vm mode"
else
	log_fail "Hardware mode requires Apple Silicon macOS (found $(uname -s)/$ARCH). Use --ci-vm for simulation."
	exit 1
fi

# 2. Secure Enclave
if [ $CI_VM -eq 1 ]; then
	log_skip "SEP presence check skipped (--ci-vm): VM guests expose no AppleSEPManager"
elif ioreg -r -c AppleSEPManager 2>/dev/null | grep -q "AppleSEPManager"; then
	log_pass "AppleSEPManager present in IORegistry"
else
	log_fail "AppleSEPManager not found. Hardware mode requires a physical Apple Silicon Mac."
	exit 1
fi

# 3. FileVault
if [ $CI_VM -eq 1 ]; then
	log_skip "FileVault check skipped (--ci-vm): VM guests report FileVault Off"
elif fdesetup status 2>/dev/null | grep -q "FileVault is On"; then
	log_pass "FileVault is On"
else
	log_fail "FileVault is OFF. Enable FileVault before handling any test data."
	exit 1
fi

# 4. Install root
if [ "$PREFIX" = "/opt/enterprise/enclave" ] && [ "$(id -u)" -ne 0 ]; then
	log_fail "Default prefix /opt/enterprise/enclave requires root. Re-run with sudo, or pass --prefix DIR."
	exit 1
fi
case "$PREFIX" in /tmp/* | /private/tmp/*) log_warn "Prefix under /tmp is world-traversable and wiped on reboot; use only for throwaway tests." ;; esac
mkdir -p "$PREFIX"/{policies,certs,bin,logs,spire/data,spire/keys}
chmod 0750 "$PREFIX"
chmod 0700 "$PREFIX"/certs "$PREFIX"/spire/keys "$PREFIX"/logs
cp examples/executive-poc/policies/*.rego "$PREFIX/policies/"
install -m 0750 scripts/break-glass.sh "$PREFIX/bin/break-glass.sh"
log_pass "Enclave tree created at $PREFIX (root 0750; certs/keys/logs 0700); break-glass.sh installed"

# 5. Local PKI — ECDSA P-256 with subjectAltName (umask 077 already in force)
if command -v openssl >/dev/null 2>&1; then
	C="$PREFIX/certs"
	EXT="$(mktemp "${TMPDIR:-/tmp}/depot-ext.XXXXXX")"
	trap 'rm -f "$EXT"' EXIT
	openssl ecparam -name prime256v1 -genkey -noout -out "$C/local-ca.key"
	openssl req -x509 -new -key "$C/local-ca.key" -sha256 -days 1 \
		-subj "/CN=depot Local Enclave Ephemeral CA" -out "$C/local-ca.crt" \
		-extensions v3_ca -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n')
	openssl ecparam -name prime256v1 -genkey -noout -out "$C/gateway.key"
	openssl req -new -key "$C/gateway.key" -sha256 -subj "/CN=127.0.0.1" -out "$C/gateway.csr"
	printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,IP:::1,URI:spiffe://%s/ns/enclave/gateway\n' "$TRUST_DOMAIN" >"$EXT"
	openssl x509 -req -in "$C/gateway.csr" -CA "$C/local-ca.crt" -CAkey "$C/local-ca.key" \
		-CAcreateserial -sha256 -days 1 -extfile "$EXT" -out "$C/gateway.crt" 2>/dev/null
	rm -f "$C/gateway.csr"
	chmod 0600 "$C"/*.key
	if openssl x509 -in "$C/gateway.crt" -noout -text | grep -q "URI:spiffe://$TRUST_DOMAIN/ns/enclave/gateway"; then
		log_pass "ECDSA P-256 CA + gateway certificate minted (24h) with SAN IP:127.0.0.1, URI:spiffe://$TRUST_DOMAIN/ns/enclave/gateway"
	else
		log_fail "gateway certificate is missing the required subjectAltName"
		exit 1
	fi
else
	log_fail "OpenSSL CLI not found; cannot mint certificates"
	exit 1
fi

# 6. pf rules: validate the file exists; loading is an explicit operator action
if [ -f examples/executive-poc/gateway/pf-rules.conf ]; then
	log_info "pf rules are NOT loaded by this script. Validate and load as an operator step:"
	echo "  sudo pfctl -vnf $REPO_ROOT/examples/executive-poc/gateway/pf-rules.conf"
	echo "  sudo pfctl -a com.enterprise.llm.isolation -f $REPO_ROOT/examples/executive-poc/gateway/pf-rules.conf && sudo pfctl -E"
fi

# 6b. v3.0 daemon accounts, socket client groups and per-daemon directories
# (GAP-01 / GAP-36). Generated by `depot-enclave launchd render`; root-only and
# idempotent, so it is an explicit operator step like pf.
if [ -f launchd/provision-accounts.sh ]; then
	log_info "v3.0 daemon accounts are NOT created by this script. Provision as an operator step:"
	echo "  sudo $REPO_ROOT/launchd/provision-accounts.sh"
fi

# 7. Attestation self-check (informational in --ci-vm mode)
if [ $CI_VM -eq 1 ]; then
	python3 examples/executive-poc/identity/macos_attestation.py || log_skip "attestation pre-flight NON-COMPLIANT in --ci-vm mode (expected: no SEP/FileVault)"
else
	python3 examples/executive-poc/identity/macos_attestation.py
fi

echo -e "\n${BOLD}${GREEN}✔ Bootstrap completed ($([ $CI_VM -eq 1 ] && echo 'CI-VM simulation mode' || echo 'hardware mode')).${RESET}"
echo "Next: ./scripts/verify-enclave.sh$([ $CI_VM -eq 1 ] && echo ' --ci-vm')"
