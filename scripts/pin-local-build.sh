#!/usr/bin/env bash
# Track C local trust root: build, ad-hoc sign and pin the custody daemon and
# the Touch ID helper so they authenticate each other by exact code hash.
#
# Whoever runs this owns the trust root. No Apple Developer account, no
# signing identity and no binary from anyone else is involved: the pins name
# the cdhashes of the binaries built here, on this Mac.
#
# What it does
#   1. Builds mcp-enclave (dev fleet CLI), enclave-custody-vaultd and the
#      development variant of the enclave-intent helper (-D MCPMAC_DEV_SAME_UID:
#      accepts a custody peer at the console user's own UID, nothing else).
#   2. Copies them to target/track-c/bin, so a later `cargo build` cannot
#      silently replace a pinned binary, and ad-hoc signs each copy with
#      Hardened Runtime and its fixed identifier (com.enterprise.enclave.
#      custody / .intent): FS-706 code-signing Mode A, on the dev fleet.
#      Refuses on a Mac with an installed enclave deployment, whose pins it
#      would otherwise replace.
#   3. Reads each cdhash and writes them to the root-owned pin file both sides
#      already trust, /Library/Application Support/EnterpriseEnclave/
#      codesign-pins.json (one `sudo`). Root ownership means a process running
#      as you cannot swap a binary and re-pin it. Entries for other
#      identifiers in an existing file are kept; these two are replaced, so
#      an older build stops being trusted.
#   4. Prints the environment for a real-custody dev fleet.
#
# Any rebuild changes a cdhash: run this script again before the next run.
# This is the development (same-UID) path. The installed path, with custody
# as UID 703 under launchd and Developer ID signing, is the beta gate
# (docs/FEATURE_MDM_FLEET_DISTRIBUTION.md).
#
# Usage: scripts/pin-local-build.sh [--no-sudo]
#   --no-sudo  build, sign and print the pin file without installing it

set -euo pipefail
umask 022

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
OUT="$TARGET_DIR/track-c/bin"
PIN_DIR="/Library/Application Support/EnterpriseEnclave"
PIN_FILE="$PIN_DIR/codesign-pins.json"
CUSTODY_ID="com.enterprise.enclave.custody"
INTENT_ID="com.enterprise.enclave.intent"
INSTALL=1
[ "${1:-}" = "--no-sudo" ] && INSTALL=0

[ "$(uname -s)" = Darwin ] || {
	echo "[FAIL] macOS only" >&2
	exit 2
}
# The pin file is shared with installed deployments. On a Mac with an
# installed (for example MDM-managed) enclave, replacing its custody/helper
# pins would break that deployment, so refuse.
if ls /Library/LaunchDaemons/com.enterprise.enclave.*.plist >/dev/null 2>&1; then
	if [ "$INSTALL" = 1 ]; then
		echo "[FAIL] an installed enclave deployment is present (/Library/LaunchDaemons/com.enterprise.enclave.*);" >&2
		echo "       the development pins would replace its pins. Uninstall it (packaging/macos/uninstall.sh)" >&2
		echo "       or use a Mac without an installed fleet. --no-sudo still builds and stages." >&2
		exit 2
	fi
	echo "[WARN] installed enclave deployment present; --no-sudo stages pins without installing" >&2
fi

echo "== build"
cargo build --locked -p mcp-enclave --features simulation --bin mcp-enclave --bin enclave-pack
cargo build --locked -p enclave-custody-vaultd --bin enclave-custody-vaultd
(cd helpers/enclaveintent && swift build -c release --build-path .build-dev -Xswiftc -DMCPMAC_DEV_SAME_UID)
HELPER_BUILD="$(cd helpers/enclaveintent && swift build -c release --build-path .build-dev -Xswiftc -DMCPMAC_DEV_SAME_UID --show-bin-path)"

echo "== copy and ad-hoc sign"
mkdir -p "$OUT"
install -m 0755 "$TARGET_DIR/debug/mcp-enclave" "$OUT/mcp-enclave"
install -m 0755 "$TARGET_DIR/debug/enclave-pack" "$OUT/enclave-pack"
install -m 0755 "$TARGET_DIR/debug/enclave-custody-vaultd" "$OUT/enclave-custody-vaultd"
install -m 0755 "$HELPER_BUILD/enclave-intent" "$OUT/enclave-intent"
# Positive control: this must be the development helper, never a fleet build.
strings "$OUT/enclave-intent" | grep -q "MCPMac intent helper dev same-UID" ||
	{
		echo "[FAIL] enclave-intent lacks the development marker" >&2
		exit 1
	}
# FS-706 Mode A: ad-hoc with Hardened Runtime.
codesign --force --sign - --options runtime --identifier "$CUSTODY_ID" "$OUT/enclave-custody-vaultd"
codesign --force --sign - --options runtime --identifier "$INTENT_ID" "$OUT/enclave-intent"
cdhash() {
	codesign --display --verbose=3 "$1" 2>&1 | awk -F= '/^CDHash=/ {print tolower($2); exit}'
}
for bin in enclave-custody-vaultd enclave-intent; do
	codesign --verify --strict "$OUT/$bin"
done
CUSTODY_HASH="$(cdhash "$OUT/enclave-custody-vaultd")"
INTENT_HASH="$(cdhash "$OUT/enclave-intent")"
for h in "$CUSTODY_HASH" "$INTENT_HASH"; do
	[[ "$h" =~ ^[0-9a-f]{40}$ ]] || {
		echo "[FAIL] unexpected cdhash: $h" >&2
		exit 1
	}
done
echo "custody  $CUSTODY_ID  $CUSTODY_HASH"
echo "helper   $INTENT_ID   $INTENT_HASH"

echo "== pin file"
STAGED="$(mktemp "${TMPDIR:-/tmp}/codesign-pins.XXXXXX")"
trap 'rm -f "$STAGED"' EXIT
# Keep other identifiers from an existing file; replace these two.
/usr/bin/python3 -I - "$PIN_FILE" "$STAGED" "$CUSTODY_ID" "$CUSTODY_HASH" "$INTENT_ID" "$INTENT_HASH" <<'PY'
import json, os, sys
existing, staged, cid, ch, iid, ih = sys.argv[1:7]
pins = {}
if os.path.isfile(existing) and not os.path.islink(existing):
    with open(existing, "rb") as f:
        doc = json.load(f)
    if doc.get("v") != 1 or not isinstance(doc.get("pins"), dict):
        sys.exit("existing pin file is not version 1; refusing to merge")
    pins = doc["pins"]
pins[cid] = [ch]
pins[iid] = [ih]
with open(staged, "w") as f:
    json.dump({"v": 1, "pins": pins}, f, indent=1, sort_keys=True)
    f.write("\n")
PY
cat "$STAGED"
if [ "$INSTALL" = 1 ]; then
	echo "Installing root-owned pins (sudo):"
	sudo install -d -o root -g wheel -m 0755 "$PIN_DIR"
	sudo install -o root -g wheel -m 0644 "$STAGED" "$PIN_FILE"
	echo "[OK] $PIN_FILE"
else
	echo "[SKIP] --no-sudo: pins staged only; the helper and custody refuse each other until installed"
fi

cat <<EOF

Real-custody dev fleet environment:
  export MCP_ENCLAVE="$OUT/mcp-enclave"
  export MCP_ENCLAVE_REAL_CUSTODY=1
  export MCP_ENCLAVE_INTENT_HELPER="$OUT/enclave-intent"
Then, at the unlocked console (docs/TRACK_C_LOCAL_CEREMONY.md):
  scripts/track-c-ceremony.sh
EOF
