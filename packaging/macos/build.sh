#!/bin/sh
# Phase 2 step 1 (GAP-15, GAP-36): build, package and sign the five daemons,
# the operator CLI / root supervisor, and UID 703's EnclaveCustody.app.
# Run as your normal user from anywhere in the repo; nothing is installed:
#
#   sh packaging/macos/build.sh
#   sudo sh packaging/macos/install.sh
#
# Signing modes (fixed at build time, see enclave-core/src/codesign.rs):
#
# * Ad-hoc (default, no Apple Developer account): every binary is signed
#   `-` with the hardened runtime and launchd/enclave-daemon.entitlements.
#   Peers then authenticate by signing identifier + exact cdhash, read from
#   dist/codesign-pins.json, which install.sh puts root-owned at
#   /Library/Application Support/EnterpriseEnclave/codesign-pins.json.
# * Team ID: set depot_SIGNING_IDENTITY ("Developer ID Application: …"),
#   depot_SIGNING_TEAM_ID and depot_PROVISIONING_PROFILE. The binaries are
#   compiled to require `anchor apple generic` + the Team ID, UID 703 gets
#   keychain-access-groups and its embedded profile, and no pins are needed.
#
# Authenticator (GAP-13), one switch:
#
# * depot_YUBIKEY=hid (default): UID 703 drives a physical FIDO2 key over
#   IOKit HID (seized). No emulator is built or installed.
# * depot_YUBIKEY=emulated: UID 703 is built with `ctap-emulator`, and the
#   out-of-process CTAPHID emulator (`enclave-fido-emulator`) is deployed
#   under its own account `_enclavefido` (UID 706). It speaks the same raw
#   64-byte reports a YubiKey does. To move to a real key, drop the switch,
#   rebuild, reinstall and enroll the key: install.sh removes the emulator.
#
# The output in .enclave-local/dist/ (gitignored) is what install.sh deploys.
set -eu
cd "$(dirname "$0")/../.."
[ "$(uname -s)" = Darwin ] || {
	echo "build.sh: run this on macOS"
	exit 1
}
[ "$(id -u)" -ne 0 ] || {
	echo "build.sh: run as your normal user (install.sh is the root step)"
	exit 1
}
# Default packaging retains its existing environment setup. Configured builds
# validate first, before sourcing any user shell setup.
if [ -z "${depot_DEPLOYMENT_CONFIG:-}" ]; then
	# shellcheck source=/dev/null
	if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi
fi

DIST="${depot_DIST:-.enclave-local/dist}"
SIGN_ID="${depot_SIGNING_IDENTITY:--}"
TEAM="${depot_SIGNING_TEAM_ID:-}"
if [ "$SIGN_ID" != "-" ] && [ -z "$TEAM" ]; then
	echo "build.sh: depot_SIGNING_IDENTITY needs depot_SIGNING_TEAM_ID (the binaries compile the Team ID in)"
	exit 2
fi
if [ -n "$TEAM" ]; then
	[ "$SIGN_ID" != "-" ] || {
		echo "build.sh: depot_SIGNING_TEAM_ID needs a real depot_SIGNING_IDENTITY"
		exit 2
	}
	[ -f "${depot_PROVISIONING_PROFILE:-}" ] || {
		echo "build.sh: Team-ID builds need depot_PROVISIONING_PROFILE for UID 703"
		exit 2
	}
	export depot_SIGNING_TEAM_ID="$TEAM"
	MODE=team-id
else
	unset depot_SIGNING_TEAM_ID
	MODE=local-pins
fi

YUBIKEY="${depot_YUBIKEY:-hid}"
case "$YUBIKEY" in
hid)
	CUSTODY_FEATURES=macos-hid
	RENDER_FLAGS=""
	;;
emulated)
	CUSTODY_FEATURES=macos-hid,ctap-emulator
	RENDER_FLAGS="--with-fido-emulator"
	;;
*)
	echo "build.sh: depot_YUBIKEY must be hid or emulated, got $YUBIKEY"
	exit 2
	;;
esac

# A host-specific public key must come from actual target provisioning.
# No private material is accepted here or shipped in the distribution.
GRANT_PUBLIC="${depot_IFC_GRANT_PUBLIC_KEY:-}"
[ "${#GRANT_PUBLIC}" -eq 64 ] || {
	echo 'build.sh: set depot_IFC_GRANT_PUBLIC_KEY to the provisioned target Ed25519 public key'
	exit 2
}
case "$GRANT_PUBLIC" in *[!0-9a-fA-F]*)
	echo 'build.sh: grant public key must be hex'
	exit 2
	;;
esac

# Configured builds require an already prepared validator before Cargo or any
# output cleanup. A missing/stale executable refuses; building it is a separate
# preparation step. The check reads protected public configuration only.
if [ -n "${depot_DEPLOYMENT_CONFIG:-}" ]; then
	DEPLOYMENT_VALIDATOR="${depot_DEPLOYMENT_VALIDATOR:-target/release/depot-enclave}"
	[ -x "$DEPLOYMENT_VALIDATOR" ] || {
		echo 'build.sh: configured build needs an existing compatible depot_DEPLOYMENT_VALIDATOR'
		exit 2
	}
	"$DEPLOYMENT_VALIDATOR" --profile "${depot_BUILD_PROFILE:-L2}" --json \
		--deployment-config "$depot_DEPLOYMENT_CONFIG" launchd deployment-check \
		--dist "$DIST" --signing-mode "$MODE" >/dev/null
	# shellcheck source=/dev/null
	if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi
fi

# Hermetic reproducible build flags (GAP-55).
ZERO_AR_DATE=1
export ZERO_AR_DATE
RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$(pwd)=/build -C link-arg=-Wl,-dead_strip"
export RUSTFLAGS

# Release binaries, exactly as shipped (no `simulation` feature, GAP-03).
cargo build --release --locked --workspace --bins
# UID 703 with its authenticator transport(s) (and the emulator, if chosen).
cargo build --release --locked -p enclave-custody-vaultd --features "$CUSTODY_FEATURES" --bins
R=target/release

rm -rf "$DIST"
mkdir -p "$DIST/bin" "$DIST/launchd"
# Optional public configuration stays at its independently provisioned protected
# path. Never copy issuer/private material or manufacture a policy during build.
set -- --profile "${depot_BUILD_PROFILE:-L2}" --json launchd render --out "$DIST/launchd"
if [ -n "${depot_DEPLOYMENT_CONFIG:-}" ]; then
	set -- "$@" --deployment-config "$depot_DEPLOYMENT_CONFIG"
fi
if [ -n "$RENDER_FLAGS" ]; then set -- "$@" "$RENDER_FLAGS"; fi
if [ -n "${depot_CUSTODY_AUTHORITY_CONFIG:-}" ]; then
	set -- "$@" --custody-authority-config "$depot_CUSTODY_AUTHORITY_CONFIG"
fi
"$R/depot-enclave" "$@" >/dev/null
echo "$YUBIKEY" >"$DIST/yubikey-transport"
ENT="$DIST/launchd/enclave-daemon.entitlements"

# binary:signing-identifier (identifiers are the launchd labels; the CLI,
# which also runs the root supervisor, is com.enterprise.enclave.ctl).
TARGETS="depot-enclave:com.enterprise.enclave.ctl
enclave-model-runnerd:com.enterprise.enclave.adapter
enclave-swarm-syncd:com.enterprise.enclave.cas
enclave-apfs-broker:com.enterprise.enclave.apfs-broker
enclave-agent-runtime:com.enterprise.enclave.ifc
enclave-zk-auditor:com.enterprise.enclave.zk
enclave-cdp-browser:com.enterprise.enclave.browser
enclave-client-gateway:com.enterprise.enclave.gateway
enclave-intent:com.enterprise.enclave.intent"
if [ "$YUBIKEY" = emulated ]; then
	TARGETS="$TARGETS
enclave-fido-emulator:com.enterprise.enclave.fido"
fi

# GAP-14: build the _enclaveintent helper
if [ -n "$TEAM" ]; then
	(cd helpers/enclaveintent && swift build -c release -Xswiftc -D -Xswiftc depot_TEAM_ID_MODE >/dev/null)
else
	(cd helpers/enclaveintent && swift build -c release >/dev/null)
fi
cp helpers/enclaveintent/.build/release/enclave-intent "$DIST/bin/enclave-intent"
# Track C: the development helper trusts a same-UID custody peer. A fleet
# package must never carry it (scripts/pin-local-build.sh builds it apart).
if strings "$DIST/bin/enclave-intent" | grep -q "depot intent helper dev same-UID"; then
	echo "[FAIL] enclave-intent is the development same-UID build; refusing to package" >&2
	exit 1
fi

sign() { # path identifier entitlements
	codesign --force --sign "$SIGN_ID" --options runtime --timestamp=none \
		--entitlements "$3" --identifier "$2" "$1"
}

echo "$TARGETS" | while IFS=: read -r bin ident; do
	[ -f "$R/$bin" ] && cp "$R/$bin" "$DIST/bin/$bin"
	if [ "$bin" = enclave-apfs-broker ] && [ -n "${depot_APFS_BROKER_ENTITLEMENTS:-}" ]; then
		[ -f "$depot_APFS_BROKER_ENTITLEMENTS" ] && [ ! -L "$depot_APFS_BROKER_ENTITLEMENTS" ] || {
			echo 'build.sh: approved broker entitlement file required'
			exit 1
		}
		sign "$DIST/bin/$bin" "$ident" "$depot_APFS_BROKER_ENTITLEMENTS"
	else
		sign "$DIST/bin/$bin" "$ident" "$ENT"
	fi
done

# UID 703 as an application bundle (FS-703 §4.1, ADR-010).
APP="$DIST/EnclaveCustody.app"
mkdir -p "$APP/Contents/MacOS"
cp packaging/EnclaveCustody.app/Contents/Info.plist "$APP/Contents/Info.plist"
cp "$R/enclave-custody-vaultd" "$APP/Contents/MacOS/enclave-custody-vaultd"
APP_ENT="$DIST/custody.entitlements"
if [ "$MODE" = team-id ]; then
	sed "s/@TEAM_ID@/$TEAM/g" packaging/EnclaveCustody.app/custody.teamid.entitlements.in >"$APP_ENT"
	cp "$depot_PROVISIONING_PROFILE" "$APP/Contents/embedded.provisionprofile"
else
	cp "$ENT" "$APP_ENT"
fi
sign "$APP" com.enterprise.enclave.custody "$APP_ENT"

# Separate browser/PKCE process; no IdP or per-login authority is generated.
python3 helpers/enclaveoidc/build.py --signing-mode "$MODE"
OIDC_APP="$DIST/EnclaveOIDC.app"
mkdir -p "$OIDC_APP/Contents/MacOS"
cp helpers/enclaveoidc/Info.plist "$OIDC_APP/Contents/Info.plist"
cp target/yubikey-oidc-production "$OIDC_APP/Contents/MacOS/enclave-oidc"
sign "$OIDC_APP" com.enterprise.enclave.oidc-broker "$ENT"

# Verify every signature: strict, hardened runtime, expected identifier.
cdhash() { codesign -dvvv "$1" 2>&1 | sed -n 's/^CDHash=//p' | head -n 1; }
check() { # path identifier
	codesign --verify --strict --verbose=1 "$1"
	info=$(codesign -dvvv "$1" 2>&1)
	echo "$info" | grep -q "^Identifier=$2\$" || {
		echo "build.sh: $1 has the wrong identifier"
		exit 1
	}
	echo "$info" | grep -q "flags=.*runtime" || {
		echo "build.sh: $1 lacks the hardened runtime"
		exit 1
	}
	h=$(cdhash "$1")
	echo "$h" | grep -Eq '^[0-9a-f]{40}$' || {
		echo "build.sh: no CDHash for $1"
		exit 1
	}
}

PINS="$DIST/codesign-pins.json"
{
	printf '{"v":1,"mode":"%s","pins":{' "$MODE"
	sep=""
	for pair in $(echo "$TARGETS" | tr '\n' ' ') "EnclaveCustody.app:com.enterprise.enclave.custody" "EnclaveOIDC.app:com.enterprise.enclave.oidc-broker"; do
		bin=${pair%%:*}
		ident=${pair#*:}
		case "$bin" in *.app) p="$DIST/$bin" ;; *) p="$DIST/bin/$bin" ;; esac
		check "$p" "$ident" >&2
		printf '%s"%s":["%s"]' "$sep" "$ident" "$(cdhash "$p")"
		sep=","
	done
	printf '}}\n'
} >"$PINS"

# Public metadata is supplied by the organizational publisher, not synthesized
# as production authority on the build host. Development signing is explicit.
. packaging/macos/public-trust.sh
mkdir -p "$DIST/tuf/repo"
if [ -n "${depot_PUBLIC_TUF_REPO:-}" ]; then
	copy_public_trust "$depot_PUBLIC_TUF_REPO" "$DIST/tuf/repo"
elif [ "${depot_DEVELOPMENT_TUF:-0}" = 1 ]; then
	echo 'FIXTURE ONLY: synthetic TUF authorities; not organizational enrollment' >&2
	mkdir -p .enclave-local/tuf-keys
	"$R/depot-enclave" --json tuf init --keys .enclave-local/tuf-keys/keys.json --repo "$DIST/tuf/repo" >/dev/null
	"$R/depot-enclave" --json tuf host-config publish --grant-key "$GRANT_PUBLIC" --profile-floor "${depot_PROFILE_FLOOR:-L1}" --keys .enclave-local/tuf-keys/keys.json --repo "$DIST/tuf/repo" >/dev/null
	"$R/depot-enclave" --json tuf policy publish --keys .enclave-local/tuf-keys/keys.json --repo "$DIST/tuf/repo" >/dev/null
	"$R/depot-enclave" --json tuf vk publish --keys .enclave-local/tuf-keys/keys.json --repo "$DIST/tuf/repo" >/dev/null
	[ -f "${depot_FIXTURE_DISTRIBUTION_CONFIG:-}" ] || {
		echo 'build.sh: fixture requires depot_FIXTURE_DISTRIBUTION_CONFIG' >&2
		exit 20
	}
	cp "$depot_FIXTURE_DISTRIBUTION_CONFIG" "$DIST/tuf/repo/enclave-distribution-v1.json"
	"$R/depot-enclave" --json tuf sign --keys .enclave-local/tuf-keys/keys.json --repo "$DIST/tuf/repo" --name enclave-distribution-v1.json --file "$DIST/tuf/repo/enclave-distribution-v1.json" --custom '{"media_type":"application/vnd.enclave.distribution.v1+json","min_profile":"L1","classification":"public_l1"}' >/dev/null
	printf '%s\n' 'SYNTHETIC FIXTURE AUTHORITIES: not organizational enrollment or production acceptance' >"$DIST/FIXTURE-AUTHORITIES.txt"
else
	echo 'build.sh: set depot_PUBLIC_TUF_REPO to a complete externally signed public repository' >&2
	exit 20
fi
require_public_trust "$DIST/tuf/repo"

# DEFECT-F-90: the physical-key MDS allowlist travels inside the dist (and so
# under SHA256SUMS and install.sh's root-owned staging) instead of being read
# by root from whatever directory install.sh happens to run in.
mkdir -p "$DIST/fido-mds"
cp packaging/fido-mds/yubico.json "$DIST/fido-mds/yubico.json"

SUMS=$(mktemp)
(cd "$DIST" && find . -type f -print0 | sort -z | xargs -0 shasum -a 256) >"$SUMS"
mv "$SUMS" "$DIST/SHA256SUMS"

echo "built $MODE distribution in $DIST (authenticator: $YUBIKEY)"
echo "  binaries: $(cd "$DIST/bin" && echo *)"
echo "  app:      $APP"
echo "  pins:     $PINS"
cat "$PINS"
echo "next: sudo sh packaging/macos/install.sh"
