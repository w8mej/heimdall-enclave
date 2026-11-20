#!/bin/sh
# packaging/pkg/build-pkg.sh — Enterprise macOS Flat Package Builder (FS-706 / D-R10)
# Uses pkgbuild and productbuild to synthesize standalone .pkg distribution.
# Production packages require depot_INSTALLER_IDENTITY; explicit developer packages are visibly unsigned.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DIST_DIR="${depot_DIST:-$REPO_ROOT/.enclave-local/dist}"
OUTPUT_DIR="${depot_PKG_OUTPUT:-$REPO_ROOT/dist}"
VERSION="3.0.0"
PKG_PROFILE="${depot_PKG_PROFILE:-L2}"
case "$PKG_PROFILE" in L1 | L2 | L3) ;; *)
	echo "invalid package profile" >&2
	exit 2
	;;
esac
DRY_RUN=0
UNSIGNED_DEVELOPMENT=0

for arg in "$@"; do
	case "$arg" in
	--dry-run) DRY_RUN=1 ;;
	--unsigned-development) UNSIGNED_DEVELOPMENT=1 ;;
	-h | --help)
		echo "Usage: $0 [VERSION] [--dry-run]"
		echo "Builds depot-Enclave-<VERSION>.pkg using pkgbuild + productbuild."
		exit 0
		;;
	*)
		if [ -z "${VERSION_SET:-}" ] && [ "${arg#-}" = "$arg" ]; then
			VERSION="$arg"
			VERSION_SET=1
		else
			echo "build-pkg.sh: unexpected argument: $arg" >&2
			exit 2
		fi
		;;
	esac
done

# Missing build artifacts are errors even in a packaging dry-run. No placeholder
# may be synthesized or presented to fleet tooling as a real enclave binary.
for required in bin/depot-enclave codesign-pins.json SHA256SUMS launchd/provision-accounts.sh; do
	[ -s "$DIST_DIR/$required" ] || {
		echo "build-pkg.sh: missing distribution artifact $required" >&2
		exit 20
	}
done
if [ "$PKG_PROFILE" = L3 ]; then
	for required in bin/enclave-apfs-broker launchd/com.enterprise.enclave.apfs-broker.plist; do
		[ -s "$DIST_DIR/$required" ] || {
			echo "build-pkg.sh: L3 requires $required" >&2
			exit 20
		}
	done
fi
[ -x "$DIST_DIR/bin/depot-enclave" ] || {
	echo 'build-pkg.sh: CLI is not executable' >&2
	exit 20
}
[ -d "$DIST_DIR/EnclaveCustody.app" ] || {
	echo 'build-pkg.sh: missing custody application' >&2
	exit 20
}
case "$VERSION" in *[!0-9A-Za-z._-]* | '')
	echo 'invalid package version' >&2
	exit 2
	;;
esac
if [ "$UNSIGNED_DEVELOPMENT" -eq 0 ] && [ -z "${depot_INSTALLER_IDENTITY:-}" ]; then
	echo 'build-pkg.sh: production requires depot_INSTALLER_IDENTITY; use --unsigned-development only for isolated development' >&2
	exit 20
fi
[ "$(uname -s)" = "Darwin" ] || {
	echo "build-pkg.sh: must be run on macOS"
	exit 1
}

. "$REPO_ROOT/packaging/macos/public-trust.sh"
require_public_trust "$DIST_DIR/tuf/repo" || exit 20
# The retained distribution is itself packaged for canonical postinstall. Refuse
# recognized private-key files anywhere in it, not only inside the public TUF
# repository. Print names/reasons only, never credential bytes.
find "$DIST_DIR" -type f -print | while IFS= read -r candidate; do
	[ -f "$candidate" ] || {
		echo 'build-pkg.sh: unsupported distribution filename' >&2
		exit 20
	}
	case "${candidate##*/}" in
	keys.json | *.key | *.p12 | *.pfx | *.p8 | *private*key* | *signing*seed*)
		echo 'build-pkg.sh: private-key file in distribution; refusing package' >&2
		exit 20
		;;
	esac
	if grep -IEq -- '-----BEGIN .*PRIVATE KEY-----' "$candidate"; then
		echo 'build-pkg.sh: private PEM material in distribution; refusing package' >&2
		exit 20
	fi
done
if [ "$UNSIGNED_DEVELOPMENT" -eq 0 ] && [ -f "$DIST_DIR/FIXTURE-AUTHORITIES.txt" ]; then
	echo 'build-pkg.sh: fixture authorities cannot be signed as a production package' >&2
	exit 20
fi
if [ "$UNSIGNED_DEVELOPMENT" -eq 0 ] && [ -f "$REPO_ROOT/scripts/release-readiness.py" ]; then
	# Evaluate the repository gate before staging or invoking either package tool.
	# Invalid evidence is as terminal as incomplete acceptance; no bypass flag.
	if ! python3 -B "$REPO_ROOT/scripts/release-readiness.py" --package-profile "$PKG_PROFILE" --distribution "$DIST_DIR"; then
		echo 'build-pkg.sh: release acceptance incomplete or invalid; refusing production package' >&2
		exit 20
	fi
fi
mkdir -p "$OUTPUT_DIR"
STAGE_DIR="$(mktemp -d /tmp/depot-pkg-stage.XXXXXX)"
# shellcheck disable=SC2329
cleanup() {
	rm -rf "$STAGE_DIR"
}
trap cleanup EXIT INT TERM

echo "==> Staging payload directory hierarchy..."
PAYLOAD_ROOT="$STAGE_DIR/root"
SCRIPTS_DIR="$STAGE_DIR/scripts"
mkdir -p "$PAYLOAD_ROOT/opt/enterprise/enclave/bin" \
	"$PAYLOAD_ROOT/opt/enterprise/enclave/sandbox" \
	"$PAYLOAD_ROOT/opt/enterprise/enclave/core" \
	"$PAYLOAD_ROOT/Library/Application Support/EnterpriseEnclave" \
	"$PAYLOAD_ROOT/Library/LaunchDaemons" \
	"$PAYLOAD_ROOT/Library/LaunchAgents" \
	"$SCRIPTS_DIR"

# All payload copies below use this private, verified tree. Do not return to
# caller-controlled source paths after validating the staged distribution.
SOURCE_DIST="$DIST_DIR"
DIST_DIR="$PAYLOAD_ROOT/opt/enterprise/enclave/dist"
mkdir -p "$DIST_DIR"
cp -pR "$SOURCE_DIST/". "$DIST_DIR/"
if [ "$UNSIGNED_DEVELOPMENT" -eq 0 ] && [ -f "$REPO_ROOT/scripts/release-readiness.py" ]; then
	if ! python3 -B "$REPO_ROOT/scripts/release-readiness.py" --package-profile "$PKG_PROFILE" --distribution "$DIST_DIR"; then
		echo 'build-pkg.sh: staged distribution differs from approved release inputs' >&2
		exit 20
	fi
fi

# Stage preinstall and postinstall scripts
cp "$REPO_ROOT/packaging/pkg/scripts/preinstall" "$SCRIPTS_DIR/preinstall"
sed "s/^PROFILE=L2$/PROFILE=$PKG_PROFILE/" "$REPO_ROOT/packaging/pkg/scripts/postinstall" >"$SCRIPTS_DIR/postinstall"
chmod +x "$SCRIPTS_DIR/preinstall" "$SCRIPTS_DIR/postinstall"

# Package support scripts
if [ -f "$DIST_DIR/launchd/provision-accounts.sh" ]; then
	cp "$DIST_DIR/launchd/provision-accounts.sh" "$SCRIPTS_DIR/provision-accounts.sh"
	cp "$DIST_DIR/launchd/provision-accounts.sh" "$PAYLOAD_ROOT/opt/enterprise/enclave/provision-accounts.sh"
fi
if [ -f "$REPO_ROOT/core/bootstrap_enclave.sh" ]; then
	cp "$REPO_ROOT/core/bootstrap_enclave.sh" "$SCRIPTS_DIR/bootstrap_enclave.sh"
	cp "$REPO_ROOT/core/bootstrap_enclave.sh" "$PAYLOAD_ROOT/opt/enterprise/enclave/core/bootstrap_enclave.sh"
	chmod +x "$PAYLOAD_ROOT/opt/enterprise/enclave/core/bootstrap_enclave.sh"
fi
if [ -f "$REPO_ROOT/core/hydrate_model.sh" ]; then
	cp "$REPO_ROOT/core/hydrate_model.sh" "$PAYLOAD_ROOT/opt/enterprise/enclave/core/hydrate_model.sh"
	chmod +x "$PAYLOAD_ROOT/opt/enterprise/enclave/core/hydrate_model.sh"
fi

# Populate the payload only from the frozen distribution.
if [ -d "$DIST_DIR/bin" ]; then
	cp -R "$DIST_DIR/bin/"* "$PAYLOAD_ROOT/opt/enterprise/enclave/bin/"
	if [ -d "$DIST_DIR/launchd" ]; then
		cp "$DIST_DIR/launchd/"*.sb "$PAYLOAD_ROOT/opt/enterprise/enclave/sandbox/" 2>/dev/null || true
		cp "$DIST_DIR/launchd/"*.plist "$PAYLOAD_ROOT/Library/LaunchDaemons/" 2>/dev/null || true
		if [ -f "$DIST_DIR/launchd/com.enterprise.enclave.intent.plist" ]; then
			mv "$PAYLOAD_ROOT/Library/LaunchDaemons/com.enterprise.enclave.intent.plist" \
				"$PAYLOAD_ROOT/Library/LaunchAgents/com.enterprise.enclave.intent.plist"
		fi
	fi
	if [ -d "$DIST_DIR/EnclaveCustody.app" ]; then
		cp -R "$DIST_DIR/EnclaveCustody.app" "$PAYLOAD_ROOT/Library/Application Support/EnterpriseEnclave/"
	fi
	if [ -f "$DIST_DIR/codesign-pins.json" ]; then
		cp "$DIST_DIR/codesign-pins.json" "$PAYLOAD_ROOT/Library/Application Support/EnterpriseEnclave/"
	fi
	mkdir -p "$PAYLOAD_ROOT/var/db/enclave/cas/tuf/repo" \
		"$PAYLOAD_ROOT/opt/enterprise/enclave/cas" \
		"$PAYLOAD_ROOT/Library/Application Support/EnterpriseEnclave/tuf"
	copy_public_trust "$DIST_DIR/tuf/repo" "$PAYLOAD_ROOT/var/db/enclave/cas/tuf/repo"
	if [ "$PKG_PROFILE" = L3 ]; then
		mkdir -p "$PAYLOAD_ROOT/var/db/enclave/apfs-broker/tuf/repo"
		copy_public_trust "$DIST_DIR/tuf/repo" "$PAYLOAD_ROOT/var/db/enclave/apfs-broker/tuf/repo"
		chmod 0700 "$PAYLOAD_ROOT/var/db/enclave/apfs-broker" "$PAYLOAD_ROOT/var/db/enclave/apfs-broker/tuf" "$PAYLOAD_ROOT/var/db/enclave/apfs-broker/tuf/repo"
		chmod 0600 "$PAYLOAD_ROOT/var/db/enclave/apfs-broker/tuf/repo/"*
	fi
	# The canonical postinstall places the bootstrap pin only on first install;
	# putting it in the flat payload would overwrite a retained pin on upgrade.
	for trust_name in enclave-host-config.json enclave-policy.cedar.v1.json vk_manifest.json enclave-distribution-v1.json; do
		cp "$DIST_DIR/tuf/repo/$trust_name" "$PAYLOAD_ROOT/opt/enterprise/enclave/cas/$trust_name"
	done
else
	echo 'build-pkg.sh: distribution disappeared during staging' >&2
	exit 20
fi

COMPONENT_PKG="$STAGE_DIR/enclave-component.pkg"
SUFFIX=""
[ "$UNSIGNED_DEVELOPMENT" -eq 0 ] || SUFFIX="-UNSIGNED-DEVELOPMENT"
FINAL_PKG="$OUTPUT_DIR/depot-Enclave-${VERSION}${SUFFIX}.pkg"

echo "==> Running pkgbuild for component package..."
if [ "$DRY_RUN" -eq 1 ]; then
	echo "Dry-run: pkgbuild --root $PAYLOAD_ROOT --scripts $SCRIPTS_DIR --identifier com.enterprise.enclave.pkg --version $VERSION --install-location / $COMPONENT_PKG"
	echo "Dry-run: packaging verification passed."
	exit 0
fi

pkgbuild --root "$PAYLOAD_ROOT" \
	--scripts "$SCRIPTS_DIR" \
	--identifier com.enterprise.enclave.pkg \
	--version "$VERSION" \
	--install-location / \
	"$COMPONENT_PKG"

echo "==> Running productbuild for distribution package..."
if [ "$UNSIGNED_DEVELOPMENT" -eq 0 ]; then
	productbuild --package "$COMPONENT_PKG" --sign "$depot_INSTALLER_IDENTITY" "$FINAL_PKG"
	/usr/sbin/pkgutil --check-signature "$FINAL_PKG"
else
	echo 'DEVELOPMENT ONLY: unsigned package; do not distribute to production'
	productbuild --package "$COMPONENT_PKG" "$FINAL_PKG"
fi
echo "==> Successfully synthesized package at: $FINAL_PKG"
