#!/bin/sh
# Phase 2 step 1 (GAP-15, GAP-36): install and bootstrap the mesh on this Mac.
# Run after packaging/macos/build.sh, from the repo:
#
#   sudo sh packaging/macos/install.sh                 # install + bootstrap
#   sudo sh packaging/macos/install.sh --no-bootstrap  # install files only
#   sudo sh packaging/macos/verify-install.sh          # exit-criteria checks
#   sudo sh packaging/macos/uninstall.sh               # undo (see its --help)
#
# What it does, idempotently:
#   1. verifies every signature in the dist and that SHA256SUMS still matches;
#   2. provisions accounts 701–705, client groups and per-daemon directories
#      (the generated launchd/provision-accounts.sh, GAP-01/GAP-36);
#   3. installs binaries to /opt/enterprise/enclave/bin, Seatbelt profiles to
#      /opt/enterprise/enclave/sandbox, UID 703's EnclaveCustody.app and the
#      cdhash pins under /Library/Application Support/EnterpriseEnclave, and
#      the six plists to /Library/LaunchDaemons — all root:wheel, not writable
#      by anyone else (the daemons trust these paths);
#   4. `launchctl bootstrap system` for the supervisor and the five daemons.
set -eu
# Direct operator entry points must not inherit executable search paths or
# interpreter startup hooks. Embedded CLI calls already start with env_clear.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
LC_ALL=C
export PATH LC_ALL
unset BASH_ENV ENV CDPATH PERL5OPT PERL5LIB PERLLIB PYTHONPATH PYTHONHOME \
	RUBYOPT RUBYLIB DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH \
	LD_PRELOAD LD_LIBRARY_PATH
# `mcp-enclave deploy install --dist DIR` runs the copy of this script that is
# embedded in the (root-owned, signed) binary, from `/`, with a scrubbed
# environment and MCPMAC_DIST set (DEFECT-F-90); the repo default below only
# applies when an operator runs this file directly.
DIST="${MCPMAC_DIST:-$(cd "$(dirname "$0")/../.." && pwd)/.enclave-local/dist}"
PROFILE="${MCPMAC_PROFILE:-L2}"
case "$PROFILE" in L1 | L2 | L3) ;; *)
	echo "install.sh: invalid profile"
	exit 2
	;;
esac
BOOTSTRAP=1
case "${1:-}" in
--no-bootstrap) BOOTSTRAP=0 ;;
-h | --help)
	sed -n '2,20p' "$0"
	exit 0
	;;
"") ;;
*)
	echo "install.sh: unknown argument $1"
	exit 2
	;;
esac
if [ "$PROFILE" = L3 ]; then
	cat >&2 <<'MCPMAC_L3_ATTESTATION_NOTICE'
L3_ATTESTATION_RISK — read before configuring L3
L3 permits verified Basic Attestation plus separate authenticated asset enrollment.
Basic Attestation verifies an approved authenticator model; it does not provide
a manufacturer-attested binding to your organization's individual asset serial.
Enterprise Attestation supplies that stronger device-identity evidence when
supported and provisioned, helping detect wrong-device enrollment or substitution.
With Basic Attestation, you rely more heavily on the enrollment authority and
its verified binding of the credential to the asset. A manually entered serial,
USB identifier or AAGUID alone is insufficient. Use Enterprise Attestation when
your organization's policy requires it; do not silently fall back to Basic.
Verify the authenticated asset binding before treating this L3 deployment as
qualified. Successful setup alone does not certify those enrollment checks.
Touch ID, signed authenticator UV, custody, revocation and other L3 gates remain required.
MCPMAC_L3_ATTESTATION_NOTICE
fi
[ "$(uname -s)" = Darwin ] || {
	echo "install.sh: run this on macOS"
	exit 1
}
[ "$(id -u)" -eq 0 ] || {
	echo "install.sh: run with sudo"
	exit 1
}
[ -f "$DIST/codesign-pins.json" ] || {
	echo "install.sh: no build in $DIST; run 'sh packaging/macos/build.sh' first (as yourself)"
	exit 1
}

# GAP-15 / DEFECT-F-12: stage everything in an isolated root-owned directory to prevent
# unprivileged workspace racing during sudo execution
STAGE_DIR=$(mktemp -d /var/run/enclave-stage.XXXXXX)
STARTED_JOBS=
STARTED_GUI_JOBS=
PRIOR_JOBS=
PRIOR_GUI_JOBS=
PAYLOAD_CHANGED=0
BROKER_QUIESCED=0
# shellcheck disable=SC2329
installer_cleanup() {
	status=$?
	trap - EXIT INT TERM HUP
	cleanup_failed=0
	if [ "$status" -ne 0 ]; then
		# A failed bootstrap must not leave a subset of the new deployment live.
		# Keep PF protection installed. Do not restart old jobs with new binaries:
		# full payload/state rollback is a separate operator recovery obligation.
		for job in $STARTED_JOBS $STARTED_GUI_JOBS; do
			launchctl bootout "$job" 2>/dev/null || true
			i=0
			while launchctl print "$job" >/dev/null 2>&1 && [ "$i" -lt 60 ]; do
				sleep 0.1
				i=$((i + 1))
			done
			if launchctl print "$job" >/dev/null 2>&1; then
				echo "FAIL: recovery could not stop $job; retain $STAGE_DIR for inspection" >&2
				cleanup_failed=1
			fi
		done
		# Before the first payload replacement, prior plist/binary pairs still
		# belong together. Recover only jobs that were actually loaded on entry.
		if [ "$PAYLOAD_CHANGED" -eq 0 ]; then
			[ "$BROKER_QUIESCED" -eq 0 ] || rm -f /var/db/enclave/apfs-broker/deployment.quiesced
			for label in $PRIOR_JOBS; do
				if ! launchctl print "system/$label" >/dev/null 2>&1; then
					if ! launchctl bootstrap system "$LD/$label.plist"; then
						echo "FAIL: recovery could not restart prior job $label; retain $STAGE_DIR" >&2
						cleanup_failed=1
					fi
				fi
			done
			for job in $PRIOR_GUI_JOBS; do
				if ! launchctl print "$job" >/dev/null 2>&1; then
					if ! launchctl bootstrap "${job%/*}" "/Library/LaunchAgents/${job##*/}.plist"; then
						echo "FAIL: recovery could not restart prior console job; retain $STAGE_DIR" >&2
						cleanup_failed=1
					fi
				fi
			done
		fi
	fi
	if [ "$cleanup_failed" -eq 0 ]; then rm -rf "$STAGE_DIR"; else status=1; fi
	exit "$status"
}
trap installer_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
chown root:wheel "$STAGE_DIR"
chmod 0700 "$STAGE_DIR"
cp -R "$DIST/"* "$STAGE_DIR/"
chown -R root:wheel "$STAGE_DIR"
chmod -R go-w "$STAGE_DIR"
DIST="$STAGE_DIR"

PREFIX=/opt/enterprise/enclave
SUPPORT="/Library/Application Support/EnterpriseEnclave"
LD=/Library/LaunchDaemons
FIDO=com.enterprise.enclave.fido
YUBIKEY=$(cat "$DIST/yubikey-transport" 2>/dev/null || echo hid)
LABELS="com.enterprise.enclave.supervisor com.enterprise.enclave.zk com.enterprise.enclave.custody com.enterprise.enclave.cas com.enterprise.enclave.adapter com.enterprise.enclave.ifc com.enterprise.enclave.browser com.enterprise.enclave.hydrate com.enterprise.enclave.gateway"
# Only L3 installs/starts the privileged helper; all distributions sign its binary.
[ "$PROFILE" != L3 ] || LABELS="${LABELS%%com.enterprise.enclave.cas*}com.enterprise.enclave.apfs-broker com.enterprise.enclave.cas${LABELS#*com.enterprise.enclave.cas}"
# GAP-13: the CTAPHID emulator starts before UID 703 when deployed.
[ "$YUBIKEY" = emulated ] && LABELS="com.enterprise.enclave.supervisor $FIDO ${LABELS#com.enterprise.enclave.supervisor }"

# BEGIN embedded public-trust inventory (kept equal to public-trust.sh)
#!/usr/bin/env bash
# Public trust inventory only. No signing key is accepted or copied. Authenticity
# is established by the organizational package/bootstrap root and runtime TUF,
# never by this structural check or by the presence of signature-shaped JSON.
PUBLIC_TUF_FILES='root.json timestamp.json snapshot.json targets.json enclave-host-config.json enclave-policy.cedar.v1.json vk_manifest.json enclave-distribution-v1.json'
check_public_trust_file() {
	trust_path=$1
	[ -f "$trust_path" ] && [ ! -L "$trust_path" ] && [ -s "$trust_path" ] || {
		echo "PUBLIC_TRUST_REQUIRED: ${trust_path##*/}" >&2
		return 1
	}
	trust_size=$(wc -c <"$trust_path")
	[ "$trust_size" -le 16777216 ] || {
		echo "PUBLIC_TRUST_OVERSIZED: ${trust_path##*/}" >&2
		return 1
	}
	if grep -Eq -- '-----BEGIN .*PRIVATE KEY-----|"(private|private_key|secret|secret_key|seed|signing_seed)"[[:space:]]*:' "$trust_path"; then
		echo "PUBLIC_TRUST_PRIVATE_MATERIAL: ${trust_path##*/}" >&2
		return 1
	fi
}
require_public_trust() {
	trust_repo=$1
	[ -d "$trust_repo" ] && [ ! -L "$trust_repo" ] || {
		echo 'PUBLIC_TRUST_REPO_REQUIRED' >&2
		return 1
	}
	for trust_name in $PUBLIC_TUF_FILES; do
		check_public_trust_file "$trust_repo/$trust_name" || return 1
	done
	trust_root_count=0
	for trust_path in "$trust_repo"/* "$trust_repo"/.[!.]* "$trust_repo"/..?*; do
		[ -e "$trust_path" ] || [ -L "$trust_path" ] || continue
		trust_name=${trust_path##*/}
		case " $PUBLIC_TUF_FILES " in
		*" $trust_name "*) ;;
		*)
			case "$trust_name" in
			*.root.json)
				trust_number=${trust_name%.root.json}
				case "$trust_number" in '' | 0* | *[!0-9]*)
					echo "PUBLIC_TRUST_UNSUPPORTED_FILE: $trust_name" >&2
					return 1
					;;
				esac
				[ "${#trust_number}" -le 10 ] && [ "$trust_number" -le 2147483647 ] || {
					echo 'PUBLIC_TRUST_ROOT_VERSION' >&2
					return 1
				}
				trust_root_count=$((trust_root_count + 1))
				[ "$trust_root_count" -le 32 ] || {
					echo 'PUBLIC_TRUST_ROOT_CHAIN_LIMIT' >&2
					return 1
				}
				check_public_trust_file "$trust_path" || return 1
				;;
			*)
				echo "PUBLIC_TRUST_UNSUPPORTED_FILE: $trust_name" >&2
				return 1
				;;
			esac
			;;
		esac
	done
}
# shellcheck disable=SC2329
copy_public_trust() {
	require_public_trust "$1" || return 1
	mkdir -p "$2"
	for trust_path in "$1"/*; do cp "$trust_path" "$2/${trust_path##*/}" || return 1; done
}
# END embedded public-trust inventory

echo "== 1. verify the build"
(cd "$DIST" && shasum -a 256 -c SHA256SUMS >/dev/null) || {
	echo "install.sh: $DIST changed since build.sh (SHA256SUMS mismatch)"
	exit 1
}
for f in "$DIST"/bin/* "$DIST/EnclaveCustody.app" "$DIST/EnclaveOIDC.app"; do
	codesign --verify --strict "$f" || {
		echo "install.sh: bad signature on $f"
		exit 1
	}
done
echo "ok: local build self-consistency (signatures and SHA256SUMS); local pins supplied with a build do not establish externally intended provenance"

[ -x "$DIST/EnclaveOIDC.app/Contents/MacOS/enclave-oidc" ] || {
	echo 'FAIL: browser broker payload missing'
	exit 1
}

# L3 requires the signed broker before any host provisioning can begin.
if [ "$PROFILE" = L3 ] && [ ! -x "$DIST/bin/enclave-apfs-broker" ]; then
	echo 'FAIL: required L3 broker executable missing'
	exit 1
fi

# The script is also a documented direct entry point. Recheck the same host
# gates as `deploy install`, using only the verified root-owned staged CLI,
# before provisioning accounts or changing the installed host. Scrub the
# operator environment just as the embedded CLI installer path does.
[ -x "$DIST/bin/mcp-enclave" ] || {
	echo "install.sh: verified staged CLI missing"
	exit 10
}
if ! /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin "$DIST/bin/mcp-enclave" deploy preflight --profile "$PROFILE"; then
	echo "install.sh: mandatory host preflight failed; installation refused"
	exit 10
fi

# Validate deterministic inputs and render with the verified staged CLI before
# stopping a working deployment or publishing replacement payloads.
case "$YUBIKEY" in
hid) [ -s "$DIST/fido-mds/yubico.json" ] || {
	echo "FAIL: verified MDS allowlist missing"
	exit 1
} ;;
emulated) ;;
*)
	echo "FAIL: unsupported YubiKey transport"
	exit 1
	;;
esac
[ ! -f "$DIST/FIXTURE-AUTHORITIES.txt" ] || {
	echo 'FAIL: synthetic fixture authority distribution cannot be installed as production'
	exit 1
}
require_public_trust "$DIST/tuf/repo" || exit 1
# Refuse an unsafe existing trust pin before accounts, payloads or jobs change.
if [ -e "$SUPPORT/tuf/root.json" ] || [ -L "$SUPPORT/tuf/root.json" ]; then
	[ -f "$SUPPORT/tuf/root.json" ] && [ ! -L "$SUPPORT/tuf/root.json" ] || {
		echo 'FAIL: unsafe existing TUF bootstrap pin'
		exit 1
	}
	case "$(stat -f '%u %Lp' "$SUPPORT/tuf/root.json")" in '0 444' | '0 644' | '0 400' | '0 600') ;; *)
		echo 'FAIL: untrusted existing TUF bootstrap pin'
		exit 1
		;;
	esac
fi
mkdir "$DIST/rendered"
if [ "$YUBIKEY" = emulated ]; then
	"$DIST/bin/mcp-enclave" --profile "$PROFILE" launchd render --out "$DIST/rendered" --with-fido-emulator
else
	"$DIST/bin/mcp-enclave" --profile "$PROFILE" launchd render --out "$DIST/rendered"
fi
cp "$DIST/rendered/"*.plist "$DIST/launchd/"
cp "$DIST/rendered/"*.sb "$DIST/launchd/"
for l in $LABELS com.enterprise.enclave.intent com.enterprise.enclave.oidc-broker; do
	[ -s "$DIST/launchd/$l.plist" ] || {
		echo "FAIL: missing rendered job $l"
		exit 1
	}
done

# File-only installation must not replace binaries/plists behind live jobs.
# Refuse before provisioning; the operator must stop them explicitly or use
# the normal coordinated install path. Include an old emulator in HID upgrades.
# HID upgrades also replace/remove the old emulator's files. The console agent
# uses the same custody bundle, so it must stop before payload replacement too.
STOP_LABELS="com.enterprise.enclave.cas com.enterprise.enclave.hydrate $LABELS"
# Include any prior L3 helper during profile changes.
STOP_LABELS="$STOP_LABELS com.enterprise.enclave.apfs-broker"
[ "$YUBIKEY" = emulated ] || STOP_LABELS="$STOP_LABELS $FIDO"
CONSOLE_UID=$(stat -f %u /dev/console 2>/dev/null || true)
case "$CONSOLE_UID" in '' | *[!0-9]*)
	echo 'FAIL: cannot check console job before installation' >&2
	exit 1
	;;
esac
# Fast user switching can retain a helper in a non-current GUI domain. Stop
# every loaded user instance before replacing either app or shared pins.
# Enumerate live launchd domains, including directory-backed users that are
# absent from dscl's local node. Unknown output refuses before payload mutation.
DOMAIN_INVENTORY=$(launchctl print system) || {
	echo 'FAIL: cannot enumerate live launchd domains; payload retained' >&2
	exit 1
}
GUI_DOMAIN_UIDS=$(printf '%s\n' "$DOMAIN_INVENTORY" | awk '
  /^[[:space:]]*subdomains = \{[[:space:]]*$/ { if (seen++) bad=1; inside=1; next }
  inside && /^[[:space:]]*\}[[:space:]]*$/ { inside=0; closed=1; next }
  inside {
    line=$0; sub(/^[[:space:]]*/, "", line); sub(/[[:space:]]*$/, "", line)
    if (line == "") next
    # Per-process XPC domains (macOS 26 lists them here) hold no console helper.
    if (line ~ /^pid\/[0-9]+$/) next
    if (line !~ /^(user|gui)\/[0-9]+([[:space:]]+\[[0-9]+\])?$/) {bad=1; next}
    sub(/^(user|gui)\//, "", line); sub(/[[:space:]].*$/, "", line)
    if (line+0 >= 500 && line+0 < 4294967295) print line
  }
  END {if (!seen || !closed || inside || bad) exit 1}
') || {
	echo 'FAIL: unsupported live launchd domain inventory; payload retained' >&2
	exit 1
}
unset DOMAIN_INVENTORY
GUI_UIDS=$({
	printf '%s\n' "$GUI_DOMAIN_UIDS"
	echo "$CONSOLE_UID"
} | sort -nu)
GUI_JOBS=
for uid in $GUI_UIDS; do
	[ "$uid" -ge 500 ] || continue
	for agent in com.enterprise.enclave.intent com.enterprise.enclave.oidc-broker; do
		GUI_JOBS="$GUI_JOBS gui/$uid/$agent"
	done
done
if [ "$BOOTSTRAP" -eq 0 ]; then
	for l in $STOP_LABELS; do
		if launchctl print "system/$l" >/dev/null 2>&1; then
			echo "FAIL: --no-bootstrap requires stopped jobs ($l is loaded)" >&2
			exit 1
		fi
	done
	for job in $GUI_JOBS; do
		if launchctl print "$job" >/dev/null 2>&1; then
			echo 'FAIL: --no-bootstrap requires stopped console helper jobs' >&2
			exit 1
		fi
	done
fi

echo "== 2. provision accounts, groups, directories"
sh "$DIST/launchd/provision-accounts.sh"
# UID 702's content-addressed store (read-only FDs are passed to UID 701).
install -d -o _enclavecas -g _enclavecas -m 0750 "$PREFIX/cas"

# Resolve the real host's grant key before stopping the old deployment. A
# mismatched signed distribution is not a reason to shut down working jobs.
"$DIST/bin/mcp-enclave" --json launchd grant-key --state-dir /var/db/enclave >"$DIST/actual-grant.json"
ACTUAL_GRANT=$(/usr/bin/plutil -extract ifc_grant_public_key raw -o - "$DIST/actual-grant.json")
EXPECTED_GRANT=$(/usr/bin/plutil -extract ifc_grant_public_key raw -o - "$DIST/tuf/repo/enclave-host-config.json")
[ "$ACTUAL_GRANT" = "$EXPECTED_GRANT" ] || {
	echo 'FAIL: provisioned grant public key differs from distribution host config; sign a config for this target before bootstrap'
	exit 1
}

# Keep the existing broker alive if publications still require retraction.
# Stop its only caller first, then inspect authenticated sealed ownership using
# the verified staged implementation. Missing/corrupt required state refuses.
if [ -d /var/db/enclave/apfs-broker ]; then
	for l in com.enterprise.enclave.hydrate com.enterprise.enclave.cas; do
		if launchctl print "system/$l" >/dev/null 2>&1; then
			[ "$BOOTSTRAP" -eq 1 ] || {
				echo 'FAIL: --no-bootstrap requires stopped CAS'
				exit 1
			}
			PRIOR_JOBS="$PRIOR_JOBS $l"
			launchctl bootout "system/$l" || exit 1
			i=0
			while launchctl print "system/$l" >/dev/null 2>&1 && [ "$i" -lt 60 ]; do
				sleep 0.1
				i=$((i + 1))
			done
			if launchctl print "system/$l" >/dev/null 2>&1; then
				echo 'FAIL: cannot stop CAS before broker inspection'
				exit 1
			fi
		fi
	done
	"$DIST/bin/enclave-apfs-broker" --quiesce-idle || {
		echo 'FAIL: retained broker publications or uncertain state require explicit retraction; broker kept available'
		exit 1
	}
	BROKER_QUIESCED=1
fi

echo "== 3. install files"
install -d -o root -g wheel -m 0755 /opt/enterprise "$PREFIX" "$PREFIX/bin" "$PREFIX/sandbox" "$SUPPORT"
# Stop running daemons before replacing their executables.
if [ "$BOOTSTRAP" -eq 1 ]; then
	for l in $STOP_LABELS; do
		if launchctl print "system/$l" >/dev/null 2>&1; then PRIOR_JOBS="$PRIOR_JOBS $l"; fi
	done
	for job in $GUI_JOBS; do
		if launchctl print "$job" >/dev/null 2>&1; then PRIOR_GUI_JOBS="$PRIOR_GUI_JOBS $job"; fi
	done
	for l in $STOP_LABELS; do launchctl bootout "system/$l" 2>/dev/null || launchctl bootout system "$LD/$l.plist" 2>/dev/null || true; done
	for job in $PRIOR_GUI_JOBS; do launchctl bootout "$job" 2>/dev/null || true; done
	for l in $STOP_LABELS; do
		i=0
		while launchctl print "system/$l" >/dev/null 2>&1 && [ "$i" -lt 60 ]; do
			sleep 0.1
			i=$((i + 1))
		done
		if launchctl print "system/$l" >/dev/null 2>&1; then
			echo "FAIL: prior job $l did not stop; refusing to replace live payload" >&2
			exit 1
		fi
	done
	for job in $PRIOR_GUI_JOBS; do
		i=0
		while launchctl print "$job" >/dev/null 2>&1 && [ "$i" -lt 60 ]; do
			sleep 0.1
			i=$((i + 1))
		done
		if launchctl print "$job" >/dev/null 2>&1; then
			echo 'FAIL: prior console job did not stop; refusing to replace live payload' >&2
			exit 1
		fi
	done
fi
PAYLOAD_CHANGED=1
for f in "$DIST"/bin/*; do install -o root -g wheel -m 0755 "$f" "$PREFIX/bin/"; done
for f in "$DIST"/launchd/*.sb; do install -o root -g wheel -m 0644 "$f" "$PREFIX/sandbox/"; done
install -o root -g wheel -m 0755 "$DIST/launchd/provision-accounts.sh" "$PREFIX/provision-accounts.sh"
rm -rf "$SUPPORT/EnclaveCustody.app"
ditto "$DIST/EnclaveCustody.app" "$SUPPORT/EnclaveCustody.app"
chown -R root:wheel "$SUPPORT/EnclaveCustody.app"
chmod -R go-w "$SUPPORT/EnclaveCustody.app"
rm -rf "$SUPPORT/EnclaveOIDC.app"
ditto "$DIST/EnclaveOIDC.app" "$SUPPORT/EnclaveOIDC.app"
chown -R root:wheel "$SUPPORT/EnclaveOIDC.app"
chmod -R go-w "$SUPPORT/EnclaveOIDC.app"
codesign --verify --strict "$SUPPORT/EnclaveOIDC.app"
install -o root -g wheel -m 0644 "$DIST/codesign-pins.json" "$SUPPORT/codesign-pins.json"
install -d -o root -g wheel -m 0755 /Library/LaunchAgents
# The profile-specific plists were rendered and checked before old jobs stopped.
for agent in com.enterprise.enclave.intent com.enterprise.enclave.oidc-broker; do
	install -o root -g wheel -m 0644 "$DIST/launchd/$agent.plist" "/Library/LaunchAgents/$agent.plist"
done
for l in $LABELS; do install -o root -g wheel -m 0644 "$DIST/launchd/$l.plist" "$LD/$l.plist"; done
for f in "$DIST"/bin/*; do codesign --verify --strict "$PREFIX/bin/$(basename "$f")"; done
if [ "$YUBIKEY" = hid ]; then
	# A physical-key install keeps no trace of the emulator: its job,
	# binary, profile, and any MDS allowlist that admits it.
	launchctl bootout "system/$FIDO" 2>/dev/null || true
	rm -f "$LD/$FIDO.plist" "$PREFIX/bin/enclave-fido-emulator" "$PREFIX/sandbox/fido.sb"
	if grep -q "MCPMac CTAPHID emulator" "$SUPPORT/fido-mds.json" 2>/dev/null; then rm -f "$SUPPORT/fido-mds.json"; fi
fi

# UID 702 TUF repository and root.json (GAP-20)
install -d -o root -g wheel -m 0755 "$SUPPORT/tuf"
install -d -o _enclavecas -g _enclavecas -m 0750 /var/db/enclave/cas/tuf /var/db/enclave/cas/tuf/repo
if [ -e "$SUPPORT/tuf/root.json" ] || [ -L "$SUPPORT/tuf/root.json" ]; then
	# Preserve independently pinned bootstrap authority. Runtime verifies numbered
	# root rotations against this pin/persisted trust, never a replacement peer pin.
	[ -f "$SUPPORT/tuf/root.json" ] && [ ! -L "$SUPPORT/tuf/root.json" ] || {
		echo 'FAIL: unsafe existing TUF bootstrap pin'
		exit 1
	}
	case "$(stat -f '%u %Lp' "$SUPPORT/tuf/root.json")" in '0 444' | '0 644' | '0 400' | '0 600') ;; *)
		echo 'FAIL: untrusted existing TUF bootstrap pin'
		exit 1
		;;
	esac
else
	install -o root -g wheel -m 0444 "$DIST/tuf/repo/root.json" "$SUPPORT/tuf/root.json"
fi
if [ "$PROFILE" = L3 ]; then
	# Protected public replica; never copy CAS-writable metadata as root authority.
	# Monotonic state and independent bootstrap pin survive ordinary upgrades.
	install -d -o root -g wheel -m 0700 /var/db/enclave/apfs-broker/tuf/repo
	for trust_path in "$DIST/tuf/repo/"*; do
		install -o root -g wheel -m 0600 "$trust_path" "/var/db/enclave/apfs-broker/tuf/repo/${trust_path##*/}"
	done
fi
if [ "$PROFILE" != L3 ]; then rm -f "$LD/com.enterprise.enclave.apfs-broker.plist"; fi
# Legacy compatibility path is not the independently protected bootstrap pin.
install -o root -g wheel -m 0444 "$DIST/tuf/repo/root.json" /var/db/enclave/cas/tuf/root.json
for trust_path in "$DIST/tuf/repo/"*; do
	trust_name=${trust_path##*/}
	install -o _enclavecas -g _enclavecas -m 0640 "$trust_path" "/var/db/enclave/cas/tuf/repo/$trust_name"
done
for trust_name in enclave-host-config.json enclave-policy.cedar.v1.json vk_manifest.json enclave-distribution-v1.json; do
	install -o _enclavecas -g _enclavecas -m 0640 "$DIST/tuf/repo/$trust_name" "$PREFIX/cas/$trust_name"
done
codesign --verify --strict "$SUPPORT/EnclaveCustody.app"
echo "ok: installed to $PREFIX, $SUPPORT, $LD"

# All physical-key trust material is installed before any daemon starts.
if [ "$YUBIKEY" = hid ]; then
	[ -s "$DIST/fido-mds/yubico.json" ] || {
		echo "FAIL: verified MDS allowlist missing"
		exit 1
	}
	install -o root -g wheel -m 0644 "$DIST/fido-mds/yubico.json" "$SUPPORT/fido-mds.json"
fi

echo "== 5. packet filter anchors (GAP-28, DEFECT-F-16)"
install -d -o root -g wheel -m 0755 /etc/pf.anchors
if [ -x "$PREFIX/bin/mcp-enclave" ]; then
	"$PREFIX/bin/mcp-enclave" pf install --anchors-dir /etc/pf.anchors --pf-conf /etc/pf.conf
else
	echo "FAIL: installed verified CLI missing"
	exit 1
fi
if [ -f /etc/pf.anchors/com.enterprise.llm.isolation ]; then
	pfctl -a com.enterprise.llm.isolation -f /etc/pf.anchors/com.enterprise.llm.isolation
fi
if [ -f /etc/pf.anchors/com.enterprise.cas.swarm ]; then
	pfctl -a com.enterprise.cas.swarm -f /etc/pf.anchors/com.enterprise.cas.swarm
fi
if [ -f /etc/pf.conf ]; then
	pfctl -f /etc/pf.conf
fi
if ! pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
	pfctl -e 2>/dev/null || pfctl -E 2>/dev/null || {
		echo "FAIL: packet filter could not be enabled"
		exit 1
	}
fi

# New payload, protected trust and retained state are now ready for serving.
# Clear only our coordination barrier; never erase ownership or rollback files.
if [ "$PROFILE" = L3 ]; then rm -f /var/db/enclave/apfs-broker/deployment.quiesced; fi
[ "$BOOTSTRAP" -eq 1 ] || {
	echo "skipped bootstrap (--no-bootstrap)"
	exit 0
}

echo "== 4. bootstrap"
# verify-install.sh scopes its Seatbelt log query to this bootstrap.
date '+%Y-%m-%d %H:%M:%S' >/var/db/enclave/.bootstrapped-at
chmod 0644 /var/db/enclave/.bootstrapped-at
rc=0
for l in $LABELS; do
	if launchctl print "system/$l" >/dev/null 2>&1; then
		launchctl bootout "system/$l" 2>/dev/null || true
		i=0
		while launchctl print "system/$l" >/dev/null 2>&1 && [ "$i" -lt 30 ]; do
			sleep 0.1
			i=$((i + 1))
		done
	fi
	launchctl enable "system/$l" 2>/dev/null || true
	# Include the attempted job even if launchctl reports a partial failure.
	STARTED_JOBS="$STARTED_JOBS system/$l"
	if launchctl bootstrap system "$LD/$l.plist"; then echo "ok: bootstrapped $l"; else
		echo "FAIL: bootstrap $l"
		rc=1
	fi
done
if [ -n "$CONSOLE_UID" ] && [ "$CONSOLE_UID" -ne 0 ]; then
	launchctl bootout "gui/$CONSOLE_UID/com.enterprise.enclave.intent" 2>/dev/null || true
	STARTED_GUI_JOBS="$STARTED_GUI_JOBS gui/$CONSOLE_UID/com.enterprise.enclave.intent"
	if launchctl bootstrap "gui/$CONSOLE_UID" "/Library/LaunchAgents/com.enterprise.enclave.intent.plist"; then
		echo "ok: bootstrapped com.enterprise.enclave.intent in gui/$CONSOLE_UID"
	else
		echo "warn: could not bootstrap com.enterprise.enclave.intent in gui/$CONSOLE_UID"
	fi
fi
if [ "$CONSOLE_UID" -ge 500 ] && [ -s "$SUPPORT/oidc-broker-identity.json" ] && [ -s "$SUPPORT/oidc-oauth.json" ]; then
	STARTED_GUI_JOBS="$STARTED_GUI_JOBS gui/$CONSOLE_UID/com.enterprise.enclave.oidc-broker"
	if ! launchctl bootstrap "gui/$CONSOLE_UID" /Library/LaunchAgents/com.enterprise.enclave.oidc-broker.plist; then
		echo 'FAIL: browser broker bootstrap failed'
		rc=1
	fi
else
	echo 'info: browser broker deferred pending protected current-session and organization OAuth configuration; A4 unavailable'
fi
if [ "$YUBIKEY" = emulated ]; then
	# The emulator publishes its MDS entry (AAGUID, attestation key) on first
	# start; install it as UID 703's allowlist, root-owned, then restart 703.
	ENTRY=/var/db/enclave/fido/mds-entry.json
	i=0
	while [ ! -s "$ENTRY" ] && [ $i -lt 50 ]; do
		sleep 0.2
		i=$((i + 1))
	done
	if [ -s "$ENTRY" ]; then
		printf '{"entries":[%s]}\n' "$(cat "$ENTRY")" >"$SUPPORT/fido-mds.json.tmp"
		chown root:wheel "$SUPPORT/fido-mds.json.tmp"
		chmod 0644 "$SUPPORT/fido-mds.json.tmp"
		mv "$SUPPORT/fido-mds.json.tmp" "$SUPPORT/fido-mds.json"
		echo "ok: installed the emulator's MDS entry as $SUPPORT/fido-mds.json"
		launchctl kickstart -k system/com.enterprise.enclave.custody >/dev/null 2>&1 || true
	else
		echo "FAIL: the emulator did not publish $ENTRY"
		rc=1
	fi

fi

sleep 1
# Wait for core sockets (supervisor, cas) to be ready
for s in supervisor cas; do
	sock="/var/run/enclave/$s/$s.sock"
	i=0
	while [ ! -S "$sock" ] && [ "$i" -lt 50 ]; do
		sleep 0.1
		i=$((i + 1))
	done
done
for l in $LABELS; do
	st=$(launchctl print "system/$l" 2>/dev/null | sed -n 's/^[[:space:]]*state = //p' | head -n 1)
	ex=$(launchctl print "system/$l" 2>/dev/null | sed -n 's/^[[:space:]]*last exit code = //p' | head -n 1)
	echo "   $l: state=${st:-unknown} last-exit=${ex:-none}"
done
echo "next: sudo sh packaging/macos/verify-install.sh"
exit "$rc"
