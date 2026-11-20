#!/bin/sh
# Phase 2 step 1 exit criteria on this Mac (GAP-15, GAP-36). Run after
# install.sh:   sudo sh packaging/macos/verify-install.sh
#
#  A. all six launchd jobs are bootstrapped, each daemon under sandbox-exec
#     with its Seatbelt profile;
#  B. the .app UID 703 creates and uses Secure Enclave keys as _piivault
#     under custody.sb with 0 errSecMissingEntitlement (-34018), and the key
#     survives a restart;
#  C. cross-daemon journal writes are denied by BOTH layers: POSIX modes
#     (as each daemon account) and Seatbelt (as root under each profile),
#     with a positive control so the check cannot pass vacuously;
#  D. the sandbox violation log for the mesh since bootstrap.
#
# Prints PASS / FAIL / INFO lines and exits non-zero if any check fails.
set -u
# Direct operator entry points must not inherit executable search paths or
# interpreter startup hooks. Embedded CLI calls already start with env_clear.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
LC_ALL=C
export PATH LC_ALL
unset BASH_ENV ENV CDPATH PERL5OPT PERL5LIB PERLLIB PYTHONPATH PYTHONHOME \
	RUBYOPT RUBYLIB DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH \
	LD_PRELOAD LD_LIBRARY_PATH
# BEGIN exclusive journal probe helper
# Return 0 only for a created-and-removed probe, 1 for refused creation, and 2
# for an invalid result or failed cleanup. Never touch predictable existing
# journal names. The command prefix is fixed by the callers below.
journal_probe_write() {
	_mcpmac_probe_directory=$1
	shift
	_mcpmac_probe_path=$("$@" /usr/bin/mktemp "$_mcpmac_probe_directory/.mcpmac-verify.XXXXXXXX" 2>/dev/null) || return 1
	case "$_mcpmac_probe_path" in
	"$_mcpmac_probe_directory"/.mcpmac-verify.*) ;;
	*) return 2 ;;
	esac
	_mcpmac_probe_suffix=${_mcpmac_probe_path#"$_mcpmac_probe_directory"/.mcpmac-verify.}
	[ "${#_mcpmac_probe_suffix}" -eq 8 ] || return 2
	case "$_mcpmac_probe_suffix" in *[!a-zA-Z0-9]*) return 2 ;; esac
	[ -n "$_mcpmac_probe_path" ] && /bin/rm -f -- "$_mcpmac_probe_path" || return 2
	return 0
}
# END exclusive journal probe helper
[ "$(uname -s)" = Darwin ] || {
	echo "verify-install.sh: run this on macOS"
	exit 1
}
[ "$(id -u)" -eq 0 ] || {
	echo "verify-install.sh: run with sudo"
	exit 1
}
PREFIX=/opt/enterprise/enclave
SB="$PREFIX/sandbox"
APP_EXE="/Library/Application Support/EnterpriseEnclave/EnclaveCustody.app/Contents/MacOS/enclave-custody-vaultd"
FAILS=0
for need in "/Library/Application Support/EnterpriseEnclave/codesign-pins.json" "$APP_EXE" "$SB/custody.sb" /Library/LaunchDaemons/com.enterprise.enclave.custody.plist; do
	[ -e "$need" ] || {
		echo "verify-install.sh: $need is missing: install.sh did not complete; rerun it first"
		exit 1
	}
done
pass() { echo "PASS $*"; }
fail() {
	echo "FAIL $*"
	FAILS=$((FAILS + 1))
}
info() { echo "INFO $*"; }
# suffix:account
DAEMONS="adapter:_llmagent cas:_enclavecas custody:_piivault ifc:_enclaveifc zk:_enclavezk browser:_cdpbrowser"

echo "== A. launchd jobs"
for l in supervisor adapter cas custody ifc zk browser gateway; do
	out=$(launchctl print "system/com.enterprise.enclave.$l" 2>/dev/null) || {
		fail "A $l not bootstrapped"
		continue
	}
	st=$(echo "$out" | sed -n 's/^[[:space:]]*state = //p' | head -n 1)
	ex=$(echo "$out" | sed -n 's/^[[:space:]]*last exit code = //p' | head -n 1)
	if [ "$l" = gateway ]; then
		if ! { echo "$out" | grep -q 'enclave-client-gateway' && echo "$out" | grep -q -- '--sandbox-profile' && echo "$out" | grep -q "$SB/gateway.sb"; }; then
			fail "A gateway missing dedicated executable or in-process sandbox argument"
			continue
		fi
	elif [ "$l" != supervisor ]; then
		if ! { echo "$out" | grep -q "/usr/bin/sandbox-exec" && echo "$out" | grep -q "$SB/$l.sb"; }; then
			fail "A $l is not launched under $SB/$l.sb"
			continue
		fi
	fi
	pid=$(echo "$out" | sed -n 's/^[[:space:]]*pid = //p' | head -n 1)
	case "$l" in
	adapter | cas | custody | ifc | zk)
		if ! echo "$out" | grep -q -- '--sandbox-profile'; then
			fail "A $l missing shared runtime sandbox argument"
			continue
		fi
		;;
	esac
	if [ "$st" = running ] && [ -n "$pid" ]; then
		pass "A $l running (pid=$pid last-exit=${ex:-none})"
	else
		fail "A $l not serving (state=${st:-?} last-exit=${ex:-none})"
	fi
	# A running daemon logs nothing on success; older lines are previous runs.
	log="/var/log/enclave/$l/$l.log"
	[ "$l" = supervisor ] && log=/var/log/enclave/supervisor.log
	if [ "$st" != running ] && [ -f "$log" ]; then info "A $l exit reason: $(tail -n 1 "$log" | cut -c1-300)"; fi
done

if [ "${MCPMAC_PROFILE:-L2}" = L3 ]; then
	echo '== A1. restricted root APFS broker layout'
	if launchctl print system/com.enterprise.enclave.apfs-broker >/dev/null 2>&1; then pass 'A1 helper job loaded'; else fail 'A1 helper job absent'; fi
	if [ -x "$PREFIX/bin/enclave-apfs-broker" ] && codesign --verify --strict "$PREFIX/bin/enclave-apfs-broker"; then pass 'A1 broker binary signature'; else fail 'A1 broker binary invalid'; fi
	if [ "$(stat -f '%u %g %Lp' /var/run/enclave/apfs-broker 2>/dev/null)" = '0 8702 2750' ]; then pass 'A1 root-owned CAS-only socket directory'; else fail 'A1 broker socket directory'; fi
	if [ -S /var/run/enclave/apfs-broker/broker.sock ] && [ "$(stat -f '%u %g %Lp' /var/run/enclave/apfs-broker/broker.sock 2>/dev/null)" = '0 8702 660' ]; then pass 'A1 root broker socket'; else fail 'A1 broker socket'; fi
	for broker_dir in /var/db/enclave/apfs-broker /var/db/enclave/apfs-broker/state /var/db/enclave/apfs-broker/tuf/repo; do
		if [ ! -L "$broker_dir" ] && [ "$(stat -f '%u %Lp' "$broker_dir" 2>/dev/null)" = '0 700' ]; then pass "A1 protected $broker_dir"; else fail "A1 unsafe $broker_dir"; fi
	done
	info 'A1 layout/signature checks do not establish authenticated serving, snapshot entitlement, APFS mount flags or retraction; inspect deploy healthcheck and macme.md acceptance.'
fi

echo "== A2. authenticated console ingress layout (F97)"
if [ "$(id -u _enclaveingress 2>/dev/null)" = 708 ]; then pass "A2 gateway account UID 708"; else fail "A2 gateway account absent or incorrect"; fi
if /usr/sbin/dseditgroup -o checkmember -m _enclaveingress _enclave_ifc_c >/dev/null 2>&1; then pass "A2 gateway may connect to IFC"; else fail "A2 gateway missing IFC client membership"; fi
if [ "$(stat -f '%Su %Lp' /var/run/enclave/gateway 2>/dev/null)" = '_enclaveingress 755' ]; then pass "A2 gateway directory owner/mode"; else fail "A2 gateway directory owner/mode incorrect"; fi
if [ -S /var/run/enclave/gateway/gateway.sock ] && [ "$(stat -f '%Su %Lp' /var/run/enclave/gateway/gateway.sock 2>/dev/null)" = '_enclaveingress 666' ]; then pass "A2 connectable gateway socket"; else fail "A2 gateway socket owner/mode incorrect"; fi
info "A2 layout checks do not establish signed caller admission, console switching or lifecycle acceptance; run the F97 cases in macme.md"

echo '== A3. separate browser broker payload'
OIDC_APP='/Library/Application Support/EnterpriseEnclave/EnclaveOIDC.app'
if [ -x "$OIDC_APP/Contents/MacOS/enclave-oidc" ] && codesign --verify --strict "$OIDC_APP"; then
	oidc_info=$(codesign -dvvv "$OIDC_APP" 2>&1)
	if echo "$oidc_info" | grep -q '^Identifier=com.enterprise.enclave.oidc-broker$'; then pass 'A3 separate broker signature/identifier'; else fail 'A3 broker identifier'; fi
else
	fail 'A3 broker executable/signature'
fi
if [ -f /Library/LaunchAgents/com.enterprise.enclave.oidc-broker.plist ] && [ ! -L /Library/LaunchAgents/com.enterprise.enclave.oidc-broker.plist ] && [ "$(stat -f '%u %g %Lp' /Library/LaunchAgents/com.enterprise.enclave.oidc-broker.plist)" = '0 0 644' ]; then
	pass 'A3 root-owned broker LaunchAgent'
else
	fail 'A3 broker LaunchAgent protection'
fi
info 'A3 payload checks do not establish current-session configuration, browser lock-state readiness, IdP authentication, reciprocal distinct-UID serving or A4 qualification; missing authority leaves A4 unavailable.'

echo "== B. Secure Enclave as UID 703 under Seatbelt"
PROBE=/var/db/enclave/custody/probe
install -d -o _piivault -g _piivault -m 0700 "$PROBE"
probe() {
	sudo -u _piivault /usr/bin/sandbox-exec -f "$SB/custody.sb" "$APP_EXE" \
		--socket-dir /var/run/enclave --no-audit --profile L2 --state-dir "$PROBE" --sep-probe 1 2>&1
}
o1=$(probe)
r1=$?
echo "$o1" | sed 's/^/     /'
if [ $r1 -eq 0 ] && echo "$o1" | grep -q '"boot_epoch_signature_verified":true'; then
	pass "B SEP epoch key created and signs as uid $(id -u _piivault) under custody.sb"
else
	fail "B SEP probe (exit $r1)"
fi
if echo "$o1" | grep -q -- "-34018"; then fail "B errSecMissingEntitlement (-34018) seen"; else pass "B 0 x -34018"; fi
o2=$(probe)
r2=$?
k1=$(echo "$o1" | sed -n 's/.*"epoch_public_key":"\([0-9a-f]*\)".*/\1/p')
k2=$(echo "$o2" | sed -n 's/.*"epoch_public_key":"\([0-9a-f]*\)".*/\1/p')
if [ $r2 -eq 0 ] && [ -n "$k1" ] && [ "$k1" = "$k2" ]; then pass "B key survives restart (same epoch public key)"; else fail "B key did not survive restart"; fi
CLOG=/var/log/enclave/custody/custody.log
if [ -f "$CLOG" ] && grep -q SEP_EPOCH_KEY_READY "$CLOG"; then
	pass "B launchd-run UID 703 opened its SEP epoch key"
	grep -q HARDWARE_PROVIDERS_UNAVAILABLE "$CLOG" && info "B UID 703 then refuses to serve (fail closed) until GAP-14 helper + GAP-13 transport"
else
	info "B no SEP_EPOCH_KEY_READY in $CLOG yet"
fi

echo "== C. cross-daemon journal writes"
MKTEMP=/usr/bin/mktemp
TMPD=$("$MKTEMP" -d /private/tmp/mcpmac-verify.XXXXXXXX) || {
	fail "C unable to create owned profile directory"
	exit 1
}
trap 'rm -rf "$TMPD"' 0
trap 'exit 1' HUP INT TERM
for me in $DAEMONS; do
	ms=${me%%:*}
	ma=${me#*:}
	# Seatbelt layer: the daemon's own profile plus permission to exec mktemp.
	prof="$TMPD/$ms.sb"
	if ! { cat "$SB/$ms.sb" && printf '(allow process-exec (literal "%s"))\n(allow file-read* (literal "%s"))\n' "$MKTEMP" "$MKTEMP"; } >"$prof"; then
		fail "C unable to construct $ms profile"
		continue
	fi
	# Positive control: its own journal directory is writable under the profile.
	if journal_probe_write "/var/log/enclave/$ms" /usr/bin/sandbox-exec -f "$prof"; then
		:
	else
		fail "C control: $ms cannot create and clean its own exclusive journal probe (check would be vacuous)"
		continue
	fi
	posix_control=0
	if journal_probe_write "/var/log/enclave/$ms" sudo -u "$ma"; then
		posix_control=1
	else
		fail "C control: $ma cannot create and clean its own POSIX journal probe (negative POSIX checks would be vacuous)"
	fi
	for other in $DAEMONS; do
		os=${other%%:*}
		[ "$os" = "$ms" ] && continue
		journal_probe_write "/var/log/enclave/$os" /usr/bin/sandbox-exec -f "$prof"
		probe_result=$?
		case "$probe_result" in
		0) fail "C seatbelt: $ms (as root) wrote $os's journal dir" ;;
		1) pass "C seatbelt denies $ms -> $os" ;;
		*) fail "C seatbelt: $ms -> $os probe cleanup/result incomplete" ;;
		esac
		if [ "$posix_control" -eq 1 ]; then
			journal_probe_write "/var/log/enclave/$os" sudo -u "$ma"
			probe_result=$?
			case "$probe_result" in
			0) fail "C posix: $ma wrote $os's journal dir" ;;
			1) pass "C posix denies $ma -> $os" ;;
			*) fail "C posix: $ma -> $os probe cleanup/result incomplete" ;;
			esac
		fi
	done
done

SINCE=$(cat /var/db/enclave/.bootstrapped-at 2>/dev/null || true)
if [ -n "$SINCE" ]; then WINDOW="--start"; else
	WINDOW="--last"
	SINCE=30m
fi
echo "== E. authenticator transport (GAP-13)"
TRANSPORT=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments" /Library/LaunchDaemons/com.enterprise.enclave.custody.plist 2>/dev/null | grep -A1 -- '--yubikey-transport' | tail -n 1 | tr -d ' ')
info "E UID 703 transport: ${TRANSPORT:-unknown}"
ylog=$(grep -h '"event":"YUBIKEY_' "$CLOG" 2>/dev/null | tail -n 1)
case "$TRANSPORT" in
emulated:*)
	sock=${TRANSPORT#emulated:}
	if launchctl print system/com.enterprise.enclave.fido 2>/dev/null | grep -q "state = running"; then pass "E emulator running as _enclavefido"; else fail "E emulator not running"; fi
	if [ -S "$sock" ] && [ "$(stat -f '%Sg %Lp' "$sock")" = "_enclave_fido_c 660" ]; then pass "E emulator socket is _enclave_fido_c 0660"; else fail "E emulator socket mode/group wrong: $(stat -f '%Su:%Sg %Lp' "$sock" 2>&1)"; fi
	# Only UID 703 may reach the authenticator.
	if sudo -u _enclaveifc /usr/bin/nc -U "$sock" </dev/null >/dev/null 2>&1; then fail "E _enclaveifc connected to the emulator"; else pass "E posix denies _enclaveifc -> emulator"; fi
	case "$ylog" in
	*'"event":"YUBIKEY_READY"'*'"allowed":true'*) pass "E launchd-run UID 703 reached the emulator under Seatbelt; MDS allows it" ;;
	*'"event":"YUBIKEY_READY"'*) fail "E UID 703 reached the emulator but the MDS check failed: $ylog" ;;
	*) fail "E UID 703 did not reach the emulator: ${ylog:-no YUBIKEY_ line in $CLOG}" ;;
	esac
	;;
hid)
	case "$ylog" in
	*'"event":"YUBIKEY_READY"'*) pass "E UID 703 reached a physical key over IOKit HID: $ylog" ;;
	*) info "E no physical key reachable yet: ${ylog:-no YUBIKEY_ line}" ;;
	esac
	;;
esac

echo "== D. sandbox violations (mesh processes, since $SINCE)"
v=$(log show "$WINDOW" "$SINCE" --style compact --predicate 'eventMessage CONTAINS "Sandbox: enclave" OR eventMessage CONTAINS "Sandbox: mcp-enclave"' 2>/dev/null | grep -v '^Timestamp' | grep -v "xwrite-from-" || true)
if [ -z "$v" ]; then
	pass "D no Seatbelt violations by the mesh"
else
	n=$(echo "$v" | wc -l | tr -d ' ')
	info "D $n Seatbelt violation lines (deduplicated below); these drive the next profile revision"
	echo "$v" | sed -E 's/^.*Sandbox: //; s/\([0-9]+\)//; s/deny\([0-9]+\)/deny/' | sort | uniq -c | sort -rn | head -n 60
fi

echo "== F. chained ceremony"
JLOG=/var/log/enclave/custody/custody-audit.jsonl
[ -f "$JLOG" ] || JLOG=/var/log/enclave/custody/audit.jsonl
if [ -f "$JLOG" ]; then
	if grep -q '"event":"CUSTODIAN_ENROLLED"' "$JLOG"; then
		pass "F custodian enrolled in audit journal"
	else
		info "F no CUSTODIAN_ENROLLED in journal yet (run: sudo /opt/enterprise/enclave/bin/mcp-enclave vault enroll)"
	fi
	if grep -q '"event":"CEREMONY_' "$JLOG"; then
		pass "F chained ceremony logged in audit journal"
		grep -E '"event":"(CEREMONY_|SLOT_ISSUED)' "$JLOG" | tail -n 5 | sed 's/^/     /'
	else
		info "F no CEREMONY_* events logged in journal yet"
	fi
else
	info "F no audit journal at $JLOG yet"
fi

echo "== G. TUF, signed host configuration and policy bundle (GAP-20, GAP-32)"
for required in root.json timestamp.json snapshot.json targets.json enclave-host-config.json enclave-policy.cedar.v1.json vk_manifest.json enclave-distribution-v1.json; do
	if [ -f "/var/db/enclave/cas/tuf/repo/$required" ] && [ -s "/var/db/enclave/cas/tuf/repo/$required" ]; then
		pass "G public TUF inventory $required staged"
	else
		fail "G public TUF inventory missing $required"
	fi
done
for required in vk_manifest.json enclave-distribution-v1.json; do
	if [ -f "$PREFIX/cas/$required" ] && [ -s "$PREFIX/cas/$required" ]; then pass "G runtime payload $required staged"; else fail "G runtime payload missing $required"; fi
done
if [ -f "/var/db/enclave/cas/tuf/root.json" ]; then
	pass "G TUF root.json installed"
else
	fail "G TUF root.json missing (/var/db/enclave/cas/tuf/root.json)"
fi
if [ -f "/opt/enterprise/enclave/cas/enclave-host-config.json" ] || [ -f "/var/db/enclave/cas/tuf/repo/enclave-host-config.json" ]; then
	pass "G signed host configuration available"
else
	fail "G signed host configuration missing"
fi
if [ -f "/opt/enterprise/enclave/cas/enclave-policy.cedar.v1.json" ] || [ -f "/var/db/enclave/cas/tuf/repo/enclave-policy.cedar.v1.json" ]; then
	pass "G signed Cedar policy bundle available"
else
	fail "G signed Cedar policy bundle missing"
fi
out_cas=$(launchctl print "system/com.enterprise.enclave.cas" 2>/dev/null || true)
st_cas=$(echo "$out_cas" | sed -n 's/^[[:space:]]*state = //p' | head -n 1)
if [ "$st_cas" = "running" ]; then
	pass "G enclave-swarm-syncd is running with TUF host configuration"
else
	fail "G cas state: ${st_cas:-not running}"
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "verify-install: all checks passed"; else echo "verify-install: $FAILS check(s) failed"; fi
[ "$FAILS" -eq 0 ]
