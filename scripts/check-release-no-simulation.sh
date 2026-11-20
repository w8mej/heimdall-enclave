#!/bin/sh
# GAP-03 / GAP-42: release builds contain no simulated custody hardware.
#
# 1. Build every release binary exactly as shipped (no `simulation` feature).
# 2. Assert none of them carries the simulation-only markers (release
#    binaries are stripped, so the check looks for string constants that only
#    the simulated SEP / virtual authenticator embed).
# 3. Assert the release custody daemon refuses `--simulated-hardware`.
#    The release custody daemon also has no CTAPHID emulator transport
#    (`--yubikey-transport emulated:` fails CTAP_EMULATOR_NOT_COMPILED; unit
#    test `ctap::transport::tests::parse_transport`).
# 4. Positive control: a `--features simulation` build does carry the
#    markers, so the check cannot pass vacuously.
set -eu
cd "$(dirname "$0")/.."
# Match the emulator protocol HELLO_MAGIC, not its generic product name.
# The CLI embeds install.sh, whose physical-key cleanup names old emulator
# metadata. That cleanup string does not establish compiled emulator transport.
MARKERS="depot virtual authenticator (simulation)
depot simulated SEP epoch key v1
depot CTAPHID emulator v1
depot MemoryDisplay (simulation)"
# DEFECT-F-64: only `simulation` builds may load an unsigned inline policy bundle.
POLICY_MARKER="depot unsigned inline policy (simulation)"
BINS="depot-enclave enclave-model-runnerd enclave-swarm-syncd enclave-custody-vaultd enclave-agent-runtime enclave-zk-auditor"

cargo build --release --locked --workspace --bins
fail=0
n=0
for b in $BINS; do
	n=$((n + 1))
	f="target/release/$b"
	[ -x "$f" ] || {
		echo "missing release binary $f"
		exit 1
	}
	echo "$MARKERS" | while IFS= read -r m; do
		if grep -aqF "$m" "$f"; then
			echo "FAIL: $f contains simulation marker: $m"
			exit 1
		fi
	done || fail=1
done
[ "$fail" -eq 0 ] || exit 1
echo "ok: no simulation markers in $n release binaries"

for b in enclave-agent-runtime depot-enclave; do
	if grep -aqF "$POLICY_MARKER" "target/release/$b"; then
		echo "FAIL: target/release/$b can load unsigned inline policy bundles ($POLICY_MARKER)"
		exit 1
	fi
done
echo "ok: release enclave-agent-runtime / depot-enclave cannot load unsigned inline policy (F-64)"

# F13: custody-only markers missed the shipped hydration mock. Inspect the
# actual CLI artifact and exercise the production path, including old hooks.
for marker in depot_TEST_TAMPER_DMG depot_INJECT_HYDRATE_FAIL; do
	if grep -aqF "$marker" target/release/depot-enclave; then
		echo "FAIL: release hydration CLI contains obsolete test hook: $marker"
		exit 1
	fi
done
python3 scripts/check-hydration-artifact.py target/release/depot-enclave

out=$(target/release/enclave-custody-vaultd --dev-same-uid --simulated-hardware --socket-dir "${TMPDIR:-/tmp}/depot-nosim-$$" --no-audit 2>&1 || true)
case "$out" in
*SIMULATION_NOT_COMPILED*) echo "ok: release custody daemon refuses --simulated-hardware" ;;
*)
	echo "FAIL: release custody daemon did not refuse --simulated-hardware: $out"
	exit 1
	;;
esac

out_zk=$(target/release/enclave-zk-auditor --dev-same-uid --accelerated-schedule --socket-dir "${TMPDIR:-/tmp}/depot-nosim-$$" --no-audit 2>&1 || true)
case "$out_zk" in
*ACCELERATED_SCHEDULE_NOT_COMPILED*) echo "ok: release zk-auditor refuses --accelerated-schedule" ;;
*)
	echo "FAIL: release zk-auditor did not refuse --accelerated-schedule: $out_zk"
	exit 1
	;;
esac

# GAP-35: Assert L3 / no-default-features enclave-agent-runtime lacks A2A marker
cargo build --release --locked -p enclave-agent-runtime --no-default-features --target-dir target/l3-runtime-check
if grep -aqF "depot A2A mTLS transport (L2 only)" target/l3-runtime-check/release/enclave-agent-runtime; then
	echo "FAIL: L3 enclave-agent-runtime contains A2A marker"
	exit 1
fi
echo "ok: L3 runtime build lacks A2A marker"
rm -rf target/l3-runtime-check

# Positive control (separate target dir so the shipped binaries are untouched).
cargo build --release --locked -p enclave-custody-vaultd --features simulation --target-dir target/sim-control
# (The CTAPHID emulator marker lives in the emulator binary, built only
# with `ctap-emulator`, which `simulation` implies.)
echo "$MARKERS" | while IFS= read -r m; do
	grep -aqF "$m" target/sim-control/release/enclave-custody-vaultd target/sim-control/release/enclave-fido-emulator || {
		echo "FAIL: control build lacks marker: $m (the check would be vacuous)"
		exit 1
	}
done
echo "ok: control build with --features simulation carries the markers"

# DEFECT-F-64 positive control: the runtime built with `simulation` carries the
# unsigned-inline-policy marker, so the absence check above is not vacuous.
cargo build --release --locked -p enclave-agent-runtime --features simulation --target-dir target/sim-policy-control
grep -aqF "$POLICY_MARKER" target/sim-policy-control/release/enclave-agent-runtime || {
	echo "FAIL: control build lacks marker: $POLICY_MARKER (the F-64 check would be vacuous)"
	exit 1
}
echo "ok: control build with --features simulation carries the F-64 policy marker"
rm -rf target/sim-policy-control
