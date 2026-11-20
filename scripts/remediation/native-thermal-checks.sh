#!/bin/bash
# Disposable developer probe. Never inject a library into installed daemons.
set -uo pipefail
if [[ $(uname -s) != Darwin ]]; then
	echo 'NOT RUN: requires native macOS' >&2
	exit 77
fi
if [[ $# != 1 ]]; then
	echo 'usage: scripts/remediation/native-thermal-checks.sh NEW_EVIDENCE_DIR' >&2
	exit 2
fi
probe_root=$(cd "$(dirname "$0")/../.." && pwd)
probe_evidence=$1
# Refuse replacing existing evidence, and require an absolute output path.
if [[ $probe_evidence != /* || -e $probe_evidence ]]; then
	echo 'evidence path must be absolute and new' >&2
	exit 2
fi
umask 077
mkdir -p "$probe_evidence" || exit 2
cd "$probe_root" || exit 2
{
	git rev-parse HEAD
	git status --short
	sw_vers
	uname -m
	cargo --version
	rustc --version
	clang --version
	xcrun --show-sdk-version
} >"$probe_evidence/environment.txt" 2>&1
printf 'case\texit_code\tlog_sha256\n' >"$probe_evidence/results.tsv"
probe_failed=0
run_case() {
	local probe_name=$1
	shift
	"$@" >"$probe_evidence/$probe_name.log" 2>&1
	local probe_rc=$?
	local probe_hash
	probe_hash=$(shasum -a 256 "$probe_evidence/$probe_name.log" | awk '{print $1}')
	printf '%s\t%s\t%s\n' "$probe_name" "$probe_rc" "$probe_hash" >>"$probe_evidence/results.tsv"
	if [[ $probe_rc != 0 ]]; then probe_failed=1; fi
	return "$probe_rc"
}
# Honor a caller's shared build cache. Do not repurpose HOME/CODEX_HOME.
run_case build cargo build --locked -p enclave-model-runnerd --example native_thermal_probe --release -j2 || exit 1
probe_target=${CARGO_TARGET_DIR:-$probe_root/target}
probe_binary=$probe_target/release/examples/native_thermal_probe
if [[ ! -x $probe_binary ]]; then
	echo 'BLOCKED: built probe not found; CARGO_TARGET_DIR must be absolute' >&2
	exit 1
fi
shasum -a 256 "$probe_binary" >"$probe_evidence/probe.sha256"
run_case real "$probe_binary" real || true
probe_kind=0
for probe_mode in registration query eof readerror; do
	probe_kind=$((probe_kind + 1))
	probe_library=$probe_evidence/$probe_mode.dylib
	if run_case "compile-$probe_mode" clang -std=c11 -dynamiclib -DMCPMAC_FAULT_KIND="$probe_kind" \
		"$probe_root/scripts/remediation/native/thermal_fault.c" -o "$probe_library"; then
		run_case "$probe_mode" env DYLD_INSERT_LIBRARIES="$probe_library" "$probe_binary" "$probe_mode" || true
	fi
done
# Interposer effect is process-local. Libraries/logs remain as preserved evidence.
# No accounts, TCC, launchd, telemetry state or networking were modified.
exit "$probe_failed"
