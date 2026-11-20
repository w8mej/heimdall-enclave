#!/usr/bin/env bash
# ==============================================================================
# scripts/run-fuzz.sh — Heimdall-Enclave Continuous Formal Fuzzing & Model Conformance Runner
# ==============================================================================
# Executes automated property fuzzing across the Rust ⟷ Lean 4 formal bridge.
# Verifies FSM bisimulation, lattice monotonicity, QIF bounds, and JCS canonicalization.
# ==============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

ITERATIONS="${PROPTEST_CASES:-5000}"
REPORT_DIR="${ROOT_DIR}/reports"

for arg in "$@"; do
	case "$arg" in
	--iterations=*)
		ITERATIONS="${arg#*=}"
		;;
	--quick)
		ITERATIONS=1000
		;;
	--exhaustive)
		ITERATIONS=20000
		;;
	--help | -h)
		echo "Usage: ./scripts/run-fuzz.sh [OPTIONS]"
		echo ""
		echo "Options:"
		echo "  --quick          Run 1,000 iterations per target (~0.1s)"
		echo "  --iterations=N   Run N iterations per target (default: 5,000)"
		echo "  --exhaustive     Run 20,000 iterations per target (~1s)"
		echo "  -h, --help       Show this help message"
		exit 0
		;;
	esac
done

export PROPTEST_CASES="${ITERATIONS}"

echo "=================================================================="
echo " Starting Formal Bisimulation & Model Conformance Fuzz Suite     "
echo "=================================================================="
echo " Engine:      proptest + coverage instrumentation"
echo " Target:      Rust Runtime ⟷ Lean 4 Specification Bridge"
echo " Iterations:  ${ITERATIONS} per subsystem target"
echo " Reports:     ${REPORT_DIR}/fuzz-report.md"
echo "=================================================================="
echo ""

# Ensure reports directory exists
mkdir -p "${REPORT_DIR}"

# Execute formal conformance fuzz tests
echo "[*] Executing property fuzzers across 9 critical invariant & adversarial wire-parser boundaries..."
cargo test \
	--package enclave-agent-runtime \
	--test formal_conformance_fuzz \
	-- \
	--test-threads=1 \
	--nocapture

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
	echo "=================================================================="
	echo " [✓] Formal Invariant Fuzzing Passed: 0 Semantic Divergences      "
	echo "=================================================================="
	if [ -f "${REPORT_DIR}/fuzz-report.md" ]; then
		echo " Audit report generated at: ${REPORT_DIR}/fuzz-report.md"
		echo " JSON metrics artifact at:  ${REPORT_DIR}/fuzz-report.json"
	fi
	exit 0
else
	echo "=================================================================="
	echo " [!] CRITICAL: Fuzzing Discovered Invariant or Bisimulation Defect"
	echo "=================================================================="
	echo " Minimal reproducing counterexample saved in proptest regressions."
	exit "$EXIT_CODE"
fi
