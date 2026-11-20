#!/usr/bin/env bash
# ==============================================================================
# scripts/verify-formal-bridge.sh — Heimdall-Enclave Formal Bridge & Anti-Drift Gate
# ==============================================================================
# Single-command verification pipeline bridging the 94-module / 1,036-theorem
# Lean 4 specification suite (`proofs/lean4/`) to the live compiled Rust enclave.
#
# Layers verified:
#   Layer 0: Static Lean axiom hygiene (0 sorry / 0 admit; 1,036 pinned theorems)
#   Layer A: Shallow Rust-to-Lean source-guard extraction (9 guards + 29 mutation tests)
#   Layer B: Live Plonky3 KoalaBear STARK AIR polynomial extraction (62/62 polynomials)
#   Layer C: Exhaustive Rust <-> pinned Lean 4.14.0 oracle correspondence
#            (7,104 CedarEngine decisions + 3,440 ContextDag transitions)
#   Layer D: 9-target continuous differential & adversarial wire-parser fuzzing
#   Layer E: Full Lean 4.14.0 kernel compiler/axiom gate (auto-run if `lake` installed)
# ==============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

FUZZ_ITERATIONS="${PROPTEST_CASES:-2000}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/heimdall-formal-bridge.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

echo "========================================================================"
echo " Heimdall-Enclave Formal Bridge & Anti-Drift Verification Gate          "
echo "========================================================================"

echo ""
echo "[Layer 0/5] Auditing Lean 4 package inventory and zero-sorry hygiene..."
python3 - <<'PY'
import json, re
from pathlib import Path

enclave_mods = sorted(Path("proofs/lean4/Enclave").glob("*.lean"))
test_mods = sorted(Path("proofs/lean4/Test").glob("*.lean"))
pinned = json.loads(Path("proofs/lean4/theorem-types.json").read_text())

sorry_hits = []
for p in Path("proofs/lean4").rglob("*.lean"):
    for idx, line in enumerate(p.read_text().splitlines(), 1):
        code = line.split("--", 1)[0]
        if re.search(r"\b(sorry|admit)\b", code):
            sorry_hits.append(f"{p}:{idx}: {line.strip()}")

if sorry_hits:
    raise SystemExit("FAIL: unproven sorry/admit found:\n" + "\n".join(sorry_hits))

print(
    f"PASS: {len(enclave_mods)} Enclave modules, {len(test_mods)} Test modules, "
    f"{len(pinned)} pinned theorem types, 0 sorry/admit."
)
PY

echo ""
echo "[Layer A/5] Verifying Rust-to-Lean source guards & 29 adversarial mutation tests..."
python3 scripts/check-transport-guards.py >/dev/null
python3 -m unittest scripts.tests.test_transport_guards.SourceTests -v

echo ""
echo "[Layer B/5] Extracting & comparing all 62 live Plonky3 KoalaBear EpochAir polynomials..."
python3 scripts/extract-epoch-air.py

echo ""
echo "[Layer C/5] Running exhaustive Rust <-> pinned Lean 4.14.0 oracle correspondence..."
cargo run --locked -q -p enclave-agent-runtime --example authorization-correspondence >"${TMP_DIR}/rust-cedar.csv"
python3 scripts/check-authorization-correspondence.py \
	--rust-output "${TMP_DIR}/rust-cedar.csv" \
	--lean-output crates/enclave-agent-runtime/tests/data/cedar-lean-4.14.0.csv

cargo run --locked -q -p enclave-agent-runtime --example context-correspondence >"${TMP_DIR}/rust-context.csv"
python3 scripts/check-context-correspondence.py \
	--rust-output "${TMP_DIR}/rust-context.csv" \
	--lean-output crates/enclave-agent-runtime/tests/data/context-lean-4.14.0.csv

echo ""
echo "[Layer D/5] Executing 9-target continuous differential & parser fuzz suite..."
./scripts/run-fuzz.sh --iterations="${FUZZ_ITERATIONS}"

echo ""
if command -v lake >/dev/null 2>&1 || [ -x "${HOME}/.elan/bin/lake" ]; then
	export PATH="${HOME}/.elan/bin:${PATH}"
	echo "[Layer E/5] Lean 4 toolchain detected — executing live kernel & correspondence gates..."
	python3 scripts/check-lean.py
	python3 scripts/check-formal-correspondence.py
	python3 scripts/check-protocol-correspondence.py
else
	echo "[Layer E/5] SKIP (offline mode): pinned Lean 4.14.0 toolchain ('lake') not installed locally."
	echo "            Install via ./scripts/install-lean-toolchain.sh or inspect .github/workflows/formal.yml."
fi

echo ""
echo "========================================================================"
echo " [✓] Formal Bridge & Anti-Drift Verification Gate PASSED                "
echo "========================================================================"
