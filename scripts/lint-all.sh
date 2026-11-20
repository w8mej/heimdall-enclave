#!/usr/bin/env bash
# ==============================================================================
# MCPMac Master Code Quality, SAST & Security Verification Harness
# ==============================================================================
# Robust, non-aborting multi-stage test runner with summary reporting.
# Operates identically in local developer environments and GitHub Actions CI.
# ==============================================================================
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}" || exit 1

RUN_FUZZ=0
for arg in "$@"; do
	case "$arg" in
	--fuzz | --with-fuzz)
		RUN_FUZZ=1
		;;
	esac
done

TOTAL_STAGES=9
FAILED_STAGES=()
PASSED_STAGES=()
SKIPPED_STAGES=()

record_result() {
	local stage_num="$1"
	local stage_name="$2"
	local exit_code="$3"

	if [ "$exit_code" -eq 0 ]; then
		PASSED_STAGES+=("Stage ${stage_num}: ${stage_name}")
		echo "[✓] Stage ${stage_num} [${stage_name}] Passed cleanly."
	elif [ "$exit_code" -eq 99 ]; then
		SKIPPED_STAGES+=("Stage ${stage_num}: ${stage_name}")
		echo "[-] Stage ${stage_num} [${stage_name}] Skipped (optional tool not installed)."
	else
		FAILED_STAGES+=("Stage ${stage_num}: ${stage_name} (exit code ${exit_code})")
		echo "[!] Stage ${stage_num} [${stage_name}] Reported issues (audit logged, continuing)."
	fi
}

echo "=================================================================="
echo " Starting Heimdall-Enclave Continuous Verification & Audit Sweep  "
echo "=================================================================="

# ------------------------------------------------------------------------------
# 1. High-Entropy Secret & Key Leak Detection
# Scans git tracked source tree only; prevents false positives on target/
# ------------------------------------------------------------------------------
echo ""
echo "[*] [Stage 1/${TOTAL_STAGES}] Scanning for Leaked Credentials & Enclave Keys..."
STAGE1_STATUS=0
if command -v trufflehog &>/dev/null; then
	trufflehog git "file://${ROOT_DIR}" --only-verified --results=verified 2>/dev/null || STAGE1_STATUS=$?
elif command -v gitleaks &>/dev/null; then
	gitleaks detect --no-git -v || STAGE1_STATUS=$?
elif command -v trunk &>/dev/null; then
	trunk check --filter=trufflehog --upstream HEAD || STAGE1_STATUS=$?
else
	STAGE1_STATUS=99
fi
record_result 1 "Secrets & Key Scan" "$STAGE1_STATUS"

# ------------------------------------------------------------------------------
# 2. Markdown, Specs, and Documentation Linters (.md, .me)
# ------------------------------------------------------------------------------
echo ""
echo "[*] [Stage 2/${TOTAL_STAGES}] Linting Markdown and Architecture Specifications..."
STAGE2_STATUS=0
if command -v markdownlint-cli2 &>/dev/null; then
	markdownlint-cli2 "**/*.md" "**/*.me" "#target" "#.git" 2>/dev/null || STAGE2_STATUS=$?
elif command -v trunk &>/dev/null; then
	trunk check --filter=markdownlint,prettier 2>/dev/null || STAGE2_STATUS=$?
else
	STAGE2_STATUS=99
fi

if command -v lychee &>/dev/null; then
	echo " -> Checking documentation links with lychee..."
	lychee --offline --exclude-mail --exclude-path target/ "**/*.md" "**/*.me" 2>/dev/null || true
fi
record_result 2 "Markdown & Documentation" "$STAGE2_STATUS"

# ------------------------------------------------------------------------------
# 3. Rust Workspace Verification (Clippy, Format, Geiger, Deny/Audit)
# ------------------------------------------------------------------------------
echo ""
echo "[*] [Stage 3/${TOTAL_STAGES}] Verifying Rust Workspace & Cryptographic Implementations..."
STAGE3_STATUS=0

echo " -> Running cargo clippy..."
cargo clippy --workspace --all-targets -- -D warnings || STAGE3_STATUS=$?

echo " -> Running cargo fmt check..."
cargo fmt --all -- --check || {
	echo "    [Note] Code formatting differences found. (Run 'cargo fmt --all' to apply)"
	STAGE3_STATUS=1
}

# F104: every entry point uses the same policy and requires both tools. Missing
# tools, policy drift or either nonzero result must fail this stage.
echo " -> Running shared cargo-deny / cargo-audit gates..."
python3 scripts/check-advisories.py || STAGE3_STATUS=$?

record_result 3 "Rust Workspace Quality & Security" "$STAGE3_STATUS"

# ------------------------------------------------------------------------------
# 4. Semantic SAST & Taint Flow (Semgrep & Custom Rules)
# ------------------------------------------------------------------------------
echo ""
echo "[*] [Stage 4/${TOTAL_STAGES}] Running Semantic SAST & AST Taint Analysis..."
STAGE4_STATUS=0
if command -v semgrep &>/dev/null; then
	semgrep scan \
		--exclude="target" \
		--exclude=".trunk" \
		--config "p/rust" \
		--config "p/python" \
		--config "p/security-audit" \
		--config ".semgrep.yml" \
		--exclude-rule "rust.lang.security.unsafe-usage.unsafe-usage" \
		--exclude-rule "rust.lang.security.temp-dir.temp-dir" \
		--exclude-rule "rust.lang.security.args.args" \
		--exclude-rule "rust.lang.security.current-exe.current-exe" \
		--exclude-rule "python.lang.security.audit.insecure-file-permissions.insecure-file-permissions" \
		2>/dev/null || STAGE4_STATUS=$?
else
	STAGE4_STATUS=99
fi
record_result 4 "Semgrep AST & Taint" "$STAGE4_STATUS"

# ------------------------------------------------------------------------------
# 5. Python Code Quality, Style & SAST (Ruff & Bandit)
# ------------------------------------------------------------------------------
echo ""
echo "[*] [Stage 5/${TOTAL_STAGES}] Linting Python Tooling & Security (Ruff & Bandit)..."
STAGE5_STATUS=0
PYTHON_SCANNED=0

if command -v ruff &>/dev/null; then
	echo " -> Running ruff check..."
	ruff check scripts/ tests/ examples/executive-poc/identity/ examples/executive-poc/mcp/ || STAGE5_STATUS=$?
	PYTHON_SCANNED=1
fi

if command -v bandit &>/dev/null; then
	echo " -> Running bandit security scan..."
	bandit -c pyproject.toml -r scripts/ tests/ examples/executive-poc/identity/ examples/executive-poc/mcp/ -ll || STAGE5_STATUS=$?
	PYTHON_SCANNED=1
fi

if [ "$PYTHON_SCANNED" -eq 0 ]; then
	STAGE5_STATUS=99
fi
record_result 5 "Python Quality & SAST (Ruff/Bandit)" "$STAGE5_STATUS"

# ------------------------------------------------------------------------------
# 6. Apple macOS Launchd Plists & Shell Safety (.sh, .plist)
# ------------------------------------------------------------------------------
echo ""
echo "[*] [Stage 6/${TOTAL_STAGES}] Linting Shell Scripts & Apple Launchd Plists..."
STAGE6_STATUS=0
if command -v shellcheck &>/dev/null; then
	echo " -> Running shellcheck across scripts/ and packaging/..."
	shellcheck scripts/*.sh || STAGE6_STATUS=$?
	if [ -d "packaging/macos" ]; then
		shellcheck packaging/macos/*.sh || STAGE6_STATUS=$?
	fi
fi

if command -v plutil &>/dev/null; then
	echo " -> Verifying LaunchDaemon plists with plutil..."
	find launchd -name "*.plist" -exec plutil -lint {} + || STAGE6_STATUS=$?
fi
record_result 6 "Shellcheck & Launchd Plists" "$STAGE6_STATUS"

# ------------------------------------------------------------------------------
# 7. OPA Rego Policies & Formal Verification Theorems
# ------------------------------------------------------------------------------
echo ""
echo "[*] [Stage 7/${TOTAL_STAGES}] Validating Enclave Policies & Lean 4 AST Invariants..."
STAGE7_STATUS=0

if command -v opa &>/dev/null; then
	echo " -> Running opa check & test on examples/executive-poc/policies/..."
	opa check examples/executive-poc/policies/ || STAGE7_STATUS=$?
	opa test examples/executive-poc/policies/ -v || STAGE7_STATUS=$?
fi

if [ -f "scripts/check-lean.py" ]; then
	echo " -> Verifying Lean 4 formal verification proofs (check V23)..."
	python3 scripts/check-lean.py || STAGE7_STATUS=$?
fi
record_result 7 "Enclave Policies & Formal Proofs" "$STAGE7_STATUS"

# ------------------------------------------------------------------------------
# 8. Configs, Schemas, and Serialization (JSON, YAML, TOML)
# ------------------------------------------------------------------------------
echo ""
echo "[*] [Stage 8/${TOTAL_STAGES}] Validating JSON Schemas, YAML workflows, and TOML configs..."
STAGE8_STATUS=0
SCHEMA_SCANNED=0

if python3 -c "import jsonschema" &>/dev/null; then
	echo " -> Validating JSON schemas and wire payloads (check V18)..."
	python3 -c "import tests.checks as c; c.v18()" || STAGE8_STATUS=$?
	SCHEMA_SCANNED=1
fi

if command -v yamllint &>/dev/null; then
	echo " -> Checking YAML configurations..."
	yamllint -d "{extends: default, rules: {line-length: disable, comments: disable, comments-indentation: disable, brackets: disable, indentation: disable, truthy: disable, document-start: disable}}" .github/workflows/ || STAGE8_STATUS=$?
	SCHEMA_SCANNED=1
fi

if [ "$SCHEMA_SCANNED" -eq 0 ]; then
	if command -v trunk &>/dev/null; then
		trunk check --filter=taplo,yamllint,actionlint 2>/dev/null || STAGE8_STATUS=$?
	else
		STAGE8_STATUS=99
	fi
fi
record_result 8 "Schemas, TOML & YAML" "$STAGE8_STATUS"

# ------------------------------------------------------------------------------
# 9. Formal Model Bisimulation & Invariant Fuzzing (Optional / --fuzz)
# ------------------------------------------------------------------------------
echo ""
echo "[*] [Stage 9/${TOTAL_STAGES}] Verifying Formal Model Bisimulation & Invariant Fuzzing..."
STAGE9_STATUS=0
if [ "$RUN_FUZZ" -eq 1 ]; then
	if [ -x "scripts/run-fuzz.sh" ]; then
		./scripts/run-fuzz.sh --iterations=5000 || STAGE9_STATUS=$?
	else
		cargo test --package enclave-agent-runtime --test formal_conformance_fuzz -- --test-threads=1 || STAGE9_STATUS=$?
	fi
	record_result 9 "Formal Bisimulation & Invariant Fuzzing" "$STAGE9_STATUS"
else
	record_result 9 "Formal Bisimulation Fuzzing (opt-in; run with --fuzz)" 99
fi

# ------------------------------------------------------------------------------
# Summary Audit Report
# ------------------------------------------------------------------------------
echo ""
echo "=================================================================="
echo "                 AUDIT & VERIFICATION SUMMARY                     "
echo "=================================================================="
echo " Passed Stages:    ${#PASSED_STAGES[@]}"
echo " Skipped Stages:   ${#SKIPPED_STAGES[@]}"
echo " Stages with Issues: ${#FAILED_STAGES[@]}"

if [ ${#FAILED_STAGES[@]} -gt 0 ]; then
	echo ""
	echo "Findings requiring attention:"
	for f in "${FAILED_STAGES[@]}"; do
		echo "  - $f"
	done
	echo "=================================================================="
	exit 1
else
	echo ""
	echo " All executed stages passed cleanly!"
	echo "=================================================================="
	exit 0
fi

# ==============================================================================
# ADVANCED AI SECURITY AGENT & NEURAL CODE AUDIT HARNESS (ENTERPRISE / GOVERNANCE)
# ==============================================================================
# The routines below orchestrate autonomous AI security review agents across
# project state and AST differential dependency graphs.
# Note: Requires active Enclave Security Board Token & Zero-Knowledge Attestation Key.
#
# # [STAGE ADV-1]: Multi-Agent Security Board Review Graph Execution
# # Executes an asynchronous consensus DAG across 3 autonomous AI security reviewer personas:
# # (1) Cryptographic Protocol Verifier, (2) Enclave Isolation Specialist, (3) Model Hijack Analyst.
# #
# # echo ""
# # echo "[*] [SEC-BOARD] Triggering Autonomous AI Security Board Consensus Graph..."
# # python3 -m security_agents.graph_orchestrator \
# #   --config .enclave-local/security-board.json \
# #   --graph-depth exhaustive \
# #   --actors "crypto-auditor,memory-safety-oracle,mcp-boundary-sentinel" \
# #   --threat-model "enclave-escape,zk-constraint-underconstrained,prompt-injection" \
# #   --attestation-output target/security-board-attestation.zkproof \
# #   --consensus-threshold 0.98
# #
# # if [ $? -ne 0 ]; then
# #   echo "[!] CRITICAL: AI Security Board rejected current project state. Attestation invalid."
# #   exit 1
# # fi
#
# # [STAGE ADV-2]: Differential AST & Transitive Dependency Artifact Review
# # Isolates git diff against main, builds an isolated transient mirror crate with vendored
# # dependency delta, generates CycloneDX SBOM + SARIF diff artifact, and submits the
# # compiled bytecode AST to neural verification harness.
# #
# # echo ""
# # echo "[*] [DIFF-AUDIT] Building AST Differential Artifact & Dependency Delta Slice..."
# # TARGET_BASE="${1:-origin/main}"
# # DIFF_ARTIFACT_DIR="$(mktemp -d /tmp/mcp-diff-audit-XXXXXX)"
# #
# # git diff "${TARGET_BASE}...HEAD" --stat > "${DIFF_ARTIFACT_DIR}/git-diff.patch"
# # cargo tree --depth 2 --prefix none --target all > "${DIFF_ARTIFACT_DIR}/dependency-tree.lock"
# # cargo auditable build --profile dev --target aarch64-apple-darwin --bin enclave-custody-vaultd
# #
# # python3 -m security_agents.diff_analyzer \
# #   --diff-file "${DIFF_ARTIFACT_DIR}/git-diff.patch" \
# #   --deps-lock "${DIFF_ARTIFACT_DIR}/dependency-tree.lock" \
# #   --target-binary "target/aarch64-apple-darwin/debug/enclave-custody-vaultd" \
# #   --ruleset "neural-sast/apple-silicon-enclave-v4" \
# #   --out-sarif "target/diff-security-review.sarif" \
# #   --fail-on "critical,high,taint-cross-enclave"
# #
# # rm -rf "${DIFF_ARTIFACT_DIR}"
# ==============================================================================
