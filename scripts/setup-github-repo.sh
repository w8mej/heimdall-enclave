#!/usr/bin/env bash
# ==============================================================================
# setup-github-repo.sh — Intelligent GitHub Setup & Reconciliation for Heimdall-Enclave
# ==============================================================================
# Inspects current remote repository configuration, compares against the
# normative specification (docs/GITHUB_SETUP_SPECIFICATION.md), and non-destructively
# applies only missing or drifted settings, preserving all user customizations.
# ==============================================================================

set -euo pipefail

# ANSI color codes
BOLD="\033[1m"
GREEN="\033[32m"
CYAN="\033[36m"
YELLOW="\033[33m"
BLUE="\033[34m"
RED="\033[31m"
RESET="\033[0m"

log_info() { echo -e "${BLUE}ℹ${RESET}  $*"; }
log_match() { echo -e "${GREEN}✓ [MATCH]${RESET} $*"; }
log_apply() { echo -e "${CYAN}→ [APPLYING]${RESET} $*"; }
log_applied() { echo -e "${GREEN}✓ [APPLIED]${RESET} $*"; }
log_preserve() { echo -e "${YELLOW}★ [PRESERVED]${RESET} $*"; }
log_warn() { echo -e "${YELLOW}⚠ [WARNING]${RESET} $*"; }
log_dry() { echo -e "${YELLOW}[DRY-RUN]${RESET} $*"; }
log_error() { echo -e "${RED}✗ [ERROR]${RESET} $*" >&2; }

# Counters & helper functions
CHANGES_APPLIED=0
ITEMS_MATCHED=0
ITEMS_PRESERVED=0

inc_matched() { ITEMS_MATCHED=$((ITEMS_MATCHED + 1)); }
inc_preserved() { ITEMS_PRESERVED=$((ITEMS_PRESERVED + 1)); }
inc_applied() { CHANGES_APPLIED=$((CHANGES_APPLIED + 1)); }

# Parse arguments & flags
DRY_RUN=0
FORCE_METADATA=0
PROTECT_MAIN=0
REPO_ARG=""

show_usage() {
	cat <<EOF
Usage: $(basename "$0") [OPTIONS] [OWNER/REPO]

Reconcile target GitHub repository with docs/GITHUB_SETUP_SPECIFICATION.md.
Pulls existing remote state and selectively applies only missing or drifted
settings, preserving any custom topics, labels, descriptions, or homepages.

Options:
  --dry-run                 Inspect remote state and display planned actions without modifying GitHub
  --force-metadata          Overwrite existing repository description and homepage if set
  --protect-main            Apply strict branch protection rules to 'main'
  -h, --help                Show this help message and exit

Target Repository Detection:
  1. Positional argument: OWNER/REPO (e.g. w8mej/heimdall-enclave)
  2. Git remote origin URL (if pointing to github.com)
  3. Authenticated GitHub user + /heimdall-enclave (e.g. \$(gh api user -q .login)/heimdall-enclave)
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--dry-run)
		DRY_RUN=1
		shift
		;;
	--force-metadata)
		FORCE_METADATA=1
		shift
		;;
	--protect-main)
		PROTECT_MAIN=1
		shift
		;;
	-h | --help)
		show_usage
		exit 0
		;;
	-*)
		log_error "Unknown option: $1"
		show_usage
		exit 1
		;;
	*)
		if [[ -z "$REPO_ARG" ]]; then
			REPO_ARG="$1"
		else
			log_error "Unexpected argument: $1"
			show_usage
			exit 1
		fi
		shift
		;;
	esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Verify required dependencies
if ! command -v gh &>/dev/null; then
	log_error "GitHub CLI (gh) is required but not installed. Install via: brew install gh"
	exit 1
fi

if ! command -v jq &>/dev/null; then
	log_error "jq is required for JSON processing. Install via: brew install jq"
	exit 1
fi

if ! gh auth status &>/dev/null; then
	log_error "gh is not logged in. Run 'gh auth login' first."
	exit 1
fi

# Auto-detect target repository if not explicitly passed
REPO="$REPO_ARG"
if [[ -z "$REPO" ]]; then
	# Try git remote origin
	REMOTE_URL=$(git remote get-url origin 2>/dev/null || echo "")
	if [[ "$REMOTE_URL" =~ github\.com[:/]([^/]+/[^/.]+)(\.git)?$ ]]; then
		REPO="${BASH_REMATCH[1]}"
	fi
fi

if [[ -z "$REPO" ]]; then
	# Try authenticated user login
	GH_USER=$(gh api user -q .login 2>/dev/null || echo "")
	if [[ -n "$GH_USER" ]]; then
		if gh api "repos/${GH_USER}/heimdall-enclave" &>/dev/null; then
			REPO="${GH_USER}/heimdall-enclave"
		fi
	fi
fi

if [[ -z "$REPO" ]]; then
	REPO="heimdall-enclave/heimdall-enclave"
fi

echo -e "${BOLD}==================================================================${RESET}"
echo -e "${BOLD} Heimdall-Enclave — Intelligent GitHub Setup & Reconciliation${RESET}"
echo -e " Target Repository: ${CYAN}${REPO}${RESET}"
if [[ $DRY_RUN -eq 1 ]]; then
	echo -e " Mode:              ${YELLOW}DRY-RUN (read-only preview)${RESET}"
else
	echo -e " Mode:              ${GREEN}LIVE RECONCILIATION${RESET}"
fi
echo -e " Specification:     docs/GITHUB_SETUP_SPECIFICATION.md"
echo -e "${BOLD}==================================================================${RESET}"
echo ""

# ------------------------------------------------------------------------------
# Fetch remote repository state
# ------------------------------------------------------------------------------
log_info "Fetching current repository state from GitHub API..."
if ! REPO_JSON=$(gh api "repos/${REPO}" 2>/dev/null); then
	log_error "Failed to access repository '${REPO}'. Check repository name and permissions."
	exit 1
fi

if ! LABELS_JSON=$(gh label list --repo "${REPO}" --json name,color,description --limit 100 2>/dev/null); then
	log_error "Failed to access labels for repository '${REPO}'."
	exit 1
fi

# Track reconciliation statistics
CHANGES_APPLIED=0
ITEMS_MATCHED=0
ITEMS_PRESERVED=0

# ==============================================================================
# Step 1: Repository Core Metadata (Description & Homepage)
# ==============================================================================
echo ""
echo -e "${BOLD}[1/6] Core Metadata Reconciliation${RESET}"
TARGET_DESC="Hardware-Attested Zero-Trust Sentinel & Post-Quantum Information Flow Control for Agentic AI on Apple Silicon"
TARGET_HOMEPAGE="https://github.com/${REPO}"

CURRENT_DESC=$(jq -r '.description // empty' <<<"$REPO_JSON")
CURRENT_HOMEPAGE=$(jq -r '.homepage // empty' <<<"$REPO_JSON")

META_ARGS=()

# Evaluate Description
if [[ "$CURRENT_DESC" == "$TARGET_DESC" ]]; then
	log_match "Description already matches specification."
	inc_matched
elif [[ -n "$CURRENT_DESC" && $FORCE_METADATA -eq 0 ]]; then
	log_preserve "Retaining existing custom description:"
	echo -e "      \"${CURRENT_DESC}\""
	echo -e "      ${BLUE}(pass --force-metadata to overwrite with normative specification)${RESET}"
	inc_preserved
else
	META_ARGS+=(--description "$TARGET_DESC")
	log_apply "Will set repository description to:"
	echo -e "      \"${TARGET_DESC}\""
	inc_applied
fi

# Evaluate Homepage
if [[ -n "$CURRENT_HOMEPAGE" && $FORCE_METADATA -eq 0 ]]; then
	log_preserve "Retaining existing custom homepage: ${CURRENT_HOMEPAGE}"
	inc_preserved
elif [[ "$CURRENT_HOMEPAGE" == "$TARGET_HOMEPAGE" ]]; then
	log_match "Homepage already matches repository URL."
	inc_matched
else
	META_ARGS+=(--homepage "$TARGET_HOMEPAGE")
	log_apply "Will set homepage to: ${TARGET_HOMEPAGE}"
	inc_applied
fi

if [[ ${#META_ARGS[@]} -gt 0 ]]; then
	if [[ $DRY_RUN -eq 1 ]]; then
		log_dry "gh repo edit \"${REPO}\" ${META_ARGS[*]}"
	else
		gh repo edit "${REPO}" "${META_ARGS[@]}"
		log_applied "Metadata successfully updated."
	fi
fi

# ==============================================================================
# Step 2: Repository Features & Merge Configuration
# ==============================================================================
echo ""
echo -e "${BOLD}[2/6] Feature Toggles & PR Merge Policy Reconciliation${RESET}"

CUR_HAS_ISSUES=$(jq -r '.has_issues' <<<"$REPO_JSON")
CUR_HAS_DISCUSSIONS=$(jq -r '.has_discussions' <<<"$REPO_JSON")
CUR_HAS_WIKI=$(jq -r '.has_wiki' <<<"$REPO_JSON")
CUR_DELETE_BRANCH=$(jq -r '.delete_branch_on_merge' <<<"$REPO_JSON")
CUR_ALLOW_MERGE_COMMIT=$(jq -r '.allow_merge_commit' <<<"$REPO_JSON")
CUR_ALLOW_SQUASH=$(jq -r '.allow_squash_merge' <<<"$REPO_JSON")
CUR_ALLOW_REBASE=$(jq -r '.allow_rebase_merge' <<<"$REPO_JSON")
CUR_ALLOW_UPDATE_BRANCH=$(jq -r '.allow_update_branch' <<<"$REPO_JSON")

FEATURE_ARGS=()

# Issues (Target: true)
if [[ "$CUR_HAS_ISSUES" == "true" ]]; then
	log_match "Issues: ENABLED"
	inc_matched
else
	FEATURE_ARGS+=(--enable-issues=true)
	log_apply "Issues is disabled -> Enabling issues"
	inc_applied
fi

# Discussions (Target: true)
if [[ "$CUR_HAS_DISCUSSIONS" == "true" ]]; then
	log_match "Discussions: ENABLED"
	inc_matched
else
	FEATURE_ARGS+=(--enable-discussions=true)
	log_apply "Discussions is disabled -> Enabling discussions"
	inc_applied
fi

# Wiki (Target: false)
if [[ "$CUR_HAS_WIKI" == "false" ]]; then
	log_match "Wiki: DISABLED (documentation lives in docs/)"
	inc_matched
else
	FEATURE_ARGS+=(--enable-wiki=false)
	log_apply "Wiki is enabled -> Disabling wiki (documentation lives in docs/)"
	inc_applied
fi

# Delete branch on merge (Target: true)
if [[ "$CUR_DELETE_BRANCH" == "true" ]]; then
	log_match "Delete head branch on merge: ENABLED"
	inc_matched
else
	FEATURE_ARGS+=(--delete-branch-on-merge=true)
	log_apply "Delete branch on merge is disabled -> Enabling"
	inc_applied
fi

# Allow merge commit (Target: false)
if [[ "$CUR_ALLOW_MERGE_COMMIT" == "false" ]]; then
	log_match "Merge commits: DISABLED (linear history enforced)"
	inc_matched
else
	FEATURE_ARGS+=(--enable-merge-commit=false)
	log_apply "Merge commits currently allowed -> Disabling (enforcing linear history)"
	inc_applied
fi

# Allow squash merge (Target: true)
if [[ "$CUR_ALLOW_SQUASH" == "true" ]]; then
	log_match "Squash merge: ENABLED"
	inc_matched
else
	FEATURE_ARGS+=(--enable-squash-merge=true)
	log_apply "Squash merge is disabled -> Enabling"
	inc_applied
fi

# Allow rebase merge (Target: true)
if [[ "$CUR_ALLOW_REBASE" == "true" ]]; then
	log_match "Rebase merge: ENABLED"
	inc_matched
else
	FEATURE_ARGS+=(--enable-rebase-merge=true)
	log_apply "Rebase merge is disabled -> Enabling"
	inc_applied
fi

# Allow update branch (Target: true)
if [[ "$CUR_ALLOW_UPDATE_BRANCH" == "true" ]]; then
	log_match "Always suggest updating PR branches: ENABLED"
	inc_matched
else
	FEATURE_ARGS+=(--allow-update-branch=true)
	log_apply "Update PR branches suggestion disabled -> Enabling"
	inc_applied
fi

if [[ ${#FEATURE_ARGS[@]} -gt 0 ]]; then
	if [[ $DRY_RUN -eq 1 ]]; then
		log_dry "gh repo edit \"${REPO}\" ${FEATURE_ARGS[*]}"
	else
		gh repo edit "${REPO}" "${FEATURE_ARGS[@]}"
		log_applied "Repository feature settings updated successfully."
	fi
fi

# ==============================================================================
# Step 3: Discoverability Topics Reconciliation
# ==============================================================================
echo ""
echo -e "${BOLD}[3/6] Discoverability Topics Reconciliation${RESET}"

TARGET_TOPICS=(
	"apple-silicon"
	"security"
	"zero-trust"
	"enclave"
	"agentic-ai"
	"depot"
	"model-context-protocol"
	"lean4"
	"formal-verification"
	"post-quantum"
	"cedar-policy"
	"rust"
	"macos"
	"darwin"
	"stark"
	"plonky3"
)

CURRENT_TOPICS_LIST=$(jq -r '.topics // [] | .[]' <<<"$REPO_JSON")

MISSING_TOPICS=()
for t in "${TARGET_TOPICS[@]}"; do
	if echo "$CURRENT_TOPICS_LIST" | grep -qx "$t"; then
		inc_matched
	else
		MISSING_TOPICS+=("$t")
	fi
done

# Identify existing custom topics not in normative target set
CUSTOM_TOPICS=()
while IFS= read -r cur_top; do
	[[ -z "$cur_top" ]] && continue
	is_target=0
	for t in "${TARGET_TOPICS[@]}"; do
		if [[ "$cur_top" == "$t" ]]; then
			is_target=1
			break
		fi
	done
	if [[ $is_target -eq 0 ]]; then
		CUSTOM_TOPICS+=("$cur_top")
	fi
done <<<"$CURRENT_TOPICS_LIST"

if [[ ${#CUSTOM_TOPICS[@]} -gt 0 ]]; then
	log_preserve "Preserved ${#CUSTOM_TOPICS[@]} user-defined topics: ${CUSTOM_TOPICS[*]}"
	ITEMS_PRESERVED=$((ITEMS_PRESERVED + ${#CUSTOM_TOPICS[@]}))
fi

if [[ ${#MISSING_TOPICS[@]} -eq 0 ]]; then
	log_match "All ${#TARGET_TOPICS[@]} normative topics are present on remote repository."
else
	TOPIC_ARGS=()
	for mt in "${MISSING_TOPICS[@]}"; do
		TOPIC_ARGS+=(--add-topic "$mt")
		log_apply "Adding missing topic: ${mt}"
		inc_applied
	done

	if [[ $DRY_RUN -eq 1 ]]; then
		log_dry "gh repo edit \"${REPO}\" ${TOPIC_ARGS[*]}"
	else
		gh repo edit "${REPO}" "${TOPIC_ARGS[@]}"
		log_applied "Added ${#MISSING_TOPICS[@]} missing topics."
	fi
fi

# ==============================================================================
# Step 4: Issue & Triage Taxonomy Labels Reconciliation
# ==============================================================================
echo ""
echo -e "${BOLD}[4/6] Issue & Triage Label Taxonomy Reconciliation${RESET}"

# Target Label Definitions: name|color|description
TARGET_LABELS=(
	"sev/critical|B60205|Immediate exploit / security boundary breach"
	"sev/high|D93F0B|High impact vulnerability or policy bypass"
	"sev/medium|FBCA04|Moderate security flaw with mitigating controls"
	"sev/low|0E8A16|Minor flaw, defense-in-depth enhancement"
	"subsystem/model-runner|1D76DB|crates/enclave-model-runnerd (UID 701)"
	"subsystem/swarm-cas|5319E7|crates/enclave-swarm-syncd (UID 702)"
	"subsystem/custody-vault|0052CC|crates/enclave-custody-vaultd (UID 703)"
	"subsystem/agent-runtime|006B75|crates/enclave-agent-runtime (UID 704)"
	"subsystem/zk-auditor|6F42C1|crates/enclave-zk-auditor (UID 705)"
	"subsystem/operator-cli|0366D6|crates/depot-enclave operator CLI"
	"subsystem/kernel-pf|D4C5F9|Darwin kernel Packet Filter & Seatbelt sandbox"
	"formal-methods/lean4|0075CA|Lean 4 mathematical proofs & theorems"
	"crypto/pqc|BFDADC|Post-quantum hybrid cryptography (ML-KEM / ML-DSA)"
	"compliance/evidence|C2E0C6|Audit trails, hash chains & compliance evidence"
)

EXISTING_LABEL_NAMES=$(jq -r '.[].name' <<<"$LABELS_JSON")
TOTAL_EXISTING_LABELS=$(jq 'length' <<<"$LABELS_JSON")

MISSING_LABELS=()
MATCHED_TARGET_LABELS=0

for label_def in "${TARGET_LABELS[@]}"; do
	IFS='|' read -r name color desc <<<"$label_def"
	if echo "$EXISTING_LABEL_NAMES" | grep -qx "$name"; then
		log_match "Label '${name}' already exists."
		inc_matched
		MATCHED_TARGET_LABELS=$((MATCHED_TARGET_LABELS + 1))
	else
		MISSING_LABELS+=("$label_def")
	fi
done

OTHER_LABELS_COUNT=$((TOTAL_EXISTING_LABELS - MATCHED_TARGET_LABELS))
if [[ $OTHER_LABELS_COUNT -gt 0 ]]; then
	log_preserve "Preserved ${OTHER_LABELS_COUNT} other custom/default labels intact."
	ITEMS_PRESERVED=$((ITEMS_PRESERVED + OTHER_LABELS_COUNT))
fi

if [[ ${#MISSING_LABELS[@]} -eq 0 ]]; then
	log_match "All ${#TARGET_LABELS[@]} normative taxonomy labels are present."
else
	for label_def in "${MISSING_LABELS[@]}"; do
		IFS='|' read -r name color desc <<<"$label_def"
		if [[ $DRY_RUN -eq 1 ]]; then
			log_dry "Would create label '${name}' (#${color}) - \"${desc}\""
		else
			gh label create "${name}" --repo "${REPO}" --color "${color}" --description "${desc}" 2>/dev/null || true
			log_applied "Created label '${name}' (#${color})"
		fi
		inc_applied
	done
fi

# ==============================================================================
# Step 5: Code Security & Analysis Status
# ==============================================================================
echo ""
echo -e "${BOLD}[5/6] Code Security & Analysis Posture${RESET}"

SEC_STATUS=$(jq -r '.security_and_analysis // empty' <<<"$REPO_JSON")
if [[ -n "$SEC_STATUS" ]]; then
	SECRET_SCAN=$(jq -r '.secret_scanning.status // "unknown"' <<<"$SEC_STATUS")
	PUSH_PROT=$(jq -r '.secret_scanning_push_protection.status // "unknown"' <<<"$SEC_STATUS")
	DEPENDABOT=$(jq -r '.dependabot_security_updates.status // "unknown"' <<<"$SEC_STATUS")

	if [[ "$SECRET_SCAN" == "enabled" ]]; then
		log_match "Secret Scanning: ENABLED"
		inc_matched
	else
		log_warn "Secret Scanning: ${SECRET_SCAN} (enable at https://github.com/${REPO}/settings/security_analysis)"
	fi

	if [[ "$PUSH_PROT" == "enabled" ]]; then
		log_match "Secret Scanning Push Protection: ENABLED"
		inc_matched
	else
		log_warn "Secret Scanning Push Protection: ${PUSH_PROT} (enable at https://github.com/${REPO}/settings/security_analysis)"
	fi

	if [[ "$DEPENDABOT" == "enabled" ]]; then
		log_match "Dependabot Security Updates: ENABLED"
		inc_matched
	else
		log_warn "Dependabot Security Updates: ${DEPENDABOT} (enable at https://github.com/${REPO}/settings/security_analysis)"
	fi
else
	log_info "Security analysis settings are managed under: https://github.com/${REPO}/settings/security_analysis"
fi

# ==============================================================================
# Step 6: Branch Protection & Social Preview Asset Guidance
# ==============================================================================
echo ""
echo -e "${BOLD}[6/6] Branch Protection & Visual Assets Guidance${RESET}"

# Check Branch Protection on main
if gh api "repos/${REPO}/branches/main/protection" &>/dev/null; then
	log_match "Branch protection is ENABLED on 'main'."
	inc_matched
else
	log_info "Branch protection on 'main': NOT YET CONFIGURED"
	if [[ $PROTECT_MAIN -eq 1 ]]; then
		log_apply "Applying normative branch protection rule to 'main'..."
		if [[ $DRY_RUN -eq 1 ]]; then
			log_dry "gh api -X PUT repos/${REPO}/branches/main/protection --input docs/GITHUB_SETUP_SPECIFICATION.md"
		else
			PROTECTION_PAYLOAD=$(
				cat <<JSON
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "VM-Compatible Verification (policy, pf, SQL AST, DLP, DPoP, schemas)",
      "Master Code Quality, SAST & Invariant Sweep"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "required_approving_review_count": 1,
    "require_last_push_approval": true
  },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_conversation_resolution": true,
  "lock_branch": false,
  "allow_fork_syncing": false
}
JSON
			)
			if gh api -X PUT "repos/${REPO}/branches/main/protection" --input - <<<"$PROTECTION_PAYLOAD" &>/dev/null; then
				log_applied "Branch protection applied to 'main'."
				inc_applied
			else
				log_warn "Could not apply branch protection automatically (status checks may need initial run first)."
			fi
		fi
	else
		echo -e "      ${BLUE}ℹ To apply branch protection after initial push, run:${RESET}"
		echo -e "        ${CYAN}${0} --protect-main ${REPO}${RESET}"
		echo -e "        Or configure in Settings → Branches → Add classic protection rule for 'main'."
	fi
fi

# Check Social Preview Asset
SOCIAL_CARD="${ROOT_DIR}/docs/assets/social-preview.jpg"
if [[ -f "$SOCIAL_CARD" ]]; then
	log_match "Local social preview card exists (${SOCIAL_CARD})"
	echo -e "      ${BLUE}ℹ GitHub requires manual upload of repository social media cards:${RESET}"
	echo -e "        1. Visit: ${CYAN}https://github.com/${REPO}/settings${RESET}"
	echo -e "        2. Scroll to 'Social preview' → Click 'Edit' → 'Upload an image'"
	echo -e "        3. Select: ${BOLD}${SOCIAL_CARD}${RESET} (1376×768 px)"
else
	log_warn "Social preview card not found at ${SOCIAL_CARD}"
fi

# Check Local Remote Configuration
LOCAL_REMOTE=$(git remote get-url origin 2>/dev/null || echo "")
if [[ -z "$LOCAL_REMOTE" ]]; then
	echo ""
	echo -e "${BOLD}Git Remote Status:${RESET}"
	log_info "Local repository does not have 'origin' remote configured yet."
	echo -e "      To connect local repository to remote and push main:"
	echo -e "        ${CYAN}git remote add origin git@github.com:${REPO}.git${RESET}"
	echo -e "        ${CYAN}git push -u origin main${RESET}"
fi

# ==============================================================================
# Summary
# ==============================================================================
echo ""
echo -e "${BOLD}==================================================================${RESET}"
echo -e "${BOLD} Reconciliation Summary for ${CYAN}${REPO}${RESET}"
echo -e "${BOLD}==================================================================${RESET}"
echo -e " Settings Matching Specification: ${GREEN}${ITEMS_MATCHED}${RESET}"
echo -e " User Customizations Preserved:   ${YELLOW}${ITEMS_PRESERVED}${RESET}"
if [[ $DRY_RUN -eq 1 ]]; then
	echo -e " Actions Pending Application:     ${CYAN}${CHANGES_APPLIED}${RESET} (Dry-Run)"
else
	echo -e " Actions Successfully Applied:    ${GREEN}${CHANGES_APPLIED}${RESET}"
fi
echo -e "${BOLD}==================================================================${RESET}"
