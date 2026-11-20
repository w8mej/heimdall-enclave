package agent.pii

import rego.v1

# ==============================================================================
# Customer PII Detection, Classification & Level-4 Custody Policy — v1.0-Legacy
#
# NO COMPLIANCE CLAIM: this policy does not implement HIPAA Safe Harbor (all 18 identifier
# categories), SOC 2, or PCI-DSS. It is a technical control for the Python simulation.
#
# Classification (monotonic, larger = more sensitive):
#   C1 Public · C2 Internal · C3 Restricted PII (names, email, phone, IP)
#   C4 Highly Sensitive (PAN, credentials/private keys, SSN/government IDs, PHI)
#
# ADR-007 Level-4 custody rule (supersedes ADR-004; remediates F-002):
#   * PANs and credentials/private keys: IRREVERSIBLE ERASURE in every profile (L1–L3);
#     they MUST NEVER enter any vault.
#   * SSNs / PHI: IRREVERSIBLE ERASURE by default and ALWAYS in L1. Reversible HPKE
#     tokenization (SYNTH-*) is permitted ONLY in L2/L3 when the signed Cedar policy grants
#     action Custody::ReversibleTokenize for the named workflow (input.custody.reversible_tokenize).
#
# Regexes in check_violation() run in OPA (Go RE2 — no look-around). The DLP engine in
# mcp/auth_proxy.py applies stricter PCRE patterns; both are exercised by verify-enclave V08/V13.
# Tests: policies/pii_guard_test.rego
# ==============================================================================

default allow_context_injection := false

allow_context_injection if {
	count(detected_violations) == 0
}

detected_violations contains violation if {
	some violation in [
		"PAYMENT_CARD_DETECTED",
		"SSN_GOVERNMENT_ID_DETECTED",
		"AUTHENTICATION_CREDENTIAL_DETECTED",
		"UNMASKED_EMAIL_DETECTED",
		"PAYLOAD_SIZE_OVERFLOW",
	]
	check_violation(violation)
}

# 1. Payment card numbers: 13–19 digits with optional space/hyphen separators (fail-closed,
#    no Luhn in RE2 — over-detection is acceptable at this gate).
check_violation("PAYMENT_CARD_DETECTED") if {
	regex.match(`(^|[^0-9])([0-9][ .-]?){12,18}[0-9]([^0-9]|$)`, input.payload_text)
}

# 2. SSNs: hyphenated, space-separated, or bare 9-digit.
check_violation("SSN_GOVERNMENT_ID_DETECTED") if {
	regex.match(`(^|[^0-9.])[0-9]{3}[- .]?[0-9]{2}[- .]?[0-9]{4}([^0-9]|$)`, input.payload_text)
}

# 3. Credentials / private keys.
check_violation("AUTHENTICATION_CREDENTIAL_DETECTED") if {
	regex.match(`(?i)(bearer\s+[a-z0-9_\-.]{20,}|ghp_[a-z0-9]{36}|github_pat_[a-z0-9_]{40,}|xox[baprs]-[a-z0-9-]{10,}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\b(akia|asia)[0-9a-z]{16}\b|\bsk-[a-z0-9_-]{20,}|\beyj[a-z0-9_-]{8,}\.eyj[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}|\b(password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token|aws_secret_access_key)\s*[:=]\s*[^\s,;]+)`, input.payload_text)
}

# 4. Any raw email address (surrogates CUST_EMAIL_<hex> contain no '@').
check_violation("UNMASKED_EMAIL_DETECTED") if {
	regex.match(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`, input.payload_text)
}

# 5. Payload ceiling (64 KiB per tool response).
check_violation("PAYLOAD_SIZE_OVERFLOW") if {
	count(input.payload_text) > 65536
}

# ------------------------------------------------------------------------------
# ADR-007 custody strategy per field class and profile
# ------------------------------------------------------------------------------
default profile := "L1"

profile := input.profile if input.profile in {"L1", "L2", "L3"}

reversible_c4_granted if {
	profile in {"L2", "L3"}
	input.custody.reversible_tokenize == true
}

# Returns the strategy for a field class. PAN/credential is unconditional erasure.
strategy("pan") := "IRREVERSIBLE_ERASE"

strategy("credential") := "IRREVERSIBLE_ERASE"

strategy("ssn") := "HPKE_REVERSIBLE_TOKENIZE" if reversible_c4_granted

strategy("ssn") := "IRREVERSIBLE_ERASE" if not reversible_c4_granted

strategy("phi") := "HPKE_REVERSIBLE_TOKENIZE" if reversible_c4_granted

strategy("phi") := "IRREVERSIBLE_ERASE" if not reversible_c4_granted

strategy("email") := "KEYED_HMAC_SURROGATE"

strategy("phone") := "KEYED_HMAC_SURROGATE"

strategy("name") := "KEYED_HMAC_SURROGATE"

# Data handed to the DLP engine. Patterns are PCRE (Python `re`), not evaluated by OPA.
redaction_spec := {
	"credit_card": {"class": "C4", "strategy": strategy("pan"), "replacement": "[REDACTED_PAN_C4]"},
	"credential": {"class": "C4", "strategy": strategy("credential"), "replacement": "[REDACTED_CREDENTIAL_C4]"},
	"ssn": {
		"class": "C4", "strategy": strategy("ssn"), "replacement": "[REDACTED_SSN_C4]",
		"pcre": `(?<![\w.-])\d{3}([- .]?)\d{2}\1\d{4}(?![\w-]|\.\d)`,
	},
	"email": {"class": "C3", "strategy": strategy("email"), "token_prefix": "CUST_EMAIL_", "mac": "HMAC-SHA256/128, per-session 256-bit key"},
	"phone": {
		"class": "C3", "strategy": strategy("phone"), "token_prefix": "CUST_PHONE_",
		"pcre": `(?<!\w)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`,
	},
	"name": {"class": "C3", "strategy": strategy("name"), "token_prefix": "CUST_NAME_"},
}
