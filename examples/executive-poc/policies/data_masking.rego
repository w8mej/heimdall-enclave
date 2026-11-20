package agent.masking

import rego.v1

# ==============================================================================
# Field Masking Rules — v1.0-Legacy
#
# Remediates F-006: pseudonyms are 128-bit KEYED HMAC-SHA256 tags under a per-session
# ephemeral key (input.session_key, >= 32 hex chars), never unsalted SHA-256[:8].
# Without a session key, tokenizable fields fail closed to erasure.
# Unclassified fields fail closed to "[REDACTED_UNCLASSIFIED]" (no raw passthrough).
#
# The Laplace differential-privacy budget below is v1.0-Legacy (CORE-V1-R06) and is
# SUPERSEDED in v3.0 by the 12,000 mb / 24h EntityKey QIF budget (FS-704 §3.3).
# Tests: policies/data_masking_test.rego
# ==============================================================================

max_daily_epsilon := 2.0

query_epsilon_cost := 0.1

budget_available if {
	input.session_accumulated_epsilon + query_epsilon_cost <= max_daily_epsilon
}

erase_fields := {
	"ssn": "[REDACTED_SSN_C4]", "social_security_number": "[REDACTED_SSN_C4]", "national_id": "[REDACTED_SSN_C4]",
	"card_number": "[REDACTED_PAN_C4]", "credit_card": "[REDACTED_PAN_C4]", "pan": "[REDACTED_PAN_C4]", "cvv": "[REDACTED_PAN_C4]",
	"password": "[REDACTED_CREDENTIAL_C4]", "api_key": "[REDACTED_CREDENTIAL_C4]", "private_key": "[REDACTED_CREDENTIAL_C4]",
}

token_prefixes := {
	"email": "CUST_EMAIL_", "user_email": "CUST_EMAIL_",
	"name": "CUST_NAME_", "full_name": "CUST_NAME_", "customer_name": "CUST_NAME_",
	"phone": "CUST_PHONE_",
}

passthrough_fields := {"id", "customer_id", "ticket_id", "tier", "status", "created_at", "updated_at", "deleted_at", "is_deleted"}

session_key_ok if {
	is_string(input.session_key)
	count(input.session_key) >= 32
}

mask_field(field_name, _) := erase_fields[field_name]

mask_field(field_name, raw_value) := masked if {
	prefix := token_prefixes[field_name]
	session_key_ok
	masked := concat("", [prefix, substring(crypto.hmac.sha256(sprintf("%s:%s", [trim_suffix(prefix, "_"), raw_value]), input.session_key), 0, 32)])
}

mask_field(field_name, _) := "[REDACTED_NO_SESSION_KEY]" if {
	token_prefixes[field_name]
	not session_key_ok
}

mask_field(field_name, raw_value) := raw_value if {
	field_name in passthrough_fields
}

mask_field(field_name, _) := "[REDACTED_UNCLASSIFIED]" if {
	not erase_fields[field_name]
	not token_prefixes[field_name]
	not field_name in passthrough_fields
}
