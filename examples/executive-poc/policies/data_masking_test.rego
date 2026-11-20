package agent.masking_test

import rego.v1

import data.agent.masking

key := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

test_email_is_128bit_keyed_hmac if {
	m := masking.mask_field("email", "jane@example.com") with input as {"session_key": key}
	startswith(m, "CUST_EMAIL_")
	count(m) == count("CUST_EMAIL_") + 32
	m != concat("", ["CUST_EMAIL_", substring(crypto.sha256("jane@example.com"), 0, 32)])
}

test_different_session_keys_uncorrelated if {
	a := masking.mask_field("name", "Jane Doe") with input as {"session_key": key}
	b := masking.mask_field("name", "Jane Doe") with input as {"session_key": "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"}
	a != b
}

test_no_session_key_fails_closed if {
	masking.mask_field("email", "jane@example.com") == "[REDACTED_NO_SESSION_KEY]" with input as {}
}

test_ssn_and_pan_erased if {
	masking.mask_field("ssn", "123-45-6789") == "[REDACTED_SSN_C4]"
	masking.mask_field("credit_card", "4111111111111111") == "[REDACTED_PAN_C4]"
}

test_unclassified_field_redacted if {
	masking.mask_field("account_balance", "12500.50") == "[REDACTED_UNCLASSIFIED]"
}

test_passthrough_field if {
	masking.mask_field("updated_at", "2026-10-01") == "2026-10-01"
}
