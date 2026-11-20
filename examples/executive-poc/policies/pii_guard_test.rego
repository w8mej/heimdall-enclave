package agent.pii_test

import rego.v1

import data.agent.pii

test_unhyphenated_ssn_detected if {
	"SSN_GOVERNMENT_ID_DETECTED" in pii.detected_violations with input as {"payload_text": "ssn 123456789 on file"}
}

test_spaced_ssn_detected if {
	"SSN_GOVERNMENT_ID_DETECTED" in pii.detected_violations with input as {"payload_text": "ssn 123 45 6789"}
}

test_pan_detected if {
	"PAYMENT_CARD_DETECTED" in pii.detected_violations with input as {"payload_text": "card 4111 1111 1111 1111"}
}

test_raw_email_blocks_injection if {
	not pii.allow_context_injection with input as {"payload_text": "contact jane@example.com"}
}

test_scrubbed_payload_allowed if {
	pii.allow_context_injection with input as {"payload_text": "contact CUST_EMAIL_0123456789abcdef0123456789abcdef ssn [REDACTED_SSN_C4]"}
}

test_pan_always_erased_every_profile if {
	every p in ["L1", "L2", "L3"] {
		pii.redaction_spec.credit_card.strategy == "IRREVERSIBLE_ERASE" with input as {"profile": p, "custody": {"reversible_tokenize": true}}
	}
}

test_ssn_erased_in_l1_even_with_grant if {
	pii.redaction_spec.ssn.strategy == "IRREVERSIBLE_ERASE" with input as {"profile": "L1", "custody": {"reversible_tokenize": true}}
}

test_ssn_erased_in_l2_without_grant if {
	pii.redaction_spec.ssn.strategy == "IRREVERSIBLE_ERASE" with input as {"profile": "L2"}
}

test_ssn_reversible_only_with_l2_grant if {
	pii.redaction_spec.ssn.strategy == "HPKE_REVERSIBLE_TOKENIZE" with input as {"profile": "L2", "custody": {"reversible_tokenize": true}}
}
