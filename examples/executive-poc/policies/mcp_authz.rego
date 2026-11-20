package agent.authz

import rego.v1

# ==============================================================================
# depot Authorization Policy — v1.0-Legacy (OPA/Rego) reference prototype
# Generation: v1.0-Legacy (ADR-008: the v3.0 target is Cedar + PoP-Biscuit, not Rego)
#
# Remediates F-037 / F-039:
#   * FAIL-CLOSED: every registered tool has an explicit parameter validator; there is NO
#     catch-all that passes "any tool other than X". Unregistered tools are denied.
#   * Tool aliases are unified: execute_customer_query (CORE-V1 §4.2) and query_customer_db
#     resolve to the same canonical tool and the same SQL validator.
#   * SQL is NEVER validated with contains()/substring checks. Rego cannot parse SQL, so the
#     caller MUST attach `input.resource.sql_ast_verdict` from the recursive-descent AST guard
#     (depot/sql_guard.py; sqlparser-rs in v3.0). The verdict is bound to the exact query text
#     by `sql_sha256`, so a verdict for one query cannot be replayed for another.
#   * SPIFFE trust domain and Apple Team ID are parameters (data.config.*).
#
# Tests: policies/depot_authz_test.rego  (opa test policies/ -v)
# ==============================================================================

default allow := false

default reason := "Default deny: No matching authorization rule."

# ------------------------------------------------------------------------------
# Parameters (override via data.config.trust_domain / data.config.team_id)
# ------------------------------------------------------------------------------
default trust_domain := "corporate.internal"

trust_domain := data.config.trust_domain

default team_id := "ABC123XYZ0"

team_id := data.config.team_id

# ------------------------------------------------------------------------------
# Tool registry & aliases (unknown names resolve to nothing => deny)
# ------------------------------------------------------------------------------
tool_aliases := {
	"query_customer_db": "query_customer_db",
	"execute_customer_query": "query_customer_db",
	"search_documentation": "search_documentation",
	"format_code": "format_code",
	"generate_test_stubs": "generate_test_stubs",
	"inspect_ticket_logs": "inspect_ticket_logs",
}

canonical_tool := tool_aliases[input.resource.tool_name]

valid_clearance_matrix := {
	"developer_l1": {"search_documentation", "format_code", "generate_test_stubs"},
	"developer_l2": {"search_documentation", "format_code", "generate_test_stubs", "query_customer_db", "inspect_ticket_logs"},
	# "*" means every REGISTERED tool; parameters are still validated per tool.
	"sre_incident_commander": {"*"},
}

format_languages := {"python", "rust", "go", "typescript", "javascript", "swift", "sql", "shell"}

# ------------------------------------------------------------------------------
# Core rule
# ------------------------------------------------------------------------------
allow if {
	verify_hardware_posture
	verify_actor_identity
	verify_tool_entitlement
	verify_parameter_safety
}

verify_hardware_posture if {
	input.environment.filevault_active == true
	input.environment.network_isolated == true
	input.actor.hardware_attested == true
}

verify_actor_identity if {
	startswith(input.actor.spiffe_id, sprintf("spiffe://%s/ns/developer/workload/", [trust_domain]))
	input.actor.team_id == team_id
	input.actor.code_signature_valid == true
}

verify_tool_entitlement if {
	canonical_tool
	allowed := valid_clearance_matrix[input.actor.clearance]
	"*" in allowed
}

verify_tool_entitlement if {
	allowed := valid_clearance_matrix[input.actor.clearance]
	canonical_tool in allowed
}

# ------------------------------------------------------------------------------
# Per-tool parameter validators (explicit allowlist of keys for every tool)
# ------------------------------------------------------------------------------
param_keys := {k | some k, _ in input.resource.parameters}

verify_parameter_safety if {
	canonical_tool == "query_customer_db"
	p := input.resource.parameters
	param_keys == {"query", "max_records"}
	is_string(p.query)
	is_number(p.max_records)
	p.max_records == floor(p.max_records)
	p.max_records >= 1
	p.max_records <= 50
	v := input.resource.sql_ast_verdict
	v.valid == true
	v.statement_kind == "select"
	v.limit <= p.max_records
	v.sql_sha256 == crypto.sha256(p.query)
}

verify_parameter_safety if {
	canonical_tool == "search_documentation"
	param_keys == {"query"}
	is_string(input.resource.parameters.query)
	count(input.resource.parameters.query) >= 1
	count(input.resource.parameters.query) <= 512
}

verify_parameter_safety if {
	canonical_tool == "format_code"
	param_keys == {"language", "source"}
	input.resource.parameters.language in format_languages
	is_string(input.resource.parameters.source)
	count(input.resource.parameters.source) <= 65536
}

verify_parameter_safety if {
	canonical_tool == "generate_test_stubs"
	param_keys == {"module"}
	is_string(input.resource.parameters.module)
	count(input.resource.parameters.module) >= 1
	count(input.resource.parameters.module) <= 256
}

verify_parameter_safety if {
	canonical_tool == "inspect_ticket_logs"
	param_keys == {"ticket_id"}
	regex.match(`^T-[0-9]{1,8}$`, input.resource.parameters.ticket_id)
}

# ------------------------------------------------------------------------------
# Diagnostic reasons (mutually exclusive)
# ------------------------------------------------------------------------------
reason := "Access granted: Hardware posture, identity, entitlement and per-tool parameter validation passed." if {
	allow
}

reason := "Access denied: Hardware posture failed (FileVault, pf firewall, or SEP unverified)." if {
	not verify_hardware_posture
}

reason := "Access denied: Untrusted workload identity (Invalid SPIFFE ID, Team ID, or binary signature)." if {
	verify_hardware_posture
	not verify_actor_identity
}

reason := "Access denied: Tool not registered or clearance entitlement not satisfied." if {
	verify_hardware_posture
	verify_actor_identity
	not verify_tool_entitlement
}

reason := "Access denied: Parameter safety violated (per-tool validator or SQL AST guard rejected the call)." if {
	verify_hardware_posture
	verify_actor_identity
	verify_tool_entitlement
	not verify_parameter_safety
}
