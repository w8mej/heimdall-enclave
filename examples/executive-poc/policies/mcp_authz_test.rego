package agent.authz_test

import rego.v1

import data.agent.authz

good_actor := {
	"spiffe_id": "spiffe://corporate.internal/ns/developer/workload/code-assistant/501",
	"team_id": "ABC123XYZ0",
	"clearance": "developer_l2",
	"code_signature_valid": true,
	"hardware_attested": true,
}

good_env := {"filevault_active": true, "network_isolated": true}

q := "SELECT id, updated_at, deleted_at FROM customers LIMIT 10"

good_verdict := {"valid": true, "statement_kind": "select", "limit": 10, "sql_sha256": crypto.sha256(q)}

sql_input(name, actor, verdict) := {
	"actor": actor,
	"environment": good_env,
	"resource": {"tool_name": name, "parameters": {"query": q, "max_records": 10}, "sql_ast_verdict": verdict},
}

test_valid_sql_allowed if {
	authz.allow with input as sql_input("query_customer_db", good_actor, good_verdict)
}

test_alias_execute_customer_query_uses_same_validator if {
	authz.allow with input as sql_input("execute_customer_query", good_actor, good_verdict)
}

# F-037: the alias under sre_incident_commander used to skip ALL SQL checks.
test_sre_alias_without_ast_verdict_denied if {
	sre := object.union(good_actor, {"clearance": "sre_incident_commander"})
	inp := {"actor": sre, "environment": good_env, "resource": {"tool_name": "execute_customer_query", "parameters": {"query": "SELECT  * FROM customers", "max_records": 10}}}
	not authz.allow with input as inp
}

test_invalid_ast_verdict_denied if {
	not authz.allow with input as sql_input("query_customer_db", good_actor, object.union(good_verdict, {"valid": false}))
}

test_verdict_bound_to_query_text if {
	forged := object.union(good_verdict, {"sql_sha256": crypto.sha256("SELECT id FROM customers")})
	not authz.allow with input as sql_input("query_customer_db", good_actor, forged)
}

test_max_records_ceiling if {
	inp := {"actor": good_actor, "environment": good_env, "resource": {"tool_name": "query_customer_db", "parameters": {"query": q, "max_records": 51}, "sql_ast_verdict": good_verdict}}
	not authz.allow with input as inp
}

test_unregistered_tool_denied_even_for_wildcard_role if {
	sre := object.union(good_actor, {"clearance": "sre_incident_commander"})
	inp := {"actor": sre, "environment": good_env, "resource": {"tool_name": "execute_shell", "parameters": {"cmd": "id"}}}
	not authz.allow with input as inp
}

test_extra_parameter_rejected if {
	inp := {"actor": good_actor, "environment": good_env, "resource": {"tool_name": "search_documentation", "parameters": {"query": "pf", "shell": "rm -rf /"}}}
	not authz.allow with input as inp
}

test_search_documentation_allowed if {
	inp := {"actor": good_actor, "environment": good_env, "resource": {"tool_name": "search_documentation", "parameters": {"query": "pf rules"}}}
	authz.allow with input as inp
}

test_l1_cannot_query_db if {
	l1 := object.union(good_actor, {"clearance": "developer_l1"})
	not authz.allow with input as sql_input("query_customer_db", l1, good_verdict)
}

test_hardware_posture_required if {
	inp := object.union(sql_input("query_customer_db", good_actor, good_verdict), {"environment": {"filevault_active": false, "network_isolated": true}})
	not authz.allow with input as inp
	authz.reason == "Access denied: Hardware posture failed (FileVault, pf firewall, or SEP unverified)." with input as inp
}

test_trust_domain_is_parameterized if {
	local := object.union(good_actor, {"spiffe_id": "spiffe://local.dev/ns/developer/workload/code-assistant/501"})
	not authz.allow with input as sql_input("query_customer_db", local, good_verdict)
	authz.allow with input as sql_input("query_customer_db", local, good_verdict) with data.config.trust_domain as "local.dev"
}

test_wrong_team_id_denied if {
	bad := object.union(good_actor, {"team_id": "ZZZ999ZZZ9"})
	not authz.allow with input as sql_input("query_customer_db", bad, good_verdict)
}
