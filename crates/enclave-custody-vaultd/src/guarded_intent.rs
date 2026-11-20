//! Closed candidate4 intent shape and purpose/stage consistency. This supplies
//! no repository, policy, enrollment, role-byte or publication authority.
use super::{hex_bytes, MAX_INTEGER};
use enclave_core::{err, error::EnclaveResult, fail};
use serde_json::Value;

fn fields(value: &Value, names: &[&str]) -> EnclaveResult<()> {
    let object = value
        .as_object()
        .ok_or_else(|| err!(EINVAL, "CANDIDATE_INTENT_SCHEMA"))?;
    if object.len() != names.len() || names.iter().any(|name| !object.contains_key(*name)) {
        fail!(EINVAL, "CANDIDATE_INTENT_SCHEMA");
    }
    Ok(())
}
fn hash(value: &Value) -> EnclaveResult<()> {
    hex_bytes(
        value
            .as_str()
            .ok_or_else(|| err!(EINVAL, "CANDIDATE_INTENT_SCHEMA"))?,
        32,
        32,
    )?;
    Ok(())
}
fn integer(value: &Value, minimum: u64, maximum: u64) -> EnclaveResult<u64> {
    value
        .as_u64()
        .filter(|n| *n >= minimum && *n <= maximum)
        .ok_or_else(|| err!(EINVAL, "CANDIDATE_INTENT_SCHEMA"))
}

pub(super) fn check(intent: &Value) -> EnclaveResult<()> {
    fields(
        intent,
        &[
            "protocol",
            "purpose",
            "action",
            "profile",
            "repository_id",
            "publication_id",
            "policy_sha256",
            "policy_version",
            "authority_generation",
            "authority_ticket_sha256",
            "scope",
            "metadata",
            "root_policy",
            "linked_metadata",
        ],
    )?;
    if intent["protocol"] != "depot.guarded-tuf-approval.v2"
        || intent["action"] != "A4"
        || !matches!(intent["profile"].as_str(), Some("L2" | "L3"))
    {
        fail!(EINVAL, "CANDIDATE_INTENT_SCHEMA");
    }
    for key in [
        "repository_id",
        "publication_id",
        "policy_sha256",
        "authority_ticket_sha256",
    ] {
        hash(&intent[key])?;
    }
    for key in ["policy_version", "authority_generation"] {
        integer(&intent[key], 0, MAX_INTEGER)?;
    }
    let scope = &intent["scope"];
    let scope_keys = [
        "host_sha256",
        "fleet_sha256",
        "boot_sha256",
        "incident_sha256",
        "namespace_sha256",
        "release_policy_sha256",
    ];
    fields(scope, &scope_keys)?;
    for key in scope_keys {
        if !scope[key].is_null() {
            hash(&scope[key])?;
        }
    }
    let metadata = intent["metadata"]
        .as_array()
        .ok_or_else(|| err!(EINVAL, "CANDIDATE_INTENT_SCHEMA"))?;
    let links = intent["linked_metadata"]
        .as_array()
        .ok_or_else(|| err!(EINVAL, "CANDIDATE_INTENT_SCHEMA"))?;
    if intent["purpose"] == "unquarantine" {
        if !metadata.is_empty()
            || !links.is_empty()
            || !intent["root_policy"].is_null()
            || [
                "host_sha256",
                "boot_sha256",
                "incident_sha256",
                "release_policy_sha256",
            ]
            .iter()
            .any(|key| scope[*key].is_null())
        {
            fail!(EINVAL, "CANDIDATE_INTENT_SCOPE");
        }
        return Ok(());
    }
    if intent["purpose"] != "tuf-publication"
        || [
            "host_sha256",
            "boot_sha256",
            "incident_sha256",
            "release_policy_sha256",
        ]
        .iter()
        .any(|key| !scope[*key].is_null())
        || scope["fleet_sha256"].is_null()
        || scope["namespace_sha256"].is_null()
    {
        fail!(EINVAL, "CANDIDATE_INTENT_SCOPE");
    }
    if metadata.len() != 1 {
        fail!(EINVAL, "CANDIDATE_INTENT_STAGE");
    }
    let role = &metadata[0];
    fields(
        role,
        &[
            "role",
            "base_version",
            "new_version",
            "signed_body_sha256",
            "signed_body_bytes",
            "expires_utc_ms",
        ],
    )?;
    let name = role["role"]
        .as_str()
        .ok_or_else(|| err!(EINVAL, "CANDIDATE_INTENT_SCHEMA"))?;
    if !matches!(name, "root" | "targets" | "snapshot" | "timestamp") {
        fail!(EINVAL, "CANDIDATE_INTENT_STAGE");
    }
    let base = integer(&role["base_version"], 0, MAX_INTEGER)?;
    let new = integer(&role["new_version"], 0, MAX_INTEGER)?;
    if new <= base {
        fail!(EINVAL, "CANDIDATE_INTENT_VERSION");
    }
    integer(&role["signed_body_bytes"], 1, 1024 * 1024)?;
    integer(&role["expires_utc_ms"], 0, MAX_INTEGER)?;
    hash(&role["signed_body_sha256"])?;
    let root = &intent["root_policy"];
    if name == "root" {
        fields(
            root,
            &[
                "old_root_sha256",
                "new_root_sha256",
                "old_signer_policy_sha256",
                "new_signer_policy_sha256",
            ],
        )?;
        for key in [
            "old_root_sha256",
            "new_root_sha256",
            "old_signer_policy_sha256",
            "new_signer_policy_sha256",
        ] {
            hash(&root[key])?;
        }
        if base.checked_add(1) != Some(new) || root["old_root_sha256"] == root["new_root_sha256"] {
            fail!(EINVAL, "CANDIDATE_INTENT_VERSION");
        }
    } else if !root.is_null() {
        fail!(EINVAL, "CANDIDATE_INTENT_STAGE");
    }
    let child = match name {
        "snapshot" => Some("targets"),
        "timestamp" => Some("snapshot"),
        _ => None,
    };
    if links.len() != usize::from(child.is_some()) {
        fail!(EINVAL, "CANDIDATE_INTENT_STAGE");
    }
    if let Some(child) = child {
        let link = &links[0];
        fields(
            link,
            &["role", "version", "envelope_sha256", "envelope_bytes"],
        )?;
        if link["role"] != child {
            fail!(EINVAL, "CANDIDATE_INTENT_STAGE");
        }
        integer(&link["version"], 1, MAX_INTEGER)?;
        integer(&link["envelope_bytes"], 1, 1024 * 1024)?;
        hash(&link["envelope_sha256"])?;
    }
    Ok(())
}
