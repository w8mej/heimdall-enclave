use super::*;
use crate::ctap::{assertion::CredentialKey, rp_id_hash};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

struct Fixture {
    issuer: SigningKey,
    sep: p256::ecdsa::SigningKey,
    fido: SigningKey,
    credential: EnrolledCredential,
    intent: Value,
    context: Value,
    proof: Value,
}
impl Fixture {
    fn new() -> Self {
        let issuer = SigningKey::from_bytes(&[51; 32]);
        let sep = p256::ecdsa::SigningKey::from_slice(&[52; 32]).unwrap();
        let fido = SigningKey::from_bytes(&[53; 32]);
        let credential = EnrolledCredential {
            credential_id: vec![7; 32],
            key: CredentialKey::Ed25519(fido.verifying_key()),
            aaguid: [0; 16],
            firmware_version: 0,
        };
        let vector: Value =
            serde_json::from_str(include_str!("../tests/fixtures/vector-2.json")).unwrap();
        let mut intent = vector["intent"].clone();
        intent["profile"] = json!("L3");
        let mut context = vector["context"].clone();
        context["stage"] = json!("final-dispatch");
        context["sep_key_sha256"] = json!(hex::encode(digest(
            sep.verifying_key().to_encoded_point(false).as_bytes()
        )));
        let mut public = (-8i32).to_be_bytes().to_vec();
        public.extend_from_slice(fido.verifying_key().as_bytes());
        context["fido_key_sha256"] = json!(hex::encode(digest(&public)));
        context["credential_id_sha256"] = json!(hex::encode(digest(&credential.credential_id)));
        let mut constraints = intent.clone();
        constraints["authority_ticket_sha256"] = json!("0".repeat(64));
        let certificate = json!({"protocol":"mcpmac.approval-freshness.v2",
            "publication_id":intent["publication_id"],"repository_id":intent["repository_id"],
            "purpose":intent["purpose"],"policy_sha256":intent["policy_sha256"],
            "policy_version":intent["policy_version"],"authority_generation":intent["authority_generation"],
            "issued_utc_ms":1000,"not_before_utc_ms":1000,"expires_utc_ms":5000,
            "nonce_sha256":context["nonce_sha256"],"intent_constraints_sha256":hex::encode(digest(&jcs(&constraints).unwrap())),
            "stage":"final-dispatch"});
        let certificate_bytes = jcs(&certificate).unwrap();
        let mut issuer_message = b"MCPMac-Approval-Freshness-v2\x00".to_vec();
        issuer_message.extend_from_slice(
            &u32::try_from(certificate_bytes.len())
                .unwrap()
                .to_be_bytes(),
        );
        issuer_message.extend_from_slice(&certificate_bytes);
        let freshness = json!({"certificate":certificate,
            "issuer_key_sha256":hex::encode(digest(issuer.verifying_key().as_bytes())),
            "signature_ed25519_hex":hex::encode(issuer.sign(&issuer_message).to_bytes())});
        intent["authority_ticket_sha256"] = json!(hex::encode(digest(&jcs(&freshness).unwrap())));
        let proof = json!({"protocol":"mcpmac.custodian-proof.v2","intent":intent,"context":context,
            "freshness":freshness,"sep_signature_hex":"","credential_id_hex":hex::encode(&credential.credential_id),
            "authenticator_data_hex":"","algorithm":-8,"assertion_signature_hex":""});
        let mut f = Self {
            issuer,
            sep,
            fido,
            credential,
            intent,
            context,
            proof,
        };
        f.resign(0x05, 1);
        f
    }
    fn resign(&mut self, flags: u8, count: u32) {
        let d = digest(&jcs(&self.proof["intent"]).unwrap());
        let c = digest(&jcs(&self.proof["context"]).unwrap());
        let n = hex::decode(self.proof["context"]["nonce_sha256"].as_str().unwrap()).unwrap();
        let t = hex::decode(self.proof["context"]["start_ns_hex"].as_str().unwrap()).unwrap();
        let mut message = b"MCPMac-SEP-Approval-v2\0".to_vec();
        message.extend_from_slice(&d);
        message.extend_from_slice(&c);
        message.extend_from_slice(&n);
        message.extend_from_slice(&t);
        let signature: SepSignature = self.sep.sign(&message);
        let signature = signature.normalize_s().unwrap_or(signature).to_bytes();
        self.proof["sep_signature_hex"] = json!(hex::encode(signature));
        let mut challenge = b"MCPMac-CTAP-Approval-v2\0".to_vec();
        challenge.extend_from_slice(&d);
        challenge.extend_from_slice(&c);
        challenge.extend_from_slice(&signature);
        challenge.extend_from_slice(&t);
        let mut auth = rp_id_hash().to_vec();
        auth.push(flags);
        auth.extend_from_slice(&count.to_be_bytes());
        let mut signed = auth.clone();
        signed.extend_from_slice(&digest(&challenge));
        self.proof["authenticator_data_hex"] = json!(hex::encode(auth));
        self.proof["assertion_signature_hex"] =
            json!(hex::encode(self.fido.sign(&signed).to_bytes()));
    }
    fn reauthorize(&mut self) {
        let mut constraints = self.intent.clone();
        constraints["authority_ticket_sha256"] = json!("0".repeat(64));
        let certificate = &mut self.proof["freshness"]["certificate"];
        for key in [
            "publication_id",
            "repository_id",
            "purpose",
            "policy_sha256",
            "policy_version",
            "authority_generation",
        ] {
            certificate[key] = self.intent[key].clone();
        }
        certificate["intent_constraints_sha256"] =
            json!(hex::encode(digest(&jcs(&constraints).unwrap())));
        let bytes = jcs(certificate).unwrap();
        let mut message = b"MCPMac-Approval-Freshness-v2\0".to_vec();
        message.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        message.extend_from_slice(&bytes);
        self.proof["freshness"]["signature_ed25519_hex"] =
            json!(hex::encode(self.issuer.sign(&message).to_bytes()));
        self.intent["authority_ticket_sha256"] =
            json!(hex::encode(digest(&jcs(&self.proof["freshness"]).unwrap())));
        self.proof["intent"] = self.intent.clone();
        self.resign(0x05, 1);
    }
    fn run(
        &self,
        counters: &mut SignCountStore,
        time: impl FnMut() -> EnclaveResult<TrustedUtcRange>,
    ) -> EnclaveResult<CandidateProofFacts> {
        let intent = jcs(&self.intent).unwrap();
        let context = jcs(&self.context).unwrap();
        let issuer = self.issuer.verifying_key();
        let trust = CandidateProofTrust {
            intent_jcs: &intent,
            context_jcs: &context,
            sep_key: self.sep.verifying_key(),
            credential: &self.credential,
            freshness_issuer: &issuer,
            maximum_ttl_ms: 4000,
        };
        check_candidate_proof(&jcs(&self.proof).unwrap(), &trust, counters, time)
    }
}
fn now() -> EnclaveResult<TrustedUtcRange> {
    Ok(TrustedUtcRange {
        earliest: 2000,
        latest: 2001,
    })
}

#[test]
fn genuine_candidate_issuer_sep_and_ctap_chain_passes_once_and_consumes_counter() {
    let f = Fixture::new();
    let mut counts = SignCountStore::default();
    let facts = f.run(&mut counts, now).unwrap();
    assert_eq!(facts.sign_count, 1);
    assert_eq!(facts.intent_sha256, digest(&jcs(&f.intent).unwrap()));
    assert!(f.run(&mut counts, now).is_err());
}

#[test]
fn candidate_preserves_literal_number_objects_before_signature_binding() {
    let mut f = Fixture::new();
    // Establish a genuine chain first. Change only the wire intent afterwards;
    // the independently approved intent and all three signatures stay intact.
    assert!(f.run(&mut SignCountStore::default(), now).is_ok());
    let version = f.intent["policy_version"].as_u64().unwrap().to_string();
    let mut literal = Map::new();
    literal.insert(
        "$serde_json::private::Number".into(),
        Value::String(version),
    );
    f.proof["intent"]["policy_version"] = Value::Object(literal);
    let mut counts = SignCountStore::default();
    assert!(
        f.run(&mut counts, now).is_err(),
        "wire map must not become the approved integer"
    );
    assert_eq!(counts.get_credential(&f.credential), 0);
}

#[test]
fn validly_signed_candidate_still_refuses_closed_intent_scope_and_stage_violations() {
    for mutation in 0..15 {
        let mut f = Fixture::new();
        match mutation {
            0 => {
                f.intent["unsigned_admin_bypass"] = json!(true);
            }
            1 => {
                f.intent.as_object_mut().unwrap().remove("root_policy");
            }
            2 => {
                f.intent["scope"]["unknown"] = json!(null);
            }
            3 => {
                f.intent["scope"]
                    .as_object_mut()
                    .unwrap()
                    .remove("host_sha256");
            }
            4 => {
                f.intent["scope"]["fleet_sha256"] = json!(null);
            }
            5 => {
                f.intent["scope"]["namespace_sha256"] = json!("*");
            }
            6 => {
                f.intent["scope"]["host_sha256"] = json!("11".repeat(32));
            }
            7 => {
                let role = f.intent["metadata"][0].clone();
                f.intent["metadata"].as_array_mut().unwrap().push(role);
            }
            8 => {
                f.intent["root_policy"] = json!({});
            }
            9 => {
                f.intent["metadata"][0]["new_version"] =
                    f.intent["metadata"][0]["base_version"].clone();
            }
            10 => {
                f.intent["metadata"][0]["role"] = json!("snapshot");
            }
            11 => {
                f.intent["linked_metadata"] = json!([{"role":"targets","version":1,"envelope_bytes":1,"envelope_sha256":"11".repeat(32)}]);
            }
            12 => {
                f.intent["metadata"][0]["unknown"] = json!(false);
            }
            13 => {
                f.intent["metadata"][0]["signed_body_bytes"] = json!(0);
            }
            _ => {
                f.intent["purpose"] = json!("unquarantine");
            }
        }
        // Issue fresh genuine issuer/SEP/CTAP signatures for the hostile intent;
        // rejection cannot be attributed to stale signatures or ticket hashes.
        f.reauthorize();
        let mut counts = SignCountStore::default();
        let error = f.run(&mut counts, now).unwrap_err();
        assert!(
            error.reason.starts_with("CANDIDATE_INTENT_") || error.is("CANDIDATE_HEX"),
            "mutation {mutation}: {error:?}"
        );
        assert_eq!(counts.get_credential(&f.credential), 0);
    }
}

#[test]
fn candidate_role_and_recovery_shapes_are_checked_without_granting_role_authority() {
    for role in ["root", "targets", "snapshot", "timestamp", "recovery"] {
        let mut f = Fixture::new();
        if role == "recovery" {
            f.intent["purpose"] = json!("unquarantine");
            f.intent["metadata"] = json!([]);
            for key in [
                "host_sha256",
                "boot_sha256",
                "incident_sha256",
                "release_policy_sha256",
            ] {
                f.intent["scope"][key] = json!("77".repeat(32));
            }
        } else {
            f.intent["metadata"][0]["role"] = json!(role);
            if role == "root" {
                f.intent["root_policy"] = json!({"old_root_sha256":"11".repeat(32),
                "new_root_sha256":"22".repeat(32),"old_signer_policy_sha256":"33".repeat(32),"new_signer_policy_sha256":"44".repeat(32)});
            }
            if matches!(role, "snapshot" | "timestamp") {
                f.intent["linked_metadata"] = json!([{
                "role":if role=="snapshot" {"targets"}else{"snapshot"},"version":1,
                "envelope_sha256":"55".repeat(32),"envelope_bytes":123}]);
            }
        }
        f.reauthorize();
        assert_eq!(
            f.run(&mut SignCountStore::default(), now)
                .unwrap()
                .sign_count,
            1
        );
    }
}

#[test]
fn candidate_issuer_domain_and_big_endian_certificate_length_are_mandatory() {
    for mutation in 0..3 {
        let mut f = Fixture::new();
        let certificate = jcs(&f.proof["freshness"]["certificate"]).unwrap();
        let mut message = if mutation == 0 {
            Vec::new()
        } else {
            b"MCPMac-Approval-Freshness-v2\0".to_vec()
        };
        if mutation == 1 {
            message.extend_from_slice(&(certificate.len() as u32).to_le_bytes());
        }
        if mutation == 2 {
            message.extend_from_slice(&((certificate.len() + 1) as u32).to_be_bytes());
        }
        message.extend_from_slice(&certificate);
        f.proof["freshness"]["signature_ed25519_hex"] =
            json!(hex::encode(f.issuer.sign(&message).to_bytes()));
        f.intent["authority_ticket_sha256"] =
            json!(hex::encode(digest(&jcs(&f.proof["freshness"]).unwrap())));
        f.proof["intent"] = f.intent.clone();
        f.resign(0x05, 1);
        let mut counts = SignCountStore::default();
        assert!(f
            .run(&mut counts, now)
            .unwrap_err()
            .is("CANDIDATE_ISSUER_SIGNATURE"));
        assert_eq!(counts.get_credential(&f.credential), 0);
    }
}
#[test]
fn candidate_refuses_issuer_sep_ctap_substitution_uv_and_unbound_context() {
    for mutation in 0..8 {
        let mut f = Fixture::new();
        let mut counts = SignCountStore::default();
        match mutation {
            0 => f.proof["freshness"]["signature_ed25519_hex"] = json!("00".repeat(64)),
            1 => f.proof["sep_signature_hex"] = json!("00".repeat(64)),
            2 => {
                f.proof["assertion_signature_hex"] = json!(hex::encode(
                    f.fido.sign(&digest(&jcs(&f.intent).unwrap())).to_bytes()
                ))
            }
            3 => f.resign(0x01, 1),
            4 => f.proof["context"]["publication_id"] = json!("11".repeat(32)),
            5 => f.proof["algorithm"] = json!(-7),
            6 => f.proof["credential_id_hex"] = json!("99".repeat(32)),
            _ => {
                f.proof["intent"]["policy_version"] = json!(9);
                f.resign(0x05, 1);
            }
        }
        assert!(f.run(&mut counts, now).is_err(), "mutation {mutation}");
        assert_eq!(
            counts.get_credential(&f.credential),
            0,
            "mutation {mutation}"
        );
    }
}
#[test]
fn candidate_trusted_time_uncertainty_and_late_check_cannot_extend_authority() {
    let f = Fixture::new();
    for range in [
        TrustedUtcRange {
            earliest: 999,
            latest: 2000,
        },
        TrustedUtcRange {
            earliest: 2000,
            latest: 5000,
        },
        TrustedUtcRange {
            earliest: 4000,
            latest: 3999,
        },
    ] {
        let mut counts = SignCountStore::default();
        assert!(f.run(&mut counts, || Ok(range)).is_err());
        assert_eq!(counts.get_credential(&f.credential), 0);
    }
    let mut counts = SignCountStore::default();
    let mut calls = 0;
    assert!(f
        .run(&mut counts, || {
            calls += 1;
            Ok(TrustedUtcRange {
                earliest: 2000,
                latest: if calls == 1 { 2001 } else { 5000 },
            })
        })
        .is_err());
    assert_eq!(
        counts.get_credential(&f.credential),
        1,
        "genuine progress remains consumed after later denial"
    );
    let mut counts = SignCountStore::default();
    let mut calls = 0;
    assert!(f
        .run(&mut counts, || {
            calls += 1;
            Ok(if calls == 1 {
                TrustedUtcRange {
                    earliest: 3000,
                    latest: 3001,
                }
            } else {
                TrustedUtcRange {
                    earliest: 2000,
                    latest: 2001,
                }
            })
        })
        .is_err());
    assert_eq!(
        counts.get_credential(&f.credential),
        1,
        "later clock regression retains genuine counter progress"
    );
}

#[test]
fn candidate_rejects_genuinely_signed_unnegotiated_authenticator_extension() {
    let mut f = Fixture::new();
    f.resign(0x85, 1);
    let mut auth = hex::decode(f.proof["authenticator_data_hex"].as_str().unwrap()).unwrap();
    // CBOR {"unknown": true}, signed by the genuine enrolled credential.
    auth.extend_from_slice(b"\xa1\x67unknown\xf5");
    let mut challenge = b"MCPMac-CTAP-Approval-v2\0".to_vec();
    challenge.extend_from_slice(&digest(&jcs(&f.intent).unwrap()));
    challenge.extend_from_slice(&digest(&jcs(&f.context).unwrap()));
    challenge
        .extend_from_slice(&hex::decode(f.proof["sep_signature_hex"].as_str().unwrap()).unwrap());
    challenge.extend_from_slice(&hex::decode(f.context["start_ns_hex"].as_str().unwrap()).unwrap());
    let mut signed = auth.clone();
    signed.extend_from_slice(&digest(&challenge));
    let signature = f.fido.sign(&signed).to_bytes().to_vec();
    let assertion = AssertionResponse {
        credential_id: Some(f.credential.credential_id.clone()),
        auth_data: auth.clone(),
        signature: signature.clone(),
    };
    verify_assertion(
        &f.credential,
        &assertion,
        &digest(&challenge),
        true,
        &mut SignCountStore::default(),
    )
    .unwrap();
    f.proof["authenticator_data_hex"] = json!(hex::encode(auth));
    f.proof["assertion_signature_hex"] = json!(hex::encode(signature));
    let mut counts = SignCountStore::default();
    assert!(f.run(&mut counts, now).is_err());
    assert_eq!(counts.get_credential(&f.credential), 0);
}
#[test]
fn strict_candidate_wire_rejects_duplicates_floats_unknown_fields_and_noncanonical_hex() {
    let f = Fixture::new();
    let intent = jcs(&f.intent).unwrap();
    let context = jcs(&f.context).unwrap();
    let issuer = f.issuer.verifying_key();
    let trust = CandidateProofTrust {
        intent_jcs: &intent,
        context_jcs: &context,
        sep_key: f.sep.verifying_key(),
        credential: &f.credential,
        freshness_issuer: &issuer,
        maximum_ttl_ms: 4000,
    };
    for wire in [
        b"{\"a\":1,\"a\":1}".to_vec(),
        b"{\"a\":1.5}".to_vec(),
        b"{\"a\":9007199254740992}".to_vec(),
        serde_json::to_vec_pretty(&f.proof).unwrap(),
        vec![b' '; MAX_WIRE + 1],
    ] {
        assert!(check_candidate_proof(&wire, &trust, &mut SignCountStore::default(), now).is_err());
    }
    for mutation in 0..2 {
        let mut proof = f.proof.clone();
        if mutation == 0 {
            proof["unknown"] = json!(true);
        } else {
            proof["credential_id_hex"] = json!("AA".repeat(32));
        }
        assert!(check_candidate_proof(
            &jcs(&proof).unwrap(),
            &trust,
            &mut SignCountStore::default(),
            now
        )
        .is_err());
    }
}

#[test]
fn candidate_es256_credential_uses_actual_authenticator_data_signature() {
    let mut f = Fixture::new();
    let fido = p256::ecdsa::SigningKey::from_slice(&[54; 32]).unwrap();
    f.credential.key = CredentialKey::Es256(*fido.verifying_key());
    let mut public = (-7i32).to_be_bytes().to_vec();
    public.extend_from_slice(fido.verifying_key().to_encoded_point(false).as_bytes());
    f.context["fido_key_sha256"] = json!(hex::encode(digest(&public)));
    f.proof["context"] = f.context.clone();
    f.proof["algorithm"] = json!(-7);
    f.resign(0x05, 1);
    let mut challenge = b"MCPMac-CTAP-Approval-v2\0".to_vec();
    challenge.extend_from_slice(&digest(&jcs(&f.intent).unwrap()));
    challenge.extend_from_slice(&digest(&jcs(&f.context).unwrap()));
    challenge
        .extend_from_slice(&hex::decode(f.proof["sep_signature_hex"].as_str().unwrap()).unwrap());
    challenge.extend_from_slice(&hex::decode(f.context["start_ns_hex"].as_str().unwrap()).unwrap());
    let mut signed = hex::decode(f.proof["authenticator_data_hex"].as_str().unwrap()).unwrap();
    signed.extend_from_slice(&digest(&challenge));
    let signature: SepSignature = fido.sign(&signed);
    f.proof["assertion_signature_hex"] = json!(hex::encode(signature.to_der().as_bytes()));
    assert_eq!(
        f.run(&mut SignCountStore::default(), now)
            .unwrap()
            .sign_count,
        1
    );
}

#[test]
fn genuine_proof_intent_binds_actual_parent_body_and_complete_signed_child() {
    use enclave_crypto::tuf::{Role, TufClient, SPEC_VERSION};
    const ROOT: &[u8] = include_bytes!("../../enclave-crypto/tests/data/yubikey-olpc1/root.json");
    const CHILD: &[u8] =
        include_bytes!("../../enclave-crypto/tests/data/yubikey-olpc1/snapshot.json");
    let client = TufClient::bootstrap(ROOT).unwrap();
    let expires = "2030-01-01T00:00:00Z";
    let body = json!({"_type":"timestamp","spec_version":SPEC_VERSION,"version":1,"expires":expires,
        "meta":{"snapshot.json":{"version":1,"length":CHILD.len(),"hashes":{"sha256":hex::encode(digest(CHILD))}}}});
    let bytes = enclave_crypto::canonical_json::to_canonical_json_bytes(&body).unwrap();
    let mut f = Fixture::new();
    f.intent["metadata"] = json!([{"role":"timestamp","base_version":0,"new_version":1,
        "signed_body_sha256":hex::encode(digest(&bytes)),"signed_body_bytes":bytes.len(),
        "expires_utc_ms":enclave_crypto::time::parse_rfc3339_utc(expires).unwrap() as u64*1000}]);
    f.intent["linked_metadata"] = json!([{"role":"snapshot","version":1,
        "envelope_sha256":hex::encode(digest(CHILD)),"envelope_bytes":CHILD.len()}]);
    f.reauthorize();
    // The same exact intent has a genuine issuer/SEP/CTAP chain and a genuine
    // separately pinned standard-TUF child. Neither diagnostic grants signing.
    f.run(&mut SignCountStore::default(), now).unwrap();
    let intent = jcs(&f.intent).unwrap();
    let facts = check_candidate_parent_linkage(&client, &intent, &bytes, &[CHILD], 2).unwrap();
    assert_eq!(facts.role, Role::Timestamp);
    assert_eq!(facts.child.role, Role::Snapshot);
    assert_eq!(facts.signed_body_sha256, digest(&bytes));
    assert_eq!(facts.child.sha256, digest(CHILD));
    assert!(check_candidate_parent_linkage(&client, &intent, &bytes, &[], 2).is_err());
    assert!(check_candidate_parent_linkage(&client, &intent, &bytes, &[CHILD, CHILD], 2).is_err());
    let mut changed = CHILD.to_vec();
    changed[10] ^= 1;
    assert!(check_candidate_parent_linkage(&client, &intent, &bytes, &[&changed], 2).is_err());
    let mut changed = body.clone();
    changed["meta"]["snapshot.json"]["length"] = json!(CHILD.len() + 1);
    let changed = enclave_crypto::canonical_json::to_canonical_json_bytes(&changed).unwrap();
    assert!(check_candidate_parent_linkage(&client, &intent, &changed, &[CHILD], 2).is_err());
    let mut changed = f.intent.clone();
    changed["metadata"][0]["signed_body_bytes"] = json!(bytes.len() + 1);
    assert!(
        check_candidate_parent_linkage(&client, &jcs(&changed).unwrap(), &bytes, &[CHILD], 2)
            .is_err()
    );
    changed = f.intent.clone();
    changed["unsigned_override"] = json!(true);
    assert!(
        check_candidate_parent_linkage(&client, &jcs(&changed).unwrap(), &bytes, &[CHILD], 2)
            .is_err()
    );
    let mut literal = Map::new();
    literal.insert("$serde_json::private::Number".into(), json!("1"));
    changed = f.intent.clone();
    changed["metadata"][0]["new_version"] = Value::Object(literal);
    assert!(
        check_candidate_parent_linkage(&client, &jcs(&changed).unwrap(), &bytes, &[CHILD], 2)
            .is_err()
    );
}
