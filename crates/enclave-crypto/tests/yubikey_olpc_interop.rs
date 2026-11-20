//! External canonicalization/signature fixtures. Public synthetic test authority
//! only; no SEP, authenticator, guarded signer or production protocol approval.
use ed25519_dalek::{Signer, SigningKey};
use enclave_crypto::tuf::{self, Signed, TargetsMeta, TufClient};
use serde_json::Value;
use sha2::{Digest, Sha256};

const ROOT: &[u8] = include_bytes!("data/yubikey-olpc1/root.json");
const TARGETS: &[u8] = include_bytes!("data/yubikey-olpc1/targets.json");
const SNAPSHOT: &[u8] = include_bytes!("data/yubikey-olpc1/snapshot.json");
const TIMESTAMP: &[u8] = include_bytes!("data/yubikey-olpc1/timestamp.json");
const NOW: i64 = 1_800_000_000;

#[test]
fn external_securesystemslib_openssl_roles_verify_and_rust_signs_identical_bytes() {
    let provenance: Value = serde_json::from_str(include_str!("data/yubikey-olpc1/provenance.json")).unwrap();
    for (name, bytes) in [("root", ROOT), ("targets", TARGETS), ("snapshot", SNAPSHOT), ("timestamp", TIMESTAMP)] {
        let value: Value = serde_json::from_slice(bytes).unwrap();
        let canonical = enclave_crypto::canonical_json::to_canonical_json_bytes(&value["signed"]).unwrap();
        assert_eq!(hex::encode(&canonical), provenance["signed_preimages_hex"][name].as_str().unwrap());
        assert_eq!(hex::encode(Sha256::digest(bytes)), provenance["file_sha256"][format!("{name}.json")].as_str().unwrap());
    }
    let mut client = TufClient::bootstrap(ROOT).unwrap();
    client.refresh(TIMESTAMP, SNAPSHOT, TARGETS, NOW).unwrap();
    let target = client.verify_target("synthetic.txt", b"abc", NOW).unwrap();
    assert_eq!(target.custom.as_ref().unwrap()["description"], "line\nnext\t\"quoted\"\\path");
    assert!(client.verify_target("synthetic.txt", b"abd", NOW).is_err());
    let external: Signed<TargetsMeta> = serde_json::from_slice(TARGETS).unwrap();
    let key = SigningKey::from_bytes(&[73; 32]);
    let local = tuf::sign(&external.signed, &[&key]).unwrap();
    assert_eq!(local.signatures, external.signatures);
    let olpc = enclave_crypto::canonical_json::to_canonical_json_bytes(&external.signed).unwrap();
    let jcs = enclave_core::jcs::to_jcs_bytes(&external.signed).unwrap();
    assert_ne!(olpc, jcs, "control characters and Unicode sort order distinguish the profiles");
    assert_ne!(key.sign(&olpc).to_bytes(), key.sign(&jcs).to_bytes());
}

#[test]
fn externally_signed_chain_refuses_modified_parent_links_and_reformatted_children() {
    let mut reformatted: Value = serde_json::from_slice(TARGETS).unwrap();
    let pretty = serde_json::to_vec_pretty(&reformatted).unwrap();
    assert_ne!(pretty, TARGETS);
    assert!(TufClient::bootstrap(ROOT).unwrap().refresh(TIMESTAMP, SNAPSHOT, &pretty, NOW).is_err());
    reformatted["signed"]["targets"]["synthetic.txt"]["custom"]["description"] = Value::String("substituted".into());
    let substituted = serde_json::to_vec(&reformatted).unwrap();
    assert!(TufClient::bootstrap(ROOT).unwrap().refresh(TIMESTAMP, SNAPSHOT, &substituted, NOW).is_err());
    let mut snapshot: Value = serde_json::from_slice(SNAPSHOT).unwrap();
    snapshot["signed"]["meta"]["targets.json"]["hashes"]["sha256"] = Value::String(hex::encode(Sha256::digest(&substituted)));
    assert!(TufClient::bootstrap(ROOT).unwrap().refresh(TIMESTAMP, &serde_json::to_vec(&snapshot).unwrap(), &substituted, NOW).is_err());
}
