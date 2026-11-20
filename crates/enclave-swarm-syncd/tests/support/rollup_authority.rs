//! Explicit software TUF/issuer fixtures. These do not attest hardware custody
//! or supply the missing private-membership/compliance relation.
use enclave_core::{ipc::PeerCredentials, profile::Profile};
use enclave_crypto::{
    pqc::HybridSigningKey,
    tuf::{target_file, RepoBuilder},
};
use enclave_swarm_syncd::service::{CasRequest, CasService};
use enclave_zk_auditor::{
    cohort::digest_bytes,
    receiver_trust::TRUST_TARGET,
    rollup::ComplianceRollupProofV1 as Frame,
    zk::{
        engine::{hiding_vk_digest, prove_epoch_private, EpochStatement, SlotKind},
        manifest::{VkManifestV1, VK_MANIFEST_TARGET},
    },
};
use std::{collections::BTreeMap, path::Path};

pub const EXP: &str = "2030-01-01T00:00:00Z";

pub struct Authority {
    pub manifest: Vec<u8>,
    pub trust: Vec<u8>,
    profile: Profile,
    key: HybridSigningKey,
}

impl Authority {
    pub fn new(profile: Profile) -> Self {
        let key = HybridSigningKey::generate();
        let authority = if profile == Profile::L3 {
            serde_json::json!({"kind":"l3_cohort","root_hex":hex::encode([3;32]),"size":48})
        } else {
            serde_json::json!({"kind":"l2_hybrid_anchor","public_key_hex":hex::encode(key.verifying_key().to_bytes())})
        };
        Self {
            manifest: VkManifestV1::production_hiding().to_json_bytes().unwrap(),
            trust: serde_json::to_vec(&serde_json::json!({"v":1,"authority":authority})).unwrap(),
            profile,
            key,
        }
    }

    pub fn install(
        &self,
        service: &CasService,
        store: &Path,
        repo: &RepoBuilder,
        peer: &PeerCredentials,
    ) {
        let mut targets = BTreeMap::new();
        for (name, bytes) in [
            (VK_MANIFEST_TARGET, &self.manifest),
            (TRUST_TARGET, &self.trust),
        ] {
            std::fs::write(store.join(name), bytes).unwrap();
            targets.insert(name.into(), target_file(bytes, None));
        }
        let targets = repo.targets(1, EXP, targets).unwrap();
        let snapshot = repo.snapshot(1, EXP, 1, &targets).unwrap();
        let timestamp = repo.timestamp(1, EXP, 1, &snapshot).unwrap();
        service
            .handle(
                peer,
                CasRequest::TufRefresh {
                    roots: vec![],
                    timestamp: timestamp.into(),
                    snapshot: snapshot.into(),
                    targets: targets.into(),
                },
            )
            .unwrap();
    }

    pub fn frame(&self, marker: u8) -> Vec<u8> {
        let nullifier_e = [marker; 32];
        let qif = digest_bytes(&enclave_core::poseidon2::hash_bytes(
            b"depot-QifTree-v1",
            &nullifier_e,
        ));
        let statement = EpochStatement {
            vk_digest: hiding_vk_digest(),
            profile: self.profile.number(),
            policy_blake3: [1; 32],
            tuf_snapshot_root: [2; 32],
            qif_cap_mb: 12000,
            r_fleet_pk: [3; 32],
            j_prev: [4; 32],
            j_curr: [5; 32],
            nullifier_e,
            qif_root_prev: qif,
            qif_root_curr: qif,
            s_start: 1,
            s_end: 1,
            used_in: 0,
            used_out: 1,
            cohort_size: if self.profile == Profile::L3 { 48 } else { 0 },
        };
        let proof = prove_epoch_private(&statement, &[SlotKind::Fold { delta_mb: 1 }]).unwrap();
        let anchors = (self.profile == Profile::L2)
            .then(|| vec![Frame::sign_l2_hybrid_anchor(&statement, &self.key)]);
        Frame::build(&statement, proof, Some(48), true, anchors).unwrap()
    }
}
