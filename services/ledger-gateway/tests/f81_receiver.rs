//! Real OHTTP receiver authority rejection/valid-use tests; fixture keys are software authorities.
use enclave_crypto::pqc::HybridSigningKey;
use enclave_zk_auditor::receiver_trust::ReceiverTrust;
use enclave_zk_auditor::rollup::ComplianceRollupProofV1 as Frame;
use enclave_zk_auditor::zk::engine::{EpochStatement,SlotKind,prove_epoch,vk_digest};
use ledger_gateway::{LedgerGateway,create_ohttp_rollup_request};
fn statement(profile:u8,size:u32,root:[u8;32])->EpochStatement {
    let nullifier_e=[4;32];let qif=enclave_zk_auditor::cohort::digest_bytes(&enclave_core::poseidon2::hash_bytes(b"MCPMac-QifTree-v1",&nullifier_e));
    EpochStatement {vk_digest:vk_digest(),profile,policy_blake3:[1;32],tuf_snapshot_root:[2;32],qif_cap_mb:12000,r_fleet_pk:root,
        j_prev:[4;32],j_curr:[5;32],nullifier_e,qif_root_prev:qif,qif_root_curr:qif,s_start:1,s_end:1,used_in:0,used_out:3,cohort_size:size}
}
fn l2(st:&EpochStatement,key:Option<&HybridSigningKey>)->Vec<u8> {
    Frame::build(st,prove_epoch(st,&[SlotKind::Fold {delta_mb:3}]).unwrap(),None,false,
        Some(vec![key.map(|key|Frame::sign_l2_hybrid_anchor(st,key)).unwrap_or_else(||"3045".into())])).unwrap()
}
#[test]
fn actual_ohttp_receiver_refuses_unconfigured_forged_foreign_and_wrong_statement_signatures() {
    let expected=HybridSigningKey::generate();let foreign=HybridSigningKey::generate();let st=statement(2,0,[3;32]);
    let (disabled,kc)=LedgerGateway::new(1,Default::default());let valid=l2(&st,Some(&expected));
    assert!(disabled.handle_ohttp_post(&create_ohttp_rollup_request(&kc,&valid).unwrap()).unwrap_err().is("ROLLUP_RECEIVER_TRUST_REQUIRED"));
    let gateway=disabled.with_receiver_trust(ReceiverTrust::l2_anchor(expected.verifying_key()).unwrap());
    for bytes in [l2(&st,None),l2(&st,Some(&foreign))] {
        assert!(Frame::verify(&bytes,&[vk_digest()]).is_ok(),"the original accounting-only receiver admitted this frame");
        let error=gateway.handle_ohttp_post(&create_ohttp_rollup_request(&kc,&bytes).unwrap()).unwrap_err();assert!(error.is("FRAME_VERIFY_FAILED"));
        assert!(gateway.verified_frames().is_empty(),"failed authority checks must not mutate ledger");
    }
    let other=EpochStatement {policy_blake3:[9;32],..st.clone()};
    let original=Frame::decode(&valid).unwrap();
    let wrong=Frame::build(&st,original.proof,None,false,Some(vec![Frame::sign_l2_hybrid_anchor(&other,&expected)])).unwrap();
    assert!(gateway.handle_ohttp_post(&create_ohttp_rollup_request(&kc,&wrong).unwrap()).is_err());
    assert!(gateway.handle_ohttp_post(&create_ohttp_rollup_request(&kc,&valid).unwrap()).unwrap().accepted);
    let replay=gateway.handle_ohttp_post(&create_ohttp_rollup_request(&kc,&valid).unwrap()).unwrap();
    assert!(!replay.accepted && replay.duplicate);assert_eq!(gateway.verified_frames().len(),1);
}
#[test]
fn actual_l3_receiver_pins_cohort_root_and_count_without_claiming_membership() {
    let (gateway,kc)=LedgerGateway::new(1,Default::default());
    let gateway=gateway.with_receiver_trust(ReceiverTrust::l3_cohort([3;32],32).unwrap());
    for (root,size,accepted) in [([9;32],32,false),([3;32],48,false),([3;32],32,true)] {
        let st=statement(3,size,root);
        let bytes=Frame::build(&st,prove_epoch(&st,&[SlotKind::Fold {delta_mb:3}]).unwrap(),Some(size as u64),true,None).unwrap();
        assert_eq!(bytes.len(),327680);
        assert!(Frame::verify(&bytes,&[vk_digest()]).is_ok());
        let result=gateway.handle_ohttp_post(&create_ohttp_rollup_request(&kc,&bytes).unwrap());
        if accepted {assert!(result.unwrap().accepted);} else {assert!(result.is_err());assert!(gateway.verified_frames().is_empty());}
    }
    // No membership witness was used. Pinning cannot close F78 or establish an anonymity set.
}
#[test]
fn actual_binary_requires_an_explicit_authority_or_named_accounting_fixture() {
    let out=std::process::Command::new(env!("CARGO_BIN_EXE_ledger-gateway")).arg("--dev-in-memory").output().unwrap();
    assert!(!out.status.success());assert!(String::from_utf8_lossy(&out.stderr).contains("select exactly one"));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("Gateway key config:"));
    let out=std::process::Command::new(env!("CARGO_BIN_EXE_ledger-gateway")).args(["--dev-in-memory","--accounting-fixture"]).output().unwrap();
    assert!(out.status.success());assert!(String::from_utf8_lossy(&out.stdout).contains("ACCOUNTING FIXTURE ONLY"));
}
