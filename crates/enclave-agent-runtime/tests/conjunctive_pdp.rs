//! FS-704 end-to-end: heap labels → PoP-Biscuit delegation → conjunctive
//! `Cedar ∧ Biscuit` decision, QIF settlement and delegation conservation.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use enclave_agent_runtime::cedar_engine::{CedarEngine, ToolResource};
use enclave_agent_runtime::delegation::{DelegationManager, MAX_TREE_CALLS};
use enclave_agent_runtime::heap::CapabilityHeap;
use enclave_agent_runtime::pdp::{Pdp, ToolCallRequest};
use enclave_core::ifc_envelope::VaultTier;
use enclave_core::ipc::PeerCredentials;
use enclave_core::label::{Conf, SlotKind};
use enclave_core::profile::{ActionClass, Profile};
use enclave_core::qif::QifLedger;
use enclave_crypto::biscuit_auth::AuthorizerLimits;
use enclave_crypto::pop_biscuit::{
    make_call, spec_limits, ClockCaveat, DelegationCaveats, Transport, WireClock,
};

struct Fx {
    pdp: Pdp,
    heap: CapabilityHeap,
    dm: DelegationManager,
    orch: SigningKey,
    child: SigningKey,
    peer: PeerCredentials,
}

fn fx() -> Fx {
    let boot = enclave_core::seq::new_boot_epoch_id();
    let limits = AuthorizerLimits {
        max_time: Duration::from_millis(50),
        ..spec_limits()
    };
    Fx {
        pdp: Pdp::new(
            CedarEngine::baseline_bundle().unwrap(),
            boot.clone(),
            Profile::L2,
            limits,
        ),
        heap: CapabilityHeap::new(boot),
        dm: DelegationManager::new(),
        orch: SigningKey::generate(&mut rand_core::OsRng),
        child: SigningKey::generate(&mut rand_core::OsRng),
        peer: PeerCredentials {
            uid: 704,
            gid: 704,
            pid: Some(4242),
            audit_token: Some([1, 2, 3, 4, 5, 4242, 7, 8]),
            code_identity: None,
            tls_channel_binding: None,
        },
    }
}

fn tool() -> ToolResource {
    ToolResource {
        name: "depot://postgres/select_bounded".into(),
        action_class: ActionClass::A1,
        sink_clearance: Conf::C3,
        namespace: "dev-billing".into(),
        mutates_root: false,
    }
}

fn caveats(f: &Fx, qmax: i64) -> DelegationCaveats {
    DelegationCaveats {
        tools: vec!["depot://postgres/select_bounded".into()],
        target_namespace: "dev-billing".into(),
        max_row_count: 25,
        max_qif_call_millibits: qmax,
        clock: ClockCaveat::Uds {
            local_boot_id: f.pdp.boot_epoch_id().to_owned(),
            mach_continuous_time_ns_expiry: u32::MAX as u64,
        },
    }
}

fn req(
    f: &Fx,
    token: &enclave_crypto::biscuit_auth::Biscuit,
    seq: u64,
    slots: Vec<(SlotKind, String)>,
    t: ToolResource,
) -> ToolCallRequest {
    let args = br#"{"limit":10,"table":"invoices"}"#.to_vec();
    let clock = WireClock {
        local_boot_id: Some(f.pdp.boot_epoch_id().to_owned()),
        mach_continuous_time_ns_expiry: Some(u32::MAX as u64),
        ..Default::default()
    };
    let w = make_call(
        token,
        &f.child,
        &f.peer.channel_binding(),
        &args,
        seq,
        Transport::Uds,
        clock,
    )
    .unwrap();
    ToolCallRequest {
        agent: "db_researcher".into(),
        tool: t,
        args_jcs: args,
        arg_slots: slots,
        literal_structural: false,
        row_count: 10,
        qif_mb: 1000,
        hw_grant: false,
        wire_cbor: w.to_cbor().unwrap(),
    }
}

#[test]
fn conjunction_requires_both_engines() {
    let mut f = fx();
    let root =
        f.dm.mint_root(
            &f.pdp,
            &f.orch.verifying_key().to_bytes(),
            &[0u8; 32],
            12_000,
            &[tool().name],
        )
        .unwrap();
    let child =
        f.dm.spawn(
            &root,
            &caveats(&f, 4000),
            &f.child.verifying_key().to_bytes(),
            &f.peer.channel_binding(),
        )
        .unwrap();
    let v = f
        .heap
        .ingest_tool_output(
            "describe",
            &"ab".repeat(32),
            b"invoices".to_vec(),
            Conf::C2,
            &[],
            "depot://db",
            VaultTier::None,
        )
        .unwrap();
    // Both allow.
    let d = f
        .pdp
        .authorize(
            &f.heap,
            &f.peer,
            &req(
                &f,
                &child,
                1,
                vec![(SlotKind::BoundLiteral, v.handle.clone())],
                tool(),
            ),
            1,
            0,
        )
        .unwrap();
    assert!(d.cedar_allow && d.biscuit_allow && d.allow, "{d:?}");
    assert_eq!(d.depth, Some(1));
    // Cedar denies (write-down: C2 input to a C1 sink) while Biscuit allows.
    let mut low = tool();
    low.sink_clearance = Conf::C1;
    let d = f
        .pdp
        .authorize(
            &f.heap,
            &f.peer,
            &req(
                &f,
                &child,
                2,
                vec![(SlotKind::BoundLiteral, v.handle.clone())],
                low,
            ),
            1,
            0,
        )
        .unwrap();
    assert!(
        !d.cedar_allow && !d.biscuit_allow && !d.allow,
        "BLP is enforced by both engines: {d:?}"
    );
    // Biscuit denies (tool outside the attenuated set) while Cedar allows.
    let mut other = tool();
    other.name = "depot://postgres/describe_table".into();
    let d = f
        .pdp
        .authorize(
            &f.heap,
            &f.peer,
            &req(
                &f,
                &child,
                3,
                vec![(SlotKind::BoundLiteral, v.handle.clone())],
                other,
            ),
            1,
            0,
        )
        .unwrap();
    assert!(d.cedar_allow && !d.biscuit_allow && !d.allow, "{d:?}");
    // Replay of seq 1 is denied by the Biscuit path.
    let d = f
        .pdp
        .authorize(
            &f.heap,
            &f.peer,
            &req(
                &f,
                &child,
                1,
                vec![(SlotKind::BoundLiteral, v.handle.clone())],
                tool(),
            ),
            1,
            0,
        )
        .unwrap();
    assert!(!d.allow && d.biscuit_error.unwrap().contains("REPLAY"));
}

#[test]
fn t3_handle_in_ast_slot_fails_before_either_engine() {
    let mut f = fx();
    let root =
        f.dm.mint_root(
            &f.pdp,
            &f.orch.verifying_key().to_bytes(),
            &[0u8; 32],
            12_000,
            &[tool().name],
        )
        .unwrap();
    let child =
        f.dm.spawn(
            &root,
            &caveats(&f, 4000),
            &f.child.verifying_key().to_bytes(),
            &f.peer.channel_binding(),
        )
        .unwrap();
    let inj = f
        .heap
        .ingest_tool_output(
            "issues",
            &"ab".repeat(32),
            b"DROP TABLE invoices".to_vec(),
            Conf::C2,
            &[],
            "gh://issue/1",
            VaultTier::None,
        )
        .unwrap();
    let e = f
        .pdp
        .authorize(
            &f.heap,
            &f.peer,
            &req(
                &f,
                &child,
                1,
                vec![(SlotKind::AstStructural, inj.handle)],
                tool(),
            ),
            1,
            0,
        )
        .unwrap_err();
    assert!(e.is("T3_BIBA_VIOLATION"));
    // A forged handle never reaches the engines either.
    let e = f
        .pdp
        .authorize(
            &f.heap,
            &f.peer,
            &req(
                &f,
                &child,
                2,
                vec![(SlotKind::BoundLiteral, "$v_999".into())],
                tool(),
            ),
            1,
            0,
        )
        .unwrap_err();
    assert!(e.is("HANDLE_FORGERY"));
}

#[test]
fn stolen_token_on_another_channel_is_useless() {
    let mut f = fx();
    let root =
        f.dm.mint_root(
            &f.pdp,
            &f.orch.verifying_key().to_bytes(),
            &[0u8; 32],
            12_000,
            &[tool().name],
        )
        .unwrap();
    let child =
        f.dm.spawn(
            &root,
            &caveats(&f, 4000),
            &f.child.verifying_key().to_bytes(),
            &f.peer.channel_binding(),
        )
        .unwrap();
    let v = f
        .heap
        .ingest_tool_output(
            "describe",
            &"ab".repeat(32),
            b"x".to_vec(),
            Conf::C1,
            &[],
            "u",
            VaultTier::None,
        )
        .unwrap();
    let r = req(
        &f,
        &child,
        1,
        vec![(SlotKind::BoundLiteral, v.handle)],
        tool(),
    );
    let thief = PeerCredentials {
        uid: 501,
        gid: 20,
        pid: Some(666),
        audit_token: Some([9; 8]),
        code_identity: None,
        tls_channel_binding: None,
    };
    let d = f.pdp.authorize(&f.heap, &thief, &r, 1, 0).unwrap();
    assert!(
        !d.allow
            && d.biscuit_error
                .unwrap()
                .contains("POP_CHANNEL_BINDING_MISMATCH")
    );
}

#[test]
fn fallible_declassifier_has_one_paid_error_outcome() {
    let mut f = fx();
    let mut ledger = QifLedger::new(Profile::L2);
    let v = f
        .heap
        .ingest_tool_output(
            "t",
            &"ab".repeat(32),
            b"opaque".to_vec(),
            Conf::C3,
            &["cust-error".into()],
            "u",
            VaultTier::None,
        )
        .unwrap();
    let mut errors = Vec::new();
    for variant in 0..3 {
        let err = f
            .pdp
            .declassify_enum(
                &mut f.heap,
                &mut ledger,
                "orchestrator",
                &v.handle,
                2,
                |_| match variant {
                    0 => Err(enclave_core::err!(
                        EINVAL,
                        "PAYLOAD_SECRET_A",
                        "private detail A"
                    )),
                    1 => Err(enclave_core::err!(
                        EIO,
                        "PAYLOAD_SECRET_B",
                        "private detail B"
                    )),
                    _ => Ok(2),
                },
                1,
            )
            .unwrap_err();
        errors.push(err.to_string());
        assert!(err.is("DECLASSIFIER_FAILED"), "{err}");
    }
    assert!(errors.windows(2).all(|e| e[0] == e[1]), "{errors:?}");
    assert_eq!(
        ledger.used(&v.entity_keys[0], 1),
        3 * enclave_core::qif::millibits_for_outcomes(3)
    );
    f.pdp
        .declassify_enum(
            &mut f.heap,
            &mut ledger,
            "orchestrator",
            &v.handle,
            2,
            |_| Ok(1),
            1,
        )
        .unwrap();
    assert_eq!(
        ledger.used(&v.entity_keys[0], 1),
        4 * enclave_core::qif::millibits_for_outcomes(3)
    );
}

#[test]
fn declassify_enum_qif_budget_and_fanin() {
    let mut f = fx();
    let mut ledger = QifLedger::new(Profile::L2);
    let v = f
        .heap
        .ingest_tool_output(
            "sentry",
            &"ab".repeat(32),
            b"service=payments crash".to_vec(),
            Conf::C4,
            &["cust-42".into()],
            "sentry://1",
            VaultTier::A4,
        )
        .unwrap();
    // 3 calls of K=15 plus one failure (4 bits each) = 12 bits: allowed. The 4th exceeds 12.0 bits.
    for _ in 0..3 {
        let out = f
            .pdp
            .declassify_enum(
                &mut f.heap,
                &mut ledger,
                "orchestrator",
                &v.handle,
                15,
                |_| Ok(3),
                1,
            )
            .unwrap();
        assert_eq!(out.label.t, enclave_core::label::Taint::T2);
    }
    let e = f
        .pdp
        .declassify_enum(
            &mut f.heap,
            &mut ledger,
            "orchestrator",
            &v.handle,
            15,
            |_| Ok(3),
            2,
        )
        .unwrap_err();
    assert!(e.is("QIF_BUDGET_EXCEEDED"), "{e}");
    // Out-of-range classifier output fails closed.
    let w = f
        .heap
        .ingest_tool_output(
            "t",
            &"ab".repeat(32),
            b"y".to_vec(),
            Conf::C3,
            &["cust-7".into()],
            "u",
            VaultTier::None,
        )
        .unwrap();
    assert!(f
        .pdp
        .declassify_enum(
            &mut f.heap,
            &mut ledger,
            "orchestrator",
            &w.handle,
            2,
            |_| Ok(2),
            3
        )
        .is_err());
    // |E| > 64 → E2BIG before any charge.
    let mut hs = vec![];
    for i in 0..65 {
        hs.push(
            f.heap
                .ingest_tool_output(
                    "t",
                    &"ab".repeat(32),
                    vec![i],
                    Conf::C3,
                    &[format!("c{i}")],
                    "u",
                    VaultTier::None,
                )
                .unwrap()
                .handle,
        );
    }
    let joined = f
        .heap
        .derive(
            &hs[..64],
            enclave_core::label::Label::BOTTOM,
            b"agg".to_vec(),
            "Agg",
        )
        .unwrap();
    assert_eq!(joined.entity_keys.len(), 64);
    assert!(f
        .heap
        .derive(
            &hs,
            enclave_core::label::Label::BOTTOM,
            b"agg".to_vec(),
            "Agg"
        )
        .unwrap_err()
        .is("PROVENANCE_FANIN_EXCEEDED"));
}

#[test]
fn delegation_checked_slice_matches_wide_integer_oracle() {
    let values = [i64::MIN, -1, 0, 1, 12000, i64::MAX - 1, i64::MAX];
    for delegated in values {
        for slice in values {
            for budget in values {
                let sum = i128::from(delegated) + i128::from(slice);
                let expected = if delegated >= 0 && slice >= 0 && sum <= i128::from(budget) {
                    Some(sum as i64)
                } else {
                    None
                };
                assert_eq!(
                    enclave_agent_runtime::delegation::checked_slice_total(
                        delegated, slice, budget
                    ),
                    expected
                );
            }
        }
    }
}

#[test]
fn delegation_overflow_rejected_before_token_or_budget_mutation() {
    let mut f = fx();
    assert!(f
        .dm
        .mint_root(
            &f.pdp,
            &f.orch.verifying_key().to_bytes(),
            &[0; 32],
            -1,
            &[tool().name]
        )
        .unwrap_err()
        .is("ROOT_BUDGET_NEGATIVE"));
    let root =
        f.dm.mint_root(
            &f.pdp,
            &f.orch.verifying_key().to_bytes(),
            &[0; 32],
            i64::MAX,
            &[tool().name],
        )
        .unwrap();
    let cb = f.peer.channel_binding();
    f.dm.spawn(
        &root,
        &caveats(&f, i64::MAX),
        &f.child.verifying_key().to_bytes(),
        &cb,
    )
    .unwrap();
    for _ in 0..2 {
        let e =
            f.dm.spawn(
                &root,
                &caveats(&f, 1),
                &f.child.verifying_key().to_bytes(),
                &cb,
            )
            .unwrap_err();
        assert!(e.is("QIF_CONSERVATION_VIOLATION"));
    }
}

#[test]
fn delegation_conserves_qif_and_bounds_tree_calls() {
    let mut f = fx();
    let root =
        f.dm.mint_root(
            &f.pdp,
            &f.orch.verifying_key().to_bytes(),
            &[0u8; 32],
            12_000,
            &[tool().name],
        )
        .unwrap();
    let cb = f.peer.channel_binding();
    let a =
        f.dm.spawn(
            &root,
            &caveats(&f, 6000),
            &f.child.verifying_key().to_bytes(),
            &cb,
        )
        .unwrap();
    let _b =
        f.dm.spawn(
            &root,
            &caveats(&f, 6000),
            &f.child.verifying_key().to_bytes(),
            &cb,
        )
        .unwrap();
    // 8 children x 12 bits amplification is impossible: the parent slice is exhausted.
    let e =
        f.dm.spawn(
            &root,
            &caveats(&f, 1),
            &f.child.verifying_key().to_bytes(),
            &cb,
        )
        .unwrap_err();
    assert!(e.is("QIF_CONSERVATION_VIOLATION"));
    // Grandchild limited by the child's slice.
    assert!(f
        .dm
        .spawn(
            &a,
            &caveats(&f, 6001),
            &f.child.verifying_key().to_bytes(),
            &cb
        )
        .is_err());
    let g =
        f.dm.spawn(
            &a,
            &caveats(&f, 3000),
            &f.child.verifying_key().to_bytes(),
            &cb,
        )
        .unwrap();
    for _ in 0..MAX_TREE_CALLS {
        f.dm.record_call(&g).unwrap();
    }
    assert!(
        f.dm.record_call(&root)
            .unwrap_err()
            .is("TREE_CALL_BUDGET_EXHAUSTED"),
        "budget is per tree"
    );
}

#[test]
fn sealed_and_unsealed_tokens_share_the_same_accounting_identity() {
    let mut f = fx();
    let root =
        f.dm.mint_root(
            &f.pdp,
            &f.orch.verifying_key().to_bytes(),
            &[0u8; 32],
            12_000,
            &[tool().name],
        )
        .unwrap();
    let sealed = root.seal().unwrap();
    assert_ne!(root.to_vec().unwrap(), sealed.to_vec().unwrap());
    assert_eq!(
        root.revocation_identifiers(),
        sealed.revocation_identifiers()
    );
    for index in 0..MAX_TREE_CALLS {
        let token = if index % 2 == 0 { &root } else { &sealed };
        assert_eq!(f.dm.record_call(token).unwrap(), index + 1);
    }
    assert!(f
        .dm
        .record_call(&sealed)
        .unwrap_err()
        .is("TREE_CALL_BUDGET_EXHAUSTED"));
    assert!(f
        .dm
        .record_call(&root)
        .unwrap_err()
        .is("TREE_CALL_BUDGET_EXHAUSTED"));
}

#[test]
fn failed_attenuation_of_a_sealed_parent_does_not_reserve_a_slice() {
    let mut f = fx();
    let root =
        f.dm.mint_root(
            &f.pdp,
            &f.orch.verifying_key().to_bytes(),
            &[0u8; 32],
            12_000,
            &[tool().name],
        )
        .unwrap();
    let sealed = root.seal().unwrap();
    let child_pk = f.child.verifying_key().to_bytes();
    let cb = f.peer.channel_binding();
    let restrictions = caveats(&f, 12_000);
    assert!(f.dm.spawn(&sealed, &restrictions, &child_pk, &cb).is_err());
    f.dm.spawn(&root, &restrictions, &child_pk, &cb).unwrap();
    assert!(f
        .dm
        .spawn(&root, &caveats(&f, 1), &child_pk, &cb)
        .unwrap_err()
        .is("QIF_CONSERVATION_VIOLATION"));
}

#[test]
fn delegated_and_spent_slices_are_exclusive_and_failures_do_not_mutate_them() {
    let mut f = fx();
    let root =
        f.dm.mint_root(
            &f.pdp,
            &f.orch.verifying_key().to_bytes(),
            &[0; 32],
            4000,
            &[tool().name],
        )
        .unwrap();
    let child_pk = f.child.verifying_key().to_bytes();
    let cb = f.peer.channel_binding();
    let child =
        f.dm.spawn(&root, &caveats(&f, 3000), &child_pk, &cb)
            .unwrap();
    assert!(f
        .dm
        .record_call_with_charge(&root, -1)
        .unwrap_err()
        .is("QIF_CONSERVATION_VIOLATION"));
    assert_eq!(f.dm.record_call_with_charge(&root, 1000).unwrap(), 1);
    assert!(f
        .dm
        .record_call_with_charge(&root, 1)
        .unwrap_err()
        .is("QIF_CONSERVATION_VIOLATION"));
    assert!(f
        .dm
        .spawn(&root, &caveats(&f, 1), &child_pk, &cb)
        .unwrap_err()
        .is("QIF_CONSERVATION_VIOLATION"));
    assert_eq!(f.dm.record_call_with_charge(&child, 3000).unwrap(), 2);
    assert!(f
        .dm
        .record_call_with_charge(&child, 1)
        .unwrap_err()
        .is("QIF_CONSERVATION_VIOLATION"));
    assert_eq!(f.dm.record_call(&root).unwrap(), 3);
}

#[test]
fn cumulative_spending_cannot_be_redelegated() {
    let mut f = fx();
    let root =
        f.dm.mint_root(
            &f.pdp,
            &f.orch.verifying_key().to_bytes(),
            &[0; 32],
            4000,
            &[tool().name],
        )
        .unwrap();
    assert_eq!(f.dm.record_call_with_charge(&root, 3000).unwrap(), 1);
    let child_pk = f.child.verifying_key().to_bytes();
    let cb = f.peer.channel_binding();
    assert!(f
        .dm
        .spawn(&root, &caveats(&f, 1001), &child_pk, &cb)
        .unwrap_err()
        .is("QIF_CONSERVATION_VIOLATION"));
    let child =
        f.dm.spawn(&root, &caveats(&f, 1000), &child_pk, &cb)
            .unwrap();
    assert_eq!(f.dm.record_call_with_charge(&child, 1000).unwrap(), 2);
    assert!(f
        .dm
        .record_call_with_charge(&root, 1)
        .unwrap_err()
        .is("QIF_CONSERVATION_VIOLATION"));
}

#[test]
fn exhausted_call_counter_does_not_also_consume_a_qif_slice() {
    let mut f = fx();
    let root =
        f.dm.mint_root(
            &f.pdp,
            &f.orch.verifying_key().to_bytes(),
            &[0; 32],
            4000,
            &[tool().name],
        )
        .unwrap();
    for _ in 0..MAX_TREE_CALLS {
        f.dm.record_call(&root).unwrap();
    }
    assert!(f
        .dm
        .record_call_with_charge(&root, 1000)
        .unwrap_err()
        .is("TREE_CALL_BUDGET_EXHAUSTED"));
    let child_pk = f.child.verifying_key().to_bytes();
    let cb = f.peer.channel_binding();
    f.dm.spawn(&root, &caveats(&f, 4000), &child_pk, &cb)
        .unwrap();
}
