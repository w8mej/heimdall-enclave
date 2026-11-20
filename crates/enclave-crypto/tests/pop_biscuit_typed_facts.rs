//! DEFECT-F-77: PoP-Biscuit holder facts come from typed Datalog, and the
//! mTLS lifetime bound uses the signed expiry plus a verifier-side skew.

use std::collections::HashMap;
use std::time::Duration;

use biscuit_auth::builder::Term;
use biscuit_auth::{AuthorizerLimits, Biscuit, KeyPair, PublicKey};
use ed25519_dalek::SigningKey;
use enclave_crypto::pop_biscuit::{
    attenuate, check_mtls_lifetime, make_call, mint_root, parse_and_verify_token, spec_limits,
    verify_call, AuthorityClaims, ClockCaveat, DelegationCaveats, RequestFacts, Transport,
    VerifyContext, WireClock, MAX_SKEW_MS, MAX_TTL_MS, VERIFIER_MTLS_SKEW_MS,
};
use rand_core::OsRng;

const NOW_MS: u64 = 1_793_884_860_000;
const TOOL: &str = "mcp://postgres/select_bounded";
const NS: &str = "dev-billing";

struct Fx {
    root: KeyPair,
    boot: String,
    orch: SigningKey,
    child: SigningKey,
    cb_orch: [u8; 32],
    cb_child: [u8; 32],
}

fn fx() -> Fx {
    Fx {
        root: KeyPair::new(),
        boot: enclave_core::seq::new_boot_epoch_id(),
        orch: SigningKey::generate(&mut OsRng),
        child: SigningKey::generate(&mut OsRng),
        cb_orch: [1u8; 32],
        cb_child: [2u8; 32],
    }
}

fn claims(f: &Fx) -> AuthorityClaims {
    AuthorityClaims {
        boot_uuid: f.boot.clone(),
        effective_profile: 2,
        policy_bundle_blake3: [9u8; 32],
        max_c_clearance: 3,
        total_qif_budget_millibits: 12_000,
        allowed_tools: None,
    }
}

fn mtls_caveats(exp: u64, ns: &str) -> DelegationCaveats {
    DelegationCaveats {
        tools: vec![TOOL.into()],
        target_namespace: ns.into(),
        max_row_count: 25,
        max_qif_call_millibits: 4000,
        clock: ClockCaveat::Mtls {
            utc_epoch_ms_expiry: exp,
        },
    }
}

fn root_token(f: &Fx) -> Biscuit {
    mint_root(
        &f.root,
        &claims(f),
        &f.orch.verifying_key().to_bytes(),
        &f.cb_orch,
    )
    .unwrap()
}

fn child_token(f: &Fx, exp: u64, ns: &str) -> Biscuit {
    let child_pk = f.child.verifying_key().to_bytes();
    attenuate(
        &root_token(f),
        &mtls_caveats(exp, ns),
        &child_pk,
        &f.cb_child,
    )
    .unwrap()
}

fn sealed(token: &Biscuit) -> Vec<u8> {
    token.seal().unwrap().to_vec().unwrap()
}

fn request(ns: &str) -> RequestFacts {
    RequestFacts {
        tool: TOOL.into(),
        target_namespace: ns.into(),
        row_count_bound: 10,
        qif_call_millibits: 1000,
        arg_taint_in_ast_slot: 1,
        input_confidentiality: 2,
        sink_clearance: 3,
    }
}

fn ctx<'a>(f: &'a Fx, pk: &'a PublicKey, cb: [u8; 32], ns: &str) -> VerifyContext<'a> {
    VerifyContext {
        root_public_key: pk,
        local_boot_id: &f.boot,
        now_mach_ns: 0,
        now_utc_ms: NOW_MS,
        observed_channel_binding: cb,
        allow_mtls: true,
        received_args_blake3: *blake3::hash(b"{}").as_bytes(),
        request: request(ns),
        limits: AuthorizerLimits {
            max_time: Duration::from_millis(50),
            ..spec_limits()
        },
    }
}

/// The presenter's wire hints: expiry and skew are both unsigned.
fn wire_clock(hint_exp: u64, hint_skew: u64) -> WireClock {
    WireClock {
        utc_epoch_ms_expiry: Some(hint_exp),
        max_ttl_ms: Some(MAX_TTL_MS),
        skew_ms: Some(hint_skew),
        ..Default::default()
    }
}

fn call_mtls(
    f: &Fx,
    token: &Biscuit,
    key: &SigningKey,
    cb: [u8; 32],
    clock: WireClock,
    ns: &str,
) -> Result<(), String> {
    let wire = make_call(token, key, &cb, b"{}", 1, Transport::MtlsExporter, clock).unwrap();
    let pk = f.root.public();
    let mut replay = HashMap::new();
    verify_call(&wire, &ctx(f, &pk, cb, ns), &mut replay)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// The review's skew point, plus the bypass it implies: a token whose
/// *signed* lifetime exceeds the ceiling is refused even if the presenter
/// sends a short wire expiry and the maximum wire skew.
#[test]
fn f77_lying_wire_hints_cannot_pass_an_over_long_signed_lifetime() {
    let f = fx();
    let signed_exp = NOW_MS + MAX_TTL_MS + VERIFIER_MTLS_SKEW_MS + 1;
    let token = child_token(&f, signed_exp, NS);
    let hint = wire_clock(NOW_MS + 1_000, MAX_SKEW_MS);
    let e = call_mtls(&f, &token, &f.child, f.cb_child, hint, NS).unwrap_err();
    assert!(e.contains("POP_TTL_TOO_LONG"), "{e}");
}

/// The bound uses the verifier constant: a presenter declaring zero skew
/// does not narrow it, and one at the maximum does not widen it.
#[test]
fn f77_bound_is_verifier_side_regardless_of_wire_skew() {
    let f = fx();
    let at_ceiling = NOW_MS + MAX_TTL_MS + VERIFIER_MTLS_SKEW_MS;
    let token = child_token(&f, at_ceiling, NS);
    for hint_skew in [0, MAX_SKEW_MS] {
        let hint = wire_clock(at_ceiling, hint_skew);
        assert_eq!(
            call_mtls(&f, &token, &f.child, f.cb_child, hint, NS),
            Ok(())
        );
    }
}

/// Pure gate: boundaries and the unbounded case.
#[test]
fn f77_check_mtls_lifetime_boundaries() {
    let ceiling = MAX_TTL_MS + VERIFIER_MTLS_SKEW_MS;
    assert!(check_mtls_lifetime(Some(NOW_MS + ceiling), NOW_MS).is_ok());
    assert!(check_mtls_lifetime(Some(NOW_MS + ceiling + 1), NOW_MS)
        .unwrap_err()
        .is("POP_TTL_TOO_LONG"));
    // Already expired: the ceiling passes; Datalog `now <= exp` then denies.
    assert!(check_mtls_lifetime(Some(NOW_MS - 1), NOW_MS).is_ok());
    assert!(check_mtls_lifetime(None, NOW_MS)
        .unwrap_err()
        .is("POP_TTL_UNBOUNDED"));
    assert!(check_mtls_lifetime(Some(u64::MAX), 0)
        .unwrap_err()
        .is("POP_TTL_TOO_LONG"));
}

/// A token with no signed mTLS expiry (the depth-0 root) cannot be used over
/// mTLS on the strength of the presenter's wire hint alone.
#[test]
fn f77_mtls_without_signed_expiry_is_refused() {
    let f = fx();
    let root = root_token(&f);
    let hint = wire_clock(NOW_MS + 1_000, 0);
    let e = call_mtls(&f, &root, &f.orch, f.cb_orch, hint, NS).unwrap_err();
    assert!(e.contains("POP_TTL_UNBOUNDED"), "{e}");
}

/// The verifier records the earliest signed expiry across all blocks.
#[test]
fn f77_signed_expiry_is_the_minimum_over_blocks() {
    let f = fx();
    let near = NOW_MS + 10_000;
    let grandchild = SigningKey::generate(&mut OsRng);
    let token = attenuate(
        &child_token(&f, near, NS),
        &mtls_caveats(NOW_MS + 86_400_000, NS),
        &grandchild.verifying_key().to_bytes(),
        &[3u8; 32],
    )
    .unwrap();
    let facts = parse_and_verify_token(&sealed(&token), &f.root.public()).unwrap();
    assert_eq!(facts.mtls_expiry_utc_ms, Some(near));
    assert_eq!(facts.depth, 2);
    assert_eq!(facts.tip_public_key, grandchild.verifying_key().to_bytes());
}

/// String terms that contain the printed form of a holder fact are data, not
/// facts: the typed read ignores them, so the tip holder and the ambient-fact
/// count are unaffected.
#[test]
fn f77_holder_token_sequence_inside_a_string_is_not_a_fact() {
    let f = fx();
    let fake = hex_of(&[0xEE; 32]);
    let injected = format!(
        "{NS}\");\npop_holder(1, hex:{fake}, hex:{fake});\ncheck if target_namespace(\"{NS}"
    );
    let token = child_token(&f, NOW_MS + 10_000, &injected);
    let facts = parse_and_verify_token(&sealed(&token), &f.root.public()).unwrap();
    assert_eq!(facts.tip_public_key, f.child.verifying_key().to_bytes());
    assert_eq!(facts.tip_channel_binding, f.cb_child);
}

/// A rule in block 0 that derives an extra `pop_holder` makes the evaluated
/// world disagree with the blocks' typed facts: refused.
#[test]
fn f77_rule_derived_holder_is_refused_by_world_cross_check() {
    let f = fx();
    let orch_pk = f.orch.verifying_key().to_bytes();
    let mut p = HashMap::new();
    p.insert("boot".to_owned(), Term::Str(f.boot.clone()));
    p.insert("policy".to_owned(), Term::Bytes(vec![9u8; 32]));
    p.insert("pk".to_owned(), Term::Bytes(orch_pk.to_vec()));
    p.insert("cb".to_owned(), Term::Bytes(f.cb_orch.to_vec()));
    p.insert("fake".to_owned(), Term::Bytes(vec![0xEE; 32]));
    let code = r#"
        boot_uuid({boot});
        policy_bundle_blake3({policy});
        pop_holder(0, {pk}, {cb});
        pop_holder(1, {fake}, {fake}) <- boot_uuid($b);
    "#;
    let root = Biscuit::builder()
        .code_with_params(code, p, HashMap::new())
        .and_then(|b| b.build(&f.root))
        .unwrap();
    let child_pk = f.child.verifying_key().to_bytes();
    let token = attenuate(
        &root,
        &mtls_caveats(NOW_MS + 10_000, NS),
        &child_pk,
        &f.cb_child,
    )
    .unwrap();
    let e = parse_and_verify_token(&sealed(&token), &f.root.public()).unwrap_err();
    assert!(e.is("POP_HOLDER_INVALID"), "{e}");
}

/// Non-vacuity for the cross-check: the same root without the deriving rule
/// verifies, so the refusal above is caused by the derived holder.
#[test]
fn f77_same_root_without_derived_holder_verifies() {
    let f = fx();
    let token = child_token(&f, NOW_MS + 10_000, NS);
    let facts = parse_and_verify_token(&sealed(&token), &f.root.public()).unwrap();
    assert_eq!(facts.depth, 1);
    assert_eq!(facts.policy_bundle_blake3, [9u8; 32]);
    assert_eq!(facts.mtls_expiry_utc_ms, Some(NOW_MS + 10_000));
    assert_eq!(
        call_mtls(
            &f,
            &token,
            &f.child,
            f.cb_child,
            wire_clock(NOW_MS + 10_000, 0),
            NS
        ),
        Ok(())
    );
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
