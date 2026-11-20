//! DEFECT-F-75: unauthenticated senders must not be able to saturate the
//! DPoP replay cache that key-bound proofs depend on.
//!
//! Without an `expected_jkt`, a proof is self-signed by a key anyone can
//! mint. Such proofs now fill a separate *unbound* pool; proofs whose key
//! matched the caller's `expected_jkt` fill the *bound* pool.

use enclave_crypto::dpop::{DpopKey, DpopRequest, DpopVerifier};

const URI: &str = "https://enclave.local.internal/depot/tools/call";
const NOW: i64 = 1_793_884_860;
const CAP: usize = 4;

fn unbound_req() -> DpopRequest<'static> {
    DpopRequest {
        htm: "POST",
        htu: URI,
        ..Default::default()
    }
}

fn bound_req(jkt: &str) -> DpopRequest<'_> {
    DpopRequest {
        expected_jkt: Some(jkt),
        ..unbound_req()
    }
}

fn proof(k: &DpopKey, jti: &str, iat: i64) -> String {
    k.create_proof("POST", URI, iat, jti, None).unwrap()
}

/// Fill the unbound pool to capacity with fresh attacker keys and jtis, then
/// show the next unbound proof is refused (fail closed, as before).
fn flood_unbound(v: &mut DpopVerifier, n: usize) {
    for i in 0..n {
        let attacker = DpopKey::generate();
        let jti = format!("jti-f75-flood-{i:08}");
        v.verify(&proof(&attacker, &jti, NOW), &unbound_req(), NOW)
            .unwrap();
    }
    let e = v
        .verify(
            &proof(&DpopKey::generate(), "jti-f75-flood-overflow", NOW),
            &unbound_req(),
            NOW,
        )
        .unwrap_err();
    assert!(e.is("DPOP_REPLAY_CACHE_SATURATED"), "{e}");
}

/// The review's attack: an unauthenticated flood of self-signed proofs fills
/// the cache. Key-bound proofs from the legitimate holder must still pass.
#[test]
fn f75_unbound_flood_cannot_deny_bound_proofs() {
    let mut v = DpopVerifier::new(60, 300, CAP);
    flood_unbound(&mut v, CAP);
    let legit = DpopKey::generate();
    let jkt = legit.thumbprint();
    for i in 0..CAP {
        let jti = format!("jti-f75-legit-{i:08}");
        let ok = v.verify(&proof(&legit, &jti, NOW), &bound_req(&jkt), NOW);
        assert!(
            ok.is_ok(),
            "bound proof {i} denied after unbound flood: {ok:?}"
        );
    }
}

/// An attacker cannot reach the bound pool: a proof by any other key fails
/// `DPOP_JKT_MISMATCH` before admission and occupies no slot.
#[test]
fn f75_mismatched_key_never_occupies_bound_slots() {
    let mut v = DpopVerifier::new(60, 300, CAP);
    let legit = DpopKey::generate();
    let jkt = legit.thumbprint();
    for i in 0..(CAP * 4) {
        let jti = format!("jti-f75-mismatch-{i:06}");
        let e = v
            .verify(
                &proof(&DpopKey::generate(), &jti, NOW),
                &bound_req(&jkt),
                NOW,
            )
            .unwrap_err();
        assert!(e.is("DPOP_JKT_MISMATCH"), "{e}");
    }
    for i in 0..CAP {
        let jti = format!("jti-f75-legit2-{i:07}");
        assert!(v
            .verify(&proof(&legit, &jti, NOW), &bound_req(&jkt), NOW)
            .is_ok());
    }
    let e = v
        .verify(
            &proof(&legit, "jti-f75-legit2-overflow", NOW),
            &bound_req(&jkt),
            NOW,
        )
        .unwrap_err();
    assert!(
        e.is("DPOP_REPLAY_CACHE_SATURATED"),
        "bound pool is still capped: {e}"
    );
}

/// Strict mode: `max_unbound_cache = 0` gates every admission on a bound key.
#[test]
fn f75_binding_required_mode_refuses_unbound_proofs() {
    let mut v = DpopVerifier::new(60, 300, CAP).with_unbound_capacity(0);
    let k = DpopKey::generate();
    let e = v
        .verify(
            &proof(&k, "jti-f75-strict-0000001", NOW),
            &unbound_req(),
            NOW,
        )
        .unwrap_err();
    assert!(e.is("DPOP_KEY_BINDING_REQUIRED"), "{e}");
    let jkt = k.thumbprint();
    assert!(v
        .verify(
            &proof(&k, "jti-f75-strict-0000002", NOW),
            &bound_req(&jkt),
            NOW
        )
        .is_ok());
}

/// Partitioning must not open a replay path: a proof accepted in one pool is
/// a replay in the other.
#[test]
fn f75_replay_is_detected_across_pools() {
    let mut v = DpopVerifier::new(60, 300, CAP);
    let k = DpopKey::generate();
    let jkt = k.thumbprint();
    let p = proof(&k, "jti-f75-xpool-0000001", NOW);
    v.verify(&p, &bound_req(&jkt), NOW).unwrap();
    assert!(v
        .verify(&p, &unbound_req(), NOW + 1)
        .unwrap_err()
        .is("DPOP_REPLAY"));
    let p = proof(&k, "jti-f75-xpool-0000002", NOW);
    v.verify(&p, &unbound_req(), NOW).unwrap();
    assert!(v
        .verify(&p, &bound_req(&jkt), NOW + 1)
        .unwrap_err()
        .is("DPOP_REPLAY"));
    assert!(v
        .verify(&p, &unbound_req(), NOW + 1)
        .unwrap_err()
        .is("DPOP_REPLAY"));
}

/// Entries are keyed by `(jkt, jti)`: an attacker who learns or guesses a
/// legitimate client's next `jti` cannot pre-register it under their own key.
#[test]
fn f75_foreign_key_cannot_poison_a_jti() {
    let mut v = DpopVerifier::new(60, 300, CAP);
    let attacker = DpopKey::generate();
    let legit = DpopKey::generate();
    let jkt = legit.thumbprint();
    let jti = "jti-f75-poison-0000001";
    v.verify(&proof(&attacker, jti, NOW), &unbound_req(), NOW)
        .unwrap();
    assert!(v
        .verify(&proof(&legit, jti, NOW), &bound_req(&jkt), NOW)
        .is_ok());
}

/// The unbound pool still drains after the replay window, as before.
#[test]
fn f75_unbound_pool_recovers_after_replay_window() {
    let mut v = DpopVerifier::new(60, 300, CAP);
    flood_unbound(&mut v, CAP);
    let later = NOW + 301;
    let k = DpopKey::generate();
    assert!(v
        .verify(
            &proof(&k, "jti-f75-recover-000001", later),
            &unbound_req(),
            later
        )
        .is_ok());
}
