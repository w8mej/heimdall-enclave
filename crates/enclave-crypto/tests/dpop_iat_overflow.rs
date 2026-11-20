//! DEFECT-F-74: the DPoP `iat` window check must never overflow.
//!
//! A DPoP proof is signed by the key in its own header, so any sender can
//! produce a validly signed proof carrying any `iat`. Under the workspace
//! release profile (`overflow-checks = true`, `panic = "abort"`) an
//! overflowing `now - iat` or `.abs()` would abort the host process. Every
//! extreme `iat` must instead be rejected with `DPOP_IAT_OUT_OF_WINDOW`.

use enclave_crypto::dpop::{verify_egress_dpop, DpopKey, DpopRequest, DpopVerifier};

const URI: &str = "https://enclave.local.internal/depot/tools/call";
const NOW: i64 = 1_793_884_860;

fn req() -> DpopRequest<'static> {
    DpopRequest {
        htm: "POST",
        htu: URI,
        ..Default::default()
    }
}

fn verify_at(iat: i64, now: i64, jti: &str) -> Result<i64, String> {
    let k = DpopKey::generate();
    let p = k.create_proof("POST", URI, iat, jti, None).unwrap();
    let mut v = DpopVerifier::default();
    v.verify(&p, &req(), now)
        .map(|ok| ok.iat)
        .map_err(|e| e.to_string())
}

fn assert_out_of_window(iat: i64, now: i64) {
    let k = DpopKey::generate();
    let p = k
        .create_proof("POST", URI, iat, "jti-f74-extreme-000001", None)
        .unwrap();
    let mut v = DpopVerifier::default();
    let e = v.verify(&p, &req(), now).unwrap_err();
    assert!(
        e.is("DPOP_IAT_OUT_OF_WINDOW"),
        "iat={iat} now={now}: expected DPOP_IAT_OUT_OF_WINDOW, got {e}"
    );
}

/// Review validation step 1, verbatim: `iat = i64::MIN` and `iat = i64::MAX`
/// both return `DPOP_IAT_OUT_OF_WINDOW`.
#[test]
fn f74_iat_i64_min_and_max_are_out_of_window() {
    assert_out_of_window(i64::MIN, NOW);
    assert_out_of_window(i64::MAX, NOW);
}

/// The overflow also depends on `now`: cover both signs and the extremes of
/// the verifier's own clock argument, so no (now, iat) pair can trap. Each
/// pair is either accepted (|now - iat| <= 60) or rejected as out of window.
#[test]
fn f74_extreme_now_and_iat_combinations_never_trap() {
    let edges = [
        i64::MIN,
        i64::MIN + 1,
        -1,
        0,
        1,
        NOW,
        i64::MAX - 1,
        i64::MAX,
    ];
    for &now in &edges {
        for &iat in &edges {
            let in_window = iat.abs_diff(now) <= 60;
            match verify_at(iat, now, "jti-f74-matrix-0000001") {
                Ok(got) => assert!(in_window && got == iat, "iat={iat} now={now}"),
                Err(e) => assert!(
                    !in_window && e.contains("DPOP_IAT_OUT_OF_WINDOW"),
                    "iat={iat} now={now}: {e}"
                ),
            }
        }
    }
}

/// Non-vacuity: the window still works at its exact boundary.
#[test]
fn f74_window_boundary_is_inclusive_and_symmetric() {
    assert_eq!(
        verify_at(NOW - 60, NOW, "jti-f74-edge-000000001"),
        Ok(NOW - 60)
    );
    assert_eq!(
        verify_at(NOW + 60, NOW, "jti-f74-edge-000000002"),
        Ok(NOW + 60)
    );
    assert_out_of_window(NOW - 61, NOW);
    assert_out_of_window(NOW + 61, NOW);
}

/// The one-shot helper (`verify_egress_dpop`) shares the same check.
#[test]
fn f74_verify_egress_dpop_rejects_extreme_iat() {
    let k = DpopKey::generate();
    for iat in [i64::MIN, i64::MAX] {
        let p = k
            .create_proof("POST", URI, iat, "jti-f74-egress-000001", None)
            .unwrap();
        let e = verify_egress_dpop(&p, "POST", URI, None, Some(&k.thumbprint()), NOW).unwrap_err();
        assert!(e.is("DPOP_IAT_OUT_OF_WINDOW"), "{e}");
    }
}

/// A verifier configured with a huge or negative skew must not overflow
/// either. A negative skew is nonsensical and is treated as zero (fail
/// closed): only `iat == now` passes.
#[test]
fn f74_misconfigured_skew_fails_closed_without_trapping() {
    let k = DpopKey::generate();
    let mut wide = DpopVerifier::new(i64::MAX, 300, 16);
    let p = k
        .create_proof("POST", URI, i64::MIN, "jti-f74-skew-0000001", None)
        .unwrap();
    // |NOW - i64::MIN| exceeds i64::MAX, so even an i64::MAX skew rejects it.
    assert!(wide
        .verify(&p, &req(), NOW)
        .unwrap_err()
        .is("DPOP_IAT_OUT_OF_WINDOW"));
    let mut negative = DpopVerifier::new(-5, 300, 16);
    let p = k
        .create_proof("POST", URI, NOW + 1, "jti-f74-skew-0000002", None)
        .unwrap();
    assert!(negative
        .verify(&p, &req(), NOW)
        .unwrap_err()
        .is("DPOP_IAT_OUT_OF_WINDOW"));
    let p = k
        .create_proof("POST", URI, NOW, "jti-f74-skew-0000003", None)
        .unwrap();
    assert!(negative.verify(&p, &req(), NOW).is_ok());
}

/// The replay-cache expiry `now + replay_window_s` must not overflow when the
/// clock argument is at the top of the range.
#[test]
fn f74_replay_expiry_saturates_at_i64_max() {
    let k = DpopKey::generate();
    let mut v = DpopVerifier::default();
    let p = k
        .create_proof("POST", URI, i64::MAX, "jti-f74-expiry-000001", None)
        .unwrap();
    assert!(v.verify(&p, &req(), i64::MAX).is_ok());
    assert!(v
        .verify(&p, &req(), i64::MAX)
        .unwrap_err()
        .is("DPOP_REPLAY"));
}

/// The pure gate agrees with the review's formula
/// `now.checked_sub(iat).map(i64::unsigned_abs)` (None = out of window)
/// wherever that formula is defined, and is total where it is not.
#[test]
fn f74_pure_gate_matches_review_formula() {
    use enclave_crypto::dpop::iat_within_skew;
    let edges = [
        i64::MIN,
        i64::MIN + 1,
        -61,
        -60,
        -1,
        0,
        1,
        60,
        61,
        i64::MAX - 1,
        i64::MAX,
    ];
    for &now in &edges {
        for &iat in &edges {
            for skew in [-1i64, 0, 60, i64::MAX] {
                let review = now
                    .checked_sub(iat)
                    .map(i64::unsigned_abs)
                    .is_some_and(|d| d <= u64::try_from(skew).unwrap_or(0));
                let ours = iat_within_skew(now, iat, skew);
                if now.checked_sub(iat).is_some() {
                    assert_eq!(ours, review, "now={now} iat={iat} skew={skew}");
                } else {
                    // Distance exceeds i64::MAX, so it is outside every skew.
                    assert!(!ours, "now={now} iat={iat} skew={skew}");
                }
            }
        }
    }
}
