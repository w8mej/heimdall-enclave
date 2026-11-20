//! DEFECT-F-76: the bespoke hybrid KEM must not be put on the wire under the
//! IANA X-Wing code point, and the sources must not describe it as X-Wing.

use enclave_crypto::ohttp::{
    bhttp_post, decapsulate, encapsulate, gateway_keypair, KEM_ID, KEM_ID_HYBRID_MCPMAC,
    KEM_ID_XWING_IANA,
};

fn request() -> Vec<u8> {
    bhttp_post(
        "ledger.corporate.internal",
        "/v1/rollup",
        "application/cbor",
        &[0x5a; 64],
    )
}

fn with_kem_id(enc: &[u8], kem_id: u16) -> Vec<u8> {
    let mut out = enc.to_vec();
    out[1..3].copy_from_slice(&kem_id.to_be_bytes());
    out
}

#[test]
fn f76_hybrid_requests_carry_the_local_id_not_xwing() {
    assert_eq!(KEM_ID_XWING_IANA, 0x647A);
    assert_ne!(KEM_ID_HYBRID_MCPMAC, KEM_ID_XWING_IANA);
    assert_ne!(KEM_ID_HYBRID_MCPMAC, KEM_ID);
    let (cfg, sk) = gateway_keypair(3);
    let enc = encapsulate(&cfg, &request()).unwrap();
    assert_eq!(u16::from_be_bytes([enc[1], enc[2]]), 0xFF41);
    assert!(decapsulate(3, &sk, &enc).is_ok());
}

/// A request labelled X-Wing (as a standards-conformant peer would send) is
/// refused with an explicit reason instead of being decapsulated with a
/// different construction.
#[test]
fn f76_xwing_labelled_request_is_refused_explicitly() {
    let (cfg, sk) = gateway_keypair(3);
    let enc = encapsulate(&cfg, &request()).unwrap();
    let e = decapsulate(3, &sk, &with_kem_id(&enc, KEM_ID_XWING_IANA)).unwrap_err();
    assert!(e.is("OHTTP_KEM_XWING_UNSUPPORTED"), "{e}");
}

/// Non-vacuity: other unknown ids still fail as a generic header error, and
/// the untouched request still opens.
#[test]
fn f76_other_unknown_ids_fail_as_header_errors() {
    let (cfg, sk) = gateway_keypair(3);
    let enc = encapsulate(&cfg, &request()).unwrap();
    for id in [0x0000u16, 0x0041, 0x647B, 0xFF40, 0xFFFF] {
        let e = decapsulate(3, &sk, &with_kem_id(&enc, id)).unwrap_err();
        assert!(e.is("OHTTP_HEADER"), "id {id:#06x}: {e}");
    }
    assert!(decapsulate(3, &sk, &enc).is_ok());
}

/// Doc-drift guard: every mention of X-Wing in the crate's sources must be a
/// disclaimer (a "not"/refusal within the same or an adjacent line).
#[test]
fn f76_sources_do_not_claim_xwing() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.contains("X-Wing") {
                continue;
            }
            let lo = i.saturating_sub(1);
            let hi = (i + 2).min(lines.len());
            let ctx = lines[lo..hi].join(" ").to_lowercase();
            let disclaims = ["not", "never", "refuse", "unsupported"]
                .iter()
                .any(|w| ctx.contains(w));
            assert!(
                disclaims,
                "{}:{} mentions X-Wing without disclaiming it: {line}",
                path.display(),
                i + 1
            );
        }
    }
}
