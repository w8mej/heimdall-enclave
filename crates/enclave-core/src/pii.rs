//! Deterministic PII detectors used at `_piivault` ingress (ADR-007):
//! payment PANs (Luhn), credentials / private keys, US SSNs, and `C3`
//! identifiers (email, phone). Detection is conservative: anything that
//! *might* be a PAN or credential is erased.

use regex_lite::Regex;
use std::sync::OnceLock;

/// Detected kind.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum PiiKind {
    /// Payment card number — always erased.
    Pan,
    /// Credential / private key / API token — always erased.
    Credential,
    /// US SSN (`C4`).
    Ssn,
    /// Protected health information (`C4`, declared by the caller's schema).
    Phi,
    /// Email (`C3`).
    Email,
    /// Phone (`C3`).
    Phone,
    /// Personal name (`C3`, declared by schema).
    Name,
}

impl PiiKind {
    /// `C4` kinds.
    pub fn is_c4(self) -> bool {
        matches!(
            self,
            PiiKind::Pan | PiiKind::Credential | PiiKind::Ssn | PiiKind::Phi
        )
    }
    /// Irreversible-erasure token.
    pub fn erasure_token(self) -> &'static str {
        match self {
            PiiKind::Pan => "[REDACTED_PAN_C4]",
            PiiKind::Credential => "[REDACTED_CREDENTIAL_C4]",
            PiiKind::Ssn => "[REDACTED_SSN_C4]",
            PiiKind::Phi => "[REDACTED_CLINICAL_C4]",
            PiiKind::Email => "[REDACTED_EMAIL_C3]",
            PiiKind::Phone => "[REDACTED_PHONE_C3]",
            PiiKind::Name => "[REDACTED_NAME_C3]",
        }
    }
}

/// Luhn checksum over ASCII digits.
pub fn luhn_ok(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    for (i, d) in digits.iter().rev().enumerate() {
        let mut v = (d - b'0') as u32;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum.is_multiple_of(10)
}

/// SSA validity rules: area ∉ {000, 666, 900–999}, group ≠ 00, serial ≠ 0000.
pub fn ssn_valid(d: &[u8]) -> bool {
    if d.len() != 9 {
        return false;
    }
    let area = &d[..3];
    area != b"000" && area != b"666" && area[0] != b'9' && &d[3..5] != b"00" && &d[5..] != b"0000"
}

// Borrow regex matches rather than collecting their sensitive digits in a
// second allocation. Keep the existing ASCII filter even when a regex's \d
// matches a non-ASCII digit; this preserves the scanner's validation semantics.
fn pan_match_valid(text: &str) -> bool {
    let digits = text.bytes().filter(u8::is_ascii_digit);
    let count = digits.clone().count();
    if !(13..=19).contains(&count) {
        return false;
    }
    let mut sum = 0u32;
    for (i, d) in digits.rev().enumerate() {
        let mut v = (d - b'0') as u32;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum.is_multiple_of(10)
}

fn ssn_match_valid(text: &str) -> bool {
    let mut count = 0;
    let mut area_zero = true;
    let mut area_sixes = true;
    let mut area_starts_nine = false;
    let mut group_zero = true;
    let mut serial_zero = true;
    for d in text.bytes().filter(u8::is_ascii_digit) {
        count += 1;
        if count == 1 {
            area_starts_nine = d == b'9';
        }
        match count {
            1..=3 => {
                area_zero &= d == b'0';
                area_sixes &= d == b'6';
            }
            4..=5 => group_zero &= d == b'0',
            6..=9 => serial_zero &= d == b'0',
            _ => return false,
        }
    }
    count == 9
        && !area_zero
        && !area_sixes
        && !area_starts_nine
        && !group_zero
        && !serial_zero
}

struct Res {
    cred: Vec<Regex>,
    pan: Regex,
    ssn: Regex,
    email: Regex,
    phone: Regex,
}

fn res() -> &'static Res {
    static R: OnceLock<Res> = OnceLock::new();
    R.get_or_init(|| Res {
        cred: [
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)",
            r"\bAKIA[0-9A-Z]{16}\b",
            r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
            r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
            r"\bsk-[A-Za-z0-9_-]{20,}",
            r"\bAIza[0-9A-Za-z_-]{35}\b",
            r"(?i)\b(password|passwd|secret|api[_-]?key)\s*[:=]\s*\S{6,}",
        ]
        .iter()
        .map(|p| Regex::new(p).expect("static regex"))
        .collect(),
        pan: Regex::new(r"\b(?:\d[ -]?){12,18}\d\b").expect("static regex"),
        ssn: Regex::new(r"\b(\d{3})[- ]?(\d{2})[- ]?(\d{4})\b").expect("static regex"),
        email: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
            .expect("static regex"),
        phone: Regex::new(r"(?:\+?1[ .-]?)?\(?\b\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}\b")
            .expect("static regex"),
    })
}

/// A detected span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    /// Start byte.
    pub start: usize,
    /// End byte.
    pub end: usize,
    /// Kind.
    pub kind: PiiKind,
}

/// Find PII spans in free text (credentials, PANs, SSNs, emails, phones),
/// non-overlapping, with the most severe kind winning.
pub fn scan(text: &str) -> Vec<Span> {
    let r = res();
    let mut spans: Vec<Span> = Vec::new();
    let push = |s: usize, e: usize, k: PiiKind, spans: &mut Vec<Span>| {
        if !spans.iter().any(|x| s < x.end && x.start < e) {
            spans.push(Span {
                start: s,
                end: e,
                kind: k,
            });
        }
    };
    for re in &r.cred {
        for m in re.find_iter(text) {
            push(m.start(), m.end(), PiiKind::Credential, &mut spans);
        }
    }
    for m in r.pan.find_iter(text) {
        if pan_match_valid(m.as_str()) {
            push(m.start(), m.end(), PiiKind::Pan, &mut spans);
        }
    }
    for c in r.ssn.captures_iter(text) {
        let m = c.get(0).expect("group 0");
        if ssn_match_valid(m.as_str()) {
            push(m.start(), m.end(), PiiKind::Ssn, &mut spans);
        }
    }
    for m in r.email.find_iter(text) {
        push(m.start(), m.end(), PiiKind::Email, &mut spans);
    }
    for m in r.phone.find_iter(text) {
        push(m.start(), m.end(), PiiKind::Phone, &mut spans);
    }
    spans.sort_by_key(|s| s.start);
    spans
}

/// Classify a whole field value, honouring a schema-declared kind.
pub fn classify(value: &str, declared: Option<PiiKind>) -> Option<PiiKind> {
    let detected = scan(value).into_iter().map(|s| s.kind).min();
    match (declared, detected) {
        // PANs and credentials always win, whatever the schema says.
        (_, Some(k @ (PiiKind::Pan | PiiKind::Credential))) => Some(k),
        (Some(d), _) => Some(d),
        (None, d) => d,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_core_kinds() {
        assert_eq!(classify("4111 1111 1111 1111", None), Some(PiiKind::Pan));
        assert_eq!(classify("4111111111111112", None), None); // fails Luhn
        assert_eq!(classify("078-05-1120", None), Some(PiiKind::Ssn));
        assert_eq!(classify("078051120", None), Some(PiiKind::Ssn));
        assert_eq!(classify("666-05-1120", None), None);
        assert_eq!(
            classify("AKIAIOSFODNN7EXAMPLE", None),
            Some(PiiKind::Credential)
        );
        assert_eq!(
            classify(
                "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
                None
            ),
            Some(PiiKind::Credential)
        );
        assert_eq!(classify("jane@example.com", None), Some(PiiKind::Email));
        assert_eq!(classify("+1 415-555-0100", None), Some(PiiKind::Phone));
        // A PAN hidden in a field declared as a name is still a PAN.
        assert_eq!(
            classify("4111-1111-1111-1111", Some(PiiKind::Name)),
            Some(PiiKind::Pan)
        );
    }

    #[test]
    fn scan_free_text() {
        let s = scan("ssn 078-05-1120 card 4111 1111 1111 1111 mail a@b.io");
        let kinds: Vec<PiiKind> = s.iter().map(|x| x.kind).collect();
        assert_eq!(kinds, vec![PiiKind::Ssn, PiiKind::Pan, PiiKind::Email]);
    }
}

#[cfg(test)]
mod scanner_owner_tests {
    use super::*;

    fn copied_digits(text: &str) -> Vec<u8> {
        // Synthetic test-only oracle for the scanner's previous owned scratch.
        text.bytes().filter(u8::is_ascii_digit).collect()
    }

    #[test]
    fn borrowed_pan_validation_matches_public_slice_helper_corpus() {
        let mut accepted_lengths = [false; 7];
        for len in 0..=24 {
            for seed in 0..64usize {
                let mut state = seed + 1;
                let mut text = String::new();
                for index in 0..len {
                    state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                    text.push(char::from(b'0' + ((state >> 16) % 10) as u8));
                    match (index + seed) % 4 {
                        0 => text.push(' '),
                        1 => text.push('-'),
                        2 => text.push('٣'),
                        _ => {}
                    }
                }
                let digits = copied_digits(&text);
                let expected = (13..=19).contains(&digits.len()) && luhn_ok(&digits);
                assert_eq!(pan_match_valid(&text), expected, "len={len}, seed={seed}");
                if expected {
                    accepted_lengths[len - 13] = true;
                }
            }
        }
        assert!(accepted_lengths.into_iter().all(|accepted| accepted));
        for text in [
            "4111111111111111",
            "4111 1111 1111 1111",
            "4111-1111-1111-1112",
        ] {
            let digits = copied_digits(text);
            assert_eq!(pan_match_valid(text), luhn_ok(&digits));
        }
    }

    #[test]
    fn borrowed_ssn_validation_matches_public_slice_helper_all_areas_and_boundaries() {
        for area in 0..1000 {
            for group in [0, 1, 5, 99] {
                for serial in [0, 1, 1120, 9999] {
                    let text = format!("{area:03}-٣{group:02} {serial:04}");
                    assert_eq!(
                        ssn_match_valid(&text),
                        ssn_valid(&copied_digits(&text)),
                        "area={area}, group={group}, serial={serial}"
                    );
                }
            }
        }
        for text in [
            "",
            "٣٤٥",
            "078-05-112",
            "078-05-11200",
            "٠78-05-1120",
            "078-05-112٠",
            "078 05 1120",
            "078051120",
            "9٣00-05-1120",
            "666-05-1120",
        ] {
            assert_eq!(ssn_match_valid(text), ssn_valid(&copied_digits(text)));
        }
    }

    fn previous_scan(text: &str) -> Vec<Span> {
        let r = res();
        let mut spans: Vec<Span> = Vec::new();
        let mut push = |start, end, kind| {
            if !spans.iter().any(|x| start < x.end && x.start < end) {
                spans.push(Span { start, end, kind });
            }
        };
        for re in &r.cred {
            for m in re.find_iter(text) {
                push(m.start(), m.end(), PiiKind::Credential);
            }
        }
        for m in r.pan.find_iter(text) {
            let digits = copied_digits(m.as_str());
            if (13..=19).contains(&digits.len()) && luhn_ok(&digits) {
                push(m.start(), m.end(), PiiKind::Pan);
            }
        }
        for c in r.ssn.captures_iter(text) {
            let m = c.get(0).expect("group 0");
            if ssn_valid(&copied_digits(m.as_str())) {
                push(m.start(), m.end(), PiiKind::Ssn);
            }
        }
        for m in r.email.find_iter(text) {
            push(m.start(), m.end(), PiiKind::Email);
        }
        for m in r.phone.find_iter(text) {
            push(m.start(), m.end(), PiiKind::Phone);
        }
        spans.sort_by_key(|s| s.start);
        spans
    }

    #[test]
    fn actual_scan_matches_previous_scan_unicode_boundaries_and_precedence() {
        let cases = [
            "",
            "plain text",
            "4111111111111111",
            "4111111111111112",
            "4222222222222",
            "378282246310005",
            "6011-1111-1111-1117",
            "4111111111111111111",
            "41111111111111111111",
            "x4111111111111111x",
            "4111 1111 1111 1111",
            "078-05-1120",
            "000-05-1120",
            "666-05-1120",
            "900-05-1120",
            "078-00-1120",
            "078-05-0000",
            "078051120",
            "078 05 1120",
            "٠78-05-1120",
            "078-05-112٠",
            "٤111111111111111",
            "411111111111111١",
            "password=4111111111111111",
            "secret=078-05-1120",
            "a@b.io +1 415-555-0100",
            "é ssn 078-05-1120 card 4111-1111-1111-1111 mail a@b.io",
            "-----BEGIN PRIVATE KEY-----4111111111111111-----END PRIVATE KEY-----",
        ];
        for text in cases {
            assert_eq!(scan(text), previous_scan(text), "synthetic case: {text:?}");
        }
        let joined = cases.join(" | ");
        assert_eq!(scan(&joined), previous_scan(&joined));
    }

    #[test]
    fn actual_scan_keeps_exact_byte_spans_and_credential_precedence() {
        let text = "é card 4111 1111 1111 1111 SSN 078-05-1120 mail a@b.io";
        let expected: Vec<Span> = [
            ("4111 1111 1111 1111", PiiKind::Pan),
            ("078-05-1120", PiiKind::Ssn),
            ("a@b.io", PiiKind::Email),
        ]
        .into_iter()
        .map(|(matched, kind)| {
            let start = text.find(matched).unwrap();
            Span {
                start,
                end: start + matched.len(),
                kind,
            }
        })
        .collect();
        assert_eq!(scan(text), expected);
        let text = "password=4111111111111111";
        assert_eq!(
            scan(text),
            vec![Span {
                start: 0,
                end: text.len(),
                kind: PiiKind::Credential,
            }]
        );
    }
}
