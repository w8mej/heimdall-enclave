//! RFC 8785 JSON Canonicalization Scheme (JCS).
//!
//! Used for `d_JCS = SHA-256(JCS(IntentPayloadV1))` (FS-703 §3.2) and for the
//! depot tool-integrity pin `blake3(JCS(tools/list))` (FS-704 §4.2).
//!
//! * Object members are sorted by the UTF-16 code units of their names.
//! * Strings use the minimal JSON escape set; non-ASCII is emitted as UTF-8.
//! * Numbers use the ECMAScript `Number.prototype.toString` algorithm
//!   (RFC 8785 §3.2.2.3). Non-finite numbers fail closed.

use serde::Serialize;
use serde_json::Value;

use crate::error::EnclaveResult;
use crate::{err, fail};

/// Canonicalize any serializable value.
pub fn to_jcs_bytes<T: Serialize>(value: &T) -> EnclaveResult<Vec<u8>> {
    let v = serde_json::to_value(value).map_err(|e| err!(EINVAL, "JCS_SERIALIZE", "{e}"))?;
    let mut out = Vec::with_capacity(256);
    write_value(&v, &mut out)?;
    Ok(out)
}

/// Canonicalize a `serde_json::Value`.
pub fn canonicalize(value: &Value) -> EnclaveResult<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    canonicalize_into(value, &mut out)?;
    Ok(out)
}

/// Append a canonical value to a caller-owned buffer.
///
/// On failure, an already-written prefix remains owned by the caller. Sensitive
/// callers must guard the buffer before this call and erase it on every exit.
/// This does not erase parser/number-formatting temporaries or past allocations.
pub fn canonicalize_into(value: &Value, out: &mut Vec<u8>) -> EnclaveResult<()> {
    write_value(value, out)
}

/// Parse arbitrary JSON text and return its canonical form.
pub fn canonicalize_str(json: &str) -> EnclaveResult<Vec<u8>> {
    let v: Value = serde_json::from_str(json).map_err(|e| err!(EINVAL, "JCS_PARSE", "{e}"))?;
    canonicalize(&v)
}

fn write_value(v: &Value, out: &mut Vec<u8>) -> EnclaveResult<()> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i.unsigned_abs() > (1u64 << 53) {
                    // Outside IEEE-754 exact range: RFC 8785 requires the
                    // double interpretation; I-JSON forbids such integers.
                    fail!(EINVAL, "JCS_INTEGER_OUT_OF_RANGE", "{i}");
                }
                out.extend_from_slice(i.to_string().as_bytes());
            } else if let Some(u) = n.as_u64() {
                if u > (1u64 << 53) {
                    fail!(EINVAL, "JCS_INTEGER_OUT_OF_RANGE", "{u}");
                }
                out.extend_from_slice(u.to_string().as_bytes());
            } else {
                let f = n.as_f64().ok_or_else(|| err!(EINVAL, "JCS_NUMBER"))?;
                out.extend_from_slice(es_number_to_string(f)?.as_bytes());
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(x, out)?;
            }
            out.push(b']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write_value(&m[*k], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes())
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// ECMAScript `Number::toString(10)` for a finite double (ECMA-262 §7.1.12.1).
pub fn es_number_to_string(x: f64) -> EnclaveResult<String> {
    if !x.is_finite() {
        fail!(EINVAL, "JCS_NON_FINITE_NUMBER");
    }
    if x == 0.0 {
        return Ok("0".into());
    }
    let neg = x < 0.0;
    // Rust's `{:e}` emits the shortest round-tripping digit string.
    let e = format!("{:e}", x.abs());
    let (mant, exp) = e
        .split_once('e')
        .ok_or_else(|| err!(EINVAL, "JCS_NUMBER_FMT"))?;
    let exp: i32 = exp.parse().map_err(|_| err!(EINVAL, "JCS_NUMBER_FMT"))?;
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let n = exp + 1;
    let mut s = String::new();
    if neg {
        s.push('-');
    }
    if k <= n && n <= 21 {
        s.push_str(&digits);
        s.extend(std::iter::repeat_n('0', (n - k) as usize));
    } else if 0 < n && n <= 21 {
        s.push_str(&digits[..n as usize]);
        s.push('.');
        s.push_str(&digits[n as usize..]);
    } else if -6 < n && n <= 0 {
        s.push_str("0.");
        s.extend(std::iter::repeat_n('0', (-n) as usize));
        s.push_str(&digits);
    } else {
        s.push_str(&digits[..1]);
        if k > 1 {
            s.push('.');
            s.push_str(&digits[1..]);
        }
        s.push('e');
        s.push(if n > 0 { '+' } else { '-' });
        s.push_str(&(n - 1).abs().to_string());
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_owned_canonicalization_appends_identical_bytes() {
        let value = serde_json::json!({"z": [true, null, "private\ntext"], "a": 4.5});
        let expected = canonicalize(&value).unwrap();
        let mut out = b"retained:".to_vec();
        canonicalize_into(&value, &mut out).unwrap();
        assert_eq!(&out[..9], b"retained:");
        assert_eq!(&out[9..], expected);
    }

    #[test]
    fn caller_retains_partial_prefix_on_existing_number_refusal() {
        let value = serde_json::json!(["private-prefix", 9_007_199_254_740_993u64]);
        let mut out = Vec::new();
        let error = canonicalize_into(&value, &mut out).unwrap_err();
        assert!(error.is("JCS_INTEGER_OUT_OF_RANGE"));
        assert_eq!(out, br#"["private-prefix","#);
        assert!(canonicalize(&value).unwrap_err().is("JCS_INTEGER_OUT_OF_RANGE"));
    }

    #[test]
    fn sorts_keys_and_strips_whitespace() {
        let a = canonicalize_str(r#"{ "b": 1, "a": [true, null, "x"] }"#).unwrap();
        let b = canonicalize_str(r#"{"a":[true,null,"x"],"b":1}"#).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, br#"{"a":[true,null,"x"],"b":1}"#);
    }

    #[test]
    fn rfc8785_utf16_sort_order() {
        // RFC 8785 §3.2.3 example: sorting by UTF-16 code units.
        let j = r#"{"€":"Euro Sign","\r":"Carriage Return","דּ":"Hebrew Letter Dalet With Dagesh","1":"One","😀":"Emoji: Grinning Face","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis"}"#;
        let c = String::from_utf8(canonicalize_str(j).unwrap()).unwrap();
        let order: Vec<&str> = [
            "Carriage Return",
            "One",
            "Control",
            "Latin Small",
            "Euro Sign",
            "Emoji",
            "Hebrew",
        ]
        .to_vec();
        let mut last = 0;
        for o in order {
            let p = c.find(o).unwrap();
            assert!(p >= last, "{o} out of order in {c}");
            last = p;
        }
    }

    #[test]
    fn rfc8785_number_vectors() {
        // RFC 8785 Appendix B (subset) and ECMA-262 behaviour.
        let cases: &[(f64, &str)] = &[
            (0.0, "0"),
            (-0.0, "0"),
            (1e21, "1e+21"),
            (1e20, "100000000000000000000"),
            (123456789.0, "123456789"),
            (0.000001, "0.000001"),
            (0.0000001, "1e-7"),
            (4.5, "4.5"),
            (-1.5e-10, "-1.5e-10"),
            (333333333.3333332, "333333333.3333332"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (9007199254740992.0, "9007199254740992"),
        ];
        for (x, want) in cases {
            assert_eq!(es_number_to_string(*x).unwrap(), *want, "{x}");
        }
        assert!(es_number_to_string(f64::NAN).is_err());
    }

    #[test]
    fn escapes_controls() {
        let c = canonicalize(&serde_json::json!({"k":"a\u{0001}\"\n"})).unwrap();
        assert_eq!(c, br#"{"k":"a\u0001\"\n"}"#);
    }
}
