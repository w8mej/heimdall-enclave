//! OLPC Canonical JSON serialization per securesystemslib specification.
//!
//! Standard: <http://wiki.laptop.org/go/Canonical_JSON>
//! Securesystemslib implementation: `securesystemslib.formats.encode_canonical`
//!
//! Rules:
//! - No whitespace between tokens.
//! - Dictionary keys are sorted lexically by UTF-8 bytes.
//! - Strings only have `\` and `"` escaped (`\\` and `\"`). Other characters
//!   (e.g., newlines, tabs, UTF-8 sequences) are not escaped.
//! - Numbers: integers only (decimal). Floating point numbers are rejected with
//!   `CANONICAL_JSON_FLOAT`.
//! - Booleans: `true` and `false`.
//! - Null: `null`.

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::Serialize;
use serde_json::Value;

/// Serialize a value to OLPC Canonical JSON bytes.
pub fn to_canonical_json_bytes<T: Serialize>(val: &T) -> EnclaveResult<Vec<u8>> {
    let value: Value =
        serde_json::to_value(val).map_err(|e| err!(EINVAL, "CANONICAL_JSON_SERIALIZE", "{e}"))?;
    to_canonical_json_value(&value)
}

/// Serialize a `serde_json::Value` to OLPC Canonical JSON bytes.
pub fn to_canonical_json_value(val: &Value) -> EnclaveResult<Vec<u8>> {
    let mut out = Vec::new();
    encode_value(val, &mut out)?;
    Ok(out)
}

fn encode_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for &b in s.as_bytes() {
        match b {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'"' => out.extend_from_slice(b"\\\""),
            _ => out.push(b),
        }
    }
    out.push(b'"');
}

fn encode_value(val: &Value, out: &mut Vec<u8>) -> EnclaveResult<()> {
    match val {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => {
            if *b {
                out.extend_from_slice(b"true");
            } else {
                out.extend_from_slice(b"false");
            }
        }
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                out.extend_from_slice(n.to_string().as_bytes());
            } else {
                fail!(
                    EINVAL,
                    "CANONICAL_JSON_FLOAT",
                    "floats are not permitted in canonical JSON: {n}"
                );
            }
        }
        Value::String(s) => encode_string(s, out),
        Value::Array(arr) => {
            out.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            out.push(b'{');
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            for (i, (k, v)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode_string(k, out);
                out.push(b':');
                encode_value(v, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonical_json_primitives() {
        assert_eq!(
            to_canonical_json_value(&json!("")).unwrap(),
            b"\"\"".as_slice()
        );
        assert_eq!(
            to_canonical_json_value(&json!([1, 2, 3])).unwrap(),
            b"[1,2,3]".as_slice()
        );
        assert_eq!(
            to_canonical_json_value(&json!([])).unwrap(),
            b"[]".as_slice()
        );
        assert_eq!(
            to_canonical_json_value(&json!({"A": [99]})).unwrap(),
            b"{\"A\":[99]}".as_slice()
        );
        assert_eq!(
            to_canonical_json_value(&json!({"x": 3, "y": 2})).unwrap(),
            b"{\"x\":3,\"y\":2}".as_slice()
        );
    }

    #[test]
    fn test_canonical_json_key_sorting() {
        assert_eq!(
            to_canonical_json_value(&json!({"b": 1, "a": 2, "c": 3})).unwrap(),
            b"{\"a\":2,\"b\":1,\"c\":3}".as_slice()
        );
    }

    #[test]
    fn test_canonical_json_string_escaping() {
        // Only \ and " are escaped. Newlines and emoji are raw UTF-8.
        let val = json!({"path": "foo\\bar\"baz\nqux", "emoji": "🎉"});
        let bytes = to_canonical_json_value(&val).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(s, "{\"emoji\":\"🎉\",\"path\":\"foo\\\\bar\\\"baz\nqux\"}");
    }

    #[test]
    fn test_canonical_json_float_rejection() {
        let err = to_canonical_json_value(&json!({"val": 123.45})).unwrap_err();
        assert!(err.is("CANONICAL_JSON_FLOAT"));
    }
}
