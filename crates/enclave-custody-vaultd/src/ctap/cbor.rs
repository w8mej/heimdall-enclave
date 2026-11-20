//! Small helpers over `ciborium::Value` for CTAP2's integer-keyed maps.

use ciborium::Value;
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};

/// Encode a value.
pub fn encode(v: &Value) -> EnclaveResult<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).map_err(|e| err!(EINVAL, "CBOR_ENCODE", "{e}"))?;
    Ok(out)
}

/// Decode a value (bounded by the CTAPHID message cap upstream).
pub fn decode(b: &[u8]) -> EnclaveResult<Value> {
    let (value, used) = decode_prefix(b)?;
    if used != b.len() {
        fail!(EINVAL, "CBOR_TRAILING_BYTES");
    }
    Ok(value)
}

/// One bounded CTAP CBOR item, for concatenated authenticator-data fields.
pub fn decode_prefix(b: &[u8]) -> EnclaveResult<(Value, usize)> {
    if b.len() > super::hid::MAX_MESSAGE {
        fail!(E2BIG, "CBOR_SIZE_LIMIT");
    }
    let mut cursor = std::io::Cursor::new(b);
    let value: Value =
        ciborium::from_reader(&mut cursor).map_err(|e| err!(EINVAL, "CBOR_DECODE", "{e}"))?;
    validate(&value, 0)?;
    Ok((value, cursor.position() as usize))
}

fn validate(value: &Value, depth: usize) -> EnclaveResult<()> {
    if depth > 32 {
        fail!(E2BIG, "CBOR_DEPTH_LIMIT");
    }
    match value {
        Value::Map(entries) => {
            for (index, (key, value)) in entries.iter().enumerate() {
                if !matches!(key, Value::Integer(_) | Value::Text(_)) {
                    fail!(EINVAL, "CBOR_MAP_KEY_TYPE");
                }
                if entries[..index].iter().any(|(previous, _)| previous == key) {
                    fail!(EINVAL, "CBOR_DUPLICATE_MAP_KEY");
                }
                validate(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                validate(value, depth + 1)?;
            }
        }
        Value::Tag(_, _) => fail!(EINVAL, "CBOR_TAG_FORBIDDEN"),
        _ => {}
    }
    Ok(())
}

/// Build an integer-keyed map.
pub fn imap(entries: Vec<(i64, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::Integer(k.into()), v))
            .collect(),
    )
}

/// Build a text-keyed map.
pub fn tmap(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::Text(k.to_owned()), v))
            .collect(),
    )
}

/// Look up an integer key.
pub fn iget(m: &Value, k: i64) -> Option<&Value> {
    let Value::Map(es) = m else { return None };
    es.iter()
        .find(|(kk, _)| matches!(kk, Value::Integer(i) if i128::from(*i) == k as i128))
        .map(|(_, v)| v)
}

/// Look up a text key.
pub fn tget<'a>(m: &'a Value, k: &str) -> Option<&'a Value> {
    let Value::Map(es) = m else { return None };
    es.iter()
        .find(|(kk, _)| matches!(kk, Value::Text(t) if t == k))
        .map(|(_, v)| v)
}

/// Bytes field.
pub fn bytes(v: Option<&Value>) -> EnclaveResult<Vec<u8>> {
    match v {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        _ => fail!(EINVAL, "CBOR_EXPECTED_BYTES"),
    }
}

/// Integer field.
pub fn int(v: Option<&Value>) -> EnclaveResult<i64> {
    match v {
        Some(Value::Integer(i)) => {
            i64::try_from(i128::from(*i)).map_err(|_| err!(EINVAL, "CBOR_INT_RANGE"))
        }
        _ => fail!(EINVAL, "CBOR_EXPECTED_INT"),
    }
}

/// Text field.
pub fn text(v: Option<&Value>) -> EnclaveResult<String> {
    match v {
        Some(Value::Text(t)) => Ok(t.clone()),
        _ => fail!(EINVAL, "CBOR_EXPECTED_TEXT"),
    }
}

/// Bool field (default `false`).
pub fn boolean(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bool(true)))
}

/// Encode a P-256 public key as a COSE_Key for key agreement.
pub fn cose_ecdh_key(x: &[u8], y: &[u8]) -> Value {
    imap(vec![
        (1, Value::Integer(2.into())),
        (3, Value::Integer((-25i64).into())),
        (-1, Value::Integer(1.into())),
        (-2, Value::Bytes(x.to_vec())),
        (-3, Value::Bytes(y.to_vec())),
    ])
}

#[cfg(test)]
mod strict_decode_tests {
    use super::*;
    #[test]
    fn duplicate_security_fields_and_trailing_items_are_rejected() {
        let valid = imap(vec![(1, Value::Bytes(vec![1, 2]))]);
        let mut bytes = encode(&valid).unwrap();
        assert_eq!(decode(&bytes).unwrap(), valid);
        bytes.push(0);
        assert!(decode(&bytes).unwrap_err().is("CBOR_TRAILING_BYTES"));
        for duplicate in [
            imap(vec![(1, valid.clone()), (1, Value::Bool(false))]),
            tmap(vec![("uv", Value::Bool(true)), ("uv", Value::Bool(false))]),
        ] {
            assert!(decode(&encode(&duplicate).unwrap())
                .unwrap_err()
                .is("CBOR_DUPLICATE_MAP_KEY"));
        }
        let nested = imap(vec![(
            1,
            tmap(vec![("uv", Value::Bool(true)), ("uv", Value::Bool(false))]),
        )]);
        assert!(decode(&encode(&nested).unwrap())
            .unwrap_err()
            .is("CBOR_DUPLICATE_MAP_KEY"));
    }
}
