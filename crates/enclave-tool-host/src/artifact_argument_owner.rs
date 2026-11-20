//! Private argument-validation allocations, separate from borrowed caller bytes.
//!
//! Guard successful JSON parses immediately, including decoded object keys, and
//! retain canonical output even when JCS refuses after writing a private prefix.
//! Parser-internal failure copies, numeric formatter temporaries, allocator
//! history and caller/framework/kernel copies remain separate owners.

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

struct PrivateArguments {
    json: Value,
    canonical: Zeroizing<Vec<u8>>,
}

fn wipe_value(value: &mut Value) {
    match value {
        Value::String(text) => {
            #[cfg(test)]
            let before = text.len();
            text.zeroize();
            #[cfg(test)]
            observe_wiped("string", text.as_ptr(), before);
        }
        Value::Array(values) => {
            for value in values.iter_mut() {
                wipe_value(value);
            }
            values.clear();
        }
        Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                #[cfg(test)]
                let before = key.len();
                key.zeroize();
                #[cfg(test)]
                observe_wiped("key", key.as_ptr(), before);
                wipe_value(&mut value);
            }
        }
        // Scalars contain no separately allocated string. Assigning Null below
        // removes their logical value; no physical stack-erasure claim follows.
        _ => {}
    }
    *value = Value::Null;
}

impl PrivateArguments {
    fn parse(bytes: &[u8]) -> EnclaveResult<Self> {
        let json = serde_json::from_slice(bytes).map_err(|_| err!(EINVAL, "TOOL_ARGUMENT_JSON"))?;
        Ok(Self { json, canonical: Zeroizing::new(Vec::with_capacity(256)) })
    }

    fn validate(&mut self, original: &[u8]) -> EnclaveResult<()> {
        if !self.json.is_object() {
            fail!(EINVAL, "TOOL_ARGUMENT_CANONICAL");
        }
        enclave_core::jcs::canonicalize_into(&self.json, &mut self.canonical)?;
        if self.canonical.as_slice() != original {
            fail!(EINVAL, "TOOL_ARGUMENT_CANONICAL");
        }
        Ok(())
    }

    fn wipe(&mut self) {
        wipe_value(&mut self.json);
        #[cfg(test)]
        let before = self.canonical.len();
        self.canonical.zeroize();
        #[cfg(test)]
        observe_wiped("canonical", self.canonical.as_ptr(), before);
    }
}

impl Drop for PrivateArguments {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Called before issuing a ticket or running the host. Both validation owners
/// are dropped on success and every post-parse refusal before authority proceeds.
pub(super) fn validate_private_arguments(bytes: &[u8]) -> EnclaveResult<()> {
    PrivateArguments::parse(bytes)?.validate(bytes)
}

// Observe only initialized bytes in an allocation still owned by the caller,
// immediately after the production wipe and before it is freed. No freed-memory
// read, global allocator, production hook or physical-erasure assertion.
#[cfg(test)]
#[derive(Debug)]
struct WipedObservation {
    kind: &'static str,
    initialized_bytes: usize,
    all_zero: bool,
}

#[cfg(test)]
thread_local! {
    static OBSERVATIONS: std::cell::RefCell<Vec<WipedObservation>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

#[cfg(test)]
fn observe_wiped(kind: &'static str, pointer: *const u8, initialized_bytes: usize) {
    // SAFETY: every caller retains the original allocation and passes its former
    // initialized length after Zeroize, before replacing/dropping that allocation.
    let all_zero = unsafe { std::slice::from_raw_parts(pointer, initialized_bytes) }
        .iter().all(|byte| *byte == 0);
    OBSERVATIONS.with(|observations| observations.borrow_mut().push(
        WipedObservation { kind, initialized_bytes, all_zero }
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observations() -> Vec<WipedObservation> {
        OBSERVATIONS.with(|values| std::mem::take(&mut *values.borrow_mut()))
    }

    fn assert_wiped(values: &[WipedObservation], kind: &str, minimum_bytes: usize) {
        assert!(values.iter().all(|value| value.all_zero), "{values:?}");
        assert!(values.iter().any(|value|
            value.kind == kind && value.initialized_bytes >= minimum_bytes), "{values:?}");
    }

    #[test]
    fn artifact_arguments_success_drops_nested_keys_strings_and_canonical_bytes() {
        observations();
        let bytes = br#"{"private-key":{"nested-key":["private-value",true,null,42]}}"#;
        validate_private_arguments(bytes).unwrap();
        let values = observations();
        assert_wiped(&values, "key", "private-key".len());
        assert_wiped(&values, "string", "private-value".len());
        assert_wiped(&values, "canonical", bytes.len());
        assert_eq!(bytes, br#"{"private-key":{"nested-key":["private-value",true,null,42]}}"#);
    }

    #[test]
    fn artifact_arguments_noncanonical_refusal_wipes_actual_validation_owners() {
        observations();
        let bytes = br#"{ "private-key" : "private-value" }"#;
        assert!(validate_private_arguments(bytes).unwrap_err().is("TOOL_ARGUMENT_CANONICAL"));
        let values = observations();
        assert_wiped(&values, "key", "private-key".len());
        assert_wiped(&values, "string", "private-value".len());
        assert_wiped(&values, "canonical", br#"{"private-key":"private-value"}"#.len());
    }

    #[test]
    fn artifact_arguments_nonobject_refusal_wipes_strings_without_canonicalizing() {
        observations();
        assert!(validate_private_arguments(br#"["private-value"]"#)
            .unwrap_err().is("TOOL_ARGUMENT_CANONICAL"));
        let values = observations();
        assert_wiped(&values, "string", "private-value".len());
        assert!(values.iter().filter(|value| value.kind == "canonical")
            .all(|value| value.initialized_bytes == 0));
    }

    #[test]
    fn artifact_arguments_jcs_error_wipes_retained_partial_private_prefix() {
        observations();
        let bytes = br#"{"a":"private-prefix","z":9007199254740993}"#;
        assert!(validate_private_arguments(bytes).unwrap_err().is("JCS_INTEGER_OUT_OF_RANGE"));
        let values = observations();
        assert_wiped(&values, "key", 1);
        assert_wiped(&values, "string", "private-prefix".len());
        assert_wiped(&values, "canonical", br#"{"a":"private-prefix","z":"#.len());
    }

    #[test]
    fn artifact_arguments_explicit_cleanup_is_idempotent_and_drop_runs_again() {
        observations();
        let bytes = br#"{"private-key":"private-value"}"#;
        let mut owner = PrivateArguments::parse(bytes).unwrap();
        owner.validate(bytes).unwrap();
        owner.wipe();
        assert!(owner.json.is_null());
        assert!(owner.canonical.is_empty());
        let first = observations();
        assert_wiped(&first, "key", "private-key".len());
        assert_wiped(&first, "string", "private-value".len());
        assert_wiped(&first, "canonical", bytes.len());
        owner.wipe();
        drop(owner);
        let later = observations();
        assert_eq!(later.len(), 2);
        assert!(later.iter().all(|value| value.kind == "canonical"
            && value.initialized_bytes == 0 && value.all_zero));
    }

    #[test]
    fn artifact_arguments_preserve_json_shape_and_numeric_refusals() {
        observations();
        for bytes in [b"{".as_slice(), b"not-json", b"{\"x\":NaN}"] {
            assert!(validate_private_arguments(bytes).unwrap_err().is("TOOL_ARGUMENT_JSON"));
        }
        for bytes in [b"null".as_slice(), b"true", b"42", b"{} "] {
            assert!(validate_private_arguments(bytes).unwrap_err().is("TOOL_ARGUMENT_CANONICAL"));
        }
        for bytes in [
            br#"{"escaped":"a\nb","float":4.5,"unicode":"x"}"#.as_slice(),
            br#"{"empty":[],"nested":{},"number":9007199254740992}"#,
        ] {
            validate_private_arguments(bytes).unwrap();
        }
        assert!(observations().iter().all(|value| value.all_zero));
    }
}
