//! Minimal, bounds-checked `.safetensors` reader over a read-only mapping
//! (UID 702 has already sanitized the file; UID 701 re-checks every offset it
//! dereferences) plus a writer used by `enclave-pack` tooling and tests.

use std::collections::BTreeMap;

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde_json::{json, Map, Value};

/// Header cap (matches the UID 702 sanitizer).
pub const MAX_HEADER: usize = 16 * 1024 * 1024;

/// One tensor's metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TensorInfo {
    /// dtype string (`F32`, `F16`, `BF16`, `I8`, `U8`, ...).
    pub dtype: String,
    /// Shape.
    pub shape: Vec<usize>,
    /// Absolute byte range in the file.
    pub range: (usize, usize),
}

/// Parsed index.
#[derive(Debug, Clone, Default)]
pub struct TensorIndex {
    /// Tensors by name.
    pub tensors: BTreeMap<String, TensorInfo>,
    /// `__metadata__` string map.
    pub metadata: BTreeMap<String, String>,
}

fn dtype_size(d: &str) -> EnclaveResult<usize> {
    Ok(match d {
        "F64" | "I64" | "U64" => 8,
        "F32" | "I32" | "U32" => 4,
        "F16" | "BF16" | "I16" | "U16" => 2,
        "I8" | "U8" | "BOOL" | "F8_E4M3" | "F8_E5M2" => 1,
        _ => fail!(EINVAL, "SAFETENSORS_DTYPE", "{d}"),
    })
}

/// Parse the header of `file`.
pub fn parse(file: &[u8]) -> EnclaveResult<TensorIndex> {
    let n = u64::from_le_bytes(
        file.get(..8)
            .ok_or_else(|| err!(EINVAL, "SAFETENSORS_TRUNCATED"))?
            .try_into()
            .map_err(|_| err!(EINVAL, "SAFETENSORS_TRUNCATED"))?,
    ) as usize;
    if n > MAX_HEADER || 8 + n > file.len() {
        fail!(EINVAL, "SAFETENSORS_HEADER_LEN");
    }
    let base = 8 + n;
    let v: Map<String, Value> = serde_json::from_slice(&file[8..base])
        .map_err(|e| err!(EINVAL, "SAFETENSORS_HEADER_JSON", "{e}"))?;
    let mut idx = TensorIndex::default();
    for (k, t) in v {
        if k == "__metadata__" {
            // Moved, not copied: a metadata value can be a multi-MB tokenizer.
            let Value::Object(entries) = t else { fail!(EINVAL, "SAFETENSORS_METADATA") };
            for (mk, mv) in entries {
                let Value::String(text) = mv else { fail!(EINVAL, "SAFETENSORS_METADATA") };
                idx.metadata.insert(mk, text);
            }
            continue;
        }
        let dtype = t["dtype"]
            .as_str()
            .ok_or_else(|| err!(EINVAL, "SAFETENSORS_TENSOR", "{k}"))?
            .to_owned();
        let shape: Vec<usize> = t["shape"]
            .as_array()
            .ok_or_else(|| err!(EINVAL, "SAFETENSORS_TENSOR", "{k}"))?
            .iter()
            .map(|x| x.as_u64().map(|v| v as usize))
            .collect::<Option<_>>()
            .ok_or_else(|| err!(EINVAL, "SAFETENSORS_TENSOR", "{k}"))?;
        let off = t["data_offsets"]
            .as_array()
            .ok_or_else(|| err!(EINVAL, "SAFETENSORS_TENSOR", "{k}"))?;
        let (a, b) = match (
            off.first().and_then(Value::as_u64),
            off.get(1).and_then(Value::as_u64),
        ) {
            (Some(a), Some(b)) if a <= b => (a as usize, b as usize),
            _ => fail!(EINVAL, "SAFETENSORS_OFFSETS", "{k}"),
        };
        let elems = shape
            .iter()
            .try_fold(1usize, |acc, d| acc.checked_mul(*d))
            .ok_or_else(|| err!(EINVAL, "SAFETENSORS_SHAPE"))?;
        if elems.checked_mul(dtype_size(&dtype)?) != Some(b - a) || base + b > file.len() {
            fail!(EINVAL, "SAFETENSORS_OFFSETS", "{k}");
        }
        idx.tensors.insert(
            k,
            TensorInfo {
                dtype,
                shape,
                range: (base + a, base + b),
            },
        );
    }
    Ok(idx)
}

impl TensorIndex {
    /// Load a tensor as `f32` (`F32` / `F16` / `BF16`), checking the expected shape.
    pub fn f32(&self, file: &[u8], name: &str, shape: &[usize]) -> EnclaveResult<Vec<f32>> {
        let t = self
            .tensors
            .get(name)
            .ok_or_else(|| err!(EINVAL, "TENSOR_MISSING", "{name}"))?;
        if t.shape != shape {
            fail!(EINVAL, "TENSOR_SHAPE", "{name}: {:?} != {shape:?}", t.shape);
        }
        let b = file
            .get(t.range.0..t.range.1)
            .ok_or_else(|| err!(EINVAL, "SAFETENSORS_OFFSETS"))?;
        let element_bytes = match t.dtype.as_str() {
            "F32" => 4,
            "F16" | "BF16" => 2,
            d => fail!(EINVAL, "TENSOR_DTYPE", "{name}: {d}"),
        };
        // Guard the one fixed allocation before the first decoded value is
        // written. Refused tensors scrub their live initialized storage;
        // successful decoding explicitly transfers the same Vec to its caller.
        let mut v = crate::arena::FloatScratch::new(
            vec![0.0f32; b.len() / element_bytes], "safetensors-decoded");
        match t.dtype.as_str() {
            "F32" => for (value, chunk) in v.iter_mut().zip(b.as_chunks::<4>().0) {
                *value = f32::from_le_bytes(*chunk);
            },
            "F16" => for (value, chunk) in v.iter_mut().zip(b.as_chunks::<2>().0) {
                *value = half::f16::from_le_bytes(*chunk).to_f32();
            },
            "BF16" => for (value, chunk) in v.iter_mut().zip(b.as_chunks::<2>().0) {
                *value = half::bf16::from_le_bytes(*chunk).to_f32();
            },
            _ => unreachable!("dtype checked before allocation"),
        }
        if v.iter().any(|x| !x.is_finite()) {
            fail!(EINVAL, "TENSOR_NON_FINITE", "{name}");
        }
        Ok(v.into_vec())
    }

    /// Shape of a tensor.
    pub fn shape(&self, name: &str) -> Option<&[usize]> {
        self.tensors.get(name).map(|t| t.shape.as_slice())
    }

    /// Topology fingerprint: BLAKE3 over the JCS of `[(name, dtype, shape)]`.
    pub fn fingerprint(&self) -> EnclaveResult<String> {
        let v: Vec<Value> = self
            .tensors
            .iter()
            .map(|(k, t)| json!([k, t.dtype, t.shape]))
            .collect();
        Ok(
            blake3::hash(&enclave_core::jcs::to_jcs_bytes(&Value::Array(v))?)
                .to_hex()
                .to_string(),
        )
    }
}

/// Write a `.safetensors` file from `(name, shape, f32 data)` (stored as `F32`).
pub fn build_f32(tensors: &[(&str, Vec<usize>, Vec<f32>)], metadata: &[(&str, &str)]) -> Vec<u8> {
    let mut hdr = Map::new();
    if !metadata.is_empty() {
        hdr.insert(
            "__metadata__".into(),
            Value::Object(
                metadata
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), json!(v)))
                    .collect(),
            ),
        );
    }
    let mut data = Vec::new();
    for (name, shape, vals) in tensors {
        let a = data.len();
        for x in vals {
            data.extend_from_slice(&x.to_le_bytes());
        }
        hdr.insert(
            (*name).to_owned(),
            json!({"dtype": "F32", "shape": shape, "data_offsets": [a, data.len()]}),
        );
    }
    let mut h = serde_json::to_vec(&Value::Object(hdr)).unwrap_or_default();
    while !h.len().is_multiple_of(8) {
        h.push(b' ');
    }
    let mut out = (h.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(&h);
    out.extend_from_slice(&data);
    out
}

#[cfg(test)]
mod decoded_owner_tests {
    use super::*;
    use crate::arena::float_scratch_tests::{begin, finish, Event};

    fn tensor(dtype: &str, values: &[f32]) -> (TensorIndex, Vec<u8>) {
        let bytes: Vec<u8> = values.iter().flat_map(|value| match dtype {
            "F32" => value.to_le_bytes().to_vec(),
            "F16" => half::f16::from_f32(*value).to_le_bytes().to_vec(),
            "BF16" => half::bf16::from_f32(*value).to_le_bytes().to_vec(),
            _ => unreachable!(),
        }).collect();
        let header = serde_json::to_vec(&json!({"weight": {
            "dtype": dtype, "shape": [values.len()], "data_offsets": [0, bytes.len()]
        }})).unwrap();
        let mut file = (header.len() as u64).to_le_bytes().to_vec();
        file.extend(header); file.extend(bytes);
        (parse(&file).unwrap(), file)
    }

    #[test]
    fn actual_decoder_transfers_finite_f32_f16_bf16_bits_without_changing_input() {
        // Every value is exactly representable in all three admitted formats.
        let expected = [0.0f32, -0.0, 0.25, -73.5, 128.0, 2.0f32.powi(-14), 2.0f32.powi(-24)];
        for dtype in ["F32", "F16", "BF16"] {
            let (index, file) = tensor(dtype, &expected); let original = file.clone();
            begin();
            let decoded = index.f32(&file, "weight", &[expected.len()]).unwrap();
            assert_eq!(decoded.len(), expected.len());
            assert!(decoded.iter().zip(expected).all(|(a, b)| a.to_bits() == b.to_bits()));
            assert_eq!(finish(), vec![Event::Transferred("safetensors-decoded", expected.len())]);
            assert_eq!(file, original);
        }
    }

    #[test]
    fn actual_decoder_scrubs_complete_live_allocation_on_late_nonfinite_refusal() {
        for dtype in ["F32", "F16", "BF16"] {
            for invalid in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
                let (index, file) = tensor(dtype, &[73.5, -0.25, invalid]);
                let original = file.clone(); begin();
                assert!(index.f32(&file, "weight", &[3]).unwrap_err().is("TENSOR_NON_FINITE"));
                assert_eq!(finish(), vec![Event::Scrubbed("safetensors-decoded", 3, true)]);
                assert_eq!(file, original);
            }
        }
    }

    #[test]
    fn actual_decoder_preserves_metadata_refusals_before_private_allocation() {
        let (mut index, file) = tensor("F32", &[73.5, 0.25]);
        begin();
        assert!(index.f32(&file, "missing", &[2]).unwrap_err().is("TENSOR_MISSING"));
        assert!(index.f32(&file, "weight", &[3]).unwrap_err().is("TENSOR_SHAPE"));
        assert!(index.f32(&file[..file.len()-1], "weight", &[2]).unwrap_err().is("SAFETENSORS_OFFSETS"));
        index.tensors.get_mut("weight").unwrap().dtype = "I32".into();
        assert!(index.f32(&file, "weight", &[2]).unwrap_err().is("TENSOR_DTYPE"));
        assert!(finish().is_empty());
    }
}
