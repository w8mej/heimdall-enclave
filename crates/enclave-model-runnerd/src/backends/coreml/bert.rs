//! Debug-only trained BERT encoder component with a closed, pinned program.
//!
//! This fixed-shape component is deliberately absent from `Engine`, signed
//! execution-class admission and service egress. It is not a calibrated typed
//! classifier, tokenizer, resource/erasure acceptance or production backend.
//! The canonical exporter uses checkpoint data only; no Python or publisher
//! executable code runs at inference. Release calls refuse before native I/O.

use std::collections::BTreeMap;

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::safetensors::{self, TensorIndex};

/// Immutable selected upstream safetensors identity.
pub const CHECKPOINT_SHA256: &str =
    "7fb69ad9f6866d8983183c930e33828f326470bf6ad8bbb2ad4ed957a92e9414";
/// Exact selected checkpoint length, including its 5,264-byte header.
pub const CHECKPOINT_BYTES: usize = 17_739_144;
/// Exact canonical CoreML source identity, independently exported previously.
pub const MODEL_SHA256: &str = "908beb3a7a1548380bf6d61584ff9e24f259135107d946b9ada41fa454538d91";
/// Exact canonical model length.
pub const MODEL_BYTES: usize = 17_222_603;
/// Fixed number of token IDs; no implicit padding or truncation.
pub const SEQUENCE: usize = 8;
/// Encoder hidden width.
pub const WIDTH: usize = 128;
/// Exclusive token-ID bound of the pinned vocabulary.
pub const VOCABULARY: u32 = 30_522;
/// Exact number of returned finite hidden values, in token-major order.
pub const OUTPUT_VALUES: usize = SEQUENCE * WIDTH;

fn development_only() -> EnclaveResult<()> {
    if !cfg!(debug_assertions) {
        fail!(EPERM, "COREML_BERT_DEVELOPMENT_ONLY");
    }
    Ok(())
}

fn expected_shapes() -> BTreeMap<String, Vec<usize>> {
    let mut shapes = BTreeMap::from([
        (
            "bert.embeddings.word_embeddings.weight".into(),
            vec![30_522, 128],
        ),
        (
            "bert.embeddings.position_embeddings.weight".into(),
            vec![512, 128],
        ),
        (
            "bert.embeddings.token_type_embeddings.weight".into(),
            vec![2, 128],
        ),
        ("bert.embeddings.LayerNorm.weight".into(), vec![128]),
        ("bert.embeddings.LayerNorm.bias".into(), vec![128]),
        ("bert.pooler.dense.weight".into(), vec![128, 128]),
        ("bert.pooler.dense.bias".into(), vec![128]),
        ("cls.predictions.bias".into(), vec![30_522]),
        (
            "cls.predictions.transform.dense.weight".into(),
            vec![128, 128],
        ),
        ("cls.predictions.transform.dense.bias".into(), vec![128]),
        (
            "cls.predictions.transform.LayerNorm.weight".into(),
            vec![128],
        ),
        ("cls.predictions.transform.LayerNorm.bias".into(), vec![128]),
        ("cls.seq_relationship.weight".into(), vec![2, 128]),
        ("cls.seq_relationship.bias".into(), vec![2]),
    ]);
    for block in 0..2 {
        for (suffix, shape) in [
            ("attention.self.query.weight", vec![128, 128]),
            ("attention.self.key.weight", vec![128, 128]),
            ("attention.self.value.weight", vec![128, 128]),
            ("attention.output.dense.weight", vec![128, 128]),
            ("intermediate.dense.weight", vec![512, 128]),
            ("output.dense.weight", vec![128, 512]),
            ("attention.self.query.bias", vec![128]),
            ("attention.self.key.bias", vec![128]),
            ("attention.self.value.bias", vec![128]),
            ("attention.output.dense.bias", vec![128]),
            ("intermediate.dense.bias", vec![512]),
            ("output.dense.bias", vec![128]),
            ("attention.output.LayerNorm.weight", vec![128]),
            ("attention.output.LayerNorm.bias", vec![128]),
            ("output.LayerNorm.weight", vec![128]),
            ("output.LayerNorm.bias", vec![128]),
        ] {
            shapes.insert(format!("bert.encoder.layer.{block}.{suffix}"), shape);
        }
    }
    shapes
}

fn checked_index(checkpoint: &[u8]) -> EnclaveResult<TensorIndex> {
    if checkpoint.len() != CHECKPOINT_BYTES
        || hex::encode(Sha256::digest(checkpoint)) != CHECKPOINT_SHA256
    {
        fail!(EACCES, "COREML_BERT_CHECKPOINT_PIN");
    }
    // The immutable byte pin precedes JSON parsing. The generic safetensors
    // reader is not being used to authorize arbitrary duplicate-key headers.
    let idx = safetensors::parse(checkpoint)?;
    let metadata: BTreeMap<String, String> = BTreeMap::from([
        (
            "cls.predictions.decoder.weight".into(),
            "bert.embeddings.word_embeddings.weight".into(),
        ),
        ("format".into(), "pt".into()),
        (
            "cls.predictions.decoder.bias".into(),
            "cls.predictions.bias".into(),
        ),
    ]);
    let shapes = expected_shapes();
    if idx.metadata != metadata
        || idx.tensors.len() != 46
        || shapes.len() != 46
        || idx.tensors.keys().ne(shapes.keys())
    {
        fail!(EACCES, "COREML_BERT_TENSOR_VOCABULARY");
    }
    let mut ranges = Vec::with_capacity(46);
    for (name, shape) in shapes {
        let tensor = &idx.tensors[&name];
        let size = shape.iter().product::<usize>() * 4;
        if tensor.dtype != "F32"
            || tensor.shape != shape
            || tensor.range.1.checked_sub(tensor.range.0) != Some(size)
        {
            fail!(EINVAL, "COREML_BERT_TENSOR_SHAPE");
        }
        let bytes = checkpoint
            .get(tensor.range.0..tensor.range.1)
            .ok_or_else(|| err!(EINVAL, "COREML_BERT_TENSOR_RANGE"))?;
        // Validate all 46 tensors, including pretrained heads that this encoder
        // does not instantiate. Their presence is not a class-admission claim.
        if bytes
            .as_chunks::<4>()
            .0
            .iter()
            .any(|word| !f32::from_le_bytes(*word).is_finite())
        {
            fail!(EINVAL, "COREML_BERT_NONFINITE_WEIGHT");
        }
        ranges.push(tensor.range);
    }
    ranges.sort_unstable();
    let header = u64::from_le_bytes(checkpoint[..8].try_into().unwrap());
    if header != 5264 {
        fail!(EINVAL, "COREML_BERT_HEADER");
    }
    let mut cursor = 8 + header as usize;
    for (start, end) in ranges {
        if start != cursor {
            fail!(EINVAL, "COREML_BERT_TENSOR_RANGE");
        }
        cursor = end;
    }
    if cursor != checkpoint.len() {
        fail!(EINVAL, "COREML_BERT_TENSOR_RANGE");
    }
    Ok(idx)
}

fn varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 128 {
        out.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    out.push(value as u8);
}
fn integer(field: u32, value: u64, out: &mut Vec<u8>) {
    varint(u64::from(field) << 3, out);
    varint(value, out);
}
fn length(field: u32, size: usize, out: &mut Vec<u8>) {
    varint((u64::from(field) << 3) | 2, out);
    varint(size as u64, out);
}
fn bytes(field: u32, value: &[u8], out: &mut Vec<u8>) {
    length(field, value.len(), out);
    out.extend_from_slice(value);
}
fn feature(name: &str, shape: &[usize]) -> Vec<u8> {
    let mut array = Vec::new();
    for &dimension in shape {
        integer(1, dimension as u64, &mut array);
    }
    integer(2, 65568, &mut array); // CoreML FLOAT32 multiarray.
    let mut kind = Vec::new();
    bytes(5, &array, &mut kind);
    let mut result = Vec::new();
    bytes(1, name.as_bytes(), &mut result);
    bytes(3, &kind, &mut result);
    result
}

// Only public schema/name/dimension bytes use ordinary growable Vecs above.
// Every private model byte goes into this fixed initialized allocation. No
// capacity-changing method or mutable Vec reference escapes its owner.
struct BertBytes {
    values: Vec<u8>,
    used: usize,
    limit: usize,
    #[cfg(test)]
    owner: &'static str,
    #[cfg(test)]
    allocation: (usize, usize),
}
impl BertBytes {
    fn zeroed(length: usize, owner: &'static str) -> Self {
        let mut bytes = Self::adopt(vec![0; length], owner);
        bytes.used = 0;
        bytes
    }
    fn adopt(values: Vec<u8>, _owner: &'static str) -> Self {
        Self {
            used: values.len(),
            limit: values.len(),
            #[cfg(test)]
            allocation: (values.as_ptr() as usize, values.capacity()),
            values,
            #[cfg(test)]
            owner: _owner,
        }
    }
    fn extend(&mut self, value: &[u8]) -> EnclaveResult<()> {
        let end = self
            .used
            .checked_add(value.len())
            .filter(|&end| end <= self.limit)
            .ok_or_else(|| err!(E2BIG, "COREML_BERT_GRAPH_CAPACITY"))?;
        self.values[self.used..end].copy_from_slice(value);
        self.used = end;
        Ok(())
    }
    fn varint(&mut self, mut value: u64) -> EnclaveResult<()> {
        while value >= 128 {
            self.extend(&[(value as u8 & 127) | 128])?;
            value >>= 7;
        }
        self.extend(&[value as u8])
    }
    fn length(&mut self, field: u32, size: usize) -> EnclaveResult<()> {
        self.varint((u64::from(field) << 3) | 2)?;
        self.varint(u64::try_from(size).map_err(|_| err!(E2BIG, "COREML_BERT_GRAPH_CAPACITY"))?)
    }
    fn weight_prefix(&mut self, field: u32, size: usize) -> EnclaveResult<()> {
        self.length(field, encoded_bytes_size(1, size)?)?;
        self.length(1, size)
    }
    fn weight(&mut self, field: u32, value: &[u8]) -> EnclaveResult<()> {
        self.weight_prefix(field, value.len())?;
        self.extend(value)
    }
    fn fill_exact(
        &mut self,
        length: usize,
        fill: impl FnOnce(&mut Self) -> EnclaveResult<()>,
    ) -> EnclaveResult<()> {
        let end = self
            .used
            .checked_add(length)
            .filter(|&end| end <= self.limit)
            .ok_or_else(|| err!(E2BIG, "COREML_BERT_GRAPH_CAPACITY"))?;
        let previous = self.limit;
        self.limit = end;
        let result = fill(self);
        self.limit = previous;
        result?;
        if self.used != end {
            fail!(EIO, "COREML_BERT_GRAPH_LENGTH");
        }
        Ok(())
    }
    fn prepend(&mut self, public_header: &[u8]) -> EnclaveResult<()> {
        let end = self
            .used
            .checked_add(public_header.len())
            .filter(|&end| end <= self.limit)
            .ok_or_else(|| err!(E2BIG, "COREML_BERT_GRAPH_CAPACITY"))?;
        self.values.copy_within(..self.used, public_header.len());
        self.values[..public_header.len()].copy_from_slice(public_header);
        self.used = end;
        Ok(())
    }
    fn as_slice(&self) -> &[u8] {
        &self.values[..self.used]
    }
    fn into_vec(mut self) -> EnclaveResult<Vec<u8>> {
        if self.used != self.values.len() {
            fail!(EIO, "COREML_BERT_GRAPH_LENGTH");
        }
        #[cfg(test)]
        export_owner_tests::transferred(
            self.owner,
            self.used,
            self.allocation == (self.values.as_ptr() as usize, self.values.capacity()),
        );
        Ok(std::mem::take(&mut self.values))
    }
}
impl Drop for BertBytes {
    fn drop(&mut self) {
        if self.values.is_empty() {
            return;
        }
        for byte in &mut self.values {
            // SAFETY: the initialized original current allocation remains
            // exclusively owned and live throughout every volatile write.
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        export_owner_tests::scrubbed(
            self.owner,
            self.used,
            &self.values,
            self.allocation == (self.values.as_ptr() as usize, self.values.capacity()),
        );
    }
}

fn checked_sum(parts: &[usize]) -> EnclaveResult<usize> {
    parts.iter().try_fold(0usize, |total, &part| {
        total
            .checked_add(part)
            .ok_or_else(|| err!(E2BIG, "COREML_BERT_GRAPH_CAPACITY"))
    })
}
fn varint_size(mut value: u64) -> usize {
    let mut size = 1;
    while value >= 128 {
        size += 1;
        value >>= 7;
    }
    size
}
fn encoded_bytes_size(field: u32, size: usize) -> EnclaveResult<usize> {
    let length = u64::try_from(size).map_err(|_| err!(E2BIG, "COREML_BERT_GRAPH_CAPACITY"))?;
    checked_sum(&[
        varint_size((u64::from(field) << 3) | 2),
        varint_size(length),
        size,
    ])
}
fn encoded_weight_size(field: u32, size: usize) -> EnclaveResult<usize> {
    encoded_bytes_size(field, encoded_bytes_size(1, size)?)
}
fn matrix_bytes(rows: usize, columns: usize) -> EnclaveResult<usize> {
    if rows == 0 || columns == 0 {
        fail!(EINVAL, "COREML_BERT_EMBEDDING_SHAPE");
    }
    rows.checked_mul(columns)
        .and_then(|size| size.checked_mul(4))
        .ok_or_else(|| err!(E2BIG, "COREML_BERT_GRAPH_CAPACITY"))
}
fn transpose_embedding(
    out: &mut BertBytes,
    word: &[u8],
    rows: usize,
    columns: usize,
) -> EnclaveResult<()> {
    if matrix_bytes(rows, columns)? != word.len() {
        fail!(EINVAL, "COREML_BERT_EMBEDDING_SHAPE");
    }
    // CoreML EmbeddingND stores [width,vocabulary], unlike checkpoint rows.
    // Copy each original Float32 bit pattern straight into the final owner.
    for channel in 0..columns {
        for token in 0..rows {
            let start = (token * columns + channel) * 4;
            out.extend(&word[start..start + 4])?;
        }
    }
    Ok(())
}
fn position_offsets(
    out: &mut BertBytes,
    position: &[u8],
    types: &[u8],
    count: usize,
    width: usize,
) -> EnclaveResult<()> {
    let position_bytes = count
        .checked_mul(4)
        .ok_or_else(|| err!(E2BIG, "COREML_BERT_GRAPH_CAPACITY"))?;
    let type_bytes = width
        .checked_mul(4)
        .ok_or_else(|| err!(E2BIG, "COREML_BERT_GRAPH_CAPACITY"))?;
    if width == 0 || position.len() < position_bytes || types.len() < type_bytes {
        fail!(EINVAL, "COREML_BERT_POSITION_SHAPE");
    }
    for i in 0..count {
        let a = f32::from_le_bytes(position[4 * i..4 * i + 4].try_into().unwrap());
        let j = i % width;
        let b = f32::from_le_bytes(types[4 * j..4 * j + 4].try_into().unwrap());
        // Preserve the original f64 addition and single f32 rounding.
        out.extend(&((f64::from(a) + f64::from(b)) as f32).to_le_bytes())?;
    }
    Ok(())
}

struct Graph<'a> {
    idx: &'a TensorIndex,
    checkpoint: &'a [u8],
    layers: BertBytes,
    count: usize,
}
impl<'a> Graph<'a> {
    fn raw(&self, name: &str) -> &'a [u8] {
        let (start, end) = self.idx.tensors[name].range;
        &self.checkpoint[start..end]
    }
    fn layer_with(
        &mut self,
        name: &str,
        inputs: &[&str],
        op: u32,
        parameter_size: usize,
        fill: impl FnOnce(&mut BertBytes) -> EnclaveResult<()>,
    ) -> EnclaveResult<String> {
        let mut header = Vec::new();
        bytes(1, name.as_bytes(), &mut header);
        for input in inputs {
            bytes(2, input.as_bytes(), &mut header);
        }
        bytes(3, name.as_bytes(), &mut header);
        length(op, parameter_size, &mut header);
        self.layers
            .length(1, checked_sum(&[header.len(), parameter_size])?)?;
        self.layers.extend(&header)?;
        self.layers.fill_exact(parameter_size, fill)?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| err!(E2BIG, "COREML_BERT_GRAPH_CAPACITY"))?;
        Ok(name.into())
    }
    // These parameter slices contain only the fixed public operation schema.
    fn layer(
        &mut self,
        name: &str,
        inputs: &[&str],
        op: u32,
        parameters: &[u8],
    ) -> EnclaveResult<String> {
        self.layer_with(name, inputs, op, parameters.len(), |out| {
            out.extend(parameters)
        })
    }
    fn constant(&mut self, name: &str, shape: &[usize], values: &[u8]) -> EnclaveResult<String> {
        let mut header = Vec::new();
        for &d in shape {
            integer(1, d as u64, &mut header);
        }
        let size = checked_sum(&[header.len(), encoded_weight_size(2, values.len())?])?;
        self.layer_with(name, &[], 1070, size, |out| {
            out.extend(&header)?;
            out.weight(2, values)
        })
    }
    fn linear(&mut self, name: &str, input: &str, parameter: &str) -> EnclaveResult<String> {
        let w = format!("{parameter}.weight");
        let b = format!("{parameter}.bias");
        let shape = &self.idx.tensors[&w].shape;
        let weights = self.raw(&w);
        let bias = self.raw(&b);
        let mut header = Vec::new();
        integer(5, shape[1] as u64, &mut header);
        integer(6, shape[0] as u64, &mut header);
        integer(7, 1, &mut header);
        let size = checked_sum(&[
            header.len(),
            encoded_weight_size(8, weights.len())?,
            encoded_weight_size(9, bias.len())?,
        ])?;
        self.layer_with(name, &[input], 1045, size, |out| {
            out.extend(&header)?;
            out.weight(8, weights)?;
            out.weight(9, bias)
        })
    }
    fn norm(&mut self, name: &str, input: &str, parameter: &str) -> EnclaveResult<String> {
        let weights = self.raw(&format!("{parameter}.weight"));
        let bias = self.raw(&format!("{parameter}.bias"));
        let mut header = Vec::new();
        integer(1, WIDTH as u64, &mut header);
        varint((2 << 3) | 5, &mut header);
        header.extend_from_slice(&1e-12_f32.to_le_bytes());
        let size = checked_sum(&[
            header.len(),
            encoded_weight_size(3, weights.len())?,
            encoded_weight_size(4, bias.len())?,
        ])?;
        self.layer_with(name, &[input], 1350, size, |out| {
            out.extend(&header)?;
            out.weight(3, weights)?;
            out.weight(4, bias)
        })
    }
    fn embedding(&mut self, word: &[u8], rows: usize, columns: usize) -> EnclaveResult<String> {
        if matrix_bytes(rows, columns)? != word.len() {
            fail!(EINVAL, "COREML_BERT_EMBEDDING_SHAPE");
        }
        let mut header = Vec::new();
        integer(1, rows as u64, &mut header);
        integer(2, columns as u64, &mut header);
        let size = checked_sum(&[header.len(), encoded_weight_size(20, word.len())?])?;
        self.layer_with("token_embedding", &["tokens"], 1040, size, |out| {
            out.extend(&header)?;
            out.weight_prefix(20, word.len())?;
            transpose_embedding(out, word, rows, columns)
        })
    }
    fn position_and_type(&mut self) -> EnclaveResult<String> {
        let position = self.raw("bert.embeddings.position_embeddings.weight");
        let types = self.raw("bert.embeddings.token_type_embeddings.weight");
        let mut header = Vec::new();
        for d in [SEQUENCE, WIDTH] {
            integer(1, d as u64, &mut header);
        }
        let bytes = matrix_bytes(SEQUENCE, WIDTH)?;
        let size = checked_sum(&[header.len(), encoded_weight_size(2, bytes)?])?;
        self.layer_with("position_and_type0", &[], 1070, size, |out| {
            out.extend(&header)?;
            out.weight_prefix(2, bytes)?;
            position_offsets(out, position, types, OUTPUT_VALUES, WIDTH)
        })
    }
    fn build(mut self) -> EnclaveResult<Vec<u8>> {
        let word = self.raw("bert.embeddings.word_embeddings.weight");
        let embedded = self.embedding(word, VOCABULARY as usize, WIDTH)?;
        let position = self.position_and_type()?;
        let sum = self.layer("embedding_sum", &[&embedded, &position], 880, &[])?;
        let mut x = self.norm("embedding_norm", &sum, "bert.embeddings.LayerNorm")?;
        let scale = self.constant("attention_scale", &[1], &0.125_f32.to_le_bytes())?;
        for block in 0..2 {
            let prefix = format!("bert.encoder.layer.{block}.");
            let label = format!("block{block}_");
            let mut heads = Vec::new();
            for part in ["query", "key", "value"] {
                let value = self.linear(
                    &format!("{label}{part}"),
                    &x,
                    &format!("{prefix}attention.self.{part}"),
                )?;
                let mut p = Vec::new();
                for d in [SEQUENCE, 2, 64] {
                    integer(1, d as u64, &mut p);
                }
                let value = self.layer(&format!("{label}{part}_reshape"), &[&value], 1140, &p)?;
                let mut p = Vec::new();
                for d in [1, 0, 2] {
                    integer(1, d, &mut p);
                }
                heads.push(self.layer(&format!("{label}{part}_heads"), &[&value], 985, &p)?);
            }
            let mut p = Vec::new();
            integer(2, 1, &mut p);
            let scores =
                self.layer(&format!("{label}scores"), &[&heads[0], &heads[1]], 1045, &p)?;
            let scores = self.layer(
                &format!("{label}scaled_scores"),
                &[&scores, &scale],
                900,
                &[],
            )?;
            let mut p = Vec::new();
            integer(1, 2, &mut p);
            let probabilities =
                self.layer(&format!("{label}probabilities"), &[&scores], 950, &p)?;
            let context = self.layer(
                &format!("{label}context"),
                &[&probabilities, &heads[2]],
                1045,
                &[],
            )?;
            let mut p = Vec::new();
            for d in [1, 0, 2] {
                integer(1, d, &mut p);
            }
            let context = self.layer(&format!("{label}context_transpose"), &[&context], 985, &p)?;
            let mut p = Vec::new();
            for d in [SEQUENCE, WIDTH] {
                integer(1, d as u64, &mut p);
            }
            let context = self.layer(&format!("{label}context_flat"), &[&context], 1140, &p)?;
            let attention = self.linear(
                &format!("{label}attention_out"),
                &context,
                &format!("{prefix}attention.output.dense"),
            )?;
            let residual = self.layer(
                &format!("{label}attention_residual"),
                &[&x, &attention],
                880,
                &[],
            )?;
            let normalized = self.norm(
                &format!("{label}attention_norm"),
                &residual,
                &format!("{prefix}attention.output.LayerNorm"),
            )?;
            let intermediate = self.linear(
                &format!("{label}intermediate"),
                &normalized,
                &format!("{prefix}intermediate.dense"),
            )?;
            let mut p = Vec::new();
            integer(1, 0, &mut p);
            let activated = self.layer(&format!("{label}exact_gelu"), &[&intermediate], 795, &p)?;
            let output = self.linear(
                &format!("{label}output"),
                &activated,
                &format!("{prefix}output.dense"),
            )?;
            let residual = self.layer(
                &format!("{label}output_residual"),
                &[&normalized, &output],
                880,
                &[],
            )?;
            x = self.norm(
                &format!("{label}output_norm"),
                &residual,
                &format!("{prefix}output.LayerNorm"),
            )?;
        }
        if self.count != 51 || x != "block1_output_norm" {
            fail!(EIO, "COREML_BERT_SOURCE_GRAPH");
        }
        let mut description = Vec::new();
        bytes(1, &feature("tokens", &[SEQUENCE, 1]), &mut description);
        bytes(10, &feature(&x, &[SEQUENCE, WIDTH]), &mut description);
        let mut mapping = Vec::new();
        integer(5, 1, &mut mapping);
        self.layers.extend(&mapping)?; // exact neural network array-shape mapping.
        let mut header = Vec::new();
        integer(1, 4, &mut header);
        bytes(2, &description, &mut header);
        length(500, self.layers.used, &mut header);
        self.layers.prepend(&header)?;
        if self.layers.used != MODEL_BYTES
            || hex::encode(Sha256::digest(self.layers.as_slice())) != MODEL_SHA256
        {
            fail!(EACCES, "COREML_BERT_CANONICAL_MODEL_PIN");
        }
        self.layers.into_vec()
    }
}

/// Exact canonical program generated from all validated pinned checkpoint data.
/// The program executes only the encoder; verified unused pretrained heads are
/// not instantiated and are not being reclassified as an RLCD head.
pub struct CanonicalBertGraph {
    /// Complete fixed CoreML Model protobuf.
    pub model: Vec<u8>,
}
impl std::fmt::Debug for CanonicalBertGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CanonicalBertGraph")
            .field("bytes", &self.model.len())
            .field("expected_sha256", &MODEL_SHA256)
            .finish()
    }
}
impl CanonicalBertGraph {
    /// Export the immutable encoder in a debug build, without native I/O.
    pub fn from_checkpoint(checkpoint: &[u8]) -> EnclaveResult<Self> {
        development_only()?;
        let idx = checked_index(checkpoint)?;
        let model = Graph {
            idx: &idx,
            checkpoint,
            layers: BertBytes::zeroed(MODEL_BYTES, "bert-graph"),
            count: 0,
        }
        .build()?;
        Ok(Self { model })
    }
}

/// Self-observed physical footprint points around native load stages.
/// None means unknown. These are points, not independently observed stage peaks.
#[derive(Debug, Clone, Serialize)]
pub struct BertLoadMemory {
    /// Before Rust canonical export.
    pub before_export: Option<u64>,
    /// After Rust canonical export, before crossing FFI.
    pub after_export: Option<u64>,
    /// Native point immediately before compile.
    pub before_compile: Option<u64>,
    /// Native point immediately after successful compile.
    pub after_compile: Option<u64>,
    /// Native point after model load.
    pub after_load: Option<u64>,
    /// Native point after actual compiled-graph verification.
    pub after_graph: Option<u64>,
}

/// Self-observed physical points around prediction or explicit destruction.
#[derive(Debug, Clone, Serialize)]
pub struct BertOperationMemory {
    /// Physical point before the operation; not a peak.
    pub before: Option<u64>,
    /// Physical point after the operation; not proof of framework erasure.
    pub after: Option<u64>,
}

/// Full checked encoder output. Debug output deliberately omits hidden values.
pub struct BertPrediction {
    /// Token-major 8×128 finite values; internal debug-component data only.
    pub hidden: [f32; OUTPUT_VALUES],
    /// Native physical points surrounding this prediction.
    pub memory: BertOperationMemory,
}
impl std::fmt::Debug for BertPrediction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BertPrediction")
            .field("values", &OUTPUT_VALUES)
            .field("memory", &self.memory)
            .finish()
    }
}

fn validate_tokens(tokens: &[u32]) -> EnclaveResult<()> {
    if tokens.len() != SEQUENCE || tokens.iter().any(|&id| id >= VOCABULARY) {
        fail!(EINVAL, "COREML_BERT_TOKEN_IDS");
    }
    Ok(())
}

// Own the fixed private output before its first native write. Only this live
// storage is covered: public result copies, prior stack/register/compiler
// copies and native/framework buffers remain separate owners.
#[cfg(any(target_os = "macos", test))]
struct BertOutputScratch<'a> {
    values: &'a mut [f32; OUTPUT_VALUES],
}
#[cfg(any(target_os = "macos", test))]
impl Drop for BertOutputScratch<'_> {
    fn drop(&mut self) {
        for value in self.values.iter_mut() {
            // SAFETY: each initialized element is exclusively borrowed and
            // remains live throughout its volatile overwrite.
            unsafe {
                std::ptr::write_volatile(value, 0.0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        output_owner_tests::scrubbed(self.values);
    }
}

// The production macOS path supplies the synchronous FFI call while retaining
// its native mutex. Tests exercise this same owner with synthetic writers;
// neither the callback nor a returned error may retain a borrow of the arrays.
#[cfg(any(target_os = "macos", test))]
fn predict_owned_output(
    predict: impl FnOnce(&mut [f32; OUTPUT_VALUES], &mut [u64; 2]) -> EnclaveResult<i32>,
) -> EnclaveResult<BertPrediction> {
    let mut values = [0.0; OUTPUT_VALUES];
    // The guard moves only its exclusive borrow, never the private array.
    let output = BertOutputScratch {
        values: &mut values,
    };
    let mut points = [0u64; 2];
    let status = predict(output.values, &mut points)?;
    if status != 0 || output.values.iter().any(|value| !value.is_finite()) {
        fail!(EIO, "COREML_BERT_PREDICTION_FAILED", "status={status}");
    }
    // Preserve the public by-value array API. The private source storage is
    // scrubbed before the admitted result transfers to its existing caller.
    let hidden = *output.values;
    drop(output);
    Ok(BertPrediction {
        hidden,
        memory: operation_memory(points),
    })
}

// The public export Vec transfers into this private load owner without a
// payload copy or reallocation. Neither callback success nor error/unwind can
// release the private current model bytes without scrubbing them first.
#[cfg(any(target_os = "macos", test))]
fn with_owned_bert_model<R>(
    graph: CanonicalBertGraph,
    load: impl FnOnce(&[u8]) -> EnclaveResult<R>,
) -> EnclaveResult<R> {
    let model = BertBytes::adopt(graph.model, "bert-load");
    load(model.as_slice())
}

/// Reusable debug-only trained encoder, disconnected from production admission.
pub struct CoreMlBertEncoder {
    load_memory: BertLoadMemory,
    #[cfg(target_os = "macos")]
    native: std::sync::Mutex<NativeBert>,
}
impl std::fmt::Debug for CoreMlBertEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreMlBertEncoder")
            .field("model_sha256", &MODEL_SHA256)
            .field("load_memory", &self.load_memory)
            .finish()
    }
}
impl CoreMlBertEncoder {
    /// Validate/export the selected checkpoint, compile/load with CPU-only
    /// CoreML, and verify the exact pinned 96-layer public compiled structure.
    /// Release and unsupported-platform calls refuse before native/file I/O.
    pub fn load(checkpoint: &[u8]) -> EnclaveResult<Self> {
        development_only()?;
        #[cfg(not(target_os = "macos"))]
        {
            let _ = checkpoint;
            fail!(ENOSYS, "COREML_BERT_PLATFORM_UNAVAILABLE");
        }
        #[cfg(target_os = "macos")]
        {
            let before_export = enclave_core::resource::current_phys_footprint_bytes();
            let graph = CanonicalBertGraph::from_checkpoint(checkpoint)?;
            with_owned_bert_model(graph, |model| {
                let after_export = enclave_core::resource::current_phys_footprint_bytes();
                let mut points = [0u64; 4];
                let mut status = -1;
                // SAFETY: exact owned canonical bytes and fixed writable out-buffers
                // remain live until synchronous FFI returns; no borrow is retained.
                let pointer = unsafe {
                    enclave_coreml_bert_create(
                        model.as_ptr(),
                        model.len(),
                        points.as_mut_ptr(),
                        &mut status,
                    )
                };
                let Some(pointer) = std::ptr::NonNull::new(pointer) else {
                    fail!(EIO, "COREML_BERT_LOAD_FAILED", "status={status}");
                };
                let native = NativeBert {
                    pointer: Some(pointer),
                };
                if status != 0 {
                    drop(native);
                    fail!(EIO, "COREML_BERT_LOAD_FAILED", "status={status}");
                }
                let known = |value| (value > 0).then_some(value);
                Ok(Self {
                    native: std::sync::Mutex::new(native),
                    load_memory: BertLoadMemory {
                        before_export,
                        after_export,
                        before_compile: known(points[0]),
                        after_compile: known(points[1]),
                        after_load: known(points[2]),
                        after_graph: known(points[3]),
                    },
                })
            })
        }
    }
    /// Stage points collected at actual Rust/native boundaries.
    pub fn load_memory(&self) -> &BertLoadMemory {
        &self.load_memory
    }
    /// Encode exactly eight valid IDs, with segment zero and all-token attention.
    /// No text tokenization, truncation, padding, classifier or egress is implied.
    pub fn encode(&self, tokens: &[u32]) -> EnclaveResult<BertPrediction> {
        development_only()?;
        validate_tokens(tokens)?;
        #[cfg(not(target_os = "macos"))]
        {
            fail!(ENOSYS, "COREML_BERT_PLATFORM_UNAVAILABLE");
        }
        #[cfg(target_os = "macos")]
        {
            let native = self
                .native
                .lock()
                .map_err(|_| err!(EIO, "COREML_BERT_MODEL_LOCK"))?;
            let pointer = native
                .pointer
                .ok_or_else(|| err!(EIO, "COREML_BERT_CLOSED"))?;
            predict_owned_output(|output, points| {
                // SAFETY: fixed checked input/output buffers stay borrowed
                // under the single native owner mutex; the bridge retains
                // neither and cannot outlive the private output guard.
                Ok(unsafe {
                    enclave_coreml_bert_predict(
                        pointer.as_ptr(),
                        tokens.as_ptr(),
                        tokens.len(),
                        output.as_mut_ptr(),
                        output.len(),
                        points.as_mut_ptr(),
                    )
                })
            })
        }
    }
    /// Destroy the native owner once and report before/after physical points.
    /// Ordinary Drop also destroys it; neither operation proves physical erasure.
    pub fn close(mut self) -> EnclaveResult<BertOperationMemory> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = &mut self;
            fail!(ENOSYS, "COREML_BERT_PLATFORM_UNAVAILABLE");
        }
        #[cfg(target_os = "macos")]
        {
            Ok(self
                .native
                .get_mut()
                .map_err(|_| err!(EIO, "COREML_BERT_MODEL_LOCK"))?
                .destroy())
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn operation_memory(points: [u64; 2]) -> BertOperationMemory {
    BertOperationMemory {
        before: (points[0] > 0).then_some(points[0]),
        after: (points[1] > 0).then_some(points[1]),
    }
}
#[cfg(target_os = "macos")]
struct NativeBert {
    pointer: Option<std::ptr::NonNull<std::ffi::c_void>>,
}
// SAFETY: ownership may move between threads, but all native prediction access
// is serialized by the enclosing mutex and no borrowed Rust buffer is retained.
#[cfg(target_os = "macos")]
unsafe impl Send for NativeBert {}
#[cfg(target_os = "macos")]
impl NativeBert {
    fn destroy(&mut self) -> BertOperationMemory {
        let mut points = [0u64; 2];
        if let Some(pointer) = self.pointer.take() {
            // SAFETY: unique retained owner, removed before the sole release.
            unsafe {
                enclave_coreml_bert_destroy(pointer.as_ptr(), points.as_mut_ptr());
            }
        }
        operation_memory(points)
    }
}
#[cfg(target_os = "macos")]
impl Drop for NativeBert {
    fn drop(&mut self) {
        self.destroy();
    }
}
#[cfg(target_os = "macos")]
extern "C" {
    fn enclave_coreml_bert_create(
        bytes: *const u8,
        length: usize,
        points: *mut u64,
        status: *mut i32,
    ) -> *mut std::ffi::c_void;
    fn enclave_coreml_bert_predict(
        model: *mut std::ffi::c_void,
        tokens: *const u32,
        length: usize,
        output: *mut f32,
        count: usize,
        points: *mut u64,
    ) -> i32;
    fn enclave_coreml_bert_destroy(model: *mut std::ffi::c_void, points: *mut u64);
}

#[cfg(test)]
mod output_owner_tests {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        static EVENTS: RefCell<Option<Vec<(usize, bool)>>> = const { RefCell::new(None) };
    }
    fn begin() {
        EVENTS.with(|events| *events.borrow_mut() = Some(Vec::new()));
    }
    fn finish() -> Vec<(usize, bool)> {
        EVENTS.with(|events| events.borrow_mut().take().unwrap())
    }
    // Inspect only still-live guard storage after its production volatile wipe
    // and fence. Retain no values, pointer or reference to private storage.
    pub(super) fn scrubbed(values: &[f32; OUTPUT_VALUES]) {
        EVENTS.with(|events| {
            if let Some(events) = events.borrow_mut().as_mut() {
                events.push((
                    values.len(),
                    values.iter().all(|value| value.to_bits() == 0),
                ));
            }
        });
    }

    fn expected_scrub() -> Vec<(usize, bool)> {
        vec![(OUTPUT_VALUES, true)]
    }

    #[test]
    fn actual_bert_output_helper_preserves_all_finite_bits_and_points_after_private_scrub() {
        // Include negative zero, subnormals and finite extremes so cleanup
        // cannot silently alter any of the admitted public Float32 values.
        let pattern = [
            0.0,
            -0.0,
            f32::from_bits(1),
            f32::from_bits(0x8000_0001),
            f32::MAX,
            f32::MIN,
            0.25,
            -73.5,
        ];
        let expected: [f32; OUTPUT_VALUES] = std::array::from_fn(|i| pattern[i % pattern.len()]);
        for points in [[0, 0], [0, 17], [99, 0], [99, 117]] {
            begin();
            let result = predict_owned_output(|output, observed_points| {
                assert!(
                    output.iter().all(|value| value.to_bits() == 0),
                    "the guard precedes the first private write"
                );
                assert_eq!(*observed_points, [0, 0]);
                output.copy_from_slice(&expected);
                *observed_points = points;
                Ok(0)
            })
            .unwrap();
            assert_eq!(
                finish(),
                expected_scrub(),
                "private scrub precedes the public result"
            );
            assert!(result
                .hidden
                .iter()
                .zip(expected)
                .all(|(a, b)| a.to_bits() == b.to_bits()));
            assert_eq!(result.memory.before, (points[0] > 0).then_some(points[0]));
            assert_eq!(result.memory.after, (points[1] > 0).then_some(points[1]));
        }
    }

    #[test]
    fn actual_bert_output_helper_scrubs_partial_status_failure_and_late_nonfinite_refusal() {
        for status in [-1, -2, -3, -4, -5, -6, -7, -8, -9, -90, i32::MAX] {
            begin();
            let error = predict_owned_output(|output, points| {
                output[0] = 17.0;
                output[OUTPUT_VALUES / 2] = -0.25;
                *points = [11, 0];
                Ok(status)
            })
            .unwrap_err();
            assert!(error.is("COREML_BERT_PREDICTION_FAILED"));
            assert!(error.to_string().contains(&format!("status={status}")));
            assert_eq!(finish(), expected_scrub());
        }
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            begin();
            let error = predict_owned_output(|output, points| {
                output.fill(17.0);
                output[OUTPUT_VALUES - 1] = value;
                *points = [11, 27];
                Ok(0)
            })
            .unwrap_err();
            assert!(error.is("COREML_BERT_PREDICTION_FAILED"));
            assert!(error.to_string().contains("status=0"));
            assert_eq!(finish(), expected_scrub());
        }
    }

    #[test]
    fn actual_bert_output_helper_scrubs_partial_fallible_callback_without_replacing_error() {
        begin();
        let error = predict_owned_output(|output, _| {
            output[0] = 73.5;
            output[OUTPUT_VALUES - 1] = -31.25;
            Err(err!(EIO, "COREML_BERT_SYNTHETIC_CALLBACK"))
        })
        .unwrap_err();
        assert!(error.is("COREML_BERT_SYNTHETIC_CALLBACK"));
        assert_eq!(finish(), expected_scrub());
    }

    #[test]
    fn actual_bert_output_helper_scrubs_partial_output_on_genuine_rust_unwind() {
        begin();
        let result = std::panic::catch_unwind(|| {
            predict_owned_output(|output, _| {
                output[0] = 73.5;
                output[OUTPUT_VALUES - 1] = -31.25;
                panic!("synthetic synchronous BERT callback unwind");
            })
        });
        assert!(result.is_err());
        assert_eq!(finish(), expected_scrub());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bert_fixed_input_contract_has_no_implicit_padding_truncation_or_vocabulary_wrap() {
        validate_tokens(&[0, 1, 2, 3, 4, 5, 6, 30_521]).unwrap();
        for tokens in [
            vec![],
            vec![0; 7],
            vec![0; 9],
            vec![30_522; 8],
            vec![u32::MAX; 8],
        ] {
            assert!(validate_tokens(&tokens)
                .unwrap_err()
                .is("COREML_BERT_TOKEN_IDS"));
        }
    }
    #[test]
    fn bert_exact_checkpoint_pin_precedes_untrusted_header_parsing() {
        for bytes in [vec![], vec![0xff; 10], vec![0xff; CHECKPOINT_BYTES]] {
            let error = CanonicalBertGraph::from_checkpoint(&bytes).unwrap_err();
            assert!(error.is(if cfg!(debug_assertions) {
                "COREML_BERT_CHECKPOINT_PIN"
            } else {
                "COREML_BERT_DEVELOPMENT_ONLY"
            }));
        }
    }

    #[cfg(all(target_os = "macos", debug_assertions))]
    #[test]
    fn bert_native_directory_owner_preserves_unowned_collision_and_releases_owned_directory() {
        extern "C" {
            fn enclave_coreml_bert_directory_ownership_check() -> i32;
        }
        // SAFETY: the bridge accepts no pointers/path and creates only its own
        // bounded temporary fixture; this hook is not compiled for release.
        let result = unsafe { enclave_coreml_bert_directory_ownership_check() };
        assert_eq!(result, 0);
    }
}

#[cfg(test)]
mod export_owner_tests {
    use super::*;
    use crate::safetensors::TensorInfo;
    use std::cell::RefCell;

    #[derive(Debug, PartialEq)]
    struct Event {
        owner: &'static str,
        used: usize,
        initialized: usize,
        zero: bool,
        stable: bool,
        transfer: bool,
    }
    thread_local! {
        static EVENTS: RefCell<Option<Vec<Event>>> = const { RefCell::new(None) };
    }
    fn begin() {
        EVENTS.with(|events| *events.borrow_mut() = Some(Vec::new()));
    }
    fn finish() -> Vec<Event> {
        EVENTS.with(|events| events.borrow_mut().take().unwrap())
    }
    pub(super) fn scrubbed(owner: &'static str, used: usize, values: &[u8], stable: bool) {
        // Inspect initialized original storage after the production wipe/fence,
        // before it is deallocated. Retain no payload, pointer or reference.
        EVENTS.with(|events| {
            if let Some(events) = events.borrow_mut().as_mut() {
                events.push(Event {
                    owner,
                    used,
                    initialized: values.len(),
                    zero: values.iter().all(|&byte| byte == 0),
                    stable,
                    transfer: false,
                });
            }
        });
    }
    pub(super) fn transferred(owner: &'static str, used: usize, stable: bool) {
        EVENTS.with(|events| {
            if let Some(events) = events.borrow_mut().as_mut() {
                events.push(Event {
                    owner,
                    used,
                    initialized: used,
                    zero: false,
                    stable,
                    transfer: true,
                });
            }
        });
    }
    fn wiped(owner: &'static str, used: usize, initialized: usize) -> Vec<Event> {
        vec![Event {
            owner,
            used,
            initialized,
            zero: true,
            stable: true,
            transfer: false,
        }]
    }
    // Retain the previous growable parameter/layer encoding as a distinct
    // synthetic wire oracle. It shares neither new cursor/size nor owner code.
    fn old_weight(field: u32, value: &[u8], out: &mut Vec<u8>) {
        let mut prefix = Vec::new();
        length(1, value.len(), &mut prefix);
        length(field, prefix.len() + value.len(), out);
        out.extend_from_slice(&prefix);
        out.extend_from_slice(value);
    }
    fn old_layer(name: &str, inputs: &[&str], op: u32, parameters: &[u8]) -> Vec<u8> {
        let mut header = Vec::new();
        bytes(1, name.as_bytes(), &mut header);
        for input in inputs {
            bytes(2, input.as_bytes(), &mut header);
        }
        bytes(3, name.as_bytes(), &mut header);
        length(op, parameters.len(), &mut header);
        let mut out = Vec::new();
        length(1, header.len() + parameters.len(), &mut out);
        out.extend_from_slice(&header);
        out.extend_from_slice(parameters);
        out
    }
    fn word_bits(count: usize) -> Vec<u8> {
        let bits = [
            0x8000_0000u32,
            1,
            0x007f_ffff,
            0x7f7f_ffff,
            0xff7f_ffff,
            0x3eaa_aaab,
            0x3f80_0000,
        ];
        (0..count)
            .flat_map(|i| bits[i % bits.len()].to_le_bytes())
            .collect()
    }
    fn assert_layer(
        idx: &TensorIndex,
        checkpoint: &[u8],
        expected: &[u8],
        emit: impl FnOnce(&mut Graph<'_>) -> EnclaveResult<String>,
    ) {
        begin();
        let mut graph = Graph {
            idx,
            checkpoint,
            layers: BertBytes::zeroed(expected.len(), "test-graph"),
            count: 0,
        };
        emit(&mut graph).unwrap();
        assert_eq!(graph.count, 1);
        assert!(graph.layers.as_slice() == expected);
        drop(graph);
        assert_eq!(
            finish(),
            wiped("test-graph", expected.len(), expected.len())
        );
    }

    #[test]
    fn fixed_writer_matches_retained_wire_at_varint_boundaries_and_transfers_same_allocation() {
        for size in [0usize, 1, 126, 127, 128, 16382, 16383, 16384] {
            let input: Vec<u8> = (0..size).map(|i| (i * 73 + 19) as u8).collect();
            let mut expected = Vec::new();
            old_weight(20, &input, &mut expected);
            assert_eq!(encoded_weight_size(20, size).unwrap(), expected.len());
            begin();
            let mut out = BertBytes::zeroed(expected.len() + 3, "test-wire");
            let allocation = out.values.as_ptr();
            out.weight(20, &input).unwrap();
            out.prepend(&[0x08, 0x04, 0x00]).unwrap();
            let public = out.into_vec().unwrap();
            assert!(public.as_ptr() == allocation);
            assert!(&public[..3] == [0x08, 0x04, 0x00] && public[3..] == expected);
            assert_eq!(
                finish(),
                vec![Event {
                    owner: "test-wire",
                    used: public.len(),
                    initialized: public.len(),
                    zero: false,
                    stable: true,
                    transfer: true
                }]
            );
        }
        assert!(checked_sum(&[usize::MAX, 1])
            .unwrap_err()
            .is("COREML_BERT_GRAPH_CAPACITY"));
        assert!(encoded_bytes_size(1, usize::MAX)
            .unwrap_err()
            .is("COREML_BERT_GRAPH_CAPACITY"));
    }

    #[test]
    fn actual_embedding_layer_streams_exact_transpose_without_a_private_parameter_allocation() {
        let idx = TensorIndex::default();
        for (rows, columns) in [(1, 1), (2, 3), (3, 2), (127, 1), (1, 128), (129, 33)] {
            let word = word_bits(rows * columns);
            let before = Sha256::digest(&word);
            let mut p = Vec::new();
            integer(1, rows as u64, &mut p);
            integer(2, columns as u64, &mut p);
            let mut transposed = Vec::new();
            for channel in 0..columns {
                for token in 0..rows {
                    let start = (token * columns + channel) * 4;
                    transposed.extend_from_slice(&word[start..start + 4]);
                }
            }
            old_weight(20, &transposed, &mut p);
            let expected = old_layer("token_embedding", &["tokens"], 1040, &p);
            assert_layer(&idx, &[], &expected, |graph| {
                graph.embedding(&word, rows, columns)
            });
            assert!(Sha256::digest(&word) == before);
        }
    }

    #[test]
    fn actual_linear_norm_constant_and_position_layers_preserve_wire_and_rounded_bits() {
        let weights = word_bits(6);
        let bias = word_bits(2);
        let checkpoint = [weights.clone(), bias.clone()].concat();
        let idx = TensorIndex {
            tensors: BTreeMap::from([
                (
                    "fixture.weight".into(),
                    TensorInfo {
                        dtype: "F32".into(),
                        shape: vec![2, 3],
                        range: (0, weights.len()),
                    },
                ),
                (
                    "fixture.bias".into(),
                    TensorInfo {
                        dtype: "F32".into(),
                        shape: vec![2],
                        range: (weights.len(), checkpoint.len()),
                    },
                ),
            ]),
            metadata: BTreeMap::new(),
        };
        let mut p = Vec::new();
        integer(5, 3, &mut p);
        integer(6, 2, &mut p);
        integer(7, 1, &mut p);
        old_weight(8, &weights, &mut p);
        old_weight(9, &bias, &mut p);
        assert_layer(
            &idx,
            &checkpoint,
            &old_layer("dense", &["input"], 1045, &p),
            |graph| graph.linear("dense", "input", "fixture"),
        );
        let mut p = Vec::new();
        integer(1, WIDTH as u64, &mut p);
        varint((2 << 3) | 5, &mut p);
        p.extend_from_slice(&1e-12_f32.to_le_bytes());
        old_weight(3, &weights, &mut p);
        old_weight(4, &bias, &mut p);
        assert_layer(
            &idx,
            &checkpoint,
            &old_layer("norm", &["input"], 1350, &p),
            |graph| graph.norm("norm", "input", "fixture"),
        );
        let mut p = Vec::new();
        integer(1, 2, &mut p);
        integer(1, 3, &mut p);
        old_weight(2, &weights, &mut p);
        assert_layer(
            &idx,
            &checkpoint,
            &old_layer("constant", &[], 1070, &p),
            |graph| graph.constant("constant", &[2, 3], &weights),
        );
        // Deliberately finite cancellation/rounding/subnormal inputs. The old
        // oracle retains its complete synthetic offset Vec; production streams.
        let position: Vec<f32> = (0..OUTPUT_VALUES)
            .map(|i| [1.0, -1.0, f32::from_bits(1), 0.33333334][i % 4])
            .collect();
        let types: Vec<f32> = (0..WIDTH)
            .map(|i| [-1.0, 1.0, f32::from_bits(1), -0.3333333][i % 4])
            .collect();
        let raw_position: Vec<u8> = position
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        let raw_types: Vec<u8> = types.iter().flat_map(|value| value.to_le_bytes()).collect();
        let checkpoint = [raw_position.clone(), raw_types].concat();
        let idx = TensorIndex {
            tensors: BTreeMap::from([
                (
                    "bert.embeddings.position_embeddings.weight".into(),
                    TensorInfo {
                        dtype: "F32".into(),
                        shape: vec![SEQUENCE, WIDTH],
                        range: (0, raw_position.len()),
                    },
                ),
                (
                    "bert.embeddings.token_type_embeddings.weight".into(),
                    TensorInfo {
                        dtype: "F32".into(),
                        shape: vec![1, WIDTH],
                        range: (raw_position.len(), checkpoint.len()),
                    },
                ),
            ]),
            metadata: BTreeMap::new(),
        };
        let offsets: Vec<u8> = position
            .iter()
            .enumerate()
            .flat_map(|(i, &a)| ((f64::from(a) + f64::from(types[i % WIDTH])) as f32).to_le_bytes())
            .collect();
        let mut p = Vec::new();
        integer(1, SEQUENCE as u64, &mut p);
        integer(1, WIDTH as u64, &mut p);
        old_weight(2, &offsets, &mut p);
        assert_layer(
            &idx,
            &checkpoint,
            &old_layer("position_and_type0", &[], 1070, &p),
            |graph| graph.position_and_type(),
        );
    }

    #[test]
    fn checked_partial_cursor_submessage_and_unwind_paths_scrub_original_initialized_storage() {
        begin();
        let mut out = BertBytes::zeroed(16, "test-error");
        out.extend(&[17, 29, 43]).unwrap();
        assert!(out
            .extend(&[91; 14])
            .unwrap_err()
            .is("COREML_BERT_GRAPH_CAPACITY"));
        assert_eq!(out.used, 3);
        assert!(out.values[3..].iter().all(|&byte| byte == 0));
        assert!(out
            .fill_exact(2, |out| out.extend(&[7; 3]))
            .unwrap_err()
            .is("COREML_BERT_GRAPH_CAPACITY"));
        assert_eq!(out.used, 3);
        assert!(out
            .fill_exact(3, |out| out.extend(&[11]))
            .unwrap_err()
            .is("COREML_BERT_GRAPH_LENGTH"));
        assert_eq!(out.used, 4);
        drop(out);
        assert_eq!(finish(), wiped("test-error", 4, 16));
        begin();
        let mut out = BertBytes::zeroed(8, "test-short");
        out.extend(&[7]).unwrap();
        assert!(out.into_vec().unwrap_err().is("COREML_BERT_GRAPH_LENGTH"));
        assert_eq!(finish(), wiped("test-short", 1, 8));
        begin();
        let unwind = std::panic::catch_unwind(|| {
            let mut out = BertBytes::zeroed(32, "test-unwind");
            out.extend(&[79]).unwrap();
            let _ = out.fill_exact(8, |out| {
                out.extend(&[31, 47]).unwrap();
                panic!("synthetic graph writer unwind");
            });
        });
        assert!(unwind.is_err());
        assert_eq!(finish(), wiped("test-unwind", 3, 32));
    }

    #[test]
    fn same_public_model_vec_is_adopted_through_synchronous_load_success_error_and_unwind() {
        for mode in 0..3 {
            let expected = word_bits(33);
            let values = expected.clone();
            let pointer = values.as_ptr();
            begin();
            let outcome = std::panic::catch_unwind(move || {
                with_owned_bert_model(CanonicalBertGraph { model: values }, |model| {
                    assert!(model.as_ptr() == pointer);
                    assert!(model == expected);
                    if mode == 2 {
                        panic!("synthetic owned model load unwind");
                    }
                    if mode == 1 {
                        return Err(err!(EIO, "COREML_BERT_SYNTHETIC_LOAD"));
                    }
                    Ok(73u32)
                })
            });
            match mode {
                0 => assert_eq!(outcome.unwrap().unwrap(), 73),
                1 => assert!(outcome
                    .unwrap()
                    .unwrap_err()
                    .is("COREML_BERT_SYNTHETIC_LOAD")),
                _ => assert!(outcome.is_err()),
            }
            assert_eq!(finish(), wiped("bert-load", 132, 132));
        }
    }

    #[test]
    fn shape_overflow_and_partial_layer_errors_refuse_without_an_unowned_private_copy() {
        let idx = TensorIndex::default();
        for (rows, columns, word) in [(0, 1, vec![]), (1, 0, vec![]), (2, 2, vec![7; 4])] {
            begin();
            let mut graph = Graph {
                idx: &idx,
                checkpoint: &[],
                layers: BertBytes::zeroed(64, "test-shape"),
                count: 0,
            };
            assert!(graph
                .embedding(&word, rows, columns)
                .unwrap_err()
                .is("COREML_BERT_EMBEDDING_SHAPE"));
            assert_eq!(graph.layers.used, 0);
            drop(graph);
            assert_eq!(finish(), wiped("test-shape", 0, 64));
        }
        assert!(matrix_bytes(usize::MAX, 2)
            .unwrap_err()
            .is("COREML_BERT_GRAPH_CAPACITY"));
        begin();
        let mut out = BertBytes::zeroed(8, "test-offsets");
        assert!(position_offsets(&mut out, &[0; 4], &[0; 4], 2, 1)
            .unwrap_err()
            .is("COREML_BERT_POSITION_SHAPE"));
        assert_eq!(out.used, 0);
        drop(out);
        assert_eq!(finish(), wiped("test-offsets", 0, 8));
        begin();
        let mut graph = Graph {
            idx: &idx,
            checkpoint: &[],
            layers: BertBytes::zeroed(64, "test-layer"),
            count: 0,
        };
        let error = graph
            .layer_with("partial", &[], 880, 8, |out| {
                out.extend(&[73, 91])?;
                Err(err!(EIO, "COREML_BERT_SYNTHETIC_LAYER"))
            })
            .unwrap_err();
        assert!(error.is("COREML_BERT_SYNTHETIC_LAYER"));
        let used = graph.layers.used;
        assert!(used > 2);
        drop(graph);
        assert_eq!(finish(), wiped("test-layer", used, 64));
        begin();
        assert!(CanonicalBertGraph::from_checkpoint(&[0xff; 10]).is_err());
        assert!(finish().is_empty());
    }

    #[test]
    fn complete_private_graph_pin_failure_scrubs_its_single_full_model_allocation() {
        // Test-only private graph construction exercises all51 production layer
        // paths with synthetic tensors. Public export still requires the exact
        // immutable checkpoint; this synthetic graph MUST fail the final pin.
        let mut idx = TensorIndex::default();
        let mut checkpoint = Vec::new();
        for (name, shape) in expected_shapes() {
            let start = checkpoint.len();
            let size = shape.iter().product::<usize>() * 4;
            checkpoint.resize(start + size, 0);
            for word in checkpoint[start..].chunks_exact_mut(4) {
                word.copy_from_slice(&1.0f32.to_le_bytes());
            }
            idx.tensors.insert(
                name,
                TensorInfo {
                    dtype: "F32".into(),
                    shape,
                    range: (start, start + size),
                },
            );
        }
        let before = Sha256::digest(&checkpoint);
        begin();
        let graph = Graph {
            idx: &idx,
            checkpoint: &checkpoint,
            layers: BertBytes::zeroed(MODEL_BYTES, "bert-graph"),
            count: 0,
        };
        assert!(graph
            .build()
            .unwrap_err()
            .is("COREML_BERT_CANONICAL_MODEL_PIN"));
        assert!(Sha256::digest(&checkpoint) == before);
        assert_eq!(finish(), wiped("bert-graph", MODEL_BYTES, MODEL_BYTES));
    }
}
