//! Actual CPU CoreML classifier over a deliberately closed, single-layer graph.
//!
//! The graph is generated from authenticated safetensors, rather than admitting
//! a publisher's operator-name declaration or parsing arbitrary CoreML programs.
//! Only a bounded dense classifier is supported; this is not an encoder backend.

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use sha2::{Digest, Sha256};

use crate::classes::rlcd::RlcdBackend;
use crate::safetensors::TensorIndex;
use crate::topology::{OpAttestor, OpFamily};

fn varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 128 {
        output.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    output.push(value as u8);
}

fn integer(field: u32, value: u64, output: &mut Vec<u8>) {
    varint(u64::from(field) << 3, output);
    varint(value, output);
}

fn bytes(field: u32, value: &[u8], output: &mut Vec<u8>) {
    varint((u64::from(field) << 3) | 2, output);
    varint(value.len() as u64, output);
    output.extend_from_slice(value);
}

fn feature(name: &[u8], size: usize) -> Vec<u8> {
    let mut array = Vec::new();
    integer(1, size as u64, &mut array);
    integer(2, 65568, &mut array); // CoreML ArrayFeatureType.FLOAT32.
    let mut kind = Vec::new();
    bytes(5, &array, &mut kind);
    let mut result = Vec::new();
    bytes(1, name, &mut result);
    bytes(3, &kind, &mut result);
    result
}

// These lengths are used only after the public exporter checks the bounded
// 2..=256 classes and 1..=256 width. They count the unchanged protobuf encoding
// without first constructing an unguarded copy of any tensor bytes.
fn varint_len(mut value: u64) -> usize {
    let mut length = 1;
    while value >= 128 {
        length += 1;
        value >>= 7;
    }
    length
}
fn integer_len(field: u32, value: u64) -> usize {
    varint_len(u64::from(field) << 3) + varint_len(value)
}
fn bytes_len(field: u32, length: usize) -> usize {
    varint_len((u64::from(field) << 3) | 2) + varint_len(length as u64) + length
}

// A fixed initialized allocation: only checked slice writes are exposed, so
// private protobuf construction cannot reallocate after its first secret byte.
// Existing SecretBytes cannot transfer its Vec to the public graph API; the
// per-class byte owners are private. No new dependency or mlock claim is added.
struct GraphBytes {
    values: Vec<u8>,
    used: usize,
    #[cfg(test)]
    owner: &'static str,
    #[cfg(test)]
    allocation: (usize, usize),
}
impl GraphBytes {
    fn zeroed(length: usize, owner: &'static str) -> Self {
        let mut bytes = Self::adopt(vec![0; length], owner);
        bytes.used = 0;
        bytes
    }
    fn adopt(values: Vec<u8>, _owner: &'static str) -> Self {
        Self {
            used: values.len(),
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
            .filter(|&end| end <= self.values.len())
            .ok_or_else(|| err!(E2BIG, "COREML_GRAPH_CAPACITY"))?;
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
    fn integer(&mut self, field: u32, value: u64) -> EnclaveResult<()> {
        self.varint(u64::from(field) << 3)?;
        self.varint(value)
    }
    fn bytes(&mut self, field: u32, value: &[u8]) -> EnclaveResult<()> {
        self.varint((u64::from(field) << 3) | 2)?;
        self.varint(value.len() as u64)?;
        self.extend(value)
    }
    fn into_vec(mut self) -> Vec<u8> {
        #[cfg(test)]
        export_owner_tests::transferred(
            self.owner,
            self.used,
            self.allocation == (self.values.as_ptr() as usize, self.values.capacity()),
        );
        // The unused suffix is still its original zero initialization. Neither
        // truncation nor the explicit ownership transfer reallocates storage.
        self.values.truncate(self.used);
        std::mem::take(&mut self.values)
    }
}
impl std::ops::Deref for GraphBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.values[..self.used]
    }
}
impl Drop for GraphBytes {
    fn drop(&mut self) {
        for value in &mut self.values {
            // SAFETY: each initialized byte remains exclusively owned/live.
            unsafe {
                std::ptr::write_volatile(value, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        if !self.values.is_empty() {
            export_owner_tests::scrubbed(
                self.owner,
                self.used,
                &self.values,
                self.allocation == (self.values.as_ptr() as usize, self.values.capacity()),
            );
        }
    }
}

/// Exact framework input generated from a bounded admitted dense classifier.
#[derive(Debug)]
pub struct CanonicalLinearGraph {
    /// Canonical Model protobuf containing exactly one innerProduct layer.
    pub model: Vec<u8>,
    /// SHA-256 of the exact program bytes supplied to CoreML.
    pub sha256: String,
    /// Input feature width.
    pub input_width: usize,
    /// Output cardinality.
    pub classes: usize,
}

impl CanonicalLinearGraph {
    /// Build the complete graph from actual tensor values, admitting the only
    /// instantiated operator before any framework compilation or prediction.
    pub fn build(
        classes: usize,
        width: usize,
        weights: &[f32],
        bias: &[f32],
        attest: &mut OpAttestor,
    ) -> EnclaveResult<Self> {
        if !(2..=256).contains(&classes)
            || !(1..=256).contains(&width)
            || weights.len() != classes * width
            || bias.len() != classes
            || weights.iter().chain(bias).any(|x| !x.is_finite())
        {
            fail!(EINVAL, "COREML_LINEAR_SHAPE_OR_VALUE");
        }
        attest.admit(OpFamily::ClassifierHead)?;
        // Fields follow Apple's CoreML specification (coremltools 8.3):
        // Model/ModelDescription/FeatureDescription, NeuralNetworkLayer and
        // InnerProductLayerParams. No imported model bytes or custom operations.
        let mut description = Vec::new();
        bytes(1, &feature(b"input", width), &mut description);
        bytes(10, &feature(b"output", classes), &mut description);
        let dense_length = integer_len(1, width as u64)
            + integer_len(2, classes as u64)
            + integer_len(10, 1)
            + bytes_len(20, bytes_len(1, weights.len() * 4))
            + bytes_len(21, bytes_len(1, bias.len() * 4));
        let mut dense = GraphBytes::zeroed(dense_length, "coreml-export-dense");
        dense.integer(1, width as u64)?;
        dense.integer(2, classes as u64)?;
        dense.integer(10, 1)?;
        for (field, values) in [(20, weights), (21, bias)] {
            let mut floats = GraphBytes::zeroed(values.len() * 4, "coreml-export-floats");
            for value in values {
                floats.extend(&value.to_le_bytes())?;
            }
            let mut parameters =
                GraphBytes::zeroed(bytes_len(1, floats.len()), "coreml-export-parameters");
            parameters.bytes(1, &floats)?;
            dense.bytes(field, &parameters)?;
        }
        let layer_length = bytes_len(1, b"enclave_dense_classifier".len())
            + bytes_len(2, b"input".len())
            + bytes_len(3, b"output".len())
            + bytes_len(140, dense.len());
        let mut layer = GraphBytes::zeroed(layer_length, "coreml-export-layer");
        layer.bytes(1, b"enclave_dense_classifier")?;
        layer.bytes(2, b"input")?;
        layer.bytes(3, b"output")?;
        layer.bytes(140, &dense)?;
        drop(dense);
        let mut network = GraphBytes::zeroed(bytes_len(1, layer.len()), "coreml-export-network");
        network.bytes(1, &layer)?;
        drop(layer);
        let model_length =
            integer_len(1, 1) + bytes_len(2, description.len()) + bytes_len(500, network.len());
        let mut model = GraphBytes::zeroed(model_length, "coreml-export-model");
        model.integer(1, 1)?;
        model.bytes(2, &description)?;
        model.bytes(500, &network)?;
        drop(network);
        Ok(Self {
            sha256: hex::encode(Sha256::digest(&*model)),
            model: model.into_vec(),
            input_width: width,
            classes,
        })
    }
}

// The caller has already checked the original public load gates and bounds.
// Adopt decoded allocations immediately; the generic decoder owns refusals
// before it returns them. Native/unsupported-platform callbacks borrow the same
// guarded model bytes synchronously; public graph users retain their Vec API.
fn with_owned_load_graph<T>(
    idx: &TensorIndex,
    file: &[u8],
    classes: usize,
    width: usize,
    attest: &mut OpAttestor,
    load: impl FnOnce(&[u8], String) -> EnclaveResult<T>,
) -> EnclaveResult<T> {
    let weights = crate::arena::FloatScratch::new(
        idx.f32(file, "enclave_adapter.rlcd_head.weight", &[classes, width])?,
        "coreml-load-weights",
    );
    let bias = crate::arena::FloatScratch::new(
        if idx.shape("enclave_adapter.rlcd_head.bias").is_some() {
            idx.f32(file, "enclave_adapter.rlcd_head.bias", &[classes])?
        } else {
            vec![0.; classes]
        },
        "coreml-load-bias",
    );
    let graph = CanonicalLinearGraph::build(classes, width, &weights, &bias, attest)?;
    let model = GraphBytes::adopt(graph.model, "coreml-load-model");
    drop(bias);
    drop(weights);
    load(&model, graph.sha256)
}

/// Real CoreML-backed classifier. A mutex serializes prediction on the retained
/// native model; no raw logits cross the runner's typed service boundary.
pub struct CoreMlLinear {
    width: usize,
    classes: usize,
    graph_sha256: String,
    #[cfg(target_os = "macos")]
    native: std::sync::Mutex<NativeModel>,
}

impl std::fmt::Debug for CoreMlLinear {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreMlLinear")
            .field("width", &self.width)
            .field("classes", &self.classes)
            .field("graph_sha256", &self.graph_sha256)
            .finish()
    }
}

impl CoreMlLinear {
    /// Load only the closed classifier tensor vocabulary, create the actual
    /// graph, compile it with CPU-only CoreML and retain that executable model.
    pub fn load(idx: &TensorIndex, file: &[u8], attest: &mut OpAttestor) -> EnclaveResult<Self> {
        // Native framework allocations/caches are outside the existing secure
        // arenas. Keep the real compute experiment unavailable in release until
        // resource, interruption and physical-erasure acceptance is supplied.
        if !cfg!(debug_assertions) {
            fail!(EPERM, "COREML_DEVELOPMENT_ONLY");
        }
        if idx.tensors.keys().any(|name| {
            !matches!(
                name.as_str(),
                "enclave_adapter.rlcd_head.weight"
                    | "enclave_adapter.rlcd_head.bias"
                    | "enclave_adapter.ece_calibration_lut"
            )
        }) {
            fail!(EACCES, "COREML_UNSUPPORTED_CHECKPOINT_TENSOR");
        }
        let shape = idx
            .shape("enclave_adapter.rlcd_head.weight")
            .ok_or_else(|| err!(EINVAL, "COREML_HEAD_MISSING"))?;
        if shape.len() != 2 {
            fail!(EINVAL, "COREML_HEAD_SHAPE");
        }
        let (classes, width) = (shape[0], shape[1]);
        // Bound before allocating tensors or calling CoreML.
        if !(2..=256).contains(&classes) || !(1..=256).contains(&width) {
            fail!(E2BIG, "COREML_HEAD_BOUNDS");
        }
        with_owned_load_graph(idx, file, classes, width, attest, |model, graph_sha256| {
            #[cfg(target_os = "macos")]
            {
                let mut status = 0;
                // SAFETY: the bridge copies guarded graph bytes synchronously
                // and returns one retained native owner; it retains no borrow.
                let pointer =
                    unsafe { enclave_coreml_create(model.as_ptr(), model.len(), &mut status) };
                if pointer.is_null() || status != 0 {
                    fail!(EIO, "COREML_LOAD_FAILED", "status={status}");
                }
                Ok(Self {
                    width,
                    classes,
                    graph_sha256,
                    native: std::sync::Mutex::new(NativeModel(pointer)),
                })
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = (model, graph_sha256);
                fail!(ENOSYS, "COREML_PLATFORM_UNAVAILABLE");
            }
        })
    }
}

// This is the Rust side of the actual synchronous prediction path. The native
// callback borrows fixed slices only; it cannot grow either private allocation.
// Native bridge/framework copies remain separate owners outside this scope.
#[cfg(any(target_os = "macos", test))]
fn predict_owned(
    input: &[u8],
    width: usize,
    classes: usize,
    predict: impl FnOnce(&[f32], &mut [f32]) -> EnclaveResult<i32>,
) -> EnclaveResult<Vec<f32>> {
    let features = crate::arena::FloatScratch::new(
        crate::arena::ngram_features(input, width)?,
        "coreml-features",
    );
    let mut output = crate::arena::FloatScratch::new(vec![0.; classes], "coreml-output");
    let status = predict(&features, &mut output)?;
    if status != 0 || output.iter().any(|v| !v.is_finite()) {
        fail!(EIO, "COREML_PREDICTION_FAILED", "status={status}");
    }
    drop(features);
    Ok(output.into_vec())
}

impl RlcdBackend for CoreMlLinear {
    fn classes(&self) -> usize {
        self.classes
    }
    fn logits(&self, input: &[u8]) -> EnclaveResult<Vec<f32>> {
        #[cfg(target_os = "macos")]
        {
            predict_owned(input, self.width, self.classes, |features, output| {
                let native = self
                    .native
                    .lock()
                    .map_err(|_| err!(EIO, "COREML_MODEL_LOCK"))?;
                // SAFETY: buffers have exact checked lengths and remain
                // borrowed throughout synchronous prediction. The mutex
                // prevents concurrent native use and no borrowed data escapes.
                Ok(unsafe {
                    enclave_coreml_predict(
                        native.0,
                        features.as_ptr(),
                        features.len(),
                        output.as_mut_ptr(),
                        output.len(),
                    )
                })
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = input;
            fail!(ENOSYS, "COREML_PLATFORM_UNAVAILABLE");
        }
    }
}

#[cfg(target_os = "macos")]
struct NativeModel(*mut std::ffi::c_void);
// SAFETY: CoreML model ownership may move between threads, and every access is
// serialized by CoreMlLinear's mutex. The bridge retains no borrowed Rust data.
#[cfg(target_os = "macos")]
unsafe impl Send for NativeModel {}
#[cfg(target_os = "macos")]
impl Drop for NativeModel {
    fn drop(&mut self) {
        unsafe {
            enclave_coreml_destroy(self.0);
        }
    }
}

#[cfg(target_os = "macos")]
extern "C" {
    fn enclave_coreml_create(
        bytes: *const u8,
        len: usize,
        status: *mut i32,
    ) -> *mut std::ffi::c_void;
    fn enclave_coreml_predict(
        model: *mut std::ffi::c_void,
        input: *const f32,
        len: usize,
        output: *mut f32,
        count: usize,
    ) -> i32;
    fn enclave_coreml_destroy(model: *mut std::ffi::c_void);
}

#[cfg(test)]
mod export_owner_tests {
    use super::*;
    use crate::manifest::ExecutionClass;
    use std::cell::RefCell;

    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        Scrubbed(&'static str, usize, usize, bool, bool),
        Transferred(&'static str, usize, bool),
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
    // Test-only current-allocation observation after the production overwrite
    // and fence. Record no payload bytes, address or surviving reference.
    pub(super) fn scrubbed(owner: &'static str, used: usize, values: &[u8], stable: bool) {
        EVENTS.with(|events| {
            if let Some(events) = events.borrow_mut().as_mut() {
                events.push(Event::Scrubbed(
                    owner,
                    used,
                    values.len(),
                    values.iter().all(|&value| value == 0),
                    stable,
                ));
            }
        });
    }
    pub(super) fn transferred(owner: &'static str, used: usize, stable: bool) {
        EVENTS.with(|events| {
            if let Some(events) = events.borrow_mut().as_mut() {
                events.push(Event::Transferred(owner, used, stable));
            }
        });
    }

    // Retain the previous growable exporter as a test-only byte oracle. It
    // does not share the new size counters, cursor, guards or bounded writer.
    // Its ordinary copied allocations contain synthetic fixture weights only.
    fn previous_model(classes: usize, width: usize, weights: &[f32], bias: &[f32]) -> Vec<u8> {
        let mut description = Vec::new();
        bytes(1, &feature(b"input", width), &mut description);
        bytes(10, &feature(b"output", classes), &mut description);
        let mut dense = Vec::new();
        integer(1, width as u64, &mut dense);
        integer(2, classes as u64, &mut dense);
        integer(10, 1, &mut dense);
        for (field, values) in [(20, weights), (21, bias)] {
            let mut parameters = Vec::new();
            let floats: Vec<_> = values
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect();
            bytes(1, &floats, &mut parameters);
            bytes(field, &parameters, &mut dense);
        }
        let mut layer = Vec::new();
        bytes(1, b"enclave_dense_classifier", &mut layer);
        bytes(2, b"input", &mut layer);
        bytes(3, b"output", &mut layer);
        bytes(140, &dense, &mut layer);
        let mut network = Vec::new();
        bytes(1, &layer, &mut network);
        let mut model = Vec::new();
        integer(1, 1, &mut model);
        bytes(2, &description, &mut model);
        bytes(500, &network, &mut model);
        model
    }

    fn assert_clean_export(events: &[Event], load_model: bool) {
        let mut labels = Vec::new();
        for event in events {
            match event {
                Event::Scrubbed(owner, used, initialized, zero, stable) => {
                    assert_eq!(
                        used, initialized,
                        "exact-size construction has no unused private suffix"
                    );
                    assert!(*zero && *stable, "live allocation scrubbed without growth");
                    labels.push(*owner);
                }
                Event::Transferred(owner, _, stable) => {
                    assert_eq!(*owner, "coreml-export-model");
                    assert!(*stable);
                }
            }
        }
        let mut expected = vec![
            "coreml-export-parameters",
            "coreml-export-floats",
            "coreml-export-parameters",
            "coreml-export-floats",
            "coreml-export-dense",
            "coreml-export-layer",
            "coreml-export-network",
        ];
        if load_model {
            expected.push("coreml-load-model");
        }
        assert_eq!(labels, expected);
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::Transferred(..)))
                .count(),
            1
        );
    }

    #[test]
    fn actual_export_preserves_previous_complete_bytes_digest_and_no_growth_at_shape_varint_bounds()
    {
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
        for (classes, width) in [
            (2, 1),
            (2, 2),
            (2, 15),
            (2, 16),
            (2, 127),
            (2, 128),
            (2, 256),
            (3, 127),
            (127, 1),
            (128, 2),
            (255, 255),
            (256, 256),
        ] {
            let weights: Vec<_> = (0..classes * width)
                .map(|i| pattern[i % pattern.len()])
                .collect();
            let bias: Vec<_> = (0..classes)
                .map(|i| pattern[(i + 3) % pattern.len()])
                .collect();
            let expected = previous_model(classes, width, &weights, &bias);
            let mut attest = OpAttestor::new(ExecutionClass::DiscriminativeRlcd, &[]);
            begin();
            let graph =
                CanonicalLinearGraph::build(classes, width, &weights, &bias, &mut attest).unwrap();
            let events = finish();
            assert_clean_export(&events, false);
            assert_eq!(graph.model, expected);
            assert_eq!(graph.sha256, hex::encode(Sha256::digest(&expected)));
            assert_eq!((graph.classes, graph.input_width), (classes, width));
            assert!(
                matches!(events.last(), Some(Event::Transferred("coreml-export-model", len, true))
                if *len == expected.len())
            );
        }
    }

    #[test]
    fn actual_export_shape_nonfinite_and_admission_refusals_precede_private_byte_copies() {
        for (classes, width, weights, bias) in [
            (257, 1, vec![1.; 257], vec![0.; 257]),
            (2, 0, vec![], vec![0.; 2]),
            (2, 2, vec![1.; 3], vec![0.; 2]),
            (2, 2, vec![1.; 4], vec![0.]),
            (2, 2, vec![1., 2., 3., f32::NAN], vec![0.; 2]),
            (2, 2, vec![1.; 4], vec![0., f32::INFINITY]),
            (2, 2, vec![1.; 4], vec![f32::NEG_INFINITY, 0.]),
        ] {
            let mut attest = OpAttestor::new(ExecutionClass::DiscriminativeRlcd, &[]);
            begin();
            assert!(
                CanonicalLinearGraph::build(classes, width, &weights, &bias, &mut attest)
                    .unwrap_err()
                    .is("COREML_LINEAR_SHAPE_OR_VALUE")
            );
            assert!(finish().is_empty());
        }
        let mut denied = OpAttestor::new(ExecutionClass::ArCausal, &[]);
        begin();
        assert!(
            CanonicalLinearGraph::build(2, 2, &[1.; 4], &[0.; 2], &mut denied)
                .unwrap_err()
                .is("GRAPH_OP_NOT_AUTHORISED")
        );
        assert!(finish().is_empty());
    }

    #[test]
    fn actual_private_byte_writer_scrubs_partial_capacity_refusal_and_unwind_without_growth() {
        begin();
        let refused = (|| -> EnclaveResult<()> {
            let mut bytes = GraphBytes::zeroed(12, "synthetic-refusal");
            bytes.extend(b"synthetic")?;
            bytes.extend(b"long")
        })()
        .unwrap_err();
        assert!(refused.is("COREML_GRAPH_CAPACITY"));
        assert_eq!(
            finish(),
            vec![Event::Scrubbed("synthetic-refusal", 9, 12, true, true)]
        );

        begin();
        let result = std::panic::catch_unwind(|| {
            let mut bytes = GraphBytes::zeroed(12, "synthetic-unwind");
            bytes.extend(b"secret").unwrap();
            panic!("synthetic private protobuf writer unwind");
        });
        assert!(result.is_err());
        assert_eq!(
            finish(),
            vec![Event::Scrubbed("synthetic-unwind", 6, 12, true, true)]
        );
    }

    fn checkpoint(include_bias: bool) -> (TensorIndex, Vec<u8>) {
        let mut tensors = vec![(
            "enclave_adapter.rlcd_head.weight",
            vec![2, 2],
            vec![1., 2., -3., 0.5],
        )];
        if include_bias {
            tensors.push(("enclave_adapter.rlcd_head.bias", vec![2], vec![0.25, -0.5]));
        }
        let file = crate::safetensors::build_f32(&tensors, &[]);
        (crate::safetensors::parse(&file).unwrap(), file)
    }
    fn take_load_float_events() -> Vec<crate::arena::float_scratch_tests::Event> {
        crate::arena::float_scratch_tests::finish()
            .into_iter()
            .filter(|event| match event {
                crate::arena::float_scratch_tests::Event::Scrubbed(owner, ..)
                | crate::arena::float_scratch_tests::Event::Transferred(owner, ..) => {
                    owner.starts_with("coreml-load-")
                }
            })
            .collect()
    }
    fn expected_load_float_events(bias: bool) -> Vec<crate::arena::float_scratch_tests::Event> {
        use crate::arena::float_scratch_tests::Event::Scrubbed;
        if bias {
            vec![
                Scrubbed("coreml-load-bias", 2, true),
                Scrubbed("coreml-load-weights", 4, true),
            ]
        } else {
            vec![Scrubbed("coreml-load-weights", 4, true)]
        }
    }

    #[test]
    fn actual_load_helper_scrubs_decoded_copies_before_callback_and_model_on_success_error_unwind()
    {
        for include_bias in [false, true] {
            let (index, file) = checkpoint(include_bias);
            let expected = previous_model(
                2,
                2,
                &[1., 2., -3., 0.5],
                if include_bias {
                    &[0.25, -0.5]
                } else {
                    &[0., 0.]
                },
            );
            for mode in 0..3 {
                let mut attest = OpAttestor::new(ExecutionClass::DiscriminativeRlcd, &[]);
                begin();
                crate::arena::float_scratch_tests::begin();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    with_owned_load_graph(&index, &file, 2, 2, &mut attest, |model, digest| {
                        assert_eq!(model, expected);
                        assert_eq!(digest, hex::encode(Sha256::digest(&expected)));
                        assert_eq!(
                            take_load_float_events(),
                            expected_load_float_events(true),
                            "decoded copies are scrubbed before synchronous native load"
                        );
                        match mode {
                            0 => Ok(17),
                            1 => Err(err!(EIO, "SYNTHETIC_COREML_LOAD_REFUSAL")),
                            _ => panic!("synthetic synchronous load unwind"),
                        }
                    })
                }));
                match mode {
                    0 => assert_eq!(result.unwrap().unwrap(), 17),
                    1 => assert!(result
                        .unwrap()
                        .unwrap_err()
                        .is("SYNTHETIC_COREML_LOAD_REFUSAL")),
                    _ => assert!(result.is_err()),
                }
                assert_clean_export(&finish(), true);
            }
        }
    }

    #[test]
    fn actual_load_helper_scrubs_earlier_weights_on_bias_error_and_both_on_graph_admission_error() {
        let (mut index, file) = checkpoint(true);
        index
            .tensors
            .get_mut("enclave_adapter.rlcd_head.bias")
            .unwrap()
            .shape = vec![3];
        let mut allowed = OpAttestor::new(ExecutionClass::DiscriminativeRlcd, &[]);
        begin();
        crate::arena::float_scratch_tests::begin();
        let error = with_owned_load_graph::<()>(&index, &file, 2, 2, &mut allowed, |_, _| {
            panic!("bad bias shape must precede native callback");
        })
        .unwrap_err();
        assert!(error.is("TENSOR_SHAPE"));
        assert_eq!(take_load_float_events(), expected_load_float_events(false));
        assert!(finish().is_empty());

        let (index, file) = checkpoint(true);
        let mut denied = OpAttestor::new(ExecutionClass::ArCausal, &[]);
        begin();
        crate::arena::float_scratch_tests::begin();
        let error = with_owned_load_graph::<()>(&index, &file, 2, 2, &mut denied, |_, _| {
            panic!("graph admission refusal must precede native callback");
        })
        .unwrap_err();
        assert!(error.is("GRAPH_OP_NOT_AUTHORISED"));
        assert_eq!(take_load_float_events(), expected_load_float_events(true));
        assert!(finish().is_empty());
    }
}

#[cfg(test)]
mod prediction_owner_tests {
    use super::*;
    use crate::arena::float_scratch_tests::{begin, finish, Event};

    fn failures() -> Vec<Event> {
        vec![
            Event::Scrubbed("coreml-output", 3, true),
            Event::Scrubbed("coreml-features", 8, true),
        ]
    }

    #[test]
    fn actual_rust_prediction_helper_preserves_features_output_and_cleans_features_before_transfer()
    {
        for input in [
            &b""[..],
            &b"safe synthetic input"[..],
            "café 安全".as_bytes(),
            &b"\xff\x00\xfe"[..],
        ] {
            let before = input.to_vec();
            let expected = crate::arena::ngram_features(input, 8).unwrap();
            begin();
            let result = predict_owned(input, 8, 3, |features, output| {
                assert_eq!(
                    features.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
                    expected.iter().map(|v| v.to_bits()).collect::<Vec<_>>()
                );
                assert_eq!(
                    output,
                    &[0.0, 0.0, 0.0],
                    "guard owns output before its first private write"
                );
                output.copy_from_slice(&[4.0, -2.0, 0.25]);
                Ok(0)
            })
            .unwrap();
            assert_eq!(result, vec![4.0, -2.0, 0.25]);
            assert_eq!(input, before);
            assert_eq!(
                finish(),
                vec![
                    Event::Scrubbed("coreml-features", 8, true),
                    Event::Transferred("coreml-output", 3)
                ]
            );
        }
    }

    #[test]
    fn actual_rust_prediction_helper_scrubs_partial_native_status_and_nonfinite_refusals() {
        // Exercise the actual Rust production helper without claiming CoreML
        // framework execution on unsupported platforms. The injected synchronous
        // writer stands in only for native status/partial-output behavior.
        for (status, value) in [
            (-6, 17.0),
            (-73, 21.0),
            (0, f32::NAN),
            (0, f32::INFINITY),
            (0, f32::NEG_INFINITY),
        ] {
            begin();
            let error = predict_owned(b"private fixture", 8, 3, |_, output| {
                output[0] = 0.5;
                output[1] = value;
                Ok(status)
            })
            .unwrap_err();
            assert!(error.is("COREML_PREDICTION_FAILED"));
            assert!(error.to_string().contains(&format!("status={status}")));
            assert_eq!(finish(), failures());
        }
    }

    #[test]
    fn actual_rust_prediction_helper_lock_error_and_unwind_scrub_both_fixed_allocations() {
        begin();
        // Use a genuinely poisoned standard mutex, as the actual native path
        // does, without constructing or invoking an unqualified native model.
        let lock = std::sync::Mutex::new(());
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = lock.lock().unwrap();
            panic!("synthetic model mutex poison");
        }));
        let error = predict_owned(b"private fixture", 8, 3, |_, _| {
            let _held = lock.lock().map_err(|_| err!(EIO, "COREML_MODEL_LOCK"))?;
            Ok(0)
        })
        .unwrap_err();
        assert!(error.is("COREML_MODEL_LOCK"));
        assert_eq!(finish(), failures());

        begin();
        let result = std::panic::catch_unwind(|| {
            predict_owned(b"private fixture", 8, 3, |_, output| {
                output[0] = 73.5;
                panic!("synthetic synchronous prediction unwind");
            })
        });
        assert!(result.is_err());
        assert_eq!(finish(), failures());
    }

    #[test]
    fn actual_rust_prediction_helper_feature_failure_stays_before_callback_and_private_output() {
        begin();
        let error = predict_owned(b"private fixture", 0, 3, |_, _| {
            panic!("invalid feature width must never reach prediction");
        })
        .unwrap_err();
        assert!(error.is("FEATURE_WIDTH_ZERO"));
        assert!(finish().is_empty());
    }
}
