//! Finite trained-component tests. Positive cached-model cases are explicitly
//! ignored by default, then required to run with --ignored in recorded evidence.
//! Missing inputs never become a successful trained execution.

use enclave_model_runnerd::backends::coreml::bert::{
    CanonicalBertGraph, CoreMlBertEncoder, CHECKPOINT_BYTES, CHECKPOINT_SHA256,
    MODEL_BYTES, MODEL_SHA256, OUTPUT_VALUES,
};
use sha2::{Digest, Sha256};

const ORACLE: &[u8] = include_bytes!("fixtures/bert8-reference-v1.json");
const ORACLE_SHA256: &str = "3a7d35e3d6e06a683d00e5b8406f6eefc383f6bf512255f14b80beb814d0e2c9";

fn oracle() -> serde_json::Value {
    assert_eq!(hex::encode(Sha256::digest(ORACLE)), ORACLE_SHA256);
    serde_json::from_slice(ORACLE).unwrap()
}

fn checkpoint() -> Vec<u8> {
    let path = std::env::var_os("depot_BERT_CHECKPOINT")
        .expect("set depot_BERT_CHECKPOINT to the existing pinned cache; no download or silent skip");
    let bytes = std::fs::read(path).expect("the selected cached checkpoint must be readable");
    assert_eq!(bytes.len(), CHECKPOINT_BYTES);
    assert_eq!(hex::encode(Sha256::digest(&bytes)), CHECKPOINT_SHA256);
    bytes
}

#[test]
fn retained_bert_oracle_has_exact_identity_full_shapes_and_independent_inputs() {
    let reference = oracle();
    assert_eq!(reference["checkpoint_sha256"], CHECKPOINT_SHA256);
    assert_eq!(reference["model_sha256"], MODEL_SHA256);
    assert_eq!(reference["model_bytes"], MODEL_BYTES);
    assert_eq!(reference["layers"].as_array().unwrap().len(), 51);
    let cases = reference["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    for case in cases {
        assert_eq!(case["token_ids"].as_array().unwrap().len(), 8);
        let values = case["expected"].as_array().unwrap();
        assert_eq!(values.len(), OUTPUT_VALUES);
        assert!(values.iter().all(|value| value.as_f64().is_some_and(f64::is_finite)));
    }
    assert_ne!(cases[0]["token_ids"], cases[1]["token_ids"]);
    assert_ne!(cases[0]["expected"], cases[1]["expected"]);
}

#[test]
fn trained_component_release_or_platform_and_untrusted_checkpoint_refusals_are_explicit() {
    let error = CoreMlBertEncoder::load(&[]).unwrap_err();
    assert!(error.is(if !cfg!(debug_assertions) { "COREML_BERT_DEVELOPMENT_ONLY" }
        else if !cfg!(target_os = "macos") { "COREML_BERT_PLATFORM_UNAVAILABLE" }
        else { "COREML_BERT_CHECKPOINT_PIN" }));
    for untrusted in [vec![], vec![0xff; 10], vec![0xff; CHECKPOINT_BYTES]] {
        let error = CanonicalBertGraph::from_checkpoint(&untrusted).unwrap_err();
        assert!(error.is(if cfg!(debug_assertions) { "COREML_BERT_CHECKPOINT_PIN" }
            else { "COREML_BERT_DEVELOPMENT_ONLY" }));
    }
}

#[test]
#[ignore = "requires explicit existing pinned checkpoint and canonical model paths"]
fn trained_bert_rust_export_matches_entire_retained_canonical_program() {
    assert!(cfg!(debug_assertions), "a release build cannot execute this experiment");
    let checkpoint = checkpoint();
    let graph = CanonicalBertGraph::from_checkpoint(&checkpoint).unwrap();
    let path = std::env::var_os("depot_BERT_CANONICAL_MODEL")
        .expect("set depot_BERT_CANONICAL_MODEL to the existing pinned .mlmodel cache");
    let expected = std::fs::read(path).expect("the existing canonical model must be readable");
    assert_eq!(expected.len(), MODEL_BYTES);
    assert_eq!(hex::encode(Sha256::digest(&expected)), MODEL_SHA256);
    assert!(graph.model == expected, "Rust export differs from the entire independent canonical program");
    let mut corrupted = checkpoint;
    for offset in [0, 8, CHECKPOINT_BYTES - 1] {
        corrupted[offset] ^= 1;
        assert!(CanonicalBertGraph::from_checkpoint(&corrupted).unwrap_err().is("COREML_BERT_CHECKPOINT_PIN"));
        corrupted[offset] ^= 1;
    }
    eprintln!("COREML_BERT_RUST_CANONICAL_EXPORT=true bytes={MODEL_BYTES}");
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[derive(Clone, Default, serde::Serialize)]
    struct Samples {
        max_physical_bytes: Option<u64>,
        samples: u64,
        unknown: u64,
    }
    struct Sampler {
        stop: Arc<AtomicBool>,
        values: Arc<Mutex<Samples>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl Sampler {
        fn start() -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let values = Arc::new(Mutex::new(Samples::default()));
            let ended = stop.clone(); let shared = values.clone();
            let thread = std::thread::spawn(move || {
                loop {
                    let sample = enclave_core::resource::current_phys_footprint_bytes();
                    let mut values = shared.lock().unwrap();
                    match sample {
                        Some(bytes) => {
                            values.samples += 1;
                            values.max_physical_bytes = Some(values.max_physical_bytes.unwrap_or(0).max(bytes));
                        }
                        None => values.unknown += 1,
                    }
                    drop(values);
                    if ended.load(Ordering::Acquire) { break; }
                    std::thread::sleep(Duration::from_millis(5));
                }
            });
            Self { stop, values, thread: Some(thread) }
        }
        fn finish(mut self) -> Samples {
            self.stop.store(true, Ordering::Release);
            self.thread.take().unwrap().join().expect("the physical sampler must complete");
            let result = self.values.lock().unwrap().clone();
            result
        }
    }
    impl Drop for Sampler {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() { let _ = thread.join(); }
        }
    }

    fn tokens(case: &serde_json::Value) -> Vec<u32> {
        case["token_ids"].as_array().unwrap().iter()
            .map(|value| u32::try_from(value.as_u64().unwrap()).unwrap()).collect()
    }
    fn compare(actual: &[f32], case: &serde_json::Value, reference: &serde_json::Value) -> f64 {
        let expected = case["expected"].as_array().unwrap();
        assert_eq!(actual.len(), OUTPUT_VALUES); assert_eq!(expected.len(), OUTPUT_VALUES);
        let absolute = reference["absolute_tolerance"].as_f64().unwrap();
        let relative = reference["relative_tolerance"].as_f64().unwrap();
        let mut maximum = 0f64;
        for (i, (&actual, expected)) in actual.iter().zip(expected).enumerate() {
            let expected = expected.as_f64().unwrap(); let actual = f64::from(actual);
            assert!(actual.is_finite() && expected.is_finite());
            let delta = (actual - expected).abs();
            assert!(delta <= absolute + relative * expected.abs(), "independent full reference mismatch at {i}");
            maximum = maximum.max(delta);
        }
        maximum
    }

    #[test]
    #[ignore = "requires actual macOS CoreML and explicit existing pinned checkpoint path"]
    fn trained_bert_actual_rust_native_encoder_matches_full_oracles_and_reports_physical_stages() {
        assert!(cfg!(debug_assertions), "release must refuse before native I/O");
        let checkpoint = checkpoint(); let reference = oracle();
        let cases = reference["cases"].as_array().unwrap();
        let sampler = Sampler::start();
        let encoder = Arc::new(CoreMlBertEncoder::load(&checkpoint).unwrap());
        let load_memory = encoder.load_memory().clone();
        let mut errors = Vec::new(); let mut vectors = Vec::new(); let mut prediction_memory = Vec::new();
        for case in cases {
            let result = encoder.encode(&tokens(case)).unwrap();
            errors.push(compare(&result.hidden, case, &reference));
            prediction_memory.push(result.memory);
            vectors.push(result.hidden);
        }
        let difference = vectors[0].iter().zip(vectors[1]).map(|(&a,b)| (a-b).abs()).fold(0f32, f32::max);
        assert!(difference > 0.001, "the trained result must depend on its token input");
        let arbitrary = encoder.encode(&[0, 1, 2, 3, 4, 5, 30_520, 30_521]).unwrap();
        assert!(arbitrary.hidden.iter().all(|value| value.is_finite()));
        prediction_memory.push(arbitrary.memory);
        for invalid in [vec![0;7], vec![0;9], vec![30_522;8], vec![u32::MAX;8]] {
            assert!(encoder.encode(&invalid).unwrap_err().is("COREML_BERT_TOKEN_IDS"));
        }
        // Real concurrent callers reach the same owned model; the Rust mutex
        // must serialize their native access and preserve each full result.
        let mut workers = Vec::new();
        for case in cases {
            let encoder = encoder.clone(); let case = case.clone(); let reference = reference.clone();
            workers.push(std::thread::spawn(move || {
                let output = encoder.encode(&tokens(&case)).unwrap();
                let error = compare(&output.hidden, &case, &reference);
                (error, output.memory)
            }));
        }
        for worker in workers {
            let (error, memory) = worker.join().unwrap(); errors.push(error); prediction_memory.push(memory);
        }
        let encoder = Arc::try_unwrap(encoder).expect("all native callers must be joined before close");
        let drop_memory = encoder.close().unwrap();
        // Exercise ordinary Drop ownership too, without claiming cache erasure.
        let ordinary = CoreMlBertEncoder::load(&checkpoint).unwrap();
        let ordinary_load_memory = ordinary.load_memory().clone();
        drop(ordinary);
        let after_ordinary_drop = enclave_core::resource::current_phys_footprint_bytes();
        let samples = sampler.finish();
        let stage_max = [load_memory.before_export, load_memory.after_export, load_memory.before_compile,
            load_memory.after_compile, load_memory.after_load, load_memory.after_graph,
            ordinary_load_memory.before_export, ordinary_load_memory.after_export,
            ordinary_load_memory.before_compile, ordinary_load_memory.after_compile,
            ordinary_load_memory.after_load, ordinary_load_memory.after_graph,
            drop_memory.before, drop_memory.after, after_ordinary_drop].into_iter()
            .chain(prediction_memory.iter().flat_map(|p| [p.before, p.after]))
            .flatten().max();
        let observed_max = samples.max_physical_bytes.into_iter().chain(stage_max).max();
        let cap_breached = observed_max.is_some_and(|bytes| bytes > 48 * 1024 * 1024);
        let report = serde_json::json!({
            "schema":1, "scope":"debug Rust trained encoder numerical/lifecycle evidence only",
            "checkpoint_sha256":CHECKPOINT_SHA256, "canonical_model_sha256":MODEL_SHA256,
            "oracle_sha256":ORACLE_SHA256, "native_rust_execution":true,
            "source_layers":51, "observed_compiled_layers":96, "full_reference_values_per_case":1024,
            "full_reference_cases":2, "maximum_errors":errors, "input_difference_max":difference,
            "actual_predictions":5, "actual_loads":2, "explicit_close":true, "ordinary_drop":true,
            "first_load_physical_points":load_memory, "second_load_physical_points":ordinary_load_memory,
            "prediction_physical_points":prediction_memory,
            "drop_physical_points":drop_memory, "after_ordinary_drop":after_ordinary_drop,
            "self_samples_every_ms":5, "sampling":samples, "observed_max_physical_bytes":observed_max,
            "sampled_48MiB_cap_exceeded":cap_breached,
            "physical_resource_status":if cap_breached {"FAIL_CAP_BREACH"} else {"INCOMPLETE_NOT_ACCEPTED"},
            "memory_source":"Darwin TASK_VM_INFO phys_footprint; whole test process, no baseline subtraction",
            "memory_limit":"Stage points and5ms self samples are not independent guaranteed peaks or full child/compiler/cache accounting",
            "production_admission_accepted":false, "resource_acceptance":false, "erasure_acceptance":false,
        });
        eprintln!("COREML_BERT_RUST_EXECUTION=true {}", serde_json::to_string(&report).unwrap());
    }
}
