//! UID 701 serves LLaDA within its owned-memory ceiling: the fleet daemon
//! shuts down with RSS_CEILING_BREACHED above 48 MiB of physical footprint,
//! which in-process service tests do not enforce. This file holds one test
//! so the measured process is the runner alone (weights are mapped, the
//! model computes in the worker process).
//!
//! Needs target/llada-pack and MCPMAC_MLX_WORKER; otherwise it reports a
//! skip unless MCPMAC_REQUIRE_LLADA is set.

mod common;

use common::{mapped_package_or_skip, operator};
use enclave_core::daemon::DaemonId;
use enclave_core::resource::{current_phys_footprint_bytes, MemoryCeiling};
use enclave_model_runnerd::dfa::ArgSchema;
use enclave_model_runnerd::service::{RunnerRequest, RunnerResponse};

/// As in the smoke run: SmolLM2 binds and generates first on the same
/// runner, then LLaDA rebinds. Memory the first model left behind must not
/// push LLaDA's generation over the ceiling.
#[test]
fn llada_after_smollm2_stays_within_the_runner_ceiling() {
    let Some(pack) = mapped_package_or_skip("llada-pack", "MCPMAC_REQUIRE_LLADA", "LLADA_FOOTPRINT_CHECKED") else { return };
    let Some(ar) = mapped_package_or_skip("smollm2-pack", "MCPMAC_REQUIRE_LLADA", "LLADA_FOOTPRINT_CHECKED") else { return };
    let ceiling = MemoryCeiling::for_daemon(DaemonId::ModelRunner);
    let mib = |b: u64| b as f64 / 1048576.0;
    let start = current_phys_footprint_bytes().unwrap();
    // The fleet samples continuously, so the peak is what counts.
    // Peak per phase: 0 SmolLM2, 1 LLaDA bind, 2 LLaDA generation.
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
    let peaks = std::sync::Arc::new([AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)]);
    let phase = std::sync::Arc::new(AtomicUsize::new(0));
    let done = std::sync::Arc::new(AtomicBool::new(false));
    let sampler = {
        let (peaks, phase, done) = (peaks.clone(), phase.clone(), done.clone());
        std::thread::spawn(move || while !done.load(Relaxed) {
            peaks[phase.load(Relaxed)].fetch_max(current_phys_footprint_bytes().unwrap(), Relaxed);
            std::thread::sleep(std::time::Duration::from_millis(5));
        })
    };
    let service = pack.runner_publishing(&[&ar, &pack]);
    assert!(matches!(ar.bind_on(&service, &ar.bytes()), Ok(RunnerResponse::Bound { .. })), "bind smollm2");
    let ar_prompt = "<|im_start|>user\nClassify the support ticket priority. Reply in JSON.<|im_end|>\n<|im_start|>assistant\n";
    let ar_schema = ArgSchema::Object(vec![("priority".into(), ArgSchema::Enum(vec!["urgent".into(), "routine".into()]))]);
    assert!(service.handle(&operator(), RunnerRequest::GenerateStructured {
        schema: ar_schema, len: 32, prompt: Some(ar_prompt.as_bytes().to_vec().into()),
    }).is_ok(), "smollm2 generation");
    let after_ar = current_phys_footprint_bytes().unwrap();
    phase.store(1, Relaxed);
    assert!(matches!(pack.bind_on(&service, &pack.bytes()), Ok(RunnerResponse::Bound { .. })), "bind llada");
    let bound = current_phys_footprint_bytes().unwrap();
    phase.store(2, Relaxed);
    let prompt = "<|startoftext|><|start_header_id|>user<|end_header_id|>\n\nClassify the support ticket priority as \
        routine, important, urgent or critical. Reply in JSON. Ticket: Production database is down and customers \
        cannot log in.<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n";
    let schema = ArgSchema::Object(vec![(
        "priority".into(),
        ArgSchema::Enum(["routine", "important", "urgent", "critical"].map(String::from).to_vec()),
    )]);
    let response = service.handle(&operator(), RunnerRequest::GenerateStructured {
        schema, len: 32, prompt: Some(prompt.as_bytes().to_vec().into()),
    });
    let generated = current_phys_footprint_bytes().unwrap();
    done.store(true, Relaxed);
    sampler.join().unwrap();
    let [ar_peak, bind_peak, generate_peak] = [0, 1, 2].map(|i| peaks[i].load(Relaxed));
    let peak = ar_peak.max(bind_peak).max(generate_peak);
    eprintln!("LLADA_FOOTPRINT: start {:.1}, smollm2 peak {:.1} (after {:.1}), llada bind peak {:.1} (bound {:.1}), \
        generation peak {:.1} (after {:.1}) MiB", mib(start), mib(ar_peak), mib(after_ar), mib(bind_peak), mib(bound),
        mib(generate_peak), mib(generated));
    assert!(matches!(response, Ok(RunnerResponse::Text(_))), "{response:?}");
    ceiling.check_value(bound).expect("footprint after bind");
    ceiling.check_value(generated).expect("footprint after generation");
    ceiling.check_value(peak).expect("peak footprint");
}
