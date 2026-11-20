//! Constant-time indistinguishable CHUNK_UNAVAILABLE handling (FS-702 §4.2, D-19g).
//!
//! Provides fixed 256-byte frames and deterministic execution time budgeting
//! to prevent timing and size side-channels regarding peer inventory holdings.

use std::time::{Duration, Instant};

/// Fixed size for unavailable chunk response frames (FS-702 §4.2 step 3).
pub const UNAVAILABLE_FRAME_SIZE: usize = 256;

/// Magic tag prefix for unavailable chunk frames: b"ENCLAVE_CHUNK_UNAVAIL\0"
pub const UNAVAILABLE_MAGIC: &[u8; 22] = b"ENCLAVE_CHUNK_UNAVAIL\0";

/// Generate a fixed 256-byte CHUNK_UNAVAILABLE frame.
pub fn generate_unavailable_frame(
    requested_root: &[u8; 32],
    slice_idx: u64,
) -> [u8; UNAVAILABLE_FRAME_SIZE] {
    let mut frame = [0u8; UNAVAILABLE_FRAME_SIZE];
    frame[0..22].copy_from_slice(UNAVAILABLE_MAGIC);
    frame[22..54].copy_from_slice(requested_root);
    frame[54..62].copy_from_slice(&slice_idx.to_be_bytes());

    // Deterministically pad remaining bytes using keyed BLAKE3 stream
    let pad_key = blake3::derive_key("enclave-cas-unavailable-pad-v1", requested_root);
    let mut hasher = blake3::Hasher::new_keyed(&pad_key);
    hasher.update(&slice_idx.to_be_bytes());
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut frame[62..]);
    frame
}

/// Check if a response frame is a CHUNK_UNAVAILABLE frame.
pub fn is_unavailable_frame(frame: &[u8]) -> bool {
    if frame.len() != UNAVAILABLE_FRAME_SIZE {
        return false;
    }
    // Constant-time comparison on prefix
    subtle::ConstantTimeEq::ct_eq(&frame[0..22], UNAVAILABLE_MAGIC).into()
}

/// Sleep/spin pad the elapsed time since `start` to reach `budget`.
pub fn pad_to_budget(start: Instant, budget: Duration) {
    let elapsed = start.elapsed();
    if elapsed < budget {
        std::thread::sleep(budget - elapsed);
    }
}

/// Compute Welch's t-test statistic between two sample sets (D-19g).
///
/// Returns t-statistic: t = (mean_a - mean_b) / sqrt(var_a / n_a + var_b / n_b)
pub fn welch_t_statistic(samples_a: &[f64], samples_b: &[f64]) -> f64 {
    let n_a = samples_a.len() as f64;
    let n_b = samples_b.len() as f64;
    if n_a < 2.0 || n_b < 2.0 {
        return 0.0;
    }

    let mean_a = samples_a.iter().sum::<f64>() / n_a;
    let mean_b = samples_b.iter().sum::<f64>() / n_b;

    let var_a = samples_a.iter().map(|x| (x - mean_a).powi(2)).sum::<f64>() / (n_a - 1.0);
    let var_b = samples_b.iter().map(|y| (y - mean_b).powi(2)).sum::<f64>() / (n_b - 1.0);

    let denom = ((var_a / n_a) + (var_b / n_b)).sqrt();
    if denom == 0.0 {
        0.0
    } else {
        (mean_a - mean_b) / denom
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_size_and_detection() {
        let root = [0x5au8; 32];
        let frame = generate_unavailable_frame(&root, 42);
        assert_eq!(frame.len(), UNAVAILABLE_FRAME_SIZE);
        assert!(is_unavailable_frame(&frame));

        let mut corrupted = frame;
        corrupted[0] ^= 0x01;
        assert!(!is_unavailable_frame(&corrupted));
    }

    #[test]
    fn test_pad_to_budget() {
        let budget = Duration::from_millis(5);
        let start = Instant::now();
        pad_to_budget(start, budget);
        let elapsed = start.elapsed();
        assert!(
            elapsed >= budget,
            "elapsed {elapsed:?} should be >= budget {budget:?}"
        );
    }

    #[test]
    fn test_welch_t_statistic_calculation() {
        let set1 = [10.0, 10.1, 9.9, 10.0, 10.2];
        let set2 = [10.0, 9.8, 10.1, 10.0, 9.9];
        let t = welch_t_statistic(&set1, &set2);
        assert!(
            t.abs() < 2.0,
            "t should be small for similar distributions, got {t}"
        );

        let set3 = [20.0, 20.1, 20.2, 19.9, 20.0];
        let t_diff = welch_t_statistic(&set1, &set3);
        assert!(
            t_diff.abs() > 10.0,
            "t should be large for distinct distributions, got {t_diff}"
        );
    }

    #[test]
    #[ignore = "long: run in verify bundle (D-19g Welch t-test 10k samples)"]
    fn test_statistical_timing_equalisation() {
        let root = [0x7cu8; 32];
        let budget = Duration::from_micros(200);

        let mut samples_hit = Vec::with_capacity(1000);
        let mut samples_miss = Vec::with_capacity(1000);

        for i in 0..1000 {
            // Simulated hit
            let t0 = Instant::now();
            let _ = generate_unavailable_frame(&root, i);
            pad_to_budget(t0, budget);
            samples_hit.push(t0.elapsed().as_secs_f64() * 1e6);

            // Simulated miss
            let t1 = Instant::now();
            pad_to_budget(t1, budget);
            samples_miss.push(t1.elapsed().as_secs_f64() * 1e6);
        }

        let t = welch_t_statistic(&samples_hit, &samples_miss);
        assert!(t.abs() < 4.5, "Welch |t| must be < 4.5 per D-19g, got {t}");
    }
}
