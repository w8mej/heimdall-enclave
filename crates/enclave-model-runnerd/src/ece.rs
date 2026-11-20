//! Empirical calibration agreement over 15 equal-mass bins on one pinned
//! corpus. This statistic does not establish out-of-sample calibration or
//! bound declassification leakage. Dataset/LUT independence requires curator
//! provenance outside this computation.

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};

use crate::classes::rlcd::RlcdBackend;

/// Bins.
pub const BINS: usize = 15;
/// Bound.
pub const ECE_MAX: f64 = 0.015;
/// Minimum corpus size (at least 20 samples per bin).
pub const MIN_SAMPLES: usize = BINS * 20;

/// One labelled prediction.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
pub struct Sample {
    /// Raw confidence of the predicted class.
    pub p: f64,
    /// Whether the prediction was correct.
    pub y: u8,
}

/// Corpus item. Production model evaluation requires exactly x/y, never p.
/// Precomputed p/y remains an offline arithmetic-fixture format for load_corpus.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusItem {
    /// Input sequence / text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// Pre-computed raw confidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p: Option<f64>,
    /// Ground-truth class or offline correctness label (no u8 truncation).
    pub y: usize,
}

/// Parse a JSONL corpus and check its pinned digest.
pub fn load_corpus(bytes: &[u8], pinned_blake3: &str) -> EnclaveResult<Vec<Sample>> {
    if blake3::hash(bytes).to_hex().as_str() != pinned_blake3 {
        fail!(
            EACCES,
            "CALIBRATION_CORPUS_DIGEST",
            "corpus is not the TUF-pinned enclave-calib-eval-v1"
        );
    }
    let mut v = Vec::new();
    for (i, line) in bytes.split(|b| *b == b'\n').enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let item: CorpusItem = serde_json::from_slice(line)
            .map_err(|e| err!(EINVAL, "CALIBRATION_CORPUS", "line {i}: {e}"))?;
        let p = match item.p {
            Some(p) => {
                if !(0.0..=1.0).contains(&p) || item.y > 1 {
                    fail!(EINVAL, "CALIBRATION_CORPUS", "line {i}");
                }
                p
            }
            None => fail!(
                EINVAL,
                "CALIBRATION_CORPUS",
                "line {i}: missing pre-computed confidence 'p' (use verify_with_model for 'x')"
            ),
        };
        v.push(Sample { p, y: item.y as u8 });
    }
    Ok(v)
}

/// Equal-mass ECE.
pub fn ece_equal_mass(samples: &[Sample]) -> EnclaveResult<f64> {
    if samples.len() < MIN_SAMPLES {
        fail!(
            EINVAL,
            "CALIBRATION_CORPUS_TOO_SMALL",
            "{} < {MIN_SAMPLES}",
            samples.len()
        );
    }
    let mut s: Vec<Sample> = samples.to_vec();
    s.sort_by(|a, b| a.p.total_cmp(&b.p));
    let n = s.len();
    let mut ece = 0.0;
    let mut start = 0;
    for b in 0..BINS {
        // Bin sizes differ by at most one.
        let end = (b + 1) * n / BINS;
        let bin = &s[start..end];
        if !bin.is_empty() {
            let conf = bin.iter().map(|x| x.p).sum::<f64>() / bin.len() as f64;
            let acc = bin.iter().map(|x| x.y as f64).sum::<f64>() / bin.len() as f64;
            ece += (bin.len() as f64 / n as f64) * (acc - conf).abs();
        }
        start = end;
    }
    Ok(ece)
}

/// Calibration LUT: 15 calibrated probabilities for equal-width raw-confidence bins.
#[derive(Debug, Clone, PartialEq)]
pub struct CalibrationLut(pub [f64; BINS]);

impl CalibrationLut {
    /// From a 15-element tensor (monotone non-decreasing, in `[0, 1]`).
    pub fn from_tensor(v: &[f32]) -> EnclaveResult<Self> {
        if v.len() != BINS {
            fail!(EINVAL, "ECE_LUT_SHAPE");
        }
        let mut a = [0.0; BINS];
        for (i, x) in v.iter().enumerate() {
            if !(0.0..=1.0).contains(x) || (i > 0 && (*x as f64) < a[i - 1]) {
                fail!(EINVAL, "ECE_LUT_NOT_MONOTONE");
            }
            a[i] = *x as f64;
        }
        Ok(Self(a))
    }
    /// Identity LUT (bin midpoints).
    pub fn identity() -> Self {
        let mut a = [0.0; BINS];
        for (i, x) in a.iter_mut().enumerate() {
            *x = (i as f64 + 0.5) / BINS as f64;
        }
        Self(a)
    }
    /// Map a raw confidence.
    pub fn apply(&self, p: f64) -> f64 {
        let i = ((p.clamp(0.0, 1.0) * BINS as f64) as usize).min(BINS - 1);
        self.0[i]
    }
}

/// Admission gate: ECE of LUT-calibrated corpus predictions `<= ece_max`.
pub fn verify(lut: &CalibrationLut, corpus: &[Sample], ece_max: f64) -> EnclaveResult<f64> {
    if !(0.0..=ECE_MAX).contains(&ece_max) {
        fail!(EACCES, "ECE_MAX_ABOVE_0_015");
    }
    let calibrated: Vec<Sample> = corpus
        .iter()
        .map(|s| Sample {
            p: lut.apply(s.p),
            y: s.y,
        })
        .collect();
    let e = ece_equal_mass(&calibrated)?;
    if e > ece_max {
        fail!(EACCES, "ECE_ABOVE_BOUND", "ECE {e:.5} > {ece_max}");
    }
    Ok(e)
}

/// Admission gate for RLCD models (GAP-33): runs model inference on every `{x, y}`
/// sample in chunks, applies the calibration LUT, and computes equal-mass ECE.
pub fn verify_with_model(
    backend: &dyn RlcdBackend,
    lut: &CalibrationLut,
    corpus_bytes: &[u8],
    pinned_blake3: &str,
    ece_max: f64,
) -> EnclaveResult<f64> {
    if blake3::hash(corpus_bytes).to_hex().as_str() != pinned_blake3 {
        fail!(
            EACCES,
            "CALIBRATION_CORPUS_DIGEST",
            "corpus is not the TUF-pinned enclave-calib-eval-v1"
        );
    }
    if !(0.0..=ECE_MAX).contains(&ece_max) {
        fail!(EACCES, "ECE_MAX_ABOVE_0_015");
    }
    let mut samples = Vec::new();
    const MAX_CORPUS_SAMPLES: usize = 100_000;
    for (i, line) in corpus_bytes.split(|b| *b == b'\n').enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if samples.len() >= MAX_CORPUS_SAMPLES {
            fail!(E2BIG, "CALIBRATION_CORPUS_TOO_LARGE");
        }
        let item: CorpusItem = serde_json::from_slice(line)
            .map_err(|e| err!(EINVAL, "CALIBRATION_CORPUS", "line {i}: {e}"))?;
        if item.p.is_some() {
            fail!(EINVAL, "CALIBRATION_PRECOMPUTED_FORBIDDEN", "line {i}");
        }
        if item.y >= backend.classes() {
            fail!(EINVAL, "CALIBRATION_LABEL_RANGE", "line {i}");
        }
        let (raw_p, is_correct) = if let Some(x) = &item.x {
            let logits = backend.logits(x.as_bytes())?;
            let probs = crate::arena::softmax(&logits)
                .ok_or_else(|| err!(EIO, "NON_FINITE_LOGITS", "line {i}"))?;
            if probs.len() != backend.classes() {
                fail!(EIO, "CALIBRATION_HEAD_SHAPE", "line {i}");
            }
            let (pred, conf) = probs
                .iter()
                .copied()
                .enumerate()
                .max_by(|a, b| a.1.total_cmp(&b.1))
                .ok_or_else(|| err!(EINVAL, "EMPTY_LOGITS", "line {i}"))?;
            let correct = if pred == item.y { 1u8 } else { 0u8 };
            (conf, correct)
        } else {
            fail!(
                EINVAL,
                "CALIBRATION_CORPUS",
                "line {i}: expected model input 'x'"
            );
        };
        samples.push(Sample {
            p: lut.apply(raw_p),
            y: is_correct,
        });
    }
    let e = ece_equal_mass(&samples)?;
    if e > ece_max {
        fail!(EACCES, "ECE_ABOVE_BOUND", "ECE {e:.5} > {ece_max}");
    }
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus(n: usize, skew: f64) -> Vec<Sample> {
        // Deterministic, perfectly calibrated at skew 0: in each block of 10
        // samples with confidence c, round(10c) are correct.
        (0..n)
            .map(|i| {
                let c = (1 + (i / 10) % 9) as f64 / 10.0;
                let correct = ((i % 10) as f64) < (c * 10.0).round();
                Sample {
                    p: (c + skew).clamp(0.0, 1.0),
                    y: correct as u8,
                }
            })
            .collect()
    }

    #[test]
    fn calibrated_passes_overconfident_fails() {
        let good = corpus(3000, 0.0);
        let e = ece_equal_mass(&good).unwrap();
        assert!(e <= 0.015, "{e}");
        let bad = corpus(3000, 0.08);
        assert!(ece_equal_mass(&bad).unwrap() > 0.05);
        assert!(verify(&CalibrationLut::identity(), &bad, 0.015).is_err());
        assert!(ece_equal_mass(&good[..100])
            .unwrap_err()
            .is("CALIBRATION_CORPUS_TOO_SMALL"));
    }

    #[test]
    fn equal_mass_bins_balance() {
        // All confidences identical: equal-mass still forms 15 bins.
        let s: Vec<Sample> = (0..300)
            .map(|i| Sample {
                p: 0.7,
                y: (i % 10 < 7) as u8,
            })
            .collect();
        assert!(ece_equal_mass(&s).unwrap() < 0.05);
    }
}
