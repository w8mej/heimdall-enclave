//! Class 1 `DISCRIMINATIVE_RLCD` (FS-701 §4.1): typed, quantized output
//! simplex + local anti-binary-search ledger (`<= 12.0` bits / 24 h per
//! entity) + eagerly verified ECE LUT + cross-silicon margin.

use enclave_core::error::EnclaveResult;
use enclave_core::fail;
use enclave_core::label::Conf;
use enclave_core::profile::Profile;
use enclave_core::qif::{millibits_for_outcomes, QifCharge, QifLedger};
use enclave_core::secret::SecretKey32;
use serde::{Deserialize, Serialize};

use crate::arena::{matvec, ngram_features, softmax, FloatScratch};
use crate::ece::CalibrationLut;
use crate::safetensors::TensorIndex;

/// Maximum enum cardinality crossing the boundary.
pub const MAX_CARDINALITY: u64 = 4096;

/// Backend: raw scores for `k` classes.
pub trait RlcdBackend: Send + Sync + std::fmt::Debug {
    /// Number of classes the head emits.
    fn classes(&self) -> usize;
    /// Logits.
    fn logits(&self, input: &[u8]) -> EnclaveResult<Vec<f32>>;
}

/// Reference linear head over hashed byte n-grams:
/// `enclave_adapter.rlcd_head.weight [K, D]` (+ optional `.bias [K]`).
#[derive(Debug, Clone)]
pub struct LinearHead {
    w: Vec<f32>,
    b: Vec<f32>,
    k: usize,
    d: usize,
}

impl LinearHead {
    /// Load.
    pub fn load(idx: &TensorIndex, file: &[u8]) -> EnclaveResult<Self> {
        let shape = idx
            .shape("enclave_adapter.rlcd_head.weight")
            .ok_or_else(|| enclave_core::err!(EINVAL, "TENSOR_MISSING", "rlcd_head.weight"))?
            .to_vec();
        if shape.len() != 2 || shape[0] < 2 || shape[1] == 0 {
            fail!(EINVAL, "TENSOR_SHAPE", "rlcd_head.weight");
        }
        let (k, d) = (shape[0], shape[1]);
        let w = idx.f32(file, "enclave_adapter.rlcd_head.weight", &[k, d])?;
        let b = if idx.shape("enclave_adapter.rlcd_head.bias").is_some() {
            idx.f32(file, "enclave_adapter.rlcd_head.bias", &[k])?
        } else {
            vec![0.0; k]
        };
        Ok(Self { w, b, k, d })
    }

    /// Construct directly from weights and biases.
    pub fn new(w: Vec<f32>, b: Vec<f32>, k: usize, d: usize) -> EnclaveResult<Self> {
        if k < 2 || d == 0 || w.len() != k * d || b.len() != k {
            fail!(EINVAL, "LINEAR_HEAD_SHAPE");
        }
        Ok(Self { w, b, k, d })
    }
}

impl RlcdBackend for LinearHead {
    fn classes(&self) -> usize {
        self.k
    }
    fn logits(&self, input: &[u8]) -> EnclaveResult<Vec<f32>> {
        let x = FloatScratch::new(ngram_features(input, self.d)?, "rlcd-features");
        let mut y = FloatScratch::new(matvec(&self.w, self.k, self.d, &x)?, "rlcd-head-result");
        y.iter_mut().zip(&self.b).for_each(|(a, b)| *a += b);
        Ok(y.into_vec())
    }
}

/// Output modes. No free-form strings, no raw `float32`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum RlcdMode {
    /// Arg-max over the `K` typed choices (`log2 K` bits).
    Choice,
    /// `p(class) >= threshold` evaluated inside the adapter (1 bit).
    Threshold {
        /// Class.
        class: u32,
        /// Threshold in permille.
        threshold_permille: u16,
    },
    /// 4-bit quantized decile `0..=10` of the calibrated confidence (`log2 11` bits).
    Decile,
}

/// The typed result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RlcdOutput {
    /// Index in `0..K`.
    Choice(u64),
    /// Boolean.
    Bool(bool),
    /// Decile `0..=10`.
    Decile(u8),
}

impl RlcdOutput {
    /// As an enum index (for `declassify_enum`).
    pub fn index(self) -> u64 {
        match self {
            Self::Choice(i) => i,
            Self::Bool(b) => b as u64,
            Self::Decile(d) => d as u64,
        }
    }
}

/// The gate.
#[derive(Debug)]
pub struct RlcdGate {
    backend: Box<dyn RlcdBackend>,
    lut: CalibrationLut,
    ledger: QifLedger,
    k_local: SecretKey32,
    margin: f64,
    max_fanin: usize,
}

/// Request.
#[derive(Debug, Clone)]
pub struct RlcdRequest<'a> {
    /// Payload.
    pub input: &'a [u8],
    /// Declared cardinality (must equal the head's `K` for `Choice`).
    pub cardinality: u64,
    /// Output mode.
    pub mode: RlcdMode,
    /// Provenance entity keys (`ek_*`).
    pub entities: &'a [String],
    /// Input confidentiality.
    pub conf: Conf,
}

impl RlcdGate {
    /// Bind.
    pub fn new(
        backend: Box<dyn RlcdBackend>,
        lut: CalibrationLut,
        profile: Profile,
        cap_mb: i64,
        margin: f64,
        max_fanin: u32,
    ) -> EnclaveResult<Self> {
        Ok(Self {
            backend,
            lut,
            ledger: QifLedger::new(profile).with_entity_cap(cap_mb)?,
            k_local: SecretKey32::random(),
            margin,
            max_fanin: max_fanin.min(64) as usize,
        })
    }

    /// Head cardinality.
    pub fn classes(&self) -> usize {
        self.backend.classes()
    }

    /// Bits used in the window for an entity key.
    pub fn used_mb(&mut self, key: &str, now_ms: u64) -> i64 {
        self.ledger.used(key, now_ms)
    }

    /// Evaluate.
    pub fn evaluate(
        &mut self,
        r: &RlcdRequest<'_>,
        now_ms: u64,
    ) -> EnclaveResult<(RlcdOutput, i64)> {
        if r.entities.len() > self.max_fanin {
            fail!(
                E2BIG,
                "PROVENANCE_FANIN_EXCEEDED",
                "{} > {}",
                r.entities.len(),
                self.max_fanin
            );
        }
        let k = self.backend.classes() as u64;
        let outcomes = match r.mode {
            RlcdMode::Choice => {
                if r.cardinality != k {
                    fail!(
                        EINVAL,
                        "DECLASSIFY_CARDINALITY_MISMATCH",
                        "{} != head K {k}",
                        r.cardinality
                    );
                }
                k
            }
            RlcdMode::Threshold {
                class,
                threshold_permille,
            } => {
                if class as u64 >= k || threshold_permille > 1000 || r.cardinality != 2 {
                    fail!(EINVAL, "RLCD_THRESHOLD");
                }
                2
            }
            RlcdMode::Decile => {
                if r.cardinality != 11 {
                    fail!(EINVAL, "RLCD_DECILE_CARDINALITY");
                }
                11
            }
        };
        if !(2..=MAX_CARDINALITY).contains(&outcomes) {
            fail!(E2BIG, "CARDINALITY_OUT_OF_RANGE");
        }
        let logits = FloatScratch::new(self.backend.logits(r.input)?, "rlcd-logits");
        let p = FloatScratch::new(softmax(&logits)
            .ok_or_else(|| enclave_core::err!(EIO, "RLCD_SIMPLEX", "non-finite logits"))?, "rlcd-probability");
        if p.len() as u64 != k || (p.iter().sum::<f64>() - 1.0).abs() > 1e-6 {
            fail!(EIO, "RLCD_SIMPLEX");
        }
        let (arg, pmax) =
            p.iter().enumerate().fold(
                (0usize, f64::MIN),
                |a, (i, x)| if *x > a.1 { (i, *x) } else { a },
            );
        // Unknown provenance shares one conservative bucket. Rephrasing the
        // payload must not create fresh authority to declassify it.
        let mut entities: Vec<String> = r.entities.to_vec();
        if entities.is_empty() {
            entities.push(enclave_core::qif::entity_key(
                &self.k_local,
                "uid701:rlcd:unknown-origin",
            ));
        }
        let mb = millibits_for_outcomes(outcomes);
        self.ledger.charge(
            &QifCharge {
                entities,
                conf: r.conf,
                unstructured: r.entities.is_empty() && r.conf >= Conf::C3,
                millibits: mb,
            },
            now_ms,
        )?;
        let out = match r.mode {
            RlcdMode::Choice => {
                // Cross-silicon margin: refuse a near-tie between the top two
                // classes before selecting any typed class.
                let mut sorted = FloatScratch::new(p.to_vec(), "rlcd-sorted");
                // Equal probabilities are interchangeable here. Use the
                // in-place sort so no allocator-owned merge scratch is made.
                sorted.sort_unstable_by(|a, b| b.total_cmp(a));
                if sorted.len() > 1 && sorted[0] - sorted[1] < self.margin {
                    fail!(
                        EAGAIN,
                        "RLCD_LOW_MARGIN",
                        "no class is selected for an ambiguous prediction"
                    )
                } else {
                    RlcdOutput::Choice(arg as u64)
                }
            }
            RlcdMode::Threshold {
                class,
                threshold_permille,
            } => {
                let pc = self.lut.apply(p[class as usize]);
                let thr = threshold_permille as f64 / 1000.0;
                RlcdOutput::Bool(pc >= thr + self.margin)
            }
            RlcdMode::Decile => {
                RlcdOutput::Decile((self.lut.apply(pmax) * 10.0).round().clamp(0.0, 10.0) as u8)
            }
        };
        Ok((out, mb))
    }
}

#[cfg(test)]
mod f109_tests {
    use super::*;
    #[derive(Debug)]
    struct Tie;
    impl RlcdBackend for Tie {
        fn classes(&self) -> usize {
            2
        }
        fn logits(&self, _: &[u8]) -> EnclaveResult<Vec<f32>> {
            Ok(vec![0.0, 0.0])
        }
    }
    #[test]
    fn f109_ambiguous_choice_is_an_error_not_class_zero() {
        let mut g = RlcdGate::new(
            Box::new(Tie),
            CalibrationLut::identity(),
            Profile::L2,
            12_000,
            0.001,
            64,
        )
        .unwrap();
        assert!(g
            .evaluate(
                &RlcdRequest {
                    input: b"x",
                    cardinality: 2,
                    mode: RlcdMode::Choice,
                    entities: &[],
                    conf: Conf::C3
                },
                1
            )
            .unwrap_err()
            .is("RLCD_LOW_MARGIN"));
    }

    #[derive(Debug)]
    struct ConfidentZero;
    impl RlcdBackend for ConfidentZero {
        fn classes(&self) -> usize { 2 }
        fn logits(&self, _: &[u8]) -> EnclaveResult<Vec<f32>> { Ok(vec![10.0, 0.0]) }
    }

    #[test]
    fn f109_confident_class_zero_remains_a_valid_charged_choice() {
        let mut gate = RlcdGate::new(Box::new(ConfidentZero), CalibrationLut::identity(),
            Profile::L2, 12_000, 0.001, 64).unwrap();
        let result = gate.evaluate(&RlcdRequest {
            input: b"valid confident class zero", cardinality: 2,
            mode: RlcdMode::Choice, entities: &[], conf: Conf::C3,
        }, 1).unwrap();
        assert_eq!(result, (RlcdOutput::Choice(0), 1000));
    }
}

#[cfg(test)]
mod float_owner_tests {
    use super::*;
    use crate::arena::float_scratch_tests::{begin,finish,Event};

    #[test]
    fn yk11_actual_linear_head_scrubs_features_on_success_and_matvec_error() {
        let input = b"synthetic classifier fixture";
        let mut head = LinearHead::new(vec![1.0,2.0,-1.0,0.5,-2.0,0.0,3.0,1.0],
            vec![0.25,-0.5],2,4).unwrap();
        let features = ngram_features(input,4).unwrap();
        let expected = vec![features[0]+2.0*features[1]-features[2]+0.5*features[3]+0.25,
            -2.0*features[0]+3.0*features[2]+features[3]-0.5];
        begin();
        let logits = head.logits(input).unwrap();
        assert_eq!(logits.len(),expected.len());
        assert!(logits.iter().zip(&expected).all(|(actual,expected)| (actual-expected).abs()<1e-6),
            "successful public logits transfer remains intact");
        assert_eq!(finish(),vec![Event::Transferred("rlcd-head-result",2),Event::Scrubbed("rlcd-features",4,true)]);
        head.w.pop();
        begin();
        assert!(head.logits(input).unwrap_err().is("MATVEC_SHAPE"));
        assert_eq!(finish(),vec![Event::Scrubbed("rlcd-features",4,true)]);
    }

    #[derive(Debug)]
    struct Scores(Vec<f32>);
    impl RlcdBackend for Scores {
        fn classes(&self) -> usize { 2 }
        fn logits(&self, _: &[u8]) -> EnclaveResult<Vec<f32>> { Ok(self.0.clone()) }
    }
    fn gate(scores: Vec<f32>, cap: i64) -> RlcdGate {
        RlcdGate::new(Box::new(Scores(scores)),CalibrationLut::identity(),Profile::L2,cap,0.001,64).unwrap()
    }
    fn request<'a>(mode: RlcdMode, cardinality: u64, entities: &'a [String]) -> RlcdRequest<'a> {
        RlcdRequest {input:b"synthetic classification",cardinality,mode,entities,conf:Conf::C3}
    }
    fn result_events(width: usize, sorted: bool) -> Vec<Event> {
        let mut events = vec![Event::Transferred("softmax",width)];
        if sorted { events.push(Event::Scrubbed("rlcd-sorted",width,true)); }
        events.extend([Event::Scrubbed("rlcd-probability",width,true),Event::Scrubbed("rlcd-logits",width,true)]);
        events
    }

    #[test]
    fn yk11_actual_rlcd_typed_success_scrubs_logits_probabilities_and_choice_copy() {
        let entities = vec![format!("ek_{:032x}",21)];
        for (mode,cardinality,expected,charge,sorted) in [
            (RlcdMode::Choice,2,RlcdOutput::Choice(0),1000,true),
            (RlcdMode::Threshold {class:0,threshold_permille:500},2,RlcdOutput::Bool(true),1000,false),
            (RlcdMode::Decile,11,RlcdOutput::Decile(10),3460,false),
        ] {
            let mut gate = gate(vec![10.0,0.0],12_000);
            begin();
            assert_eq!(gate.evaluate(&request(mode,cardinality,&entities),1).unwrap(),(expected,charge));
            assert_eq!(finish(),result_events(2,sorted));
            assert_eq!(gate.used_mb(&entities[0],1),charge,"cleanup does not reset accepted QIF progress");
        }
    }

    #[test]
    fn yk11_actual_rlcd_nonfinite_and_wrong_width_scrub_before_simplex_refusal() {
        let entities = vec![format!("ek_{:032x}",22)];
        for scores in [vec![f32::NAN,0.0],vec![1.0,2.0,3.0]] {
            let width = scores.len(); let finite = scores.iter().all(|value| value.is_finite());
            let mut gate = gate(scores,12_000);
            begin();
            assert!(gate.evaluate(&request(RlcdMode::Choice,2,&entities),1).unwrap_err().is("RLCD_SIMPLEX"));
            assert_eq!(finish(),if finite {result_events(width,false)} else {vec![Event::Scrubbed("rlcd-logits",width,true)]});
            assert_eq!(gate.used_mb(&entities[0],1),0,"invalid simplex never reaches charge");
        }
    }

    #[test]
    fn yk11_actual_rlcd_qif_denial_and_low_margin_scrub_without_rolling_back_accounting() {
        let entities = vec![format!("ek_{:032x}",23)];
        let req = request(RlcdMode::Choice,2,&entities);
        let mut limited = gate(vec![10.0,0.0],1000);
        assert_eq!(limited.evaluate(&req,1).unwrap(),(RlcdOutput::Choice(0),1000));
        begin();
        assert!(limited.evaluate(&req,2).unwrap_err().is("QIF_BUDGET_EXCEEDED"));
        assert_eq!(finish(),result_events(2,false));
        assert_eq!(limited.used_mb(&entities[0],2),1000,"refusal cannot reset existing QIF charge");

        let mut ambiguous = gate(vec![0.0,0.0],12_000);
        begin();
        assert!(ambiguous.evaluate(&req,1).unwrap_err().is("RLCD_LOW_MARGIN"));
        assert_eq!(finish(),result_events(2,true));
        assert_eq!(ambiguous.used_mb(&entities[0],1),1000,"post-charge margin refusal preserves its charge");
    }
}
