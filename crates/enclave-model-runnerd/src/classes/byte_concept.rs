//! Class 4 `BYTE_OR_CONCEPT` (FS-701 §4.4):
//!
//! * `BLT`: inputs are UTF-8 NFKC-normalised with zero-width / bidi controls
//!   stripped; outputs pass a byte-level DFA (invariant to patch splits) that
//!   rejects raw SSN / PAN digit runs and any `SYNTH-*` surrogate whose
//!   per-session `BLAKE3_keyed` tag does not verify (confused-deputy forgery).
//! * `LCM` / `SONAR`: concepts pass `LEACE` null-space projection, bounded-norm
//!   clamping and `N(0, σ²)` smoothing with `σ >= σ_min`, then the `SONAR`
//!   cosine canary breaker (`cos >= 0.88` trips).

use enclave_core::error::EnclaveResult;
use enclave_core::secret::SecretKey32;
use enclave_core::{err, fail};
use unicode_normalization::UnicodeNormalization;

use crate::arena::{
    finite, matvec, ngram_features, output_guard, wipe_or_abort, Arena, WipeReport,
};
use crate::safetensors::TensorIndex;
use crate::topology::{OpAttestor, OpFamily};

fn invisible(c: char) -> bool {
    matches!(c as u32, 0x00ad | 0x034f | 0x061c | 0x115f | 0x1160 | 0x17b4 | 0x17b5
        | 0x180b..=0x180f | 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x206f
        | 0x3164 | 0xfe00..=0xfe0f | 0xfeff | 0xffa0 | 0xfff0..=0xfff8
        | 0xe0000..=0xe007f | 0xe0100..=0xe01ef)
}

/// Compatibility normalization with invisible format/bidi controls removed.
pub fn canonicalize(input: &[u8]) -> EnclaveResult<String> {
    let s = std::str::from_utf8(input).map_err(|_| err!(EINVAL, "INPUT_NOT_UTF8"))?;
    Ok(s.nfkc().filter(|c| !invisible(*c)).collect())
}

/// Surrogate tag verifier (the per-session key is issued by UID 703 and
/// relayed by UID 704). Possession of this symmetric key also permits minting.
#[derive(Debug)]
pub struct SurrogateVerifier {
    key: SecretKey32,
}

impl SurrogateVerifier {
    /// From the session key.
    pub fn new(key: SecretKey32) -> Self {
        Self { key }
    }
    /// v2 tag: 128 bits of domain-separated keyed BLAKE3, base16 alphabet a–p.
    /// Matches the coordinated UID 703 issuer; legacy 24-bit tags are refused.
    pub fn tag(&self, core: &str) -> String {
        let mut message = b"enclave-surrogate-v2\0".to_vec();
        message.extend_from_slice(core.as_bytes());
        self.key.mac(&message)[..16]
            .iter()
            .flat_map(|b| [char::from(b'a' + (b >> 4)), char::from(b'a' + (b & 15))])
            .collect()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum S {
    Scan,
    Digits(u8),
}

/// Byte-level output validator. Scans raw bytes (not tokens), so `BLT`
/// patch boundaries cannot split a pattern past it.
pub fn byte_dfa_validate(out: &[u8], v: Option<&SurrogateVerifier>) -> EnclaveResult<()> {
    // Validate the canonical semantics of output too, including fullwidth PII.
    let canonical = canonicalize(out)?;
    let out = canonical.as_bytes();
    // 1. Every `SYNTH-` surrogate must carry a valid tag.
    let mut i = 0;
    let mut covered = vec![false; out.len()];
    while let Some(p) = out[i..]
        .windows(6)
        .position(|w| w == b"SYNTH-")
        .map(|p| p + i)
    {
        let end = out[p..]
            .iter()
            .position(|b| !(b.is_ascii_alphanumeric() || *b == b'-'))
            .map_or(out.len(), |e| p + e);
        let tok =
            std::str::from_utf8(&out[p..end]).map_err(|_| err!(EACCES, "SURROGATE_FORGED"))?;
        let (core, tag) = tok
            .rsplit_once('-')
            .ok_or_else(|| err!(EACCES, "SURROGATE_FORGED"))?;
        let Some(v) = v else {
            fail!(EACCES, "SURROGATE_WITHOUT_SESSION_KEY")
        };
        if !core
            .strip_prefix("SYNTH-")
            .is_some_and(|body| !body.is_empty() && body.split('-').all(|part| !part.is_empty()))
            || tag.len() != 32
            || !enclave_core::secret::ct_eq(v.tag(core).as_bytes(), tag.as_bytes())
        {
            fail!(
                EACCES,
                "SURROGATE_FORGED",
                "tag does not verify under the session key"
            );
        }
        covered[p..end].iter_mut().for_each(|c| *c = true);
        i = end;
    }
    // 2. Digit-run automaton outside verified surrogates: separators `-`, ` `,
    //    `.` are transparent; 9 digits (SSN) or 13..19 Luhn-valid (PAN) trip.
    let mut st = S::Scan;
    let mut digits: Vec<u8> = Vec::with_capacity(19);
    let check = |d: &[u8]| -> EnclaveResult<()> {
        for n in [9, 13, 14, 15, 16, 17, 18, 19] {
            if d.len() < n {
                continue;
            }
            let window = &d[d.len() - n..];
            if (n == 9 && enclave_core::pii::ssn_valid(window))
                || (n >= 13 && enclave_core::pii::luhn_ok(window))
            {
                fail!(
                    EACCES,
                    "UNREDACTED_PII_IN_OUTPUT",
                    "byte-DFA digit window of {n}"
                );
            }
        }
        Ok(())
    };
    for (j, b) in out.iter().enumerate() {
        if covered[j] {
            if st != S::Scan {
                digits.clear();
                st = S::Scan;
            }
            continue;
        }
        st = match (st, b) {
            (_, b'0'..=b'9') => {
                digits.push(*b);
                if digits.len() > 19 {
                    digits.remove(0);
                }
                check(&digits)?;
                S::Digits(digits.len() as u8)
            }
            (S::Digits(n), b'-' | b' ' | b'.') => S::Digits(n),
            (S::Digits(_), _) => {
                digits.clear();
                S::Scan
            }
            (S::Scan, _) => S::Scan,
        };
    }
    Ok(())
}

/// `LEACE` projection onto the orthogonal complement of the PII subspace.
#[derive(Debug, Clone)]
pub struct Leace {
    basis: Vec<Vec<f32>>,
}

impl Leace {
    /// From `r` spanning vectors (Gram–Schmidt orthonormalised).
    pub fn new(vectors: &[Vec<f32>]) -> EnclaveResult<Self> {
        let mut basis: Vec<Vec<f32>> = Vec::new();
        let width = vectors.first().map_or(0, Vec::len);
        for v in vectors {
            crate::arena::validate_probe(v, width)?;
            let mut u = v.clone();
            for b in &basis {
                let d: f32 = u.iter().zip(b).map(|(x, y)| x * y).sum();
                u.iter_mut().zip(b).for_each(|(x, y)| *x -= d * y);
            }
            let n = u.iter().map(|x| x * x).sum::<f32>().sqrt();
            if n < 1e-6 {
                continue;
            }
            u.iter_mut().for_each(|x| *x /= n);
            basis.push(u);
        }
        if basis.is_empty() {
            fail!(EINVAL, "LEACE_EMPTY");
        }
        Ok(Self { basis })
    }
    /// `P_⊥ c`.
    pub fn project(&self, c: &mut [f32]) {
        for b in &self.basis {
            let d: f32 = c.iter().zip(b).map(|(x, y)| x * y).sum();
            c.iter_mut().zip(b).for_each(|(x, y)| *x -= d * y);
        }
    }
    /// Residual component along the PII subspace (tests / receipts).
    pub fn residual(&self, c: &[f32]) -> f32 {
        self.basis
            .iter()
            .map(|b| c.iter().zip(b).map(|(x, y)| x * y).sum::<f32>().abs())
            .fold(0.0, f32::max)
    }
}

fn gaussian() -> f32 {
    // Box–Muller over the OS CSPRNG.
    let u1 = ((enclave_core::rng::u64() >> 11) as f64 + 1.0) / (1u64 << 53) as f64;
    let u2 = (enclave_core::rng::u64() >> 11) as f64 / (1u64 << 53) as f64;
    ((-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()) as f32
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let d: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let n =
        a.iter().map(|x| x * x).sum::<f32>().sqrt() * b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if n == 0.0 {
        0.0
    } else {
        d / n
    }
}

/// Concept stack.
pub trait ConceptBackend: Send + Sync + std::fmt::Debug {
    /// Concept width.
    fn width(&self) -> usize;
    /// `SONAR` encoder.
    fn encode(&self, text: &str) -> EnclaveResult<Vec<f32>>;
    /// Concept denoiser step.
    fn denoise(&self, c: &mut [f32]) -> EnclaveResult<()>;
    /// Surface decoder.
    fn decode(&self, c: &[f32]) -> EnclaveResult<Vec<u8>>;
}

/// Reference `SONAR`-style stack: `enclave_adapter.lcm.sonar_encoder.proj
/// [d, F]` over hashed n-grams, `enclave_adapter.lcm.concept_denoiser.weight
/// [d, d]`, nearest-phrase decoder over a codebook in `__metadata__`
/// (`enclave_adapter.lcm.codebook`, JSON string array).
#[derive(Debug, Clone)]
pub struct ReferenceConcept {
    proj: Vec<f32>,
    den: Vec<f32>,
    d: usize,
    f: usize,
    codebook: Vec<(Vec<f32>, String)>,
}

impl ReferenceConcept {
    /// Load.
    pub fn load(idx: &TensorIndex, file: &[u8]) -> EnclaveResult<Self> {
        let sh = idx
            .shape("enclave_adapter.lcm.sonar_encoder.proj")
            .ok_or_else(|| err!(EINVAL, "TENSOR_MISSING", "sonar_encoder.proj"))?
            .to_vec();
        if sh.len() != 2 {
            fail!(EINVAL, "TENSOR_SHAPE");
        }
        let (d, f) = (sh[0], sh[1]);
        let mut s = Self {
            proj: idx.f32(file, "enclave_adapter.lcm.sonar_encoder.proj", &[d, f])?,
            den: idx.f32(file, "enclave_adapter.lcm.concept_denoiser.weight", &[d, d])?,
            d,
            f,
            codebook: vec![],
        };
        let phrases: Vec<String> = serde_json::from_str(
            idx.metadata
                .get("enclave_adapter.lcm.codebook")
                .map(String::as_str)
                .unwrap_or("[]"),
        )
        .map_err(|_| err!(EINVAL, "LCM_CODEBOOK"))?;
        for p in phrases {
            let v = s.encode(&p)?;
            s.codebook.push((v, p));
        }
        Ok(s)
    }
}

impl ConceptBackend for ReferenceConcept {
    fn width(&self) -> usize {
        self.d
    }
    fn encode(&self, text: &str) -> EnclaveResult<Vec<f32>> {
        matvec(
            &self.proj,
            self.d,
            self.f,
            &ngram_features(text.as_bytes(), self.f)?,
        )
    }
    fn denoise(&self, c: &mut [f32]) -> EnclaveResult<()> {
        let y = matvec(&self.den, self.d, self.d, c)?;
        c.copy_from_slice(&y);
        finite(c, "concept")
    }
    fn decode(&self, c: &[f32]) -> EnclaveResult<Vec<u8>> {
        let best = self
            .codebook
            .iter()
            .max_by(|a, b| cosine(&a.0, c).total_cmp(&cosine(&b.0, c)))
            .ok_or_else(|| err!(EIO, "LCM_CODEBOOK_EMPTY"))?;
        Ok(best.1.clone().into_bytes())
    }
}

/// Class 4 parameters.
#[derive(Debug, Clone, Copy)]
pub struct ConceptParams {
    /// Smoothing `σ` (must be `>= σ_min`).
    pub sigma: f32,
    /// `σ_min` from the signed manifest.
    pub sigma_min: f32,
    /// Norm clamp before smoothing.
    pub max_norm: f32,
    /// `SONAR` canary threshold.
    pub canary_cos: f32,
    /// Output cap.
    pub max_output_bytes: u32,
}

/// The gate.
#[derive(Debug)]
pub struct ConceptGate {
    backend: Box<dyn ConceptBackend>,
    leace: Leace,
    canaries: Vec<Vec<f32>>,
    p: ConceptParams,
}

/// Result.
#[derive(Debug, Clone, PartialEq)]
pub struct ConceptResult {
    /// Output.
    pub output: Vec<u8>,
    /// Arena wipe.
    pub wipe: WipeReport,
}

impl ConceptGate {
    /// Bind; `σ < σ_min` is refused at admission.
    pub fn new(
        backend: Box<dyn ConceptBackend>,
        leace: Leace,
        canaries: Vec<Vec<f32>>,
        p: ConceptParams,
    ) -> EnclaveResult<Self> {
        if !(p.sigma.is_finite()
            && p.sigma_min.is_finite()
            && p.sigma_min > 0.0
            && p.sigma >= p.sigma_min)
        {
            fail!(EACCES, "SMOOTH_LCM_SIGMA_BELOW_MIN");
        }
        if !(0.5..=1.0).contains(&p.canary_cos) {
            fail!(EINVAL, "SONAR_CANARY_THRESHOLD");
        }
        if canaries.is_empty() {
            fail!(EINVAL, "SONAR_CANARIES_REQUIRED");
        }
        for c in &canaries {
            crate::arena::validate_probe(c, backend.width())?;
        }
        if leace.basis.first().map_or(0, Vec::len) != backend.width() {
            fail!(EINVAL, "LEACE_SHAPE");
        }
        if !p.max_norm.is_finite() || p.max_norm <= 0.0 {
            fail!(EINVAL, "CONCEPT_NORM_CAP");
        }
        Ok(Self {
            backend,
            leace,
            canaries,
            p,
        })
    }

    /// Run the concept pipeline.
    pub fn run(
        &self,
        input: &[u8],
        verifier: Option<&SurrogateVerifier>,
        attest: &mut OpAttestor,
    ) -> EnclaveResult<ConceptResult> {
        self.run_with_wipe(input, verifier, attest).0
    }

    /// Preserve the actual per-call wipe on backend, probe and output errors.
    pub(crate) fn run_with_wipe(
        &self,
        input: &[u8],
        verifier: Option<&SurrogateVerifier>,
        attest: &mut OpAttestor,
    ) -> (EnclaveResult<ConceptResult>, Option<WipeReport>) {
        let mut wipe_report = None;
        let result = (|| -> EnclaveResult<ConceptResult> {
            attest.admit(OpFamily::ConceptDiffusion)?;
            let text = canonicalize(input)?;
            let d = self.backend.width();
            let mut arena = Arena::floats(d)?;
            let res = (|| -> EnclaveResult<Vec<u8>> {
                let c = arena.f32_mut()?;
                c[..d].copy_from_slice(&self.backend.encode(&text)?);
                let c = &mut c[..d];
                self.backend.denoise(c)?;
                self.leace.project(c);
                let n = c.iter().map(|x| x * x).sum::<f32>().sqrt();
                if n > self.p.max_norm {
                    c.iter_mut().for_each(|x| *x *= self.p.max_norm / n);
                }
                c.iter_mut().for_each(|x| *x += self.p.sigma * gaussian());
                if self
                    .canaries
                    .iter()
                    .any(|k| cosine(c, k) >= self.p.canary_cos)
                {
                    fail!(EACCES, "SONAR_CANARY_TRIPPED");
                }
                attest.admit(OpFamily::ByteDecode)?;
                self.backend.decode(c)
            })();
            let wipe = wipe_or_abort(&arena);
            wipe_report = Some(wipe);
            let out = res?;
            byte_dfa_validate(&out, verifier)?;
            output_guard(&out, self.p.max_output_bytes)?;
            Ok(ConceptResult { output: out, wipe })
        })();
        (result, wipe_report)
    }

    /// `BLT` byte path: canonicalise + validate model output bytes.
    pub fn validate_bytes(
        &self,
        out: &[u8],
        verifier: Option<&SurrogateVerifier>,
    ) -> EnclaveResult<()> {
        byte_dfa_validate(out, verifier)?;
        output_guard(out, self.p.max_output_bytes)
    }
}
