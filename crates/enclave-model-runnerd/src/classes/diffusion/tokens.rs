//! Token-level `DINGO` denoising for real checkpoints (LLaDA).
//!
//! The same contract as the byte path: a linear unmasking schedule,
//! confidence-ordered commits checked against the trellis so the block stays
//! satisfiable, `RAEC` step-watchers, intermediate `x_t` only in an isolated
//! arena wiped on every exit, and the decoded `t = 0` output checked by the
//! DFA and the committed-output guard. Positions hold whole tokens; the
//! end-of-text token pads after the document.

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};

use super::{ConfidenceOrder, DiffusionBytes, DiffusionGate, DiffusionResult, ProbeVerdict};
use crate::arena::{output_guard, wipe_or_abort, Arena, WipeReport, Wiped};
use crate::dfa::{Dfa, Trellis};
use crate::token_lattice::TokenLattice;
use crate::tokenizer::Tokenizer;
use crate::topology::{OpAttestor, OpFamily};

/// Mask sentinel inside the arena (positions are stored as little-endian `u32`).
const MASK: u32 = u32::MAX;
/// Bytes per arena position.
const SLOT: usize = 4;
/// Trellis work budget per generation, as on the byte path.
const WORK_BUDGET: usize = 20_000_000;
/// Candidate tokens kept per masked position from one step's logits row
/// (the highest-scoring permitted ones). Bounds owned memory per step to
/// `len * MAX_CANDIDATES` pairs instead of `len * vocab` floats.
const MAX_CANDIDATES: usize = 4096;

/// A real masked-diffusion checkpoint over a closed tokenizer.
pub trait DiffusionTokenModel: Send + Sync + std::fmt::Debug {
    /// The model's tokenizer.
    fn tokenizer(&self) -> &Tokenizer;
    /// Token that pads the block after the document.
    fn end_token(&self) -> u32;
    /// Stream the logits row (`tokenizer().vocab()` wide) of every block
    /// position after `prompt`, in order, to `row`; `None` positions are
    /// masked. A row is transient: `row` reduces it before the next arrives.
    fn rows(
        &self,
        prompt: &[u32],
        x: &[Option<u32>],
        row: &mut dyn FnMut(usize, &[f32]) -> EnclaveResult<()>,
    ) -> EnclaveResult<()>;

    /// All rows collected, `[len * vocab]` (tests and tools; the gate
    /// streams instead, because a full block is tens of MB).
    fn logits(&self, prompt: &[u32], x: &[Option<u32>]) -> EnclaveResult<Vec<f32>> {
        let mut out = Vec::new();
        self.rows(prompt, x, &mut |_, r| {
            out.extend_from_slice(r);
            Ok(())
        })?;
        Ok(out)
    }
}

/// One step's reduction of a masked position's logits row: its confidence
/// (the row maximum) and the best-scoring tokens the trellis permitted when
/// the step began, a superset of what any later commit in the step allows.
struct Candidates {
    confidence: f32,
    tokens: Wiped<(u32, f32)>,
}

impl Candidates {
    fn of(row: &[f32], permitted: impl Iterator<Item = u32>) -> Self {
        let confidence = row.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let mut tokens = Wiped::new(Vec::new(), (0, 0.0));
        tokens.extend(
            permitted
                .filter(|t| (*t as usize) < row.len())
                .map(|t| (t, row[t as usize])),
        );
        // A token permitted from several states repeats; keep one of each.
        tokens.sort_unstable_by_key(|(t, _)| *t);
        tokens.dedup_by_key(|(t, _)| *t);
        let by_score = |a: &(u32, f32), b: &(u32, f32)| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0));
        if tokens.len() > MAX_CANDIDATES {
            tokens.select_nth_unstable_by(MAX_CANDIDATES, by_score);
            tokens.truncate(MAX_CANDIDATES);
        }
        tokens.sort_unstable_by(by_score);
        Self { confidence, tokens }
    }
}

impl DiffusionGate {
    /// Generate a block of `len` tokens after `prompt`, constrained by `dfa`.
    /// Keeps this invocation's measured wipe even when generation fails.
    pub(crate) fn generate_tokens_cancellable_with_wipe(
        &self,
        dfa: &Dfa,
        len: usize,
        prompt: &[u8],
        attest: &mut OpAttestor,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> (EnclaveResult<DiffusionResult>, Option<WipeReport>) {
        let mut wipe_report = None;
        let result = (|| -> EnclaveResult<DiffusionResult> {
            let start = std::time::Instant::now();
            let (Some(model), Some(trie)) = (self.backend.token_model(), self.token_trie.as_ref()) else {
                fail!(EINVAL, "DIFFUSION_TOKEN_MODEL");
            };
            if cancel.load(std::sync::atomic::Ordering::Acquire) {
                fail!(EAGAIN, "GENERATION_CANCELLED");
            }
            if len == 0 || len > self.max_output_bytes as usize {
                fail!(E2BIG, "OUTPUT_CAP_EXCEEDED");
            }
            let text = std::str::from_utf8(prompt).map_err(|_| err!(EINVAL, "PROMPT_NOT_UTF8"))?;
            let prompt_ids = Wiped::new(model.tokenizer().encode(text)?, 0u32);
            let lattice = TokenLattice::build(dfa, trie, model.end_token())?;
            Trellis::check_budget(&lattice, len)?;
            attest.admit(OpFamily::BidirectionalMask)?;
            let mut arena = Arena::new(len * SLOT)?;
            let denoised = self.denoise_tokens(
                model,
                &lattice,
                &prompt_ids,
                len,
                &mut arena,
                attest,
                cancel,
                start,
            );
            // Fence-synchronised wipe on every exit path (success, abort, error).
            let wipe = wipe_or_abort(&arena);
            wipe_report = Some(wipe);
            if let Ok(mut g) = self.last_wipe.lock() {
                *g = Some(wipe);
            }
            let (x, steps) = denoised?;
            let ids = Wiped::new(
                x.iter()
                    .copied()
                    .filter(|t| *t != model.end_token())
                    .collect(),
                0u32,
            );
            let decoded =
                DiffusionBytes::copy(&model.tokenizer().decode(&ids)?, "diffusion-committed")?;
            if !dfa.accepts(&decoded) {
                fail!(EIO, "DINGO_INVARIANT", "t = 0 output rejected by the DFA");
            }
            output_guard(&decoded, self.max_output_bytes)?;
            drop(x);
            if cancel.load(std::sync::atomic::Ordering::Acquire) {
                fail!(EAGAIN, "GENERATION_CANCELLED");
            }
            if start.elapsed() > self.deadline {
                fail!(ETIMEDOUT, "GENERATION_DEADLINE");
            }
            Ok(DiffusionResult {
                output: decoded.into_vec(),
                steps,
                wipe,
            })
        })();
        (result, wipe_report)
    }

    #[allow(clippy::too_many_arguments)]
    fn denoise_tokens(
        &self,
        model: &dyn DiffusionTokenModel,
        lattice: &TokenLattice<'_>,
        prompt: &[u32],
        len: usize,
        arena: &mut Arena,
        attest: &mut OpAttestor,
        cancel: &std::sync::atomic::AtomicBool,
        start: std::time::Instant,
    ) -> EnclaveResult<(Wiped<u32>, u32)> {
        let total = self.max_steps;
        let vocab = model.tokenizer().vocab();
        let deadline = start + self.deadline;
        let mut budget = WORK_BUDGET;
        let read = |a: &Arena| -> EnclaveResult<Wiped<Option<u32>>> {
            Ok(Wiped::new(
                a.bytes()?
                    .as_chunks::<SLOT>()
                    .0
                    .iter()
                    .map(|c| u32::from_le_bytes(*c))
                    .map(|v| (v != MASK).then_some(v))
                    .collect(),
                None,
            ))
        };
        let live = |budget_ok: bool| -> EnclaveResult<()> {
            if cancel.load(std::sync::atomic::Ordering::Acquire) {
                fail!(EAGAIN, "GENERATION_CANCELLED");
            }
            if !budget_ok || start.elapsed() > self.deadline {
                fail!(ETIMEDOUT, "GENERATION_DEADLINE");
            }
            Ok(())
        };
        for c in arena.bytes_mut()?.as_chunks_mut::<SLOT>().0 {
            c.copy_from_slice(&MASK.to_le_bytes());
        }
        let mut tr = Trellis::build(lattice, &vec![None; len]);
        // A block that cannot hold any document refuses before model compute.
        if !tr.satisfiable() {
            fail!(EIO, "DINGO_UNSATISFIABLE");
        }
        let watch = super::milestones(total);
        let mut steps = 0;
        for t in (1..=total).rev() {
            live(true)?;
            attest.admit(OpFamily::DenoiseStep)?;
            let x = read(arena)?;
            let masked: Vec<usize> = (0..len).filter(|i| x[*i].is_none()).collect();
            if masked.is_empty() {
                break;
            }
            // Linear schedule: after step t, ⌊len * (t-1) / T⌋ positions remain masked.
            let keep = len * (t as usize - 1) / total as usize;
            let commit_n = masked.len().saturating_sub(keep).max(1);
            let mut rows: Vec<Option<Candidates>> = (0..len).map(|_| None).collect();
            let mut seen = 0usize;
            model.rows(prompt, &x, &mut |i, row| {
                if i != seen || row.len() != vocab {
                    fail!(EIO, "DENOISER_SHAPE");
                }
                seen += 1;
                if x[i].is_none() {
                    rows[i] = Some(Candidates::of(row, tr.permitted(lattice, i)));
                }
                Ok(())
            })?;
            live(true)?;
            if seen != len {
                fail!(EIO, "DENOISER_SHAPE");
            }
            let candidates = |i: usize| rows[i].as_ref().expect("every masked row was reduced");
            let order = ConfidenceOrder::from_scores(&masked, |i| candidates(i).confidence)?;
            let mut cur = Wiped::new(x.to_vec(), None);
            for i in order.positions().take(commit_n) {
                // Sequential commit within the step keeps the joint block satisfiable.
                if !tr.satisfiable() {
                    fail!(EIO, "DINGO_UNSATISFIABLE");
                }
                // Best kept candidate still permitted; if earlier commits in
                // this step ruled all of them out, the lowest permitted id.
                let best = candidates(i)
                    .tokens
                    .iter()
                    .map(|(t, _)| *t)
                    .find(|t| tr.permits(lattice, i, *t))
                    .or_else(|| {
                        tr.permitted(lattice, i)
                            .filter(|t| (*t as usize) < vocab)
                            .min()
                    });
                let Some(token) = best else { fail!(EIO, "DINGO_UNSATISFIABLE") };
                cur[i] = Some(token);
                tr.commit(lattice, &cur, i, &mut budget, cancel, deadline)?;
                arena.bytes_mut()?[SLOT * i..SLOT * (i + 1)].copy_from_slice(&token.to_le_bytes());
            }
            steps += 1;
            if watch.contains(&(t - 1)) || watch.contains(&t) {
                let committed = committed_bytes(model, &cur)?;
                match self.probe.inspect(&committed, t) {
                    ProbeVerdict::Clean => {}
                    ProbeVerdict::RefusalPriming => fail!(
                        EACCES,
                        "RAEC_REFUSAL_PRIMING",
                        "step-watcher abort at t = {t}"
                    ),
                    ProbeVerdict::PiiEmerging => {
                        fail!(EACCES, "RAEC_PII_EMERGING", "step-watcher abort at t = {t}")
                    }
                }
            }
        }
        let x = read(arena)?;
        if x.iter().any(Option::is_none) {
            fail!(EIO, "DIFFUSION_INCOMPLETE");
        }
        live(true)?;
        Ok((
            Wiped::new(x.iter().map(|t| t.unwrap_or(MASK)).collect(), 0u32),
            steps,
        ))
    }
}

/// Committed text for the step-watcher: each committed token's bytes, and
/// one unknown byte per masked position. End-of-text contributes nothing.
fn committed_bytes(
    model: &dyn DiffusionTokenModel,
    x: &[Option<u32>],
) -> EnclaveResult<Wiped<Option<u8>>> {
    let mut out = Wiped::new(Vec::new(), None);
    for slot in x {
        match slot {
            Some(t) if *t == model.end_token() => {}
            Some(t) => {
                let bytes = model
                    .tokenizer()
                    .token(*t)
                    .ok_or_else(|| err!(EINVAL, "TOKEN_ID_RANGE"))?;
                out.extend(bytes.iter().map(|b| Some(*b)));
            }
            None => out.push(None),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classes::diffusion::{DiffusionBackend, StepProbe};
    use crate::dfa::ArgSchema;
    use crate::manifest::ExecutionClass;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Prefers the tokens spelling `target`, position by position.
    #[derive(Debug)]
    struct Speller {
        tokenizer: Tokenizer,
        target: Vec<u32>,
        end: u32,
        calls: std::sync::Arc<AtomicUsize>,
        cancel_after: Option<(usize, std::sync::Arc<AtomicBool>)>,
    }
    impl DiffusionTokenModel for Speller {
        fn tokenizer(&self) -> &Tokenizer {
            &self.tokenizer
        }
        fn end_token(&self) -> u32 {
            self.end
        }
        fn rows(
            &self,
            _: &[u32],
            x: &[Option<u32>],
            row: &mut dyn FnMut(usize, &[f32]) -> EnclaveResult<()>,
        ) -> EnclaveResult<()> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if let Some((after, flag)) = &self.cancel_after {
                if call >= *after {
                    flag.store(true, Ordering::SeqCst);
                }
            }
            let vocab = self.tokenizer.vocab();
            for i in 0..x.len() {
                let mut logits = vec![0.0; vocab];
                let want = self.target.get(i).copied().unwrap_or(self.end);
                // Later positions are more confident, so commits run out of order.
                logits[want as usize] = 1.0 + i as f32;
                row(i, &logits)?;
            }
            Ok(())
        }
    }
    impl DiffusionBackend for Speller {
        fn logits(&self, _: &[Option<u8>], _: u32, _: u32) -> EnclaveResult<Vec<[f32; 256]>> {
            fail!(ENOSYS, "BYTE")
        }
        fn token_model(&self) -> Option<&dyn DiffusionTokenModel> {
            Some(self)
        }
    }
    #[derive(Debug)]
    struct Clean;
    impl StepProbe for Clean {
        fn inspect(&self, _: &[Option<u8>], _: u32) -> ProbeVerdict {
            ProbeVerdict::Clean
        }
    }
    #[derive(Debug)]
    struct Pii;
    impl StepProbe for Pii {
        fn inspect(&self, _: &[Option<u8>], _: u32) -> ProbeVerdict {
            ProbeVerdict::PiiEmerging
        }
    }

    fn speller(text: &str, cancel_after: Option<(usize, std::sync::Arc<AtomicBool>)>) -> Speller {
        let tokenizer = crate::tokenizer::tiny_for_tests();
        let end = tokenizer.special("<|end|>").unwrap();
        let target = tokenizer.encode(text).unwrap();
        Speller {
            tokenizer,
            target,
            end,
            calls: std::sync::Arc::new(AtomicUsize::new(0)),
            cancel_after,
        }
    }
    fn dfa() -> Dfa {
        Dfa::compile(&ArgSchema::Object(vec![(
            "k".into(),
            ArgSchema::Enum(vec!["ab".into(), "ba".into()]),
        )]))
        .unwrap()
    }
    fn attest() -> OpAttestor {
        OpAttestor::new(ExecutionClass::DiscreteDiffusion, &[])
    }

    /// A row reduces to its maximum and at most MAX_CANDIDATES permitted
    /// tokens, best first, each once, never a token outside the row.
    #[test]
    fn a_row_keeps_only_its_best_permitted_candidates() {
        let row: Vec<f32> = (0..10_000).map(|t| ((t * 7919) % 10_007) as f32).collect();
        let permitted = (0..10_000u32).chain(0..10u32).chain([20_000]);
        let c = Candidates::of(&row, permitted);
        assert_eq!(
            c.confidence,
            row.iter().copied().fold(f32::NEG_INFINITY, f32::max)
        );
        assert_eq!(c.tokens.len(), MAX_CANDIDATES);
        assert!(c.tokens.windows(2).all(|w| w[0].1 >= w[1].1), "best first");
        let mut sorted: Vec<f32> = row.clone();
        sorted.sort_by(|a, b| b.total_cmp(a));
        assert_eq!(
            c.tokens[MAX_CANDIDATES - 1].1,
            sorted[MAX_CANDIDATES - 1],
            "exactly the top scores"
        );
        let mut ids: Vec<u32> = c.tokens.iter().map(|(t, _)| *t).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), MAX_CANDIDATES);
        assert!(ids.iter().all(|t| (*t as usize) < row.len()));
    }

    #[test]
    fn token_denoising_reaches_the_grammar_document_and_wipes_its_arena() {
        let gate = DiffusionGate::new(
            Box::new(speller(r#"{"k":"ba"}"#, None)),
            Box::new(Clean),
            4,
            256,
        )
        .unwrap();
        assert!(gate.is_token_level());
        let (result, wipe) = gate.generate_tokens_cancellable_with_wipe(
            &dfa(),
            16,
            b"go",
            &mut attest(),
            &AtomicBool::new(false),
        );
        let result = result.unwrap();
        assert_eq!(result.output, br#"{"k":"ba"}"#);
        let wipe = wipe.unwrap();
        assert!(wipe.bytes >= 16 * SLOT as u64 && wipe.residual == 0);
    }

    #[test]
    fn a_model_preferring_ungrammatical_tokens_is_held_to_the_grammar() {
        // The model wants `{"k":"zz"}`; the trellis only permits an enum value.
        let gate = DiffusionGate::new(
            Box::new(speller(r#"{"k":"zz"}"#, None)),
            Box::new(Clean),
            4,
            256,
        )
        .unwrap();
        let output = gate
            .generate_tokens_cancellable_with_wipe(
                &dfa(),
                16,
                b"",
                &mut attest(),
                &AtomicBool::new(false),
            )
            .0
            .unwrap()
            .output;
        assert!(
            output == br#"{"k":"ab"}"# || output == br#"{"k":"ba"}"#,
            "{}",
            String::from_utf8_lossy(&output)
        );
    }

    #[test]
    fn cancel_and_step_watcher_withhold_output_and_still_wipe() {
        let flag = std::sync::Arc::new(AtomicBool::new(false));
        let gate = DiffusionGate::new(
            Box::new(speller(r#"{"k":"ba"}"#, Some((2, flag.clone())))),
            Box::new(Clean),
            4,
            256,
        )
        .unwrap();
        let (result, wipe) =
            gate.generate_tokens_cancellable_with_wipe(&dfa(), 16, b"", &mut attest(), &flag);
        assert!(result.unwrap_err().is("GENERATION_CANCELLED"));
        assert_eq!(wipe.unwrap().residual, 0);

        let gate = DiffusionGate::new(
            Box::new(speller(r#"{"k":"ba"}"#, None)),
            Box::new(Pii),
            4,
            256,
        )
        .unwrap();
        let (result, wipe) = gate.generate_tokens_cancellable_with_wipe(
            &dfa(),
            16,
            b"",
            &mut attest(),
            &AtomicBool::new(false),
        );
        assert!(result.unwrap_err().is("RAEC_PII_EMERGING"));
        assert_eq!(wipe.unwrap().residual, 0);
    }

    #[test]
    fn a_block_too_short_for_the_document_refuses_before_any_model_call() {
        let model = speller(r#"{"k":"ba"}"#, None);
        let calls = model.calls.clone();
        let gate = DiffusionGate::new(Box::new(model), Box::new(Clean), 4, 256).unwrap();
        let error = gate
            .generate_tokens_cancellable_with_wipe(
                &dfa(),
                2,
                b"",
                &mut attest(),
                &AtomicBool::new(false),
            )
            .0
            .unwrap_err();
        assert!(error.is("DINGO_UNSATISFIABLE"), "{error:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
