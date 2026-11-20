//! `AR_CAUSAL` baseline: left-to-right decoding under the same DFA grammar
//! mask, discrete state only (no persistent recurrent carry-over: a
//! `PersistentStateScan` op faults under this class).

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};

use crate::arena::output_guard;
use crate::dfa::{unpad, Dfa, PAD};
use crate::safetensors::TensorIndex;
use crate::topology::{OpAttestor, OpFamily};

// Reserve the entire bound before the first private byte. Slice-only access
// and checked push keep every initialized byte in this allocation until scrub
// or explicit successful ownership transfer; no growable Vec escapes.
struct ArBytes {
    bytes: Vec<u8>,
    bound: usize,
    #[cfg(test)]
    owner: &'static str,
    #[cfg(test)]
    allocation: (usize, usize),
}
impl ArBytes {
    fn reserve(bound: usize, _owner: &'static str) -> EnclaveResult<Self> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(bound).map_err(|_| err!(ENOMEM, "AR_BYTE_CAPACITY"))?;
        Ok(Self {
            #[cfg(test)]
            allocation: (bytes.as_ptr() as usize, bytes.capacity()),
            bytes,
            bound,
            #[cfg(test)]
            owner: _owner,
        })
    }
    fn push(&mut self, byte: u8) -> EnclaveResult<()> {
        if self.bytes.len() >= self.bound {
            fail!(E2BIG, "AR_BYTE_CAPACITY");
        }
        self.bytes.push(byte);
        Ok(())
    }
    fn copy(input: &[u8], owner: &'static str) -> EnclaveResult<Self> {
        let mut guarded = Self::reserve(input.len(), owner)?;
        guarded.bytes.extend_from_slice(input);
        Ok(guarded)
    }
    fn into_vec(mut self) -> Vec<u8> {
        #[cfg(test)]
        ar_owner_tests::transferred(self.owner, self.bytes.len(),
            self.allocation == (self.bytes.as_ptr() as usize, self.bytes.capacity()));
        std::mem::take(&mut self.bytes)
    }
}
impl std::ops::Deref for ArBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] { &self.bytes }
}
impl Drop for ArBytes {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            // SAFETY: each byte is initialized and exclusively borrowed.
            unsafe { std::ptr::write_volatile(byte, 0); }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        if !self.bytes.is_empty() {
            ar_owner_tests::scrubbed(self.owner, &self.bytes,
                self.allocation == (self.bytes.as_ptr() as usize, self.bytes.capacity()));
        }
    }
}

/// Causal next-byte model.
pub trait CausalBackend: Send + Sync + std::fmt::Debug {
    /// Logits for the next byte.
    fn next(&self, prefix: &[u8]) -> EnclaveResult<[f32; 256]>;
    /// Token-level view of a real checkpoint, when this backend is one.
    fn token_model(&self) -> Option<&dyn TokenModel> {
        None
    }
}

/// Token-level causal model over a closed tokenizer (real checkpoints).
pub trait TokenModel: Send + Sync + std::fmt::Debug {
    /// The model's tokenizer.
    fn tokenizer(&self) -> &crate::tokenizer::Tokenizer;
    /// Logits over the vocabulary for the position after `ids`.
    fn logits(&self, ids: &[u32]) -> EnclaveResult<Vec<f32>>;
}

/// Token ids that end generation when the grammar already accepts.
const STOP_TOKENS: [&str; 2] = ["<|im_end|>", "<|endoftext|>"];

/// Reference bigram LM (`lm_head.weight [V=256.., d]` is the structural
/// signature; the reference uses `enclave_adapter.ar.bigram [256, 256]`).
#[derive(Debug, Clone)]
pub struct BigramLm {
    t: Vec<f32>,
}

impl BigramLm {
    /// Load.
    pub fn load(idx: &TensorIndex, file: &[u8]) -> EnclaveResult<Self> {
        Ok(Self {
            t: idx.f32(file, "enclave_adapter.ar.bigram", &[256, 256])?,
        })
    }
}

impl CausalBackend for BigramLm {
    fn next(&self, prefix: &[u8]) -> EnclaveResult<[f32; 256]> {
        let p = *prefix.last().unwrap_or(&b'\n') as usize;
        let mut o = [0f32; 256];
        o.copy_from_slice(&self.t[p * 256..(p + 1) * 256]);
        Ok(o)
    }
}

/// Grammar-constrained greedy decode without a prompt.
pub fn decode(
    backend: &dyn CausalBackend,
    dfa: &Dfa,
    max_len: usize,
    max_output_bytes: u32,
    attest: &mut OpAttestor,
) -> EnclaveResult<Vec<u8>> {
    decode_prompted(backend, &[], dfa, max_len, max_output_bytes, attest)
}

/// Grammar-constrained greedy decode after `prompt`. Token-level backends
/// decode whole tokens; byte-level reference engines refuse any prompt.
pub fn decode_prompted(
    backend: &dyn CausalBackend,
    prompt: &[u8],
    dfa: &Dfa,
    max_len: usize,
    max_output_bytes: u32,
    attest: &mut OpAttestor,
) -> EnclaveResult<Vec<u8>> {
    decode_prompted_cancellable(backend, prompt, dfa, max_len, max_output_bytes, attest, None)
}

/// As [`decode_prompted`], but a real checkpoint's token loop stops before
/// its next forward pass once `cancel` is set; the partial output is wiped.
pub fn decode_prompted_cancellable(
    backend: &dyn CausalBackend,
    prompt: &[u8],
    dfa: &Dfa,
    max_len: usize,
    max_output_bytes: u32,
    attest: &mut OpAttestor,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> EnclaveResult<Vec<u8>> {
    if let Some(model) = backend.token_model() {
        return decode_tokens(model, prompt, dfa, max_len, max_output_bytes, attest, cancel);
    }
    if !prompt.is_empty() {
        fail!(EINVAL, "PROMPT_UNSUPPORTED_BY_BACKEND");
    }
    attest.admit(OpFamily::CausalDecode)?;
    let mut out = ArBytes::reserve(max_len, "ar-partial")?;
    let mut q = dfa.start();
    while out.len() < max_len {
        if dfa.accepting(q) && dfa.step(q, PAD) == Some(q) && dfa.out(q).count() == 1 {
            break;
        }
        let l = backend.next(&out)?;
        let best = dfa.out(q).filter(|(b, _)| *b != PAD).max_by(|a, b| {
            l[a.0 as usize]
                .total_cmp(&l[b.0 as usize])
                .then(b.0.cmp(&a.0))
        });
        match best {
            Some((b, n)) => {
                out.push(b)?;
                q = n;
            }
            None if dfa.accepting(q) => break,
            None => fail!(EIO, "GRAMMAR_DEAD_END"),
        }
    }
    if !dfa.accepting(q) {
        fail!(
            E2BIG,
            "GRAMMAR_INCOMPLETE",
            "document exceeds {max_len} bytes"
        );
    }
    let terminal = ArBytes::copy(unpad(&out), "ar-output")?;
    output_guard(&terminal, max_output_bytes)?;
    drop(out);
    Ok(terminal.into_vec())
}

/// Advance `dfa` from `q` over every byte of `token`, if all are allowed.
fn walk(dfa: &Dfa, mut q: u32, token: &[u8]) -> Option<u32> {
    for b in token {
        if *b == PAD {
            return None;
        }
        q = dfa.step(q, *b)?;
    }
    Some(q)
}

/// Whole-token grammar-constrained greedy decode for a real checkpoint: at
/// each step take the highest-scoring token whose bytes the grammar accepts
/// and that fits the length bound; a stop token ends generation once the
/// grammar accepts. The same terminal grammar and output guards apply.
fn decode_tokens(
    model: &dyn TokenModel,
    prompt: &[u8],
    dfa: &Dfa,
    max_len: usize,
    max_output_bytes: u32,
    attest: &mut OpAttestor,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> EnclaveResult<Vec<u8>> {
    attest.admit(OpFamily::CausalDecode)?;
    let tokenizer = model.tokenizer();
    let text = std::str::from_utf8(prompt).map_err(|_| err!(EINVAL, "PROMPT_NOT_UTF8"))?;
    let mut ids = tokenizer.encode(text)?;
    if ids.is_empty() {
        fail!(EINVAL, "PROMPT_EMPTY");
    }
    let stops: Vec<u32> = STOP_TOKENS.iter().filter_map(|s| tokenizer.special(s)).collect();
    let mut out = ArBytes::reserve(max_len, "ar-partial")?;
    let mut q = dfa.start();
    while out.len() < max_len {
        if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Acquire)) {
            fail!(EAGAIN, "GENERATION_CANCELLED");
        }
        if dfa.accepting(q) && dfa.step(q, PAD) == Some(q) && dfa.out(q).count() == 1 {
            break;
        }
        let logits = model.logits(&ids)?;
        if logits.len() != tokenizer.vocab() || logits.iter().any(|v| !v.is_finite()) {
            fail!(EIO, "TOKEN_LOGITS_INVALID");
        }
        let mut order: Vec<u32> = (0..logits.len() as u32).collect();
        order.sort_unstable_by(|a, b| logits[*b as usize].total_cmp(&logits[*a as usize]).then(a.cmp(b)));
        let mut chosen = None;
        for id in order {
            if stops.contains(&id) {
                if dfa.accepting(q) {
                    break;
                }
                continue;
            }
            let token = tokenizer.token(id).unwrap_or_default();
            if token.is_empty() || out.len() + token.len() > max_len {
                continue;
            }
            if let Some(next) = walk(dfa, q, token) {
                chosen = Some((id, next));
                break;
            }
        }
        match chosen {
            Some((id, next)) => {
                for b in tokenizer.token(id).unwrap_or_default() {
                    out.push(*b)?;
                }
                ids.push(id);
                q = next;
            }
            None if dfa.accepting(q) => break,
            None => fail!(EIO, "GRAMMAR_DEAD_END"),
        }
    }
    if !dfa.accepting(q) {
        fail!(E2BIG, "GRAMMAR_INCOMPLETE", "document exceeds {max_len} bytes");
    }
    let terminal = ArBytes::copy(unpad(&out), "ar-output")?;
    output_guard(&terminal, max_output_bytes)?;
    drop(out);
    Ok(terminal.into_vec())
}

#[cfg(test)]
mod cancel_tests {
    use super::*;
    use crate::dfa::ArgSchema;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Token model that prefers byte `1`, counting forward passes.
    #[derive(Debug)]
    struct Counting { tokenizer: crate::tokenizer::Tokenizer, one: u32, passes: AtomicUsize }
    impl TokenModel for Counting {
        fn tokenizer(&self) -> &crate::tokenizer::Tokenizer { &self.tokenizer }
        fn logits(&self, _: &[u32]) -> EnclaveResult<Vec<f32>> {
            self.passes.fetch_add(1, Ordering::SeqCst);
            let mut logits = vec![0.0; self.tokenizer.vocab()];
            logits[self.one as usize] = 1.0;
            Ok(logits)
        }
    }
    impl CausalBackend for Counting {
        fn next(&self, _: &[u8]) -> EnclaveResult<[f32; 256]> { fail!(ENOSYS, "BYTE") }
        fn token_model(&self) -> Option<&dyn TokenModel> { Some(self) }
    }

    #[test]
    fn set_cancel_stops_token_decode_before_the_next_forward_pass() {
        let tokenizer = crate::tokenizer::tiny_for_tests();
        let one = tokenizer.encode("1").unwrap()[0];
        let model = Counting { tokenizer, one, passes: AtomicUsize::new(0) };
        let dfa = Dfa::compile(&ArgSchema::UInt { max_digits: 4 }).unwrap();
        let mut attest = OpAttestor::new(crate::manifest::ExecutionClass::ArCausal, &[]);
        let cancel = AtomicBool::new(true);
        let error = decode_prompted_cancellable(&model, b"go", &dfa, 4, 64, &mut attest, Some(&cancel)).unwrap_err();
        assert!(error.is("GENERATION_CANCELLED"));
        assert_eq!(model.passes.load(Ordering::SeqCst), 0, "no forward pass after cancel");
        cancel.store(false, Ordering::Release);
        assert!(!decode_prompted_cancellable(&model, b"go", &dfa, 4, 64, &mut attest, Some(&cancel)).unwrap().is_empty());
    }
}

#[cfg(test)]
mod ar_owner_tests {
    use super::*;
    use crate::dfa::ArgSchema;
    use crate::manifest::ExecutionClass;
    use std::cell::RefCell;

    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        Scrubbed(&'static str, usize, bool, bool),
        Transferred(&'static str, usize, bool),
    }
    thread_local! {
        static EVENTS: RefCell<Option<Vec<Event>>> = const { RefCell::new(None) };
    }
    fn begin() { EVENTS.with(|events| { *events.borrow_mut() = Some(Vec::new()); }); }
    fn finish() -> Vec<Event> { EVENTS.with(|events| events.borrow_mut().take().unwrap()) }
    // These observers read initialized still-owned storage after the actual
    // volatile wipe/fence and retain booleans/length only, never bytes/addresses.
    pub(super) fn scrubbed(owner: &'static str, bytes: &[u8], stable: bool) {
        EVENTS.with(|events| if let Some(events) = events.borrow_mut().as_mut() {
            events.push(Event::Scrubbed(owner, bytes.len(), bytes.iter().all(|b| *b == 0), stable));
        });
    }
    pub(super) fn transferred(owner: &'static str, length: usize, stable: bool) {
        EVENTS.with(|events| if let Some(events) = events.borrow_mut().as_mut() {
            events.push(Event::Transferred(owner, length, stable));
        });
    }

    #[derive(Debug)]
    struct Spell {
        wire: Vec<u8>,
        fail_at: Option<usize>,
        panic_at: Option<usize>,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl Spell {
        fn new(wire: Vec<u8>) -> Self {
            Self { wire, fail_at: None, panic_at: None,
                calls: std::sync::atomic::AtomicUsize::new(0) }
        }
    }
    impl CausalBackend for Spell {
        fn next(&self, prefix: &[u8]) -> EnclaveResult<[f32; 256]> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(prefix, &self.wire[..prefix.len()]);
            assert_ne!(self.panic_at, Some(prefix.len()), "synthetic backend unwind");
            if self.fail_at == Some(prefix.len()) { fail!(EIO, "AR_TEST_BACKEND_FAILURE"); }
            let mut scores = [-1.0; 256];
            scores[self.wire[prefix.len()] as usize] = 1.0;
            Ok(scores)
        }
    }
    fn fixture(value: &str) -> (Dfa, Spell) {
        (Dfa::compile(&ArgSchema::Enum(vec![value.into(), "zzzz_safe_alternative".into()])).unwrap(),
            Spell::new(serde_json::to_vec(value).unwrap()))
    }
    fn attest() -> OpAttestor { OpAttestor::new(ExecutionClass::ArCausal, &[]) }

    #[test]
    fn actual_decode_preserves_short_long_unicode_output_and_scrubs_partial_before_transfer() {
        for value in [String::new(), "safe".into(), "café 安全".into(), "x".repeat(1024)] {
            let (dfa, backend) = fixture(&value);
            let mut attestor = attest();
            begin();
            let result = decode(&backend, &dfa, backend.wire.len() + 17, 4096, &mut attestor).unwrap();
            assert_eq!(result, backend.wire);
            assert!(dfa.accepts(&result));
            assert_eq!(backend.calls.load(std::sync::atomic::Ordering::SeqCst), result.len(),
                "accepting PAD-only state stops before another backend call");
            assert_eq!(finish(), vec![Event::Scrubbed("ar-partial", result.len(), true, true),
                Event::Transferred("ar-output", result.len(), true)]);
            let mut expected = attest(); expected.admit(OpFamily::CausalDecode).unwrap();
            assert_eq!(attestor.operator_family_log_digest(), expected.operator_family_log_digest());
        }
        #[derive(Debug)]
        struct Tied;
        impl CausalBackend for Tied {
            fn next(&self, _: &[u8]) -> EnclaveResult<[f32; 256]> { Ok([0.0; 256]) }
        }
        let dfa = Dfa::compile(&ArgSchema::Bool).unwrap();
        begin();
        assert_eq!(decode(&Tied, &dfa, 32, 32, &mut attest()).unwrap(), b"false",
            "unchanged greedy tie-break chooses the lower byte");
        assert_eq!(finish(), vec![Event::Scrubbed("ar-partial", 5, true, true),
            Event::Transferred("ar-output", 5, true)]);
    }

    #[test]
    fn actual_backend_error_and_unwind_scrub_the_entered_partial_output() {
        for unwind in [false, true] {
            let (dfa, mut backend) = fixture("a sufficiently long safe value");
            if unwind { backend.panic_at = Some(8); } else { backend.fail_at = Some(8); }
            begin();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
                decode(&backend, &dfa, 128, 128, &mut attest())));
            if unwind { assert!(result.is_err()); }
            else { assert!(result.unwrap().unwrap_err().is("AR_TEST_BACKEND_FAILURE")); }
            assert_eq!(finish(), vec![Event::Scrubbed("ar-partial", 8, true, true)]);
        }
    }

    #[test]
    fn actual_grammar_incomplete_scrubs_every_entered_byte_without_terminal_copy() {
        let (dfa, backend) = fixture("safe");
        for max_len in [0, 1, backend.wire.len() - 1] {
            begin();
            assert!(decode(&backend, &dfa, max_len, 128, &mut attest()).unwrap_err().is("GRAMMAR_INCOMPLETE"));
            let expected = if max_len == 0 { vec![] }
                else { vec![Event::Scrubbed("ar-partial", max_len, true, true)] };
            assert_eq!(finish(), expected);
        }
    }

    #[test]
    fn actual_final_pii_canary_and_size_refusals_scrub_partial_and_terminal_output() {
        for (value, cap, reason) in [
            ("card 4111 1111 1111 1111", 128, "UNREDACTED_PII_IN_OUTPUT"),
            ("SSN 123-45-6789", 128, "UNREDACTED_PII_IN_OUTPUT"),
            ("CNRY_SEP_fixture", 128, "CANARY_TRIPPED"),
            ("safe", 1, "OUTPUT_CAP_EXCEEDED"),
        ] {
            let (dfa, backend) = fixture(value);
            begin();
            assert!(decode(&backend, &dfa, 128, cap, &mut attest()).unwrap_err().is(reason), "{reason}");
            assert_eq!(finish(), vec![Event::Scrubbed("ar-output", backend.wire.len(), true, true),
                Event::Scrubbed("ar-partial", backend.wire.len(), true, true)]);
        }
    }

    #[test]
    fn actual_attestation_and_unrepresentable_bound_refuse_before_backend_bytes() {
        let (dfa, backend) = fixture("safe");
        begin();
        let mut wrong = OpAttestor::new(ExecutionClass::DiscriminativeRlcd, &[]);
        assert!(decode(&backend, &dfa, 128, 128, &mut wrong).unwrap_err().is("GRAPH_OP_NOT_AUTHORISED"));
        assert!(decode(&backend, &dfa, usize::MAX, 128, &mut attest()).unwrap_err().is("AR_BYTE_CAPACITY"));
        assert_eq!(backend.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(finish().is_empty());
    }
}
