//! Isolated, locked scratch arenas (the CPU analogue of the per-request
//! `MTLHeap`): guard-paged, `mlock`ed, never on the shared allocator, wiped with
//! volatile writes + `SeqCst` fence and **verified** zero afterwards
//! (FS-701 §7.1: 0 residual bytes, else `SIGABRT`).

use std::time::Instant;

use enclave_core::error::EnclaveResult;
use enclave_core::guarded::GuardedRegion;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};

/// Events that force synchronous zeroization (FS-701 §4.3.1 / §4.6.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZeroizeTrigger {
    /// Sub-task / session / episode exit.
    TaskExit,
    /// `kIOMessageSystemWillSleep` (lid close).
    SystemWillSleep,
    /// `com.apple.screenIsLocked`.
    ScreenLocked,
    /// `L3` YubiKey USB removal.
    YubiKeyRemoved,
    /// Taint-label exit.
    TaintExit,
}

/// Wipe receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WipeReport {
    /// Bytes wiped.
    pub bytes: u64,
    /// Residual non-zero bytes after the wipe (must be 0).
    pub residual: u64,
    /// Wall-clock microseconds.
    pub micros: u64,
}

/// An `f32` / byte scratch arena.
#[derive(Debug)]
pub struct Arena {
    region: GuardedRegion,
    len: usize,
}

impl Arena {
    /// Allocate `len` bytes (page-rounded, zeroed).
    pub fn new(len: usize) -> EnclaveResult<Self> {
        Ok(Self {
            region: GuardedRegion::new(len.max(1))?,
            len,
        })
    }
    /// Allocate room for `n` floats.
    pub fn floats(n: usize) -> EnclaveResult<Self> {
        Self::new(n.max(1) * 4)
    }
    /// Usable length.
    pub fn len(&self) -> usize {
        self.len
    }
    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Bytes.
    pub fn bytes(&self) -> EnclaveResult<&[u8]> {
        Ok(&self.region.as_slice()?[..self.len])
    }
    /// Mutable bytes.
    pub fn bytes_mut(&mut self) -> EnclaveResult<&mut [u8]> {
        let l = self.len;
        Ok(&mut self.region.as_mut_slice()?[..l])
    }
    /// Float view.
    pub fn f32(&self) -> EnclaveResult<&[f32]> {
        let b = self.region.as_slice()?;
        // SAFETY: the region is page-aligned (so 4-byte aligned) and at least
        // `len` bytes long; every bit pattern is a valid f32.
        Ok(unsafe { std::slice::from_raw_parts(b.as_ptr().cast::<f32>(), self.len / 4) })
    }
    /// Mutable float view.
    pub fn f32_mut(&mut self) -> EnclaveResult<&mut [f32]> {
        let l = self.len / 4;
        let b = self.region.as_mut_slice()?;
        // SAFETY: as above; exclusive borrow of the region.
        Ok(unsafe { std::slice::from_raw_parts_mut(b.as_mut_ptr().cast::<f32>(), l) })
    }
    /// Seal hardware read-only (clean system states).
    pub fn seal_read_only(&self) -> EnclaveResult<()> {
        self.region.seal_read_only()
    }
    /// Whether sealed.
    pub fn is_read_only(&self) -> bool {
        self.region.is_read_only()
    }
    /// Whether wiped.
    pub fn is_wiped(&self) -> bool {
        self.region.is_scrubbed()
    }
    /// Fence-synchronised wipe + verification. A residual byte is a SEV-1:
    /// the caller aborts the process (see [`wipe_or_abort`]).
    pub fn wipe(&self) -> WipeReport {
        let t = Instant::now();
        let ok = self.region.scrub();
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        let zero = ok && self.region.verify_zeroed();
        WipeReport {
            bytes: self.region.len() as u64,
            residual: if zero { 0 } else { self.region.len() as u64 },
            micros: t.elapsed().as_micros() as u64,
        }
    }
}

/// Wipe; on any residual byte abort the process (`SIGABRT`, FS-701 §7.1).
pub fn wipe_or_abort(a: &Arena) -> WipeReport {
    let r = a.wipe();
    if r.residual != 0 {
        std::process::abort();
    }
    r
}

// Retain the exact lossy conversion allocation through scanning and refusals.
// Valid UTF-8 keeps its borrowed path; no extra allocation or copy is needed.
pub(crate) struct OutputGuardText<'a>(std::borrow::Cow<'a, str>);
impl<'a> OutputGuardText<'a> {
    pub(crate) fn as_str(&self) -> &str { self.0.as_ref() }
    pub(crate) fn from_bytes(input: &'a [u8]) -> EnclaveResult<Self> {
        if let Ok(text) = std::str::from_utf8(input) {
            return Ok(Self(std::borrow::Cow::Borrowed(text)));
        }
        // Count the standard replacement representation before copying any
        // private bytes. The only owned allocation is guarded from its first
        // write and cannot grow while constructing the scan text.
        let required = input.utf8_chunks().try_fold(0usize, |length, chunk| {
            length.checked_add(chunk.valid().len()).and_then(|length| {
                length.checked_add(if chunk.invalid().is_empty() {
                    0
                } else {
                    std::char::REPLACEMENT_CHARACTER.len_utf8()
                })
            })
        }).ok_or_else(|| err!(E2BIG, "OUTPUT_TEXT_CAPACITY"))?;
        let mut guarded = Self(std::borrow::Cow::Owned(String::new()));
        if let std::borrow::Cow::Owned(text) = &mut guarded.0 {
            text.try_reserve_exact(required).map_err(|_| err!(ENOMEM, "OUTPUT_TEXT_CAPACITY"))?;
            #[cfg(test)]
            let allocation = (text.as_ptr() as usize, text.capacity());
            for chunk in input.utf8_chunks() {
                text.push_str(chunk.valid());
                if !chunk.invalid().is_empty() {
                    text.push(std::char::REPLACEMENT_CHARACTER);
                }
            }
            #[cfg(test)]
            output_guard_owner_tests::constructed(required == text.len()
                && allocation == (text.as_ptr() as usize, text.capacity()));
        }
        Ok(guarded)
    }
}
impl Drop for OutputGuardText<'_> {
    fn drop(&mut self) {
        if let std::borrow::Cow::Owned(text) = &mut self.0 {
            // SAFETY: exclusive owned String, with no outstanding string view.
            // Every initialized byte is overwritten; the final all-NUL content
            // is valid UTF-8 before this mutable Vec borrow ends.
            let bytes = unsafe { text.as_mut_vec() };
            for byte in bytes.iter_mut() {
                // SAFETY: live initialized, exclusively borrowed byte.
                unsafe { std::ptr::write_volatile(byte, 0); }
            }
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
            #[cfg(test)]
            output_guard_owner_tests::observe(bytes);
        }
    }
}

/// Committed-output guard shared by every class: `CNRY_SEP_*` canaries trip in
/// `< 1 ms`; raw `C4` PII (PAN, SSN, credentials) never leaves UID 701.
pub fn output_guard(out: &[u8], max_output_bytes: u32) -> EnclaveResult<()> {
    if out.len() > max_output_bytes as usize {
        fail!(
            E2BIG,
            "OUTPUT_CAP_EXCEEDED",
            "{} > {max_output_bytes}",
            out.len()
        );
    }
    if out.windows(9).any(|w| w == b"CNRY_SEP_") {
        fail!(EACCES, "CANARY_TRIPPED");
    }
    let text = OutputGuardText::from_bytes(out)?;
    if let Some(s) = enclave_core::pii::scan(text.as_str())
        .into_iter()
        .find(|s| s.kind.is_c4())
    {
        fail!(
            EACCES,
            "UNREDACTED_PII_IN_OUTPUT",
            "{:?} at byte {}",
            s.kind,
            s.start
        );
    }
    Ok(())
}

/// Deterministic 64-bit SimHash over byte trigrams (fallback entity keys).
pub fn simhash(b: &[u8]) -> u64 {
    let mut acc = [0i32; 64];
    for w in b.windows(3.min(b.len().max(1))) {
        let h = u64::from_le_bytes(blake3::hash(w).as_bytes()[..8].try_into().unwrap_or([0; 8]));
        for (i, a) in acc.iter_mut().enumerate() {
            *a += if h >> i & 1 == 1 { 1 } else { -1 };
        }
    }
    acc.iter()
        .enumerate()
        .fold(0u64, |s, (i, a)| if *a > 0 { s | 1 << i } else { s })
}

/// Hashed byte n-gram features (`d` buckets, L2-normalised).
pub fn ngram_features(b: &[u8], d: usize) -> EnclaveResult<Vec<f32>> {
    if d == 0 {
        fail!(EINVAL, "FEATURE_WIDTH_ZERO");
    }
    let mut v = vec![0f32; d];
    for n in 1..=3 {
        for w in b.windows(n) {
            let h = blake3::hash(w);
            let x = u64::from_le_bytes(h.as_bytes()[..8].try_into().unwrap_or([0; 8]));
            let sign = if x >> 63 == 1 { -1.0 } else { 1.0 };
            v[(x % d as u64) as usize] += sign;
        }
    }
    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if n > 0.0 {
        v.iter_mut().for_each(|x| *x /= n);
    }
    Ok(v)
}

/// Numerically-stable softmax; `None` if any logit is non-finite.
pub fn softmax(z: &[f32]) -> Option<Vec<f64>> {
    if z.iter().any(|x| !x.is_finite()) || z.is_empty() {
        return None;
    }
    let m = z.iter().copied().fold(f32::NEG_INFINITY, f32::max) as f64;
    let mut e = FloatScratch::new(z.iter().map(|x| (*x as f64 - m).exp()).collect(), "softmax");
    let s: f64 = e.iter().sum();
    // Normalize the owned allocation in place, avoiding a discarded exponent
    // vector. The public result explicitly transfers to its caller's owner.
    e.iter_mut().for_each(|x| *x /= s);
    Some(e.into_vec())
}

/// Numeric types admitted by the private current-allocation scratch owner.
pub(crate) trait ScratchFloat: Copy {
    /// Positive all-zero representation used for volatile scrubbing.
    const ZERO: Self;
    /// Inspect the initialized representation only in before-deallocation tests.
    #[cfg(test)]
    fn zero_bits(self) -> bool;
}
impl ScratchFloat for f32 {
    const ZERO: Self = 0.0;
    #[cfg(test)]
    fn zero_bits(self) -> bool { self.to_bits() == 0 }
}
impl ScratchFloat for f64 {
    const ZERO: Self = 0.0;
    #[cfg(test)]
    fn zero_bits(self) -> bool { self.to_bits() == 0 }
}

/// Own initialized numeric scratch through fallible operations. Slice-only
/// access cannot reallocate the buffer; successful public returns must make an
/// explicit ownership transfer. This says nothing about prior allocator copies.
pub(crate) struct FloatScratch<T: ScratchFloat> {
    values: Vec<T>,
    #[cfg(test)]
    owner: &'static str,
}
impl<T: ScratchFloat> FloatScratch<T> {
    /// Adopt the exact initialized Vec; the label exists only in test builds.
    pub(crate) fn new(values: Vec<T>, _owner: &'static str) -> Self {
        Self { values, #[cfg(test)] owner: _owner }
    }
    /// Explicitly transfer the still-live result to its next owner.
    pub(crate) fn into_vec(mut self) -> Vec<T> {
        #[cfg(test)]
        float_scratch_tests::transferred(self.owner, self.values.len());
        std::mem::take(&mut self.values)
    }
}
impl<T: ScratchFloat> std::ops::Deref for FloatScratch<T> {
    type Target = [T];
    fn deref(&self) -> &[T] { &self.values }
}
impl<T: ScratchFloat> std::ops::DerefMut for FloatScratch<T> {
    fn deref_mut(&mut self) -> &mut [T] { &mut self.values }
}
impl<T: ScratchFloat> Drop for FloatScratch<T> {
    fn drop(&mut self) {
        for value in &mut self.values {
            // SAFETY: live initialized, exclusively borrowed numeric element.
            unsafe { std::ptr::write_volatile(value, T::ZERO); }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        float_scratch_tests::scrubbed(self.owner, &self.values);
    }
}

/// Dense mat-vec `y = W x` with `W` row-major `[rows, cols]`.
pub fn matvec(w: &[f32], rows: usize, cols: usize, x: &[f32]) -> EnclaveResult<Vec<f32>> {
    if w.len() != rows * cols || x.len() != cols {
        fail!(EINVAL, "MATVEC_SHAPE");
    }
    Ok(w.chunks_exact(cols)
        .map(|r| r.iter().zip(x).map(|(a, b)| a * b).sum())
        .collect())
}

/// Return `err` if `v` contains any non-finite value.
pub fn finite(v: &[f32], what: &str) -> EnclaveResult<()> {
    if v.iter().any(|x| !x.is_finite()) {
        return Err(err!(EIO, "NON_FINITE_ACTIVATION", "{what}"));
    }
    Ok(())
}

/// A heap buffer that is volatile-overwritten with `zero` on drop (transient
/// draft / logit copies that must not outlive the step).
#[derive(Debug)]
pub struct Wiped<T: Copy> {
    v: Vec<T>,
    zero: T,
}

impl<T: Copy> Wiped<T> {
    /// Wrap.
    pub fn new(v: Vec<T>, zero: T) -> Self {
        Self { v, zero }
    }
}

impl<T: Copy> std::ops::Deref for Wiped<T> {
    type Target = Vec<T>;
    fn deref(&self) -> &Vec<T> {
        &self.v
    }
}

impl<T: Copy> std::ops::DerefMut for Wiped<T> {
    fn deref_mut(&mut self) -> &mut Vec<T> {
        &mut self.v
    }
}

impl<T: Copy> Drop for Wiped<T> {
    fn drop(&mut self) {
        let z = self.zero;
        for x in self.v.iter_mut() {
            // SAFETY: `x` is a valid, aligned, exclusively borrowed element.
            unsafe { std::ptr::write_volatile(x, z) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Read-only weight bytes: a private `PROT_READ` mapping of a CAS FD, or an
/// owned buffer (tests / development).
#[derive(Debug)]
pub enum WeightBytes {
    /// `mmap(PROT_READ, MAP_PRIVATE)`.
    Mapped {
        /// Base.
        ptr: std::ptr::NonNull<u8>,
        /// Length.
        len: usize,
    },
    /// Owned.
    Owned(Vec<u8>),
}

// SAFETY: the mapping is read-only and owned exclusively by this value.
unsafe impl Send for WeightBytes {}

impl WeightBytes {
    /// Map a read-only FD. The owner (UID702 in production) remains trusted
    /// not to modify/truncate the file while admission reads this mapping.
    /// MAP_PRIVATE is not an immutable snapshot. Engines copy parsed weights
    /// into owned arrays during binding; no borrowed mapping escapes admission.
    pub fn map_fd(fd: &std::os::unix::io::OwnedFd) -> EnclaveResult<Self> {
        use std::os::unix::io::AsRawFd;
        // SAFETY: zeroed stat buffer filled by fstat on a valid fd.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: valid fd and out-pointer.
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 || st.st_size <= 0 {
            fail!(EIO, "WEIGHTS_FSTAT");
        }
        let len = st.st_size as usize;
        // SAFETY: read-only private mapping of a regular file we hold open.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                fd.as_raw_fd(),
                0,
            )
        };
        if p == libc::MAP_FAILED {
            fail!(ENOMEM, "WEIGHTS_MMAP");
        }
        let ptr =
            std::ptr::NonNull::new(p.cast::<u8>()).ok_or_else(|| err!(ENOMEM, "WEIGHTS_MMAP"))?;
        Ok(Self::Mapped { ptr, len })
    }
    /// Bytes.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            // SAFETY: the mapping is live and `len` bytes long until drop.
            Self::Mapped { ptr, len } => unsafe { std::slice::from_raw_parts(ptr.as_ptr(), *len) },
            Self::Owned(v) => v,
        }
    }
}

impl Drop for WeightBytes {
    fn drop(&mut self) {
        if let Self::Mapped { ptr, len } = self {
            // SAFETY: unmapping exactly what map_fd mapped.
            unsafe { libc::munmap(ptr.as_ptr().cast(), *len) };
        }
    }
}

/// A configured probe must have a real finite direction, not a null control.
pub fn validate_probe(direction: &[f32], width: usize) -> EnclaveResult<()> {
    let norm2: f64 = direction.iter().map(|x| (*x as f64).powi(2)).sum();
    if width == 0 || direction.len() != width || !norm2.is_finite() || norm2 <= 1e-12 {
        fail!(EINVAL, "SAFETY_PROBE_INVALID");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod float_scratch_tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum Event {
        Scrubbed(&'static str, usize, bool),
        Transferred(&'static str, usize),
    }
    thread_local! {
        static EVENTS: RefCell<Option<Vec<Event>>> = const { RefCell::new(None) };
    }
    pub(crate) fn begin() { EVENTS.with(|events| *events.borrow_mut() = Some(Vec::new())); }
    pub(crate) fn finish() -> Vec<Event> { EVENTS.with(|events| events.borrow_mut().take().unwrap()) }
    pub(super) fn transferred(owner: &'static str, len: usize) {
        EVENTS.with(|events| if let Some(events) = events.borrow_mut().as_mut() {
            events.push(Event::Transferred(owner,len));
        });
    }
    // Test-only observation while all initialized elements are still owned,
    // after their volatile scrub/fence and before Vec deallocation. Never read
    // freed storage, and record no input, feature, logit or probability values.
    pub(super) fn scrubbed<T: ScratchFloat>(owner: &'static str, values: &[T]) {
        if !values.is_empty() {
            EVENTS.with(|events| if let Some(events) = events.borrow_mut().as_mut() {
                events.push(Event::Scrubbed(owner,values.len(),values.iter().all(|v| v.zero_bits())));
            });
        }
    }

    #[test]
    fn yk11_actual_softmax_stable_extremes_shift_and_explicit_result_transfer() {
        let input = [1.0,2.0,3.0];
        begin();
        let result = softmax(&input).unwrap();
        let shifted = softmax(&[101.0,102.0,103.0]).unwrap();
        let extreme = softmax(&[-f32::MAX,0.0,f32::MAX]).unwrap();
        let tied = softmax(&[f32::MAX,f32::MAX]).unwrap();
        assert_eq!(input,[1.0,2.0,3.0],"the borrowed caller input is unchanged");
        let denominator = (-2.0f64).exp()+(-1.0f64).exp()+1.0;
        assert_eq!(result,vec![(-2.0f64).exp()/denominator,(-1.0f64).exp()/denominator,1.0/denominator]);
        assert_eq!(result,shifted);
        assert_eq!(extreme,vec![0.0,0.0,1.0]); assert_eq!(tied,vec![0.5,0.5]);
        // The sole allocation is the exact live public result. There is no
        // discarded exponent allocation; its normalization happens in place.
        assert_eq!(finish(),vec![Event::Transferred("softmax",3),Event::Transferred("softmax",3),
            Event::Transferred("softmax",3),Event::Transferred("softmax",2)]);
    }

    #[test]
    fn yk11_actual_softmax_empty_and_nonfinite_refuse_before_scratch_allocation() {
        begin();
        for input in [&[][..],&[f32::NAN,0.0][..],&[f32::INFINITY][..],&[f32::NEG_INFINITY][..]] {
            assert!(softmax(input).is_none());
        }
        assert_eq!(finish(),Vec::<Event>::new());
    }
}

#[cfg(test)]
mod output_guard_owner_tests {
    use super::*;
    use std::cell::RefCell;
    thread_local! {
        static EVENTS: RefCell<Option<Vec<(usize, bool)>>> = const { RefCell::new(None) };
        static CONSTRUCTIONS: RefCell<Option<Vec<bool>>> = const { RefCell::new(None) };
    }
    // The actual owned conversion remains live here, after its real volatile
    // scrub/fence and before String deallocation. Never read freed storage or
    // retain raw input/conversion bytes; the observer is absent in production.
    pub(super) fn observe(bytes: &[u8]) {
        EVENTS.with(|events| if let Some(events) = events.borrow_mut().as_mut() {
            events.push((bytes.len(),bytes.iter().all(|byte| *byte == 0)));
        });
    }
    pub(super) fn constructed(stable: bool) {
        CONSTRUCTIONS.with(|events| if let Some(events) = events.borrow_mut().as_mut() { events.push(stable); });
    }
    fn begin() {
        EVENTS.with(|events| *events.borrow_mut() = Some(Vec::new()));
        CONSTRUCTIONS.with(|events| *events.borrow_mut() = Some(Vec::new()));
    }
    fn finish() -> Vec<(usize, bool)> {
        CONSTRUCTIONS.with(|events| { events.borrow_mut().take(); });
        EVENTS.with(|events| events.borrow_mut().take().unwrap())
    }

    fn compare_conversion(input: &[u8]) {
        let expected = String::from_utf8_lossy(input);
        let owned = matches!(&expected, std::borrow::Cow::Owned(_));
        begin();
        let actual = OutputGuardText::from_bytes(input).unwrap();
        assert_eq!(actual.0, expected, "replacement grouping must match the standard conversion");
        drop(actual);
        let construction = CONSTRUCTIONS.with(|events| events.borrow_mut().take().unwrap());
        assert_eq!(construction, if owned { vec![true] } else { vec![] });
        assert_eq!(finish(), if owned { vec![(expected.len(), true)] } else { vec![] });
    }

    #[test]
    fn exact_reserved_conversion_matches_all_single_and_two_byte_inputs_and_multibyte_boundaries() {
        compare_conversion(b"");
        for first in 0..=255u8 {
            compare_conversion(&[first]);
            for second in 0..=255u8 { compare_conversion(&[first, second]); }
        }
        for input in [
            &b"\xe0\xa0\x80"[..], &b"\xed\xa0\x80"[..], &b"\xf0\x90\x80\x80"[..],
            &b"\xf4\x90\x80\x80"[..], &b"\xf0\x9f\x92"[..], &b"\xe1\x80a"[..],
            &b"\xffsafe\xf0\x9f\x92\xa9text\xed\xa0\x80"[..],
        ] { compare_conversion(input); }
    }

    #[test]
    fn actual_expanding_guard_conversion_retains_one_allocation_until_scrub() {
        let input = b"safe\xfftext\xfe".repeat(1024);
        begin(); output_guard(&input, input.len() as u32).unwrap();
        let construction = CONSTRUCTIONS.with(|events| events.borrow_mut().take().unwrap());
        assert_eq!(construction, vec![true]);
        assert_eq!(finish(), vec![(String::from_utf8_lossy(&input).len(), true)]);
    }

    #[test]
    fn actual_invalid_utf8_allowed_output_scrubs_exact_lossy_allocation_without_changing_input_cap() {
        for (input, maximum, converted_len) in [(&b"\xff"[..],1,3),(&b"pre\xfffix"[..],32,9),
            (&b"safe\xf0\x9f"[..],32,7),(&b"\xff\xfe"[..],32,6)] {
            let before = input.to_vec(); begin();
            output_guard(input,maximum).unwrap();
            assert_eq!(input,before); assert_eq!(finish(),vec![(converted_len,true)]);
        }
        // The one-byte input above still fits max1 even though the unchanged
        // lossy scan representation occupies3 bytes. No new policy is added.
    }

    #[test]
    fn actual_invalid_utf8_pii_refusals_scrub_temporary_and_preserve_lossy_byte_offsets() {
        for input in [&b"\xff SSN 123-45-6789"[..],&b"\xff key 4111111111111111"[..]] {
            let before = input.to_vec(); begin();
            let error = output_guard(input,4096).unwrap_err();
            assert!(error.is("UNREDACTED_PII_IN_OUTPUT"));
            assert!(error.to_string().contains("at byte 8"),"same replacement bytes precede the existing PII span: {error}");
            assert_eq!(input,before); assert_eq!(finish(),vec![(input.len()+2,true)]);
        }
    }

    #[test]
    fn actual_valid_utf8_allow_and_pii_refusal_keep_borrowed_conversion() {
        for input in ["ordinary text","safe café","SSN 123-45-6789"] {
            begin(); let result = output_guard(input.as_bytes(),4096);
            if input.starts_with("SSN") {
                let error = result.unwrap_err(); assert!(error.is("UNREDACTED_PII_IN_OUTPUT"));
                assert!(error.to_string().contains("at byte 4"));
            } else { result.unwrap(); }
            assert!(finish().is_empty(),"valid UTF8 never creates an owned conversion to scrub");
        }
    }

    #[test]
    fn actual_size_and_canary_refusals_stay_before_lossy_conversion() {
        for (input, maximum, reason) in [(&b"\xff\xfe"[..],1,"OUTPUT_CAP_EXCEEDED"),
            (&b"\xff CNRY_SEP_"[..],4096,"CANARY_TRIPPED")] {
            let before = input.to_vec(); begin();
            assert!(output_guard(input,maximum).unwrap_err().is(reason));
            assert_eq!(input,before); assert!(finish().is_empty());
        }
    }
}
