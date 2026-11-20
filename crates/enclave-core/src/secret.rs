//! Zeroizing wrappers for secrets and sensitive buffers.
//!
//! * Contents are wiped with `zeroize` (volatile writes + compiler fence, the
//!   portable equivalent of `explicit_bzero`) on drop or explicit [`SecretBytes::wipe`].
//! * `Debug` never prints contents.
//! * Best-effort `mlock(2)` keeps pages out of swap / `sleepimage`; failure to
//!   lock is reported via [`SecretBytes::is_locked`] so daemons that require it
//!   (UID 703 / 705 root keys) can fail closed.

use zeroize::{Zeroize, Zeroizing};

/// A heap secret that is zeroized on drop and never printed.
pub struct SecretBytes {
    inner: Zeroizing<Vec<u8>>,
    locked: bool,
}

impl SecretBytes {
    /// Take ownership of `v` without reallocating its existing private bytes.
    /// The slice-only API keeps its length and capacity fixed. Spare capacity
    /// remains owned until drop rather than freeing a potentially unwiped copy.
    pub fn new(v: Vec<u8>) -> Self {
        let inner = Zeroizing::new(v);
        let locked = mlock_slice(&inner);
        Self {
            inner,
            locked,
        }
    }
    /// Copy from a slice.
    pub fn from_slice(s: &[u8]) -> Self {
        Self::new(s.to_vec())
    }
    /// A zero-filled secret of `len` bytes.
    pub fn zeroed(len: usize) -> Self {
        Self::new(vec![0u8; len])
    }
    /// Borrow.
    pub fn expose(&self) -> &[u8] {
        &self.inner
    }
    /// Borrow mutably (length is fixed).
    pub fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    /// Bytes retained by the owned allocation, including spare capacity.
    /// This excludes allocator bookkeeping and is not a process RSS measure.
    pub fn allocation_bytes(&self) -> usize {
        self.inner.capacity()
    }
    /// `true` when empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    /// Whether `mlock` succeeded.
    pub fn is_locked(&self) -> bool {
        self.locked
    }
    /// Zeroize now (contents become all-zero; length preserved).
    pub fn wipe(&mut self) {
        self.inner.as_mut_slice().zeroize();
    }
    /// `true` when every byte is zero (post-wipe assertion helper).
    pub fn is_wiped(&self) -> bool {
        self.inner.iter().all(|b| *b == 0)
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.inner.as_mut_slice().zeroize();
        if self.locked {
            munlock_slice(&self.inner);
        }
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes([REDACTED; {}])", self.inner.len())
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::from_slice(self.expose())
    }
}

/// A fixed 32-byte secret key.
#[derive(Clone)]
pub struct SecretKey32(Zeroizing<[u8; 32]>);

impl SecretKey32 {
    /// Wrap raw bytes.
    pub fn new(b: [u8; 32]) -> Self {
        Self(Zeroizing::new(b))
    }
    /// Fresh random key from the OS CSPRNG.
    pub fn random() -> Self {
        let mut b = [0u8; 32];
        crate::rng::fill(&mut b);
        Self::new(b)
    }
    /// Borrow.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
    /// Borrow as slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// Keyed BLAKE3 MAC under this key.
    pub fn mac(&self, data: &[u8]) -> [u8; 32] {
        *blake3::keyed_hash(&self.0, data).as_bytes()
    }
}

impl std::fmt::Debug for SecretKey32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey32([REDACTED])")
    }
}

fn mlock_slice(s: &[u8]) -> bool {
    if s.is_empty() {
        return false;
    }
    // SAFETY: `s` is a valid, live allocation of `s.len()` bytes; mlock only
    // changes residency, never contents or validity.
    unsafe { libc::mlock(s.as_ptr().cast(), s.len()) == 0 }
}

fn munlock_slice(s: &[u8]) {
    if !s.is_empty() {
        // SAFETY: same allocation previously passed to mlock.
        unsafe {
            libc::munlock(s.as_ptr().cast(), s.len());
        }
    }
}

/// Constant-time equality for secret comparisons.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b) {
        acc |= x ^ y;
    }
    // Prevent the compiler from short-circuiting the accumulation.
    std::hint::black_box(acc) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adoption_retains_private_allocation_and_spare_capacity() {
        let mut input = Vec::with_capacity(256);
        input.extend_from_slice(b"synthetic-private-input");
        let pointer = input.as_ptr();
        let capacity = input.capacity();
        let length = input.len();
        assert!(capacity > length);

        let mut secret = SecretBytes::new(input);
        assert!(std::ptr::eq(secret.expose().as_ptr(), pointer),
            "constructor must retain the incoming private allocation");
        assert_eq!(secret.inner.capacity(), capacity);
        assert_eq!(secret.allocation_bytes(), capacity);
        assert_eq!(secret.expose(), b"synthetic-private-input");
        assert!(!format!("{secret:?}").contains("synthetic-private-input"));

        secret.wipe();
        assert_eq!(secret.len(), length);
        assert!(secret.is_wiped());
        assert!(std::ptr::eq(secret.expose().as_ptr(), pointer));
        assert_eq!(secret.inner.capacity(), capacity);
        assert_eq!(secret.allocation_bytes(), capacity);
    }

    #[test]
    fn adoption_retains_empty_reserved_allocation() {
        let input = Vec::with_capacity(256);
        let pointer = input.as_ptr();
        let capacity = input.capacity();
        assert!(capacity > 0);

        let mut secret = SecretBytes::new(input);
        assert!(secret.is_empty());
        assert!(!secret.is_locked());
        assert!(std::ptr::eq(secret.expose().as_ptr(), pointer),
            "constructor must retain even an empty reserved allocation");
        assert_eq!(secret.inner.capacity(), capacity);
        assert_eq!(secret.allocation_bytes(), capacity);
        secret.wipe();
        assert!(secret.is_empty());
        assert!(secret.is_wiped());
        assert!(std::ptr::eq(secret.expose().as_ptr(), pointer));
        assert_eq!(secret.inner.capacity(), capacity);
        assert_eq!(secret.allocation_bytes(), capacity);
    }

    #[test]
    fn wipe_and_debug_redaction() {
        let mut s = SecretBytes::from_slice(b"sk_detok_a4 material");
        assert!(!s.is_wiped());
        assert!(!format!("{s:?}").contains("material"));
        s.wipe();
        assert!(s.is_wiped());
        assert_eq!(s.len(), 20);
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
