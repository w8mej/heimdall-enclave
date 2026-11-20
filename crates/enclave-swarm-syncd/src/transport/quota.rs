//! P2P Swarm per-peer token-bucket rate limiting and APFS staging disk quota enforcement (FS-702 §4.2, GAP-59).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};

/// Token bucket for rate-limiting incoming requests from a peer.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Available tokens.
    pub tokens: f64,
    /// Maximum burst capacity.
    pub max_capacity: f64,
    /// Token refill rate per second.
    pub refill_rate_per_sec: f64,
    /// Timestamp of last token replenishment.
    pub last_refill: Instant,
}

impl TokenBucket {
    /// Initialize a new token bucket with given capacity and refill rate.
    pub fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            max_capacity: capacity,
            refill_rate_per_sec: refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Attempt to consume `cost` tokens. Returns true if permitted.
    pub fn try_consume(&mut self, cost: f64) -> bool {
        self.try_consume_at(cost, Instant::now())
    }

    fn refill_at(&mut self, now: Instant) {
        let Some(elapsed) = now.checked_duration_since(self.last_refill) else { return; };
        let elapsed = elapsed.as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate_per_sec).min(self.max_capacity);
        self.last_refill = now;
    }

    fn try_consume_at(&mut self, cost: f64, now: Instant) -> bool {
        if !cost.is_finite() || cost <= 0.0 || !self.max_capacity.is_finite()
            || self.max_capacity <= 0.0 || !self.refill_rate_per_sec.is_finite()
            || self.refill_rate_per_sec < 0.0 || !self.tokens.is_finite()
        { return false; }
        self.refill_at(now);
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

/// Thread-safe registry of peer rate limiters (GAP-59).
#[derive(Debug)]
pub struct PeerRateLimiter {
    peers: Mutex<HashMap<String, TokenBucket>>,
    default_capacity: f64,
    default_refill: f64,
    #[cfg(test)]
    clock: Option<std::sync::Arc<Mutex<Instant>>>,
}

impl PeerRateLimiter {
    /// Initialize with default bucket capacity and refill rate.
    pub fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            peers: Mutex::new(HashMap::new()),
            default_capacity: capacity,
            default_refill: refill_rate,
            #[cfg(test)]
            clock: None,
        }
    }

    /// Check and consume rate limit for a peer. Returns Err(PEER_RATE_LIMITED) if exceeded.
    pub fn check_rate_limit(&self, peer_id: &str) -> EnclaveResult<()> {
        let now = Instant::now();
        #[cfg(test)]
        let now = self.clock.as_ref().map(|c| *c.lock().unwrap()).unwrap_or(now);
        self.check_at(peer_id, now)
    }

    fn check_at(&self, peer_id: &str, now: Instant) -> EnclaveResult<()> {
        if peer_id.is_empty() || peer_id.len() > 256 {
            fail!(EAGAIN, "PEER_RATE_LIMITED");
        }
        let mut map = self.peers.lock().map_err(|_| err!(EIO, "PEER_RATE_LIMITER_LOCK"))?;
        if map.len() >= 1024 && !map.contains_key(peer_id) {
            // Replacing only a completely refilled bucket cannot grant extra
            // credit. Never evict a depleted peer and reset its burst on churn.
            map.retain(|_, bucket| {
                bucket.refill_at(now);
                bucket.tokens < bucket.max_capacity
            });
            if map.len() >= 1024 { fail!(EAGAIN, "PEER_RATE_LIMITED"); }
        }
        let bucket = map
            .entry(peer_id.to_string())
            .or_insert_with(|| TokenBucket {
                tokens: self.default_capacity, max_capacity: self.default_capacity,
                refill_rate_per_sec: self.default_refill, last_refill: now,
            });
        if bucket.try_consume_at(1.0, now) {
            Ok(())
        } else {
            fail!(
                EAGAIN,
                "PEER_RATE_LIMITED",
                "authenticated peer request budget exhausted"
            );
        }
    }

    #[cfg(test)]
    pub(crate) fn with_clock(clock: std::sync::Arc<Mutex<Instant>>) -> Self {
        Self { clock: Some(clock), ..Self::default() }
    }

    /// Immutable test observation: reading never refills or consumes a bucket.
    #[cfg(test)]
    pub(crate) fn test_snapshot(&self) -> std::collections::BTreeMap<String, (f64, f64, f64)> {
        self.peers.lock().unwrap().iter().map(|(identity, bucket)| {
            (identity.clone(), (bucket.tokens, bucket.max_capacity, bucket.refill_rate_per_sec))
        }).collect()
    }
}

impl Default for PeerRateLimiter {
    fn default() -> Self {
        Self::new(50.0, 10.0) // 50 requests burst, 10 requests/sec refill
    }
}

/// Hard disk quota manager for `/opt/enterprise/enclave/cas/staging/` (GAP-59).
#[derive(Debug)]
pub struct StagingQuotaManager {
    max_quota_bytes: u64,
    current_bytes: Mutex<u64>,
}

impl StagingQuotaManager {
    /// Initialize with quota equal to `2.5 * target_artifact_size`.
    pub fn new(max_quota_bytes: u64) -> Self {
        Self {
            max_quota_bytes,
            current_bytes: Mutex::new(0),
        }
    }

    /// Reserve space for a chunk in staging. Fails closed with STAGING_DISK_QUOTA_EXCEEDED.
    pub fn reserve_chunk(&self, chunk_size: u64) -> EnclaveResult<()> {
        let mut cur = self.current_bytes.lock().unwrap();
        let next = cur
            .checked_add(chunk_size)
            .ok_or_else(|| err!(EDQUOT, "STAGING_DISK_QUOTA_EXCEEDED"))?;
        if next > self.max_quota_bytes {
            fail!(
                EDQUOT,
                "STAGING_DISK_QUOTA_EXCEEDED",
                "Staging allocation of {chunk_size} bytes exceeds limit of {} bytes (current: {})",
                self.max_quota_bytes,
                *cur
            );
        }
        *cur = next;
        Ok(())
    }

    /// Release space when chunk is verified and moved into CAS store or deleted.
    pub fn release_chunk(&self, chunk_size: u64) {
        let mut cur = self.current_bytes.lock().unwrap();
        *cur = cur.saturating_sub(chunk_size);
    }

    /// Current allocated bytes in staging.
    pub fn current_usage(&self) -> u64 {
        *self.current_bytes.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase3_fractional_refill_and_clock_regression_preserve_credit() {
        use std::time::Duration;
        let limiter = PeerRateLimiter::default();
        let start = Instant::now();
        for _ in 0..50 { limiter.check_at("peer", start).unwrap(); }
        assert!(limiter.check_at("peer", start).unwrap_err().is("PEER_RATE_LIMITED"));
        assert!(limiter.check_at("peer", start + Duration::from_millis(99)).is_err());
        limiter.check_at("peer", start + Duration::from_millis(100)).unwrap();
        assert!(limiter.check_at("peer", start).is_err());
        assert!(limiter.check_at("peer", start + Duration::from_millis(199)).is_err());
        limiter.check_at("peer", start + Duration::from_millis(200)).unwrap();
        for _ in 0..10 { limiter.check_at("peer", start + Duration::from_millis(1200)).unwrap(); }
        assert!(limiter.check_at("peer", start + Duration::from_millis(1200)).is_err());
        limiter.check_at("other", start).unwrap();
    }

    #[test]
    fn phase3_churn_cannot_reset_a_depleted_peer_or_grow_state() {
        use std::time::Duration;
        let limiter = PeerRateLimiter::default();
        let now = Instant::now();
        for n in 0..1024 {
            for _ in 0..50 { limiter.check_at(&format!("peer-{n}"), now).unwrap(); }
        }
        assert!(limiter.check_at("new", now).is_err());
        for n in 0..1024 { assert!(limiter.check_at(&format!("peer-{n}"), now).is_err()); }
        assert_eq!(limiter.peers.lock().unwrap().len(), 1024);
        limiter.check_at("new", now + Duration::from_secs(5)).unwrap();
        assert_eq!(limiter.peers.lock().unwrap().len(), 1);
    }

    #[test]
    fn phase3_parallel_admission_cannot_overspend_a_burst() {
        let clock = std::sync::Arc::new(Mutex::new(Instant::now()));
        let limiter = std::sync::Arc::new(PeerRateLimiter::with_clock(clock));
        let workers: Vec<_> = (0..8).map(|_| {
            let limiter = limiter.clone();
            std::thread::spawn(move || (0..50).filter(|_| limiter.check_rate_limit("peer").is_ok()).count())
        }).collect();
        assert_eq!(workers.into_iter().map(|w| w.join().unwrap()).sum::<usize>(), 50);
    }

    #[test]
    fn phase3_invalid_cost_configuration_and_identity_never_grant_credit() {
        for cost in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let mut bucket = TokenBucket::new(50.0, 10.0);
            assert!(!bucket.try_consume(cost));
            assert_eq!(bucket.tokens, 50.0);
        }
        for (cap, rate) in [(f64::NAN, 10.0), (50.0, -1.0), (0.0, 10.0), (50.0, f64::INFINITY)] {
            assert!(PeerRateLimiter::new(cap, rate).check_rate_limit("peer").is_err());
        }
        let limiter = PeerRateLimiter::default();
        assert!(limiter.check_rate_limit("").is_err());
        assert!(limiter.check_rate_limit(&"x".repeat(257)).is_err());
        assert!(limiter.peers.lock().unwrap().is_empty());
    }

    #[test]
    fn test_token_bucket_burst_and_exhaustion() {
        let limiter = PeerRateLimiter::new(2.0, 0.1);
        assert!(limiter.check_rate_limit("peer-1").is_ok());
        assert!(limiter.check_rate_limit("peer-1").is_ok());
        // Third immediate request should be rate-limited
        assert!(limiter.check_rate_limit("peer-1").is_err());
        // Unrelated peer should have its own bucket
        assert!(limiter.check_rate_limit("peer-2").is_ok());
    }

    #[test]
    fn test_staging_quota_enforcement() {
        let quota = StagingQuotaManager::new(1000);
        assert!(quota.reserve_chunk(600).is_ok());
        assert_eq!(quota.current_usage(), 600);
        // Exceeding 1000 total fails closed
        assert!(quota.reserve_chunk(500).is_err());
        assert_eq!(quota.current_usage(), 600);
        // Releasing frees quota
        quota.release_chunk(400);
        assert_eq!(quota.current_usage(), 200);
        assert!(quota.reserve_chunk(500).is_ok());
        assert_eq!(quota.current_usage(), 700);
    }
}

/// Per-content-root ledger shared by every session, detached preparation,
/// export and commit in one CAS instance. Clones and sparse files get no discount.
#[derive(Debug, Clone, Default)]
pub(crate) struct ArtifactStaging(std::sync::Arc<Mutex<StagingLedger>>);
#[derive(Debug,Default)]
struct StagingLedger {
    roots:std::collections::BTreeMap<String,(u64,u64)>,
    orphans:Vec<(std::path::PathBuf,std::fs::File,u64)>,
}

/// Owned charge. It cannot outlive the file/work that owns the reservation.
#[derive(Debug)]
pub(crate) struct StagingReservation {
    registry: ArtifactStaging,
    root: String,
    bytes: u64,
}
impl ArtifactStaging {
    pub(crate) fn reserve(&self, root: &str, length: u64, bytes: u64) -> EnclaveResult<StagingReservation> {
        // floor(5*N/2), including odd and zero-length artifacts, without float.
        let maximum = length.checked_mul(2).and_then(|v| v.checked_add(length / 2))
            .ok_or_else(|| err!(EDQUOT,"STAGING_DISK_QUOTA_EXCEEDED"))?;
        let mut ledger = self.0.lock().map_err(|_| err!(EIO,"STAGING_QUOTA_LOCK"))?;
        if !ledger.orphans.is_empty() {fail!(EDQUOT,"STAGING_CLEANUP_REQUIRED");}
        let (saved, used) = ledger.roots.get(root).copied().unwrap_or((length, 0));
        let next = used.checked_add(bytes).ok_or_else(|| err!(EDQUOT,"STAGING_DISK_QUOTA_EXCEEDED"))?;
        if saved != length || next > maximum { fail!(EDQUOT,"STAGING_DISK_QUOTA_EXCEEDED"); }
        ledger.roots.insert(root.to_owned(), (length, next));
        Ok(StagingReservation { registry: self.clone(), root: root.to_owned(), bytes })
    }
    // Only exclusive private-file creators may transfer a failed cleanup here.
    // Retain the actual FD/inode, count its capacity, and block new staging
    // until the exact owned name is removed. Never refund an orphan silently.
    pub(crate) fn orphan(&self,path:std::path::PathBuf,file:std::fs::File) {
        if let Ok(mut ledger)=self.0.lock() {
            let bytes=file.metadata().map(|m|m.len()).unwrap_or(u64::MAX);
            ledger.orphans.push((path,file,bytes));
        }
    }
    pub(crate) fn retry_cleanup(&self)->EnclaveResult<()> {
        let mut ledger=self.0.lock().map_err(|_|err!(EIO,"STAGING_QUOTA_LOCK"))?;
        let mut remaining=Vec::new();
        for (path,file,bytes) in std::mem::take(&mut ledger.orphans) {
            let result=remove_owned(&path,&file);
            if result.is_err() {remaining.push((path,file,bytes));}
        }
        ledger.orphans=remaining;
        if !ledger.orphans.is_empty() {fail!(EIO,"STAGING_CLEANUP_REQUIRED");}Ok(())
    }
    pub(crate) fn reserved(&self) -> EnclaveResult<u64> {
        let ledger=self.0.lock().map_err(|_|err!(EIO,"STAGING_QUOTA_LOCK"))?;
        ledger.roots.values().map(|(_,bytes)|*bytes).chain(ledger.orphans.iter().map(|(_,_,bytes)|*bytes))
            .try_fold(0u64, |sum, bytes| sum.checked_add(bytes).ok_or_else(||err!(EDQUOT,"STAGING_DISK_QUOTA_EXCEEDED")))
    }
}

/// Delete only the exact exclusively named inode held by the creator. A moved
/// name, additional hardlink or replacement remains an explicit cleanup debt.
pub(crate) fn remove_owned(path:&std::path::Path,file:&std::fs::File)->EnclaveResult<()> {
    use std::os::unix::fs::MetadataExt;
    let held=file.metadata().map_err(|_|err!(EIO,"STAGING_CLEANUP_REQUIRED"))?;
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind()==std::io::ErrorKind::NotFound && held.nlink()==0=>return Ok(()),
        Err(_)=>fail!(EIO,"STAGING_CLEANUP_REQUIRED"),
        Ok(m)=>if !m.is_file() || m.nlink()!=1 || held.nlink()!=1 || (m.dev(),m.ino())!=(held.dev(),held.ino()) {fail!(EACCES,"STAGING_CLEANUP_IDENTITY");},
    }
    std::fs::remove_file(path).map_err(|_|err!(EIO,"STAGING_CLEANUP_REQUIRED"))
}
impl StagingReservation {
    pub(crate) fn defer_cleanup(self,path:std::path::PathBuf,file:std::fs::File) {self.registry.orphan(path,file);}
}
impl Drop for StagingReservation {
    fn drop(&mut self) {
        if let Ok(mut ledger) = self.registry.0.lock() {
            if let Some((_, used)) = ledger.roots.get_mut(&self.root) {
                *used -= self.bytes;
                if *used == 0 { ledger.roots.remove(&self.root); }
            }
        }
    }
}

#[cfg(test)]
mod artifact_tests {
    use super::*;
    #[test]
    fn exact_bound_overflow_same_root_and_owned_refunds() {
        let q=ArtifactStaging::default();
        let a=q.reserve("one", 3, 3).unwrap();
        let b=q.reserve("one", 3, 4).unwrap(); // floor(7.5)
        assert!(q.reserve("one",3,1).unwrap_err().is("STAGING_DISK_QUOTA_EXCEEDED"));
        assert!(q.reserve("one",4,0).is_err());
        assert_eq!(q.reserved().unwrap(),7);
        drop(a); assert_eq!(q.reserved().unwrap(),4);
        drop(b); assert_eq!(q.reserved().unwrap(),0);
        assert!(q.reserve("overflow",u64::MAX,0).is_err());
        assert!(q.reserve("empty",0,1).is_err());
        assert!(q.reserve("empty",0,0).is_ok());
    }
}
