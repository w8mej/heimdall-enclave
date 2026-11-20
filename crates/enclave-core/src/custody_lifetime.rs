//! Conservative local attenuation of an authenticated CAS receipt lifetime.
//!
//! Callers authenticate and validate the receipt first. This helper grants no
//! authority and assumes trustworthy local wall/boot observations. Integer CAS
//! seconds carry a full second of upper uncertainty; zero safe remainder refuses.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use crate::{err, error::EnclaveResult};

/// Local clock observations captured before beginning the receipt request.
#[derive(Debug, Clone, Copy)]
pub struct ReceiptClockAnchor {
    boot_ns: u64,
    wall: Duration,
}

/// Attenuated local bounds to retain in every derived operation or lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapturedCustodyLifetime {
    /// Exclusive local wall expiry, rounded downward, never beyond raw expiry.
    pub valid_until_unix: i64,
    /// Exclusive shared boot deadline, including the complete receipt fetch lag.
    pub deadline_ns: u64,
}

impl ReceiptClockAnchor {
    /// Observe boot BEFORE fractional wall time, before connecting/requesting.
    pub fn capture() -> EnclaveResult<Self> {
        let boot_ns=crate::clock::boot_clock_ns();
        let wall=SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_|err!(ESTALE,"CUSTODY_LIFETIME_CLOCK"))?;
        Self::from_observations(boot_ns,wall)
    }

    /// Pure constructor for trusted observations and explicitly synthetic tests.
    /// The caller must preserve the same boot-before-wall sampling order.
    pub fn from_observations(boot_ns: u64, wall: Duration) -> EnclaveResult<Self> {
        i64::try_from(wall.as_secs()).map_err(|_|err!(ESTALE,"CUSTODY_LIFETIME_CLOCK"))?;
        Ok(Self {boot_ns,wall})
    }

    /// Capture the validated receipt's remaining lifetime in local domains.
    /// Sample wall BEFORE boot here so the derived wall bound cannot exceed the
    /// boot deadline. Neither bound replaces an earlier original ceremony cap.
    pub fn capture_lifetime(&self, valid_until: i64, verified_now: i64) -> EnclaveResult<CapturedCustodyLifetime> {
        let wall=SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_|err!(ESTALE,"CUSTODY_LIFETIME_CLOCK"))?;
        self.capture_lifetime_at(valid_until,verified_now,wall,crate::clock::boot_clock_ns())
    }

    /// Conservative upper UTC second after the authenticated CAS observation.
    /// This is suitable for expiry checks; it must not replace a lower-time
    /// check for not-before/issued-at admission. Complete fetch lag is included.
    pub fn trusted_upper_unix(&self, verified_now: i64, boot_ns: u64) -> EnclaveResult<i64> {
        let uncertain=||err!(ESTALE,"CUSTODY_LIFETIME_UNCERTAIN");
        if verified_now<0 {return Err(uncertain());}
        let elapsed=boot_ns.checked_sub(self.boot_ns).ok_or_else(uncertain)?;
        let seconds=elapsed/1_000_000_000+u64::from(elapsed%1_000_000_000!=0);
        verified_now.checked_add(1).and_then(|now|now.checked_add(seconds as i64)).ok_or_else(uncertain)
    }

    /// Pure calculation using trusted post-receipt wall-before-boot observations.
    /// `verified_now` is the authenticated CAS seconds floor, not a caller hint.
    pub fn capture_lifetime_at(&self, valid_until: i64, verified_now: i64,
        wall: Duration, boot_ns: u64) -> EnclaveResult<CapturedCustodyLifetime> {
        let uncertain=||err!(ESTALE,"CUSTODY_LIFETIME_UNCERTAIN");
        if boot_ns<self.boot_ns || wall<self.wall || verified_now<0 {return Err(uncertain());}
        let expiry=u64::try_from(valid_until).map_err(|_|uncertain())?;
        let local_remaining=Duration::from_secs(expiry).checked_sub(self.wall).ok_or_else(uncertain)?;
        let local_ns=u64::try_from(local_remaining.as_nanos()).map_err(|_|uncertain())?;
        // The unknown fractional part is bounded above by the next second.
        // Starting this budget before fetch also charges all transport latency.
        let remote_seconds=verified_now.checked_add(1).and_then(|upper|valid_until.checked_sub(upper))
            .filter(|seconds|*seconds>0).ok_or_else(uncertain)?;
        let remote_ns=(remote_seconds as u64).checked_mul(1_000_000_000).ok_or_else(uncertain)?;
        let deadline_ns=self.boot_ns.checked_add(local_ns.min(remote_ns)).ok_or_else(uncertain)?;
        let remaining=deadline_ns.checked_sub(boot_ns).filter(|remaining|*remaining>0).ok_or_else(uncertain)?;
        let local_bound=wall.checked_add(Duration::from_nanos(remaining)).ok_or_else(uncertain)?;
        let valid_until_unix=i64::try_from(local_bound.as_secs()).map_err(|_|uncertain())?.min(valid_until);
        if valid_until_unix<=i64::try_from(wall.as_secs()).map_err(|_|uncertain())? {return Err(uncertain());}
        Ok(CapturedCustodyLifetime {valid_until_unix,deadline_ns})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn anchor() -> ReceiptClockAnchor {
        ReceiptClockAnchor::from_observations(1_000_000_000,Duration::from_millis(100_250)).unwrap()
    }
    #[test]
    fn ahead_cas_clock_caps_both_local_domains_and_charges_fetch_lag() {
        assert_eq!(anchor().trusted_upper_unix(995,1_500_000_000).unwrap(),997);
        let captured=anchor().capture_lifetime_at(1000,995,Duration::from_millis(100_750),1_500_000_000).unwrap();
        assert_eq!(captured,CapturedCustodyLifetime {valid_until_unix:104,deadline_ns:5_000_000_000});
        let later=anchor().capture_lifetime_at(1000,995,Duration::from_millis(102_750),3_500_000_000).unwrap();
        assert_eq!(later,captured,"time spent fetching cannot renew either bound");
        assert!(anchor().capture_lifetime_at(1000,995,Duration::from_millis(104_250),5_000_000_000).is_err());
    }
    #[test]
    fn matching_seconds_keep_upper_uncertainty_and_earlier_local_expiry() {
        assert!(anchor().capture_lifetime_at(101,100,Duration::from_millis(100_300),1_050_000_000).is_err());
        let captured=anchor().capture_lifetime_at(103,100,Duration::from_millis(100_750),1_500_000_000).unwrap();
        assert_eq!(captured,CapturedCustodyLifetime {valid_until_unix:102,deadline_ns:3_000_000_000});
        let local=anchor().capture_lifetime_at(103,99,Duration::from_millis(100_750),1_500_000_000).unwrap();
        assert_eq!(local,CapturedCustodyLifetime {valid_until_unix:103,deadline_ns:3_750_000_000});
    }
    #[test]
    fn regressions_overflow_and_no_complete_safe_second_refuse() {
        for (expiry,observed,wall,boot) in [(103,-1,100_750,1_500_000_000),
            (103,100,99_000,1_500_000_000),(103,100,100_249,1_500_000_000),
            (103,100,100_750,999_999_999),
            (101,100,100_750,1_500_000_000),(100,99,100_750,1_500_000_000),
            (i64::MAX,0,100_750,1_500_000_000),(i64::MAX,i64::MAX,100_750,1_500_000_000)] {
            assert!(anchor().capture_lifetime_at(expiry,observed,Duration::from_millis(wall),boot).is_err());
        }
        let overflow=ReceiptClockAnchor::from_observations(u64::MAX-1,Duration::from_secs(100)).unwrap();
        assert!(overflow.capture_lifetime_at(103,100,Duration::from_secs(100),u64::MAX-1).is_err());
        assert!(ReceiptClockAnchor::from_observations(0,Duration::from_secs(u64::MAX)).is_err());
        let short=ReceiptClockAnchor::from_observations(0,Duration::from_millis(100_001)).unwrap();
        assert!(short.capture_lifetime_at(102,100,Duration::from_millis(100_001),999_000_000).is_err());
    }
}
