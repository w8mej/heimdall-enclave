//! FS-703 §5.5 deterministic `CustodyLifecycleFSM`.

use enclave_core::error::EnclaveResult;
use enclave_core::fail;
use enclave_core::profile::Profile;
use serde::{Deserialize, Serialize};

/// States.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustodyState {
    /// Boot / cold RAM.
    SterileLocked,
    /// `L1` active.
    L1SepActive,
    /// `L2` tokenize-only (no detokenization key in RAM).
    L2TokenizeOnlyAirplane,
    /// `L2` single-row `A3` window.
    L2A3DetokWindow,
    /// `L2` bulk `A4` window.
    L2A4BulkWindow,
    /// `L3` 2-of-2 active.
    L3DualCustodyActive,
    /// `L3` pages frozen after a yank.
    L3VmProtNoneFreeze,
}

/// Events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustodyEvent {
    /// SEP ECDH unwrap at boot (`L1`).
    SepUnwrap,
    /// HPKE public-ingest initialised (`L2`).
    PublicIngestInit,
    /// Chained Touch ID → YubiKey unwrap of `Envelope_A3`.
    A3Unwrap,
    /// Chained unwrap of `Envelope_A4`.
    A4Unwrap,
    /// Bounded call complete → zeroize tier key.
    BoundedCallComplete,
    /// `L3` morning 2-of-2 unlock.
    DualCustodyUnlock,
    /// `kIOTerminatedNotification`.
    UsbYank,
    /// Legacy recovery signal; rejected while optional YKD-05 recovery is disabled.
    ReattestOk,
    /// Scrubbing completed after cancellation; fresh authorization is required.
    ReattestFailed,
    /// Lid sleep / screen lock / keep-alive failure.
    SleepOrLock,
}

/// The FSM.
#[derive(Debug, Clone)]
pub struct CustodyLifecycle {
    profile: Profile,
    state: CustodyState,
}

impl CustodyLifecycle {
    /// Boot into `STERILE_LOCKED`.
    pub fn boot(profile: Profile) -> Self {
        Self {
            profile,
            state: CustodyState::SterileLocked,
        }
    }
    /// Current state.
    pub fn state(&self) -> CustodyState {
        self.state
    }
    /// Apply an event; undefined transitions fail closed and leave the state unchanged.
    pub fn on(&mut self, e: CustodyEvent) -> EnclaveResult<CustodyState> {
        use CustodyEvent as E;
        use CustodyState as S;
        let next = match (self.state, e, self.profile) {
            (S::SterileLocked, E::SepUnwrap, Profile::L1) => S::L1SepActive,
            (S::SterileLocked, E::PublicIngestInit, Profile::L2) => S::L2TokenizeOnlyAirplane,
            (S::L2TokenizeOnlyAirplane, E::A3Unwrap, _) => S::L2A3DetokWindow,
            (S::L2TokenizeOnlyAirplane, E::A4Unwrap, _) => S::L2A4BulkWindow,
            (S::L2A3DetokWindow | S::L2A4BulkWindow, E::BoundedCallComplete, _) => {
                S::L2TokenizeOnlyAirplane
            }
            (S::SterileLocked, E::DualCustodyUnlock, Profile::L3) => S::L3DualCustodyActive,
            (S::L3DualCustodyActive, E::UsbYank, _) => S::L3VmProtNoneFreeze,
            (S::L3VmProtNoneFreeze, E::ReattestFailed | E::SleepOrLock, _) => S::SterileLocked,
            (S::L3DualCustodyActive | S::L1SepActive, E::SleepOrLock, _) => S::SterileLocked,
            // Sleep/lock during an open L2 window closes it and zeroizes.
            (S::L2A3DetokWindow | S::L2A4BulkWindow, E::SleepOrLock, _) => {
                S::L2TokenizeOnlyAirplane
            }
            (s, e, p) => fail!(
                EPERM,
                "CUSTODY_FSM_INVALID_TRANSITION",
                "{s:?} --{e:?}--> ? in {p}"
            ),
        };
        self.state = next;
        Ok(next)
    }
    /// Whether a detokenization key may be resident.
    pub fn detok_key_resident(&self) -> bool {
        matches!(
            self.state,
            CustodyState::L2A3DetokWindow
                | CustodyState::L2A4BulkWindow
                | CustodyState::L3DualCustodyActive
                | CustodyState::L1SepActive
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l3_yank_paths() {
        let mut f = CustodyLifecycle::boot(Profile::L3);
        f.on(CustodyEvent::DualCustodyUnlock).unwrap();
        f.on(CustodyEvent::UsbYank).unwrap();
        assert!(!f.detok_key_resident());
        assert!(f.on(CustodyEvent::ReattestOk).is_err());
        assert_eq!(f.state(), CustodyState::L3VmProtNoneFreeze);
        assert!(f.on(CustodyEvent::DualCustodyUnlock).is_err());
        assert_eq!(
            f.on(CustodyEvent::ReattestFailed).unwrap(),
            CustodyState::SterileLocked
        );
        f.on(CustodyEvent::DualCustodyUnlock).unwrap();
        assert!(f.detok_key_resident());
    }

    #[test]
    fn l2_windows_and_invalid_transitions() {
        let mut f = CustodyLifecycle::boot(Profile::L2);
        assert!(f.on(CustodyEvent::A3Unwrap).is_err());
        f.on(CustodyEvent::PublicIngestInit).unwrap();
        assert!(!f.detok_key_resident());
        f.on(CustodyEvent::A4Unwrap).unwrap();
        assert!(f.on(CustodyEvent::A3Unwrap).is_err(), "no nested windows");
        f.on(CustodyEvent::BoundedCallComplete).unwrap();
        assert_eq!(f.state(), CustodyState::L2TokenizeOnlyAirplane);
        // Profile mismatch.
        let mut g = CustodyLifecycle::boot(Profile::L1);
        assert!(g.on(CustodyEvent::DualCustodyUnlock).is_err());
    }
}
