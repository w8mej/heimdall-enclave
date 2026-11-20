//! Cumulative profiles `L1 ⊂ L2 ⊂ L3` and action classes `A1 < A2 < A3 < A4`
//! (FS-702 §3.2, FS-703 §3.1).

use serde::{Deserialize, Serialize};

use crate::error::EnclaveResult;
use crate::fail;

/// Security profile. Larger is stricter; profiles only ever ratchet upward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Profile {
    /// Startup zero-ops / `sep-biometric`.
    L1 = 1,
    /// Enterprise mesh / `step-up-yubikey`.
    L2 = 2,
    /// Classified enclave / `dual-custody-deadman`.
    L3 = 3,
}

impl Profile {
    /// All profiles.
    pub const ALL: [Profile; 3] = [Profile::L1, Profile::L2, Profile::L3];
    /// Parse `"L1".."L3"`.
    pub fn parse(s: &str) -> EnclaveResult<Self> {
        Ok(match s {
            "L1" => Profile::L1,
            "L2" => Profile::L2,
            "L3" => Profile::L3,
            _ => fail!(EINVAL, "BAD_PROFILE", "{s:?}"),
        })
    }
    /// Anti-downgrade floor: `max(workstation policy, signed TUF manifest, hint)`.
    /// A hint (URI `min_profile`, model manifest) can raise but never lower.
    pub fn effective(workstation: Profile, tuf_manifest: Profile, hints: &[Profile]) -> Profile {
        hints
            .iter()
            .copied()
            .fold(workstation.max(tuf_manifest), Profile::max)
    }
    /// Profile number used by `ComplianceRollupProofV1.profile`.
    pub fn number(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// Action sensitivity class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ActionClass {
    /// Routine tokenized.
    A1 = 1,
    /// Elevated session.
    A2 = 2,
    /// Critical intent.
    A3 = 3,
    /// Extreme / break-glass.
    A4 = 4,
}

impl ActionClass {
    /// All classes.
    pub const ALL: [ActionClass; 4] = [
        ActionClass::A1,
        ActionClass::A2,
        ActionClass::A3,
        ActionClass::A4,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_profile_never_downgrades() {
        assert_eq!(
            Profile::effective(Profile::L1, Profile::L3, &[Profile::L1]),
            Profile::L3
        );
        assert_eq!(
            Profile::effective(Profile::L2, Profile::L1, &[]),
            Profile::L2
        );
        assert_eq!(
            Profile::effective(Profile::L1, Profile::L1, &[Profile::L2]),
            Profile::L2
        );
        for a in Profile::ALL {
            for b in Profile::ALL {
                for h in Profile::ALL {
                    let e = Profile::effective(a, b, &[h]);
                    assert!(e >= a && e >= b && e >= h);
                }
            }
        }
    }
}
