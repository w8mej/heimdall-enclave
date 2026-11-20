//! FS-703 §3.1 required-factor matrix with the strict nesting invariant
//! `RequiredFactors(L1, a) ⊆ RequiredFactors(L2, a) ⊆ RequiredFactors(L3, a)`.

use std::collections::BTreeSet;

pub use enclave_core::intent_draft::{
    is_org_root_mutation, ORG_ROOT_NAMESPACES, ORG_ROOT_TOOL_PREFIXES,
};
use enclave_core::profile::{ActionClass, Profile};
use serde::{Deserialize, Serialize};

/// Authentication factors (`schemas/intent-payload-v1.schema.json`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Factor {
    /// Non-interactive SEP P-256 workload key (DPoP).
    SepWorkloadKey,
    /// Touch ID via SIP-protected `CoreAuthUI` (`.biometryCurrentSet`).
    TouchIdCoreauthui,
    /// YubiKey `CTAP 2.1` user presence.
    YubikeyUp,
    /// YubiKey PIN / UV.
    YubikeyPinUv,
    /// Synchronous ZK egress gate (FS-705).
    ZkEgressGate,
    /// Discrete `k`-of-`n` Ed25519 quorum (org root mutations).
    KofnEd25519Quorum,
    /// Out-of-band OIDC IdP step-up (A4, inherited from the L1 baseline).
    OidcStepUp,
    /// Authenticator presence (transport connected and unyanked, L3).
    YubikeyPresent,
}

/// Required factors for `(profile, action)`; `org_root_mutation` adds the
/// `k`-of-`n` quorum for `A4` TUF-root / org-policy changes in `L2`/`L3`.
pub fn required_factors(
    profile: Profile,
    action: ActionClass,
    org_root_mutation: bool,
) -> BTreeSet<Factor> {
    use Factor::*;
    let mut s = BTreeSet::from([SepWorkloadKey]);

    // L3 requires persistent hardware authenticator presence for all actions.
    if profile >= Profile::L3 {
        s.insert(YubikeyPresent);
    }

    if action >= ActionClass::A2 {
        s.insert(TouchIdCoreauthui);
    }

    if action >= ActionClass::A3 {
        if profile >= Profile::L2 {
            s.insert(YubikeyUp);
        }
        if profile >= Profile::L3 {
            s.insert(YubikeyPinUv);
            s.insert(ZkEgressGate);
        }
    }

    if action == ActionClass::A4 {
        // Higher profiles preserve the baseline's independent A4 authority.
        // Adding a key/UV/quorum does not waive IdP step-up (YKD-08).
        s.insert(OidcStepUp);
        if org_root_mutation && profile >= Profile::L2 {
            s.insert(KofnEd25519Quorum);
        }
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_nesting_invariant_holds_for_every_action() {
        for a in ActionClass::ALL {
            for org in [false, true] {
                let l1 = required_factors(Profile::L1, a, org);
                let l2 = required_factors(Profile::L2, a, org);
                let l3 = required_factors(Profile::L3, a, org);

                // L2 ⊆ L3 holds across all action classes.
                assert!(l2.is_subset(&l3), "L2 subset of L3 failed for {a:?}");

                assert!(l1.is_subset(&l2), "L1 subset of L2 failed for {a:?}");
            }
        }
        // And monotone in the action class within hardware profiles L2 and L3.
        for p in [Profile::L2, Profile::L3] {
            for w in ActionClass::ALL.windows(2) {
                assert!(
                    required_factors(p, w[0], false).is_subset(&required_factors(p, w[1], false))
                );
            }
        }
    }

    #[test]
    fn full_matrix_matches_spec() {
        use Factor::*;
        // A1
        assert_eq!(
            required_factors(Profile::L1, ActionClass::A1, false),
            BTreeSet::from([SepWorkloadKey])
        );
        assert_eq!(
            required_factors(Profile::L2, ActionClass::A1, false),
            BTreeSet::from([SepWorkloadKey])
        );
        assert_eq!(
            required_factors(Profile::L3, ActionClass::A1, false),
            BTreeSet::from([SepWorkloadKey, YubikeyPresent])
        );

        // A2
        assert_eq!(
            required_factors(Profile::L1, ActionClass::A2, false),
            BTreeSet::from([SepWorkloadKey, TouchIdCoreauthui])
        );
        assert_eq!(
            required_factors(Profile::L2, ActionClass::A2, false),
            BTreeSet::from([SepWorkloadKey, TouchIdCoreauthui])
        );
        assert_eq!(
            required_factors(Profile::L3, ActionClass::A2, false),
            BTreeSet::from([SepWorkloadKey, TouchIdCoreauthui, YubikeyPresent])
        );

        // A3
        assert_eq!(
            required_factors(Profile::L1, ActionClass::A3, false),
            BTreeSet::from([SepWorkloadKey, TouchIdCoreauthui])
        );
        assert_eq!(
            required_factors(Profile::L2, ActionClass::A3, false),
            BTreeSet::from([SepWorkloadKey, TouchIdCoreauthui, YubikeyUp])
        );
        assert_eq!(
            required_factors(Profile::L3, ActionClass::A3, false),
            BTreeSet::from([
                SepWorkloadKey,
                TouchIdCoreauthui,
                YubikeyPresent,
                YubikeyUp,
                YubikeyPinUv,
                ZkEgressGate
            ])
        );

        // A4 non-root
        assert_eq!(
            required_factors(Profile::L1, ActionClass::A4, false),
            BTreeSet::from([SepWorkloadKey, TouchIdCoreauthui, OidcStepUp])
        );
        assert_eq!(
            required_factors(Profile::L2, ActionClass::A4, false),
            BTreeSet::from([SepWorkloadKey, TouchIdCoreauthui, YubikeyUp, OidcStepUp])
        );
        assert_eq!(
            required_factors(Profile::L3, ActionClass::A4, false),
            BTreeSet::from([
                SepWorkloadKey,
                TouchIdCoreauthui,
                YubikeyPresent,
                YubikeyUp,
                YubikeyPinUv,
                ZkEgressGate,
                OidcStepUp
            ])
        );

        // A4 org root mutation
        assert_eq!(
            required_factors(Profile::L1, ActionClass::A4, true),
            BTreeSet::from([SepWorkloadKey, TouchIdCoreauthui, OidcStepUp])
        );
        assert_eq!(
            required_factors(Profile::L2, ActionClass::A4, true),
            BTreeSet::from([
                SepWorkloadKey,
                TouchIdCoreauthui,
                YubikeyUp,
                OidcStepUp,
                KofnEd25519Quorum
            ])
        );
        assert_eq!(
            required_factors(Profile::L3, ActionClass::A4, true),
            BTreeSet::from([
                SepWorkloadKey,
                TouchIdCoreauthui,
                YubikeyPresent,
                YubikeyUp,
                YubikeyPinUv,
                ZkEgressGate,
                OidcStepUp,
                KofnEd25519Quorum
            ])
        );
    }
}
