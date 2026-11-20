//! SeedGate hardware state machine (FS-702 §5.6).
//!
//! Gating states:
//! - `PullOnlyScavenger`: default boot safe state.
//! - `ActiveLanOrMeshSeed`: active seeding on LAN or mesh when on AC, unmetered, nominal thermal.
//! - `PausedMeteringShield`: paused when on hotspot or serious thermal pressure.
//! - `L3LockedZeroSeed`: permanent hardware latch in Profile L3 (never seeds).

use enclave_core::error::EnclaveResult;
use enclave_core::fail;
use enclave_core::profile::Profile;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
mod darwin {
    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        pub fn IOPSGetTimeRemainingEstimate() -> f64;
    }
}

/// Host thermal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Thermal {
    /// Nominal operating temperature.
    Nominal = 0,
    /// Fair / warm, fans spinning up.
    Fair = 1,
    /// Serious thermal throttling.
    Serious = 2,
    /// Critical thermal throttling.
    Critical = 3,
}

/// Dynamic host conditions observed from hardware and network underlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostConditions {
    /// True if connected to AC power.
    pub ac_power: bool,
    /// True if underlay network connection is unmetered (not costly).
    pub unmetered: bool,
    /// True if connected to an iPhone/cellular hotspot (e.g. OUI 00:17:F2).
    pub hotspot: bool,
    /// Thermal state.
    pub thermal: Thermal,
    /// macOS Low Power Mode enabled.
    pub low_power: bool,
}

impl Default for HostConditions {
    fn default() -> Self {
        Self {
            ac_power: true,
            unmetered: true,
            hotspot: false,
            thermal: Thermal::Nominal,
            low_power: false,
        }
    }
}

/// Probe current host conditions from Darwin kernel / IOKit.
pub fn probe_host_conditions() -> HostConditions {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: Darwin IOPS API returns -2.0 when on AC power (unlimited).
        let remaining = unsafe { darwin::IOPSGetTimeRemainingEstimate() };
        let ac_power = remaining == -2.0;
        HostConditions {
            ac_power,
            unmetered: true, // Default to unmetered unless hotspot detected
            hotspot: false,
            thermal: Thermal::Nominal,
            low_power: false,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        HostConditions::default()
    }
}

/// `SeedGateFSM` states (FS-702 §5.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeedState {
    /// Default safe state: downloads allowed via background scavenger, zero seeding.
    PullOnlyScavenger,
    /// Active seeding allowed over local LAN (L1) or mesh (L2).
    ActiveLanOrMeshSeed,
    /// Paused due to metered network, mobile hotspot, or high thermals.
    PausedMeteringShield,
    /// Profile L3 permanent latch: zero listening sockets, zero seeding.
    L3LockedZeroSeed,
}

/// The deterministic SeedGate finite state machine.
#[derive(Debug, Clone)]
pub struct SeedGateFSM {
    state: SeedState,
    profile: Profile,
}

impl SeedGateFSM {
    /// Initialize FSM with operating profile.
    pub fn new(profile: Profile) -> Self {
        let state = if profile == Profile::L3 {
            SeedState::L3LockedZeroSeed
        } else {
            SeedState::PullOnlyScavenger
        };
        Self { state, profile }
    }

    /// Current FSM state.
    pub fn state(&self) -> SeedState {
        self.state
    }

    /// Check if seeding is allowed in the current state.
    pub fn can_seed(&self) -> bool {
        self.state == SeedState::ActiveLanOrMeshSeed
    }

    /// Re-evaluate state under new host conditions (FS-702 §5.6).
    pub fn update(&mut self, c: HostConditions) -> SeedState {
        use SeedState::*;
        // L3 is a permanent hardware latch; once in L3 mode, it never transitions.
        if self.profile == Profile::L3 || self.state == L3LockedZeroSeed {
            self.state = L3LockedZeroSeed;
            return self.state;
        }

        self.state = match self.state {
            L3LockedZeroSeed => L3LockedZeroSeed,
            PullOnlyScavenger => {
                if c.hotspot || c.thermal >= Thermal::Serious {
                    PausedMeteringShield
                } else if c.ac_power && c.unmetered && c.thermal == Thermal::Nominal && !c.low_power
                {
                    ActiveLanOrMeshSeed
                } else {
                    PullOnlyScavenger
                }
            }
            ActiveLanOrMeshSeed => {
                if !c.ac_power || !c.unmetered || c.hotspot || c.thermal >= Thermal::Fair || c.low_power {
                    PullOnlyScavenger
                } else {
                    ActiveLanOrMeshSeed
                }
            }
            PausedMeteringShield => {
                if c.unmetered && !c.hotspot && c.thermal <= Thermal::Fair {
                    PullOnlyScavenger
                } else {
                    PausedMeteringShield
                }
            }
        };

        self.state
    }

    /// Verify that an upload / seed operation is permitted, failing closed otherwise.
    pub fn assert_can_seed(&self) -> EnclaveResult<()> {
        if self.profile == Profile::L3 || self.state == SeedState::L3LockedZeroSeed {
            fail!(EPERM, "L3_ZERO_SEED", "Profile L3 prohibits seeding");
        }
        match self.state {
            SeedState::ActiveLanOrMeshSeed => Ok(()),
            SeedState::PullOnlyScavenger => {
                fail!(
                    EAGAIN,
                    "SEEDING_SCAVENGER_ONLY",
                    "FSM in PullOnlyScavenger state"
                )
            }
            SeedState::PausedMeteringShield => {
                fail!(
                    EAGAIN,
                    "SEEDING_METERING_SHIELD",
                    "FSM paused for hotspot/thermal"
                )
            }
            SeedState::L3LockedZeroSeed => {
                fail!(
                    EPERM,
                    "L3_ZERO_SEED",
                    "Profile L3 permanent zero-seed latch"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seedgate_all_profile_state_condition_combinations_preserve_seed_eligibility() {
        let mut checked = 0;
        for profile in [Profile::L1, Profile::L2, Profile::L3] {
            for initial in [SeedState::PullOnlyScavenger, SeedState::ActiveLanOrMeshSeed,
                SeedState::PausedMeteringShield, SeedState::L3LockedZeroSeed] {
                for bits in 0..16 {
                    for thermal in [Thermal::Nominal, Thermal::Fair, Thermal::Serious, Thermal::Critical] {
                        let conditions = HostConditions {ac_power: bits&1!=0, unmetered: bits&2!=0,
                            hotspot: bits&4!=0, low_power: bits&8!=0, thermal};
                        let mut gate = SeedGateFSM {profile, state: initial};
                        gate.update(conditions);
                        let eligible = profile!=Profile::L3 && initial!=SeedState::L3LockedZeroSeed
                            && conditions.ac_power && conditions.unmetered && !conditions.hotspot
                            && thermal==Thermal::Nominal && !conditions.low_power;
                        assert!(!gate.can_seed() || eligible,
                            "seeded under forbidden profile/state/conditions: {profile:?} {initial:?} {conditions:?}");
                        assert_eq!(gate.assert_can_seed().is_ok(), gate.can_seed());
                        if eligible && initial!=SeedState::PausedMeteringShield {
                            assert!(gate.can_seed(), "healthy seed lost progress");
                        }
                        if initial==SeedState::PausedMeteringShield && eligible {
                            assert_eq!(gate.state(), SeedState::PullOnlyScavenger, "retain recovery hysteresis");
                        }
                        checked+=1;
                    }
                }
            }
        }
        assert_eq!(checked, 768);
    }

    #[test]
    fn seedgate_metered_without_hotspot_revokes_active_then_recovers_on_current_eligibility() {
        for profile in [Profile::L1, Profile::L2] {
            let mut gate = SeedGateFSM::new(profile);
            assert!(gate.update(HostConditions::default())==SeedState::ActiveLanOrMeshSeed);
            let metered = HostConditions {unmetered: false, ..HostConditions::default()};
            assert_eq!(gate.update(metered), SeedState::PullOnlyScavenger);
            assert!(!gate.can_seed());
            assert!(gate.assert_can_seed().unwrap_err().is("SEEDING_SCAVENGER_ONLY"));
            assert_eq!(gate.update(metered), SeedState::PullOnlyScavenger);
            assert_eq!(gate.update(HostConditions::default()), SeedState::ActiveLanOrMeshSeed);
            assert!(gate.can_seed());
        }
    }

    #[test]
    fn test_seedgate_fsm_l3_permanent_latch() {
        let mut fsm = SeedGateFSM::new(Profile::L3);
        assert_eq!(fsm.state(), SeedState::L3LockedZeroSeed);
        assert!(!fsm.can_seed());
        assert!(fsm.assert_can_seed().is_err());

        // Ideal host conditions must not unlock L3
        let perfect = HostConditions {
            ac_power: true,
            unmetered: true,
            hotspot: false,
            thermal: Thermal::Nominal,
            low_power: false,
        };
        assert_eq!(fsm.update(perfect), SeedState::L3LockedZeroSeed);
        assert!(fsm.assert_can_seed().is_err());
    }

    #[test]
    fn test_seedgate_fsm_transitions() {
        let mut fsm = SeedGateFSM::new(Profile::L2);
        assert_eq!(fsm.state(), SeedState::PullOnlyScavenger);
        assert!(!fsm.can_seed());

        // 1. Transition to ActiveLanOrMeshSeed under nominal conditions on AC
        let cond_active = HostConditions {
            ac_power: true,
            unmetered: true,
            hotspot: false,
            thermal: Thermal::Nominal,
            low_power: false,
        };
        assert_eq!(fsm.update(cond_active), SeedState::ActiveLanOrMeshSeed);
        assert!(fsm.can_seed());
        assert!(fsm.assert_can_seed().is_ok());

        // 2. Unplugging AC returns to PullOnlyScavenger
        let mut cond_battery = cond_active;
        cond_battery.ac_power = false;
        assert_eq!(fsm.update(cond_battery), SeedState::PullOnlyScavenger);
        assert!(!fsm.can_seed());

        // 3. Hotspot detection shifts to PausedMeteringShield
        let mut cond_hotspot = cond_active;
        cond_hotspot.hotspot = true;
        assert_eq!(fsm.update(cond_hotspot), SeedState::PausedMeteringShield);
        assert!(!fsm.can_seed());

        // 4. Returning to unmetered non-hotspot returns to PullOnlyScavenger first
        assert_eq!(fsm.update(cond_active), SeedState::PullOnlyScavenger);
        // Then next update on AC elevates to ActiveLanOrMeshSeed
        assert_eq!(fsm.update(cond_active), SeedState::ActiveLanOrMeshSeed);

        // 5. Thermal Fair demotes from Active to PullOnlyScavenger
        let mut cond_fair = cond_active;
        cond_fair.thermal = Thermal::Fair;
        assert_eq!(fsm.update(cond_fair), SeedState::PullOnlyScavenger);

        // 6. Thermal Serious shifts to PausedMeteringShield
        let mut cond_serious = cond_active;
        cond_serious.thermal = Thermal::Serious;
        assert_eq!(fsm.update(cond_serious), SeedState::PausedMeteringShield);
    }
}
