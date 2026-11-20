//! Swarm governance gates (FS-702 §4.1–§4.3, §5.4, §5.6; F-029, F-030).
//!
//! * Seeding only for `public_l1` artifacts whose TUF target sets
//!   `license_policy.allow_p2p_seeding == true` (default `false`), never in `L3`.
//! * `jurisdiction_shard ∈ {EU, US, APAC}`: peers exchange handshakes and
//!   chunks only within the same shard.
//! * Peer table: `<= 32` peers, `<= 1` per IPv4 address or IPv6 `/64`;
//!   peers below `2 MiB/s` over a `500 ms` window are evicted.
//! * Lazy `FUSE-T` mounts only for `public_l1` weights `> 1 GiB`, and the `pf`
//!   anchor blocks loopback access to the FUSE-T NFS port for every UID but root.
//! * `SeedGateFSM` (power, metering, thermal, profile latch).

use std::collections::BTreeMap;
use std::net::IpAddr;

use enclave_core::error::EnclaveResult;
use enclave_core::fail;
use enclave_core::profile::Profile;
use serde::{Deserialize, Serialize};

/// Artifact classification (lock schema enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// Public weights.
    PublicL1,
    /// Internal.
    InternalL2,
    /// Restricted.
    RestrictedL3,
}

impl Classification {
    /// Minimum profile implied by the classification.
    pub fn floor(self) -> Profile {
        match self {
            Classification::PublicL1 => Profile::L1,
            Classification::InternalL2 => Profile::L2,
            Classification::RestrictedL3 => Profile::L3,
        }
    }
}

/// GDPR Chapter V shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Shard {
    /// European Union.
    EU,
    /// United States.
    US,
    /// Asia-Pacific.
    APAC,
}

/// License policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicensePolicy {
    /// SPDX id.
    pub spdx_id: String,
    /// P2P seeding allowed (default false).
    #[serde(default)]
    pub allow_p2p_seeding: bool,
    /// Attribution notice digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution_notice_blake3: Option<String>,
}

/// Companion safety layer reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Companion {
    /// Role (e.g. `ece_calibration_lut`).
    pub role: String,
    /// CAS root (hex64) of the layer.
    pub blake3: String,
    /// Must be hydrated before the FD set is returned.
    pub eager_hydrate_required: bool,
}

/// Typed TUF `custom` block for MCPMac targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetPolicy {
    /// Classification.
    pub classification: Classification,
    /// Signed profile floor.
    pub min_profile: Profile,
    /// License.
    pub license_policy: LicensePolicy,
    /// Shard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction_shard: Option<Shard>,
    /// Lazy FUSE-T eligible.
    #[serde(default)]
    pub lazy_fuse_t: bool,
    /// Companions.
    #[serde(default)]
    pub companion_safety_layers: Vec<Companion>,
    /// Transport ciphertext Bao root for encrypted transport verification (FS-702 §3.1, GAP-19).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_ciphertext_bao_root: Option<String>,
    /// Emergency revocation (FS-702 §7.2, RB-202): the artifact is shredded
    /// on the refresh that adopts this flag and every holder is terminated.
    #[serde(default)]
    pub revoked: bool,
}

/// `L1` seeding decision.
pub fn may_seed(p: &TargetPolicy, effective: Profile) -> EnclaveResult<()> {
    if effective == Profile::L3 {
        fail!(EPERM, "L3_ZERO_SEED");
    }
    if !p.license_policy.allow_p2p_seeding {
        fail!(
            EPERM,
            "LICENSE_FORBIDS_SEEDING",
            "{}",
            p.license_policy.spdx_id
        );
    }
    if effective == Profile::L1 && p.classification != Classification::PublicL1 {
        fail!(EPERM, "L1_SEED_PUBLIC_ONLY");
    }
    Ok(())
}

/// Lazy FUSE-T eligibility.
pub fn may_lazy_mount(p: &TargetPolicy, size_bytes: u64, effective: Profile) -> EnclaveResult<()> {
    if !(p.lazy_fuse_t
        && p.classification == Classification::PublicL1
        && effective == Profile::L1
        && size_bytes > (1 << 30))
    {
        fail!(
            EPERM,
            "FUSE_T_NOT_PERMITTED",
            "lazy mounts are L1 public_l1 weights > 1 GiB only"
        );
    }
    Ok(())
}

/// `pf` anchor rules that block every non-root UID from the FUSE-T loopback NFS port.
pub fn fuse_t_pf_anchor(port: u16) -> String {
    format!(
        "# com.enterprise.cas.swarm — FUSE-T loopback fence (FS-702 §5.4)\n\
         pass out quick on lo0 proto tcp from any to 127.0.0.1 port {port} user root\n\
         block drop out quick on lo0 proto tcp from any to 127.0.0.1 port {port}\n\
         block drop out quick on lo0 inet6 proto tcp from any to ::1 port {port}\n"
    )
}

/// Jurisdiction fence.
pub fn same_shard(ours: Shard, peer: Shard) -> EnclaveResult<()> {
    if ours != peer {
        fail!(
            EACCES,
            "JURISDICTION_SHARD_MISMATCH",
            "{ours:?} SVID rejects {peer:?} peer"
        );
    }
    Ok(())
}

/// Peer key: IPv4 address or IPv6 `/64`.
fn sybil_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => v.to_string(),
        IpAddr::V6(v) => {
            let s = v.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

/// Bounded peer table.
#[derive(Debug, Default)]
pub struct PeerTable {
    peers: BTreeMap<String, (String, Shard)>,
}

/// Peer cap.
pub const MAX_PEERS: usize = 32;
/// Minimum throughput (bytes/s).
pub const MIN_RATE_BPS: u64 = 2 * 1024 * 1024;

impl PeerTable {
    /// Admit a peer.
    pub fn admit(
        &mut self,
        id: &str,
        ip: IpAddr,
        shard: Shard,
        our_shard: Shard,
    ) -> EnclaveResult<()> {
        same_shard(our_shard, shard)?;
        let k = sybil_key(ip);
        if self.peers.contains_key(&k) {
            fail!(EACCES, "SYBIL_PEER_PER_PREFIX", "{k}");
        }
        if self.peers.len() >= MAX_PEERS {
            fail!(EAGAIN, "PEER_TABLE_FULL");
        }
        self.peers.insert(k, (id.to_owned(), shard));
        Ok(())
    }
    /// Slow-loris eviction: `bytes` delivered over `window_ms` (>= 500 ms).
    pub fn report_throughput(&mut self, ip: IpAddr, bytes: u64, window_ms: u64) -> bool {
        if window_ms >= 500 && bytes.saturating_mul(1000) / window_ms.max(1) < MIN_RATE_BPS {
            self.peers.remove(&sybil_key(ip));
            return true;
        }
        false
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.peers.len()
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

/// Thermal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Thermal {
    /// Nominal.
    Nominal,
    /// Fair.
    Fair,
    /// Serious.
    Serious,
    /// Critical.
    Critical,
}

/// Host conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostConditions {
    /// On AC power.
    pub ac_power: bool,
    /// Underlay unmetered.
    pub unmetered: bool,
    /// Hotspot detected.
    pub hotspot: bool,
    /// Thermal.
    pub thermal: Thermal,
    /// Low power mode.
    pub low_power: bool,
}

/// `SeedGateFSM` states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeedState {
    /// Default safe state.
    PullOnlyScavenger,
    /// Seeding.
    ActiveLanOrMeshSeed,
    /// Paused for metering / heat.
    PausedMeteringShield,
    /// `L3` permanent latch.
    L3LockedZeroSeed,
}

/// The FSM.
#[derive(Debug, Clone)]
pub struct SeedGate {
    state: SeedState,
    profile: Profile,
}

impl SeedGate {
    /// Boot.
    pub fn new(profile: Profile) -> Self {
        Self {
            state: if profile == Profile::L3 {
                SeedState::L3LockedZeroSeed
            } else {
                SeedState::PullOnlyScavenger
            },
            profile,
        }
    }
    /// Current state.
    pub fn state(&self) -> SeedState {
        self.state
    }
    /// Re-evaluate under new conditions.
    pub fn update(&mut self, c: HostConditions) -> SeedState {
        use SeedState::*;
        self.state = match self.state {
            L3LockedZeroSeed => L3LockedZeroSeed,
            _ if self.profile == Profile::L3 => L3LockedZeroSeed,
            PullOnlyScavenger if c.hotspot || c.thermal >= Thermal::Serious => PausedMeteringShield,
            PullOnlyScavenger
                if c.ac_power && c.unmetered && c.thermal == Thermal::Nominal && !c.low_power =>
            {
                ActiveLanOrMeshSeed
            }
            ActiveLanOrMeshSeed
                if !c.ac_power || !c.unmetered || c.hotspot || c.thermal >= Thermal::Fair || c.low_power =>
            {
                PullOnlyScavenger
            }
            PausedMeteringShield if c.unmetered && !c.hotspot && c.thermal <= Thermal::Fair => {
                PullOnlyScavenger
            }
            s => s,
        };
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governance_seedgate_all_profile_state_condition_combinations_preserve_seed_eligibility() {
        let mut checked = 0;
        for profile in [Profile::L1, Profile::L2, Profile::L3] {
            for initial in [SeedState::PullOnlyScavenger, SeedState::ActiveLanOrMeshSeed,
                SeedState::PausedMeteringShield, SeedState::L3LockedZeroSeed] {
                for bits in 0..16 {
                    for thermal in [Thermal::Nominal, Thermal::Fair, Thermal::Serious, Thermal::Critical] {
                        let conditions = HostConditions {ac_power: bits&1!=0, unmetered: bits&2!=0,
                            hotspot: bits&4!=0, low_power: bits&8!=0, thermal};
                        let mut gate = SeedGate {profile, state: initial};
                        let state = gate.update(conditions);
                        let eligible = profile!=Profile::L3 && initial!=SeedState::L3LockedZeroSeed
                            && conditions.ac_power && conditions.unmetered && !conditions.hotspot
                            && thermal==Thermal::Nominal && !conditions.low_power;
                        assert!(state!=SeedState::ActiveLanOrMeshSeed || eligible,
                            "seeded under forbidden profile/state/conditions: {profile:?} {initial:?} {conditions:?}");
                        if eligible && initial!=SeedState::PausedMeteringShield {
                            assert_eq!(state, SeedState::ActiveLanOrMeshSeed, "healthy seed lost progress");
                        }
                        if initial==SeedState::PausedMeteringShield && eligible {
                            assert_eq!(state, SeedState::PullOnlyScavenger, "retain recovery hysteresis");
                        }
                        checked+=1;
                    }
                }
            }
        }
        assert_eq!(checked, 768);
    }

    fn pol(c: Classification, seed: bool) -> TargetPolicy {
        TargetPolicy {
            classification: c,
            min_profile: c.floor(),
            license_policy: LicensePolicy {
                spdx_id: "MIT".into(),
                allow_p2p_seeding: seed,
                attribution_notice_blake3: None,
            },
            jurisdiction_shard: Some(Shard::EU),
            lazy_fuse_t: true,
            companion_safety_layers: vec![],
            transport_ciphertext_bao_root: None,
            revoked: false,
        }
    }

    #[test]
    fn seeding_license_and_profile_gates() {
        may_seed(&pol(Classification::PublicL1, true), Profile::L1).unwrap();
        assert!(may_seed(&pol(Classification::PublicL1, false), Profile::L1)
            .unwrap_err()
            .is("LICENSE_FORBIDS_SEEDING"));
        assert!(may_seed(&pol(Classification::InternalL2, true), Profile::L1).is_err());
        assert!(may_seed(&pol(Classification::PublicL1, true), Profile::L3)
            .unwrap_err()
            .is("L3_ZERO_SEED"));
        may_lazy_mount(&pol(Classification::PublicL1, true), 2 << 30, Profile::L1).unwrap();
        assert!(
            may_lazy_mount(&pol(Classification::InternalL2, true), 2 << 30, Profile::L2).is_err()
        );
        assert!(
            may_lazy_mount(&pol(Classification::PublicL1, true), 1 << 20, Profile::L1).is_err()
        );
        assert!(fuse_t_pf_anchor(2049)
            .contains("block drop out quick on lo0 proto tcp from any to 127.0.0.1 port 2049"));
    }

    #[test]
    fn peer_table_sybil_shard_and_slowloris() {
        let mut t = PeerTable::default();
        t.admit("a", "10.0.0.1".parse().unwrap(), Shard::EU, Shard::EU)
            .unwrap();
        assert!(t
            .admit("b", "10.0.0.1".parse().unwrap(), Shard::EU, Shard::EU)
            .unwrap_err()
            .is("SYBIL_PEER_PER_PREFIX"));
        t.admit(
            "c",
            "2001:db8:1:2::1".parse().unwrap(),
            Shard::EU,
            Shard::EU,
        )
        .unwrap();
        assert!(
            t.admit(
                "d",
                "2001:db8:1:2::ffff".parse().unwrap(),
                Shard::EU,
                Shard::EU
            )
            .is_err(),
            "same /64"
        );
        assert!(t
            .admit("e", "10.0.0.9".parse().unwrap(), Shard::US, Shard::EU)
            .unwrap_err()
            .is("JURISDICTION_SHARD_MISMATCH"));
        for i in 0..40u8 {
            let _ = t.admit(
                "x",
                format!("10.1.0.{i}").parse().unwrap(),
                Shard::EU,
                Shard::EU,
            );
        }
        assert_eq!(t.len(), MAX_PEERS);
        assert!(t.report_throughput("10.0.0.1".parse().unwrap(), 512 * 1024, 500));
        assert!(!t.report_throughput("10.1.0.1".parse().unwrap(), 4 * 1024 * 1024, 1000));
    }

    #[test]
    fn seed_gate_fsm() {
        let mut g = SeedGate::new(Profile::L2);
        let good = HostConditions {
            ac_power: true,
            unmetered: true,
            hotspot: false,
            thermal: Thermal::Nominal,
            low_power: false,
        };
        assert_eq!(g.update(good), SeedState::ActiveLanOrMeshSeed);
        assert_eq!(
            g.update(HostConditions {
                ac_power: false,
                ..good
            }),
            SeedState::PullOnlyScavenger
        );
        assert_eq!(
            g.update(HostConditions {
                hotspot: true,
                ..good
            }),
            SeedState::PausedMeteringShield
        );
        assert_eq!(g.update(good), SeedState::PullOnlyScavenger);
        let mut l3 = SeedGate::new(Profile::L3);
        assert_eq!(l3.update(good), SeedState::L3LockedZeroSeed);
    }
}
