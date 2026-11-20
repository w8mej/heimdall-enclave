//! Quantitative information-flow (QIF) ledger shared by UID 701 (`Class 1`
//! anti-binary-search budget) and UID 704 (`declassify_enum` settlement).
//!
//! * Budgets are signed `i64` **millibits** (`12000 mb = 12.000 bits`); a call
//!   revealing one of `|K|` outcomes is charged `ceil(1000 * log2 |K|)`.
//! * Charges settle against a **24-hour sliding window** per `EntityKey`, and
//!   every constituent entity of an input is charged simultaneously and
//!   atomically (all-or-nothing) — FS-701 §4.1.2.
//! * Unstructured `C3`/`C4` inputs without structured keys are charged to the
//!   single `global_unstructured_c3_c4_24h_pool` (`<= 12,000 mb` in `L1`/`L2`;
//!   `<= 4,000 mb` for `C4` in `L3`) — FS-704 §3.2, F-022.
//! * `|E(input)| > 64` fails closed with `E2BIG`; `E = ∅` for `C >= C3` fails
//!   closed with `EPERM` (vacuous-set bypass).
//! * The ledger state is persisted as a keyed-MAC'd snapshot (SEP-checkpointed
//!   journal); a snapshot with a bad MAC fails closed.

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::error::EnclaveResult;
use crate::ifc_envelope::{valid_entity_key, MAX_ENTITY_FANIN};
use crate::label::Conf;
use crate::profile::Profile;
use crate::secret::SecretKey32;
use crate::{err, fail};

/// Default per-entity budget (12.0 bits).
pub const DEFAULT_ENTITY_CAP_MB: i64 = 12_000;
/// Global unstructured pool cap in `L1`/`L2` (and for `C3` in `L3`).
pub const GLOBAL_POOL_CAP_MB: i64 = 12_000;
/// Global unstructured pool cap for `C4` in `L3`.
pub const GLOBAL_POOL_C4_L3_CAP_MB: i64 = 4_000;
/// Sliding window length.
pub const WINDOW_MS: u64 = 24 * 3_600_000;
/// Reserved key naming the global unstructured pool.
pub const GLOBAL_POOL_KEY: &str = "global_unstructured_c3_c4_24h_pool";

/// `ceil(1000 * log2(k))` millibits for revealing one of `k` outcomes.
/// `k <= 1` reveals nothing.
pub fn millibits_for_outcomes(k: u64) -> i64 {
    if k <= 1 {
        return 0;
    }
    // ceil(log2(k^1000)) equals bit_length(k^1000 - 1). Exact integer
    // arithmetic removes both an unproved floating-point error bound and
    // the extra millibit previously charged just below large powers of two.
    // At most 64,000 bits are needed for any u64 input (8 KiB).
    let power = num_bigint::BigUint::from(k).pow(1000);
    (power - num_bigint::BigUint::from(1u8)).bits() as i64
}

/// Derive an entity key `ek_<32 hex>` = truncated `BLAKE3_keyed(K_vault, canonical_id)`.
pub fn entity_key(k_vault: &SecretKey32, canonical_entity_id: &str) -> String {
    let m = k_vault.mac(canonical_entity_id.as_bytes());
    format!("ek_{}", hex::encode(&m[..16]))
}

/// Fallback artifact key for unstructured inputs: `BLAKE3_keyed(K_vault, uri || simhash_bucket)`.
pub fn fallback_artifact_key(
    k_vault: &SecretKey32,
    canonical_source_uri: &str,
    simhash_bucket: u64,
) -> String {
    let mut buf = canonical_source_uri.as_bytes().to_vec();
    buf.push(0);
    buf.extend_from_slice(&simhash_bucket.to_le_bytes());
    let m = k_vault.mac(&buf);
    format!("ek_{}", hex::encode(&m[..16]))
}

/// What is being charged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QifCharge {
    /// Structured entity keys (may be empty for unstructured inputs).
    pub entities: Vec<String>,
    /// Confidentiality of the input.
    pub conf: Conf,
    /// `true` when the input is unstructured C3/C4 (also charged to the global pool).
    pub unstructured: bool,
    /// Millibits to charge.
    pub millibits: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct Bucket {
    events: VecDeque<(u64, i64)>,
}

impl Bucket {
    fn prune(&mut self, now_ms: u64) {
        while let Some((t, _)) = self.events.front() {
            if now_ms.saturating_sub(*t) >= WINDOW_MS {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }
    fn used(&self) -> i64 {
        self.events.iter().map(|(_, m)| *m).sum()
    }
}

/// The settlement ledger (single writer).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "QifLedgerSnapshot")]
pub struct QifLedger {
    profile: Profile,
    entity_cap_mb: i64,
    buckets: BTreeMap<String, Bucket>,
    /// Monotonic high-water mark of observed time (defeats clock rollback).
    high_water_ms: u64,
}

/// Unchecked snapshot representation; all public deserialization paths validate
/// it before exposing a ledger, including generic sealed-store decoding.
#[derive(Deserialize)]
struct QifLedgerSnapshot {
    profile: Profile,
    entity_cap_mb: i64,
    buckets: BTreeMap<String, Bucket>,
    high_water_ms: u64,
}

impl TryFrom<QifLedgerSnapshot> for QifLedger {
    type Error = crate::error::EnclaveError;

    fn try_from(snapshot: QifLedgerSnapshot) -> Result<Self, Self::Error> {
        let ledger = Self {
            profile: snapshot.profile,
            entity_cap_mb: snapshot.entity_cap_mb,
            buckets: snapshot.buckets,
            high_water_ms: snapshot.high_water_ms,
        };
        ledger.validate()?;
        Ok(ledger)
    }
}

/// MAC-authenticated persisted form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedLedger {
    /// JSON state.
    pub state: String,
    /// Hex keyed-BLAKE3 MAC.
    pub mac: String,
}

impl QifLedger {
    /// New ledger for a profile with the default 12,000 mb entity cap.
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            entity_cap_mb: DEFAULT_ENTITY_CAP_MB,
            buckets: BTreeMap::new(),
            high_water_ms: 0,
        }
    }

    /// Profile the ledger enforces.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// Override the per-entity cap (manifest `qif_max_millibits_per_record`, `<= 12000`).
    pub fn with_entity_cap(mut self, cap: i64) -> EnclaveResult<Self> {
        if !(0..=DEFAULT_ENTITY_CAP_MB).contains(&cap) {
            fail!(EINVAL, "QIF_CAP_OUT_OF_RANGE");
        }
        if self
            .buckets
            .iter()
            .any(|(key, bucket)| key != GLOBAL_POOL_KEY && bucket.used() > cap)
        {
            fail!(EINVAL, "QIF_CAP_BELOW_USAGE");
        }
        self.entity_cap_mb = cap;
        Ok(self)
    }

    /// Validate the induction base after restoring authenticated bytes. A MAC
    /// authenticates a snapshot; it does not establish timestamp ordering or
    /// nonnegative, bounded accounting. These invariants justify prefix pruning
    /// and the absence of signed overflow in `Bucket::used`.
    pub fn validate(&self) -> EnclaveResult<()> {
        if !(0..=DEFAULT_ENTITY_CAP_MB).contains(&self.entity_cap_mb) {
            fail!(EACCES, "QIF_LEDGER_INVALID", "entity cap");
        }
        for (key, bucket) in &self.buckets {
            if key != GLOBAL_POOL_KEY && !valid_entity_key(key) {
                fail!(EACCES, "QIF_LEDGER_INVALID", "entity key");
            }
            let cap = if key == GLOBAL_POOL_KEY {
                GLOBAL_POOL_CAP_MB
            } else {
                self.entity_cap_mb
            };
            let mut previous = 0;
            let mut used: i64 = 0;
            for &(timestamp, amount) in &bucket.events {
                if timestamp < previous || timestamp > self.high_water_ms || amount < 0 {
                    fail!(EACCES, "QIF_LEDGER_INVALID", "event order, time or amount");
                }
                used = used
                    .checked_add(amount)
                    .filter(|total| *total <= cap)
                    .ok_or_else(|| err!(EACCES, "QIF_LEDGER_INVALID", "bucket sum"))?;
                previous = timestamp;
            }
        }
        Ok(())
    }

    fn global_cap(&self, conf: Conf) -> i64 {
        if self.profile == Profile::L3 && conf == Conf::C4 {
            GLOBAL_POOL_C4_L3_CAP_MB
        } else {
            GLOBAL_POOL_CAP_MB
        }
    }

    fn clock(&mut self, now_ms: u64) -> u64 {
        // Time never moves backwards for the ledger: a rolled-back clock cannot
        // age charges out of the window early.
        self.high_water_ms = self.high_water_ms.max(now_ms);
        self.high_water_ms
    }

    /// Millibits used in the current window for `key`.
    pub fn used(&mut self, key: &str, now_ms: u64) -> i64 {
        let now = self.clock(now_ms);
        match self.buckets.get_mut(key) {
            Some(b) => {
                b.prune(now);
                b.used()
            }
            None => 0,
        }
    }

    /// Atomically settle a charge. Either every bucket is debited or none is.
    /// Exceeding any cap returns `EACCES: QIF_BUDGET_EXCEEDED` (the caller
    /// escalates to an `A3` hardware declassification grant).
    pub fn charge(&mut self, c: &QifCharge, now_ms: u64) -> EnclaveResult<()> {
        if c.millibits < 0 {
            fail!(EINVAL, "NEGATIVE_QIF_CHARGE");
        }
        if c.entities.len() > MAX_ENTITY_FANIN {
            fail!(
                E2BIG,
                "PROVENANCE_FANIN_EXCEEDED",
                "{} > {MAX_ENTITY_FANIN}",
                c.entities.len()
            );
        }
        let mut keys: Vec<(String, i64)> = Vec::with_capacity(c.entities.len() + 1);
        for e in &c.entities {
            if !valid_entity_key(e) {
                fail!(EINVAL, "BAD_ENTITY_KEY");
            }
            if !keys.iter().any(|(k, _)| k == e) {
                keys.push((e.clone(), self.entity_cap_mb));
            }
        }
        let needs_pool = c.unstructured || (c.conf >= Conf::C3 && c.entities.is_empty());
        if c.conf >= Conf::C3 && c.entities.is_empty() && !c.unstructured {
            fail!(
                EPERM,
                "EMPTY_ENTITY_SET",
                "C3/C4 input without entity keys must be marked unstructured"
            );
        }
        if needs_pool {
            keys.push((GLOBAL_POOL_KEY.to_owned(), self.global_cap(c.conf)));
        }
        let now = self.clock(now_ms);
        for (k, cap) in &keys {
            let used = match self.buckets.get_mut(k) {
                Some(b) => {
                    b.prune(now);
                    b.used()
                }
                None => 0,
            };
            let after = used
                .checked_add(c.millibits)
                .ok_or_else(|| err!(EINVAL, "QIF_OVERFLOW"))?;
            if after > *cap {
                fail!(
                    EACCES,
                    "QIF_BUDGET_EXCEEDED",
                    "{k}: {used} + {} > {cap} mb",
                    c.millibits
                );
            }
        }
        for (k, _) in keys {
            self.buckets
                .entry(k)
                .or_default()
                .events
                .push_back((now, c.millibits));
        }
        Ok(())
    }

    /// Persist with a keyed MAC.
    pub fn seal(&self, key: &SecretKey32) -> EnclaveResult<SealedLedger> {
        let state = serde_json::to_string(self).map_err(|e| err!(EIO, "QIF_SERIALIZE", "{e}"))?;
        let mac = hex::encode(key.mac(state.as_bytes()));
        Ok(SealedLedger { state, mac })
    }

    /// Restore; a bad MAC fails closed.
    pub fn unseal(s: &SealedLedger, key: &SecretKey32) -> EnclaveResult<Self> {
        let want = hex::encode(key.mac(s.state.as_bytes()));
        if !crate::secret::ct_eq(want.as_bytes(), s.mac.as_bytes()) {
            fail!(EACCES, "QIF_JOURNAL_TAMPERED");
        }
        let snapshot: QifLedgerSnapshot =
            serde_json::from_str(&s.state).map_err(|e| err!(EINVAL, "QIF_DESERIALIZE", "{e}"))?;
        snapshot.try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ek(i: u8) -> String {
        format!("ek_{}", hex::encode([i; 16]))
    }

    #[test]
    fn millibit_pricing() {
        assert_eq!(millibits_for_outcomes(1), 0);
        assert_eq!(millibits_for_outcomes(2), 1000);
        assert_eq!(millibits_for_outcomes(11), 3460); // quantized deciles
        assert_eq!(millibits_for_outcomes(4096), 12000);
        assert_eq!(millibits_for_outcomes(3), 1585);
    }

    #[test]
    fn millibit_pricing_is_monotone_across_large_power_boundaries() {
        // The old floating-point bump returned 63001 for 2^63 - 1, then
        // 63000 for 2^63. These exact ceilings cannot decrease with arity.
        for bits in 16..=63 {
            let power = 1u64 << bits;
            let exact = 1000 * i64::from(bits);
            assert_eq!(millibits_for_outcomes(power - 1), exact);
            assert_eq!(millibits_for_outcomes(power), exact);
            assert_eq!(millibits_for_outcomes(power + 1), exact + 1);
        }
        assert_eq!(millibits_for_outcomes(u64::MAX), 64000);
        assert_eq!(millibits_for_outcomes(0), 0);
    }

    #[test]
    fn binary_search_exfiltration_is_capped_at_12_bits() {
        let mut l = QifLedger::new(Profile::L2);
        let c = QifCharge {
            entities: vec![ek(1)],
            conf: Conf::C4,
            unstructured: false,
            millibits: 1000,
        };
        for i in 0..12 {
            l.charge(&c, 1000 + i).unwrap();
        }
        let e = l.charge(&c, 2000).unwrap_err();
        assert!(e.is("QIF_BUDGET_EXCEEDED"));
        // After 24h the window slides.
        l.charge(&c, 1000 + WINDOW_MS).unwrap();
    }

    #[test]
    fn charges_are_atomic_across_entities() {
        let mut l = QifLedger::new(Profile::L2);
        l.charge(
            &QifCharge {
                entities: vec![ek(2)],
                conf: Conf::C3,
                unstructured: false,
                millibits: 11_500,
            },
            0,
        )
        .unwrap();
        // Charging {1,2} with 1000 mb must fail because 2 would exceed, and 1 must remain untouched.
        let both = QifCharge {
            entities: vec![ek(1), ek(2)],
            conf: Conf::C3,
            unstructured: false,
            millibits: 1000,
        };
        assert!(l.charge(&both, 1).is_err());
        assert_eq!(l.used(&ek(1), 2), 0);
    }

    #[test]
    fn fanin_and_empty_set_fail_closed() {
        let mut l = QifLedger::new(Profile::L1);
        let many: Vec<String> = (0..65u8).map(ek).collect();
        let e = l
            .charge(
                &QifCharge {
                    entities: many,
                    conf: Conf::C3,
                    unstructured: false,
                    millibits: 1,
                },
                0,
            )
            .unwrap_err();
        assert!(e.is("PROVENANCE_FANIN_EXCEEDED"));
        let e = l
            .charge(
                &QifCharge {
                    entities: vec![],
                    conf: Conf::C4,
                    unstructured: false,
                    millibits: 1,
                },
                0,
            )
            .unwrap_err();
        assert!(e.is("EMPTY_ENTITY_SET"));
    }

    #[test]
    fn global_pool_is_shared_across_sources_and_capped_lower_for_c4_in_l3() {
        let mut l = QifLedger::new(Profile::L3);
        let un = |k: u8, mb| QifCharge {
            entities: vec![ek(k)],
            conf: Conf::C4,
            unstructured: true,
            millibits: mb,
        };
        l.charge(&un(10, 2000), 0).unwrap();
        l.charge(&un(11, 2000), 0).unwrap(); // different URI-derived key, same pool
        assert!(l
            .charge(&un(12, 1), 0)
            .unwrap_err()
            .is("QIF_BUDGET_EXCEEDED"));
        let mut l2 = QifLedger::new(Profile::L2);
        l2.charge(&un(10, 12_000), 0).unwrap();
        assert!(l2.charge(&un(13, 1), 0).is_err());
    }

    #[test]
    fn clock_rollback_does_not_refund() {
        let mut l = QifLedger::new(Profile::L2);
        let c = QifCharge {
            entities: vec![ek(5)],
            conf: Conf::C3,
            unstructured: false,
            millibits: 12_000,
        };
        l.charge(&c, WINDOW_MS + 10).unwrap();
        // Attacker rolls the clock back: still exhausted.
        assert!(l.charge(&c, 5).is_err());
    }

    #[test]
    fn sealed_snapshot_detects_tampering() {
        let k = SecretKey32::random();
        let mut l = QifLedger::new(Profile::L2);
        l.charge(
            &QifCharge {
                entities: vec![ek(7)],
                conf: Conf::C3,
                unstructured: false,
                millibits: 9000,
            },
            0,
        )
        .unwrap();
        let mut s = l.seal(&k).unwrap();
        assert_eq!(QifLedger::unseal(&s, &k).unwrap(), l);
        s.state = s.state.replace("9000", "0");
        assert!(QifLedger::unseal(&s, &k)
            .unwrap_err()
            .is("QIF_JOURNAL_TAMPERED"));
    }

    #[test]
    fn authenticated_snapshot_still_requires_well_formed_accounting() {
        let key = SecretKey32::random();
        let mut invalid = Vec::new();
        for events in [
            vec![(1, -1)],
            vec![(2, 1), (1, 1)],
            vec![(4, 1)],
            vec![(1, 12_001)],
            vec![(1, i64::MAX), (2, i64::MAX)],
        ] {
            let mut ledger = QifLedger::new(Profile::L2);
            ledger.high_water_ms = 3;
            ledger.buckets.insert(
                ek(1),
                Bucket {
                    events: events.into(),
                },
            );
            invalid.push(ledger);
        }
        let mut bad_key = QifLedger::new(Profile::L2);
        bad_key
            .buckets
            .insert("untrusted-key".into(), Bucket::default());
        invalid.push(bad_key);
        for cap in [-1, 12_001] {
            let mut ledger = QifLedger::new(Profile::L2);
            ledger.entity_cap_mb = cap;
            invalid.push(ledger);
        }
        for ledger in invalid {
            // This MAC is correct; rejection must come from semantic validation.
            let sealed = ledger.seal(&key).unwrap();
            assert!(serde_json::from_str::<QifLedger>(&sealed.state).is_err());
            assert!(QifLedger::unseal(&sealed, &key)
                .unwrap_err()
                .is("QIF_LEDGER_INVALID"));
        }
    }

    #[test]
    fn cap_reduction_cannot_invalidate_live_accounting() {
        let mut ledger = QifLedger::new(Profile::L2);
        ledger
            .charge(
                &QifCharge {
                    entities: vec![ek(1)],
                    conf: Conf::C3,
                    unstructured: false,
                    millibits: 2000,
                },
                0,
            )
            .unwrap();
        assert!(ledger
            .clone()
            .with_entity_cap(1999)
            .unwrap_err()
            .is("QIF_CAP_BELOW_USAGE"));
        ledger.with_entity_cap(2000).unwrap().validate().unwrap();
    }
}
