//! Egress registry (GAP-11, FS-705 §3.2.2, `F-025`).
//!
//! An `AbortedPreEgressTombstone(s)` attests that slot `s` was **never
//! released**. A co-signer may only attest that about its *own* behaviour, so
//! UID 703 and UID 704 each keep a persisted record of every governed slot
//! they were issued and every slot they released. Both refuse to sign a
//! tombstone for a slot they released. The issuance owner (UID 703) also
//! rejects unknown slots; UID 704 can attest its own nonrelease for an unseen
//! slot. Matching reservations in both independent registries prevent either
//! correct daemon from subsequently releasing that slot. Protection against a
//! compromised daemon additionally requires every governed release to traverse
//! a correct attestor; this registry alone does not establish that system property.
//!
//! Format: one append-only file per boot epoch,
//! `<state>/egress/<boot_epoch_id>.log`, lines `I <seq>` (issued) and
//! `R <seq>` (released), `T <seq>` (irrevocably tombstoned), `0600`,
//! `fsync` before releasing a value or returning a tombstone signature.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::EnclaveResult;
use crate::{err, fail};

#[derive(Debug, Default, Clone)]
struct EpochLog {
    issued: BTreeSet<u64>,
    released: BTreeSet<u64>,
    tombstoned: BTreeSet<u64>,
}

/// Persisted issued / released slots per boot epoch.
#[derive(Debug)]
pub struct EgressRegistry {
    dir: Option<PathBuf>,
    epochs: BTreeMap<String, EpochLog>,
    // Monotonic, instance-local uncertainty after an observed append I/O error.
    poisoned: bool,
    #[cfg(test)]
    append_test: persistence_tests::AppendTestState,
}

impl EgressRegistry {
    /// In-memory only (tests and `--no-state`).
    pub fn ephemeral() -> Self {
        Self {
            dir: None,
            epochs: BTreeMap::new(),
            poisoned: false,
            #[cfg(test)]
            append_test: persistence_tests::AppendTestState::default(),
        }
    }

    /// Open `dir`, loading every epoch log. A corrupt log fails closed.
    pub fn open(dir: &Path) -> EnclaveResult<Self> {
        crate::fsutil::private_dir(dir)?;
        let entries = std::fs::read_dir(dir)
            .map_err(|e| err!(EIO, "EGRESS_DIR", "{e}"))?;
        let epochs = Self::load_entries(entries)?;
        Ok(Self {
            dir: Some(dir.to_owned()),
            epochs,
            poisoned: false,
            #[cfg(test)]
            append_test: persistence_tests::AppendTestState::default(),
        })
    }

    // Production and private scan tests share this fallible replay loader.
    // Return no partial map when any yielded entry or epoch log refuses.
    fn load_entries(
        entries: impl Iterator<Item = std::io::Result<std::fs::DirEntry>>,
    ) -> EnclaveResult<BTreeMap<String, EpochLog>> {
        let mut epochs = BTreeMap::new();
        for e in entries {
            let e = e.map_err(|e| err!(EIO, "EGRESS_DIR", "{e}"))?;
            let p = e.path();
            let Some(epoch) = p
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".log"))
                .map(str::to_owned)
            else {
                continue;
            };
            crate::seq::validate_epoch_id(&epoch)?;
            let mut log = EpochLog::default();
            let contents = std::fs::read_to_string(&p)
                .map_err(|e| err!(EIO, "EGRESS_READ", "{e}"))?;
            // Existing writers terminate every record with LF. Do not admit a
            // parseable write prefix as a complete historical slot or repair it.
            if !contents.is_empty() && !contents.ends_with('\n') {
                fail!(EINVAL, "EGRESS_LOG_CORRUPT", "{}", p.display());
            }
            for line in contents.lines() {
                let (k, v) = line
                    .split_once(' ')
                    .ok_or_else(|| err!(EINVAL, "EGRESS_LOG_CORRUPT", "{}", p.display()))?;
                let s: u64 = v
                    .parse()
                    .map_err(|_| err!(EINVAL, "EGRESS_LOG_CORRUPT", "{}", p.display()))?;
                match k {
                    "I" => log.issued.insert(s),
                    "R" => {
                        log.issued.insert(s);
                        log.released.insert(s)
                    }
                    "T" => log.tombstoned.insert(s),
                    _ => fail!(EINVAL, "EGRESS_LOG_CORRUPT", "{}", p.display()),
                };
            }
            if !log.released.is_disjoint(&log.tombstoned) {
                fail!(EINVAL, "EGRESS_LOG_CORRUPT", "released and tombstoned slot");
            }
            epochs.insert(epoch, log);
        }
        Ok(epochs)
    }

    /// Refuse new registry authority after an observed append I/O error.
    ///
    /// This monotonic latch belongs only to this registry instance. It neither
    /// revokes authority already returned nor establishes restart/path fencing.
    /// File Drop close errors are unobserved and outside this Result boundary.
    pub fn ensure_healthy(&self) -> EnclaveResult<()> {
        if self.poisoned {
            fail!(EIO, "EGRESS_REGISTRY_POISONED");
        }
        Ok(())
    }

    fn append(&mut self, epoch: &str, rec: &str, sync: bool) -> EnclaveResult<()> {
        // Argument/policy refusals are not persistence errors.
        crate::seq::validate_epoch_id(epoch)?;
        self.ensure_healthy()?;
        let Some(d) = &self.dir else { return Ok(()) };
        let result = Self::append_io(
            d,
            epoch,
            rec,
            sync,
            #[cfg(test)]
            &mut self.append_test,
        );
        if result.is_err() {
            // Keep the first observed error intact. Bytes may already exist;
            // later authority must not infer absence from accepted memory.
            self.poisoned = true;
        }
        result
    }

    // One native persistence pipeline. Test-only stage hooks can refuse a
    // stage; the partial writer forwards actual bytes to this same owned file.
    fn append_io(
        d: &Path,
        epoch: &str,
        rec: &str,
        sync: bool,
        #[cfg(test)] test: &mut persistence_tests::AppendTestState,
    ) -> EnclaveResult<()> {
        let mut o = std::fs::OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let path = d.join(format!("{epoch}.log"));
        #[cfg(test)]
        test.before(persistence_tests::AppendStage::Open)
            .map_err(|e| err!(EIO, "EGRESS_WRITE", "{e}"))?;
        let mut f = o.open(path).map_err(|e| err!(EIO, "EGRESS_WRITE", "{e}"))?;
        let written = {
            #[cfg(test)]
            { test.write_all(&mut f, rec.as_bytes()) }
            #[cfg(not(test))]
            { f.write_all(rec.as_bytes()) }
        };
        written.map_err(|e| err!(EIO, "EGRESS_WRITE", "{e}"))?;
        if sync {
            #[cfg(test)]
            test.before(persistence_tests::AppendStage::FileSync)
                .map_err(|e| err!(EIO, "EGRESS_FSYNC", "{e}"))?;
            f.sync_all().map_err(|e| err!(EIO, "EGRESS_FSYNC", "{e}"))?;
            // Persist a newly created log's directory entry as well as bytes.
            #[cfg(test)]
            test.before(persistence_tests::AppendStage::DirectoryOpen)
                .map_err(|e| err!(EIO, "EGRESS_FSYNC", "{e}"))?;
            let directory = std::fs::File::open(d)
                .map_err(|e| err!(EIO, "EGRESS_FSYNC", "{e}"))?;
            #[cfg(test)]
            test.before(persistence_tests::AppendStage::DirectorySync)
                .map_err(|e| err!(EIO, "EGRESS_FSYNC", "{e}"))?;
            directory.sync_all().map_err(|e| err!(EIO, "EGRESS_FSYNC", "{e}"))?;
        }
        Ok(())
    }

    /// Record that `seq` was issued to this daemon.
    pub fn issued(&mut self, epoch: &str, seq: u64) -> EnclaveResult<()> {
        self.ensure_healthy()?;
        self.append(epoch, &format!("I {seq}\n"), false)?;
        self.epochs
            .entry(epoch.to_owned())
            .or_default()
            .issued
            .insert(seq);
        Ok(())
    }

    /// Record that `seq` left this daemon (persisted before returning).
    pub fn released(&mut self, epoch: &str, seq: u64) -> EnclaveResult<()> {
        self.ensure_healthy()?;
        if self.was_tombstoned(epoch, seq) {
            fail!(EACCES, "TOMBSTONE_SLOT_FINALIZED");
        }
        self.append(epoch, &format!("R {seq}\n"), true)?;
        let l = self.epochs.entry(epoch.to_owned()).or_default();
        l.issued.insert(seq);
        l.released.insert(seq);
        Ok(())
    }

    /// Historical accepted-memory fact, not authorization or proof of absent bytes.
    /// Whether `seq` was released.
    pub fn was_released(&self, epoch: &str, seq: u64) -> bool {
        self.epochs
            .get(epoch)
            .is_some_and(|l| l.released.contains(&seq))
    }

    /// Historical accepted-memory fact, not authorization or proof of absent bytes.
    /// Whether this daemon irrevocably attested nonrelease for this slot.
    pub fn was_tombstoned(&self, epoch: &str, seq: u64) -> bool {
        self.epochs
            .get(epoch)
            .is_some_and(|log| log.tombstoned.contains(&seq))
    }

    /// UID 703 owns issuance and must establish that the slot exists before
    /// signing. The reservation must become durable before the signature.
    pub fn reserve_tombstone(&mut self, epoch: &str, seq: u64) -> EnclaveResult<()> {
        self.ensure_healthy()?;
        self.may_tombstone(epoch, seq)?;
        self.reserve_nonrelease(epoch, seq)
    }

    /// UID 704 attests only its own behavior; it need not have seen a slot
    /// allocated by UID 703. A second attestor still verifies issuance.
    pub fn reserve_nonrelease(&mut self, epoch: &str, seq: u64) -> EnclaveResult<()> {
        self.ensure_healthy()?;
        crate::seq::validate_epoch_id(epoch)?;
        if self.was_released(epoch, seq) {
            fail!(EACCES, "TOMBSTONE_SLOT_RELEASED");
        }
        if !self.was_tombstoned(epoch, seq) {
            self.append(epoch, &format!("T {seq}\n"), true)?;
            self.epochs
                .entry(epoch.to_owned())
                .or_default()
                .tombstoned
                .insert(seq);
        }
        Ok(())
    }

    /// Historical accepted-memory fact, not authorization or proof of absent bytes.
    /// Whether `seq` was issued to this daemon.
    pub fn was_issued(&self, epoch: &str, seq: u64) -> bool {
        self.epochs
            .get(epoch)
            .is_some_and(|l| l.issued.contains(&seq))
    }

    /// Historical accepted-memory facts, not a registry-health decision.
    /// Released slots of `epoch` in `[from, to]`.
    pub fn released_in(&self, epoch: &str, from: u64, to: u64) -> Vec<u64> {
        self.epochs
            .get(epoch)
            .map(|l| l.released.range(from..=to).copied().collect())
            .unwrap_or_default()
    }

    /// The tombstone rule: only an issued, unreleased slot may be attested.
    pub fn may_tombstone(&self, epoch: &str, seq: u64) -> EnclaveResult<()> {
        self.ensure_healthy()?;
        if self.was_released(epoch, seq) {
            fail!(
                EACCES,
                "TOMBSTONE_SLOT_RELEASED",
                "slot {seq} of {epoch} was released"
            );
        }
        if !self.was_issued(epoch, seq) {
            fail!(
                EACCES,
                "TOMBSTONE_SLOT_UNKNOWN",
                "slot {seq} of {epoch} was never issued to this daemon"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_attestors_have_independent_terminal_registries() {
        let epoch = crate::seq::new_boot_epoch_id();
        let mut owner = EgressRegistry::ephemeral();
        let mut ifc = EgressRegistry::ephemeral();
        // One local signature does not freeze the other daemon's state.
        ifc.reserve_nonrelease(&epoch, 7).unwrap();
        owner.released(&epoch, 7).unwrap();
        assert!(owner
            .reserve_tombstone(&epoch, 7)
            .unwrap_err()
            .is("TOMBSTONE_SLOT_RELEASED"));
        // A joint reservation requires both separate local records.
        owner.issued(&epoch, 8).unwrap();
        owner.reserve_tombstone(&epoch, 8).unwrap();
        ifc.reserve_nonrelease(&epoch, 8).unwrap();
        assert!(owner
            .released(&epoch, 8)
            .unwrap_err()
            .is("TOMBSTONE_SLOT_FINALIZED"));
        assert!(ifc
            .released(&epoch, 8)
            .unwrap_err()
            .is("TOMBSTONE_SLOT_FINALIZED"));
        // Equal sequence numbers from distinct epochs cannot be combined.
        let other_epoch = crate::seq::new_boot_epoch_id();
        ifc.reserve_nonrelease(&other_epoch, 9).unwrap();
        owner.issued(&epoch, 9).unwrap();
        owner.reserve_tombstone(&epoch, 9).unwrap();
        assert!(!ifc.was_tombstoned(&epoch, 9));
        assert!(!owner.was_tombstoned(&other_epoch, 9));
    }

    #[test]
    fn tombstone_is_a_durable_terminal_state_not_a_temporary_check() {
        let d = std::env::temp_dir().join(format!("mcpmac-terminal-{}", crate::rng::u64()));
        let epoch = crate::seq::new_boot_epoch_id();
        let mut registry = EgressRegistry::open(&d).unwrap();
        registry.issued(&epoch, 1).unwrap();
        registry.reserve_tombstone(&epoch, 1).unwrap();
        assert!(registry
            .released(&epoch, 1)
            .unwrap_err()
            .is("TOMBSTONE_SLOT_FINALIZED"));
        // Non-owner co-signing permits unseen slots, but still freezes them.
        registry.reserve_nonrelease(&epoch, 7).unwrap();
        registry.issued(&epoch, 7).unwrap();
        assert!(registry.released(&epoch, 7).is_err());
        assert!(registry
            .reserve_tombstone(&epoch, 8)
            .unwrap_err()
            .is("TOMBSTONE_SLOT_UNKNOWN"));
        registry.released(&epoch, 2).unwrap();
        assert!(registry
            .reserve_nonrelease(&epoch, 2)
            .unwrap_err()
            .is("TOMBSTONE_SLOT_RELEASED"));
        drop(registry);
        let mut reopened = EgressRegistry::open(&d).unwrap();
        assert!(reopened.was_tombstoned(&epoch, 1));
        assert!(reopened.was_tombstoned(&epoch, 7));
        assert!(reopened.was_issued(&epoch, 2));
        assert!(reopened
            .released(&epoch, 1)
            .unwrap_err()
            .is("TOMBSTONE_SLOT_FINALIZED"));
        let before = std::fs::read(d.join(format!("{epoch}.log"))).unwrap();
        reopened.reserve_tombstone(&epoch, 1).unwrap();
        assert_eq!(
            std::fs::read(d.join(format!("{epoch}.log"))).unwrap(),
            before
        );
        // A valid-format but contradictory restored log is also rejected.
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(d.join(format!("{epoch}.log")))
            .unwrap();
        writeln!(file, "R 1").unwrap();
        assert!(EgressRegistry::open(&d)
            .unwrap_err()
            .is("EGRESS_LOG_CORRUPT"));
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn released_slots_cannot_be_tombstoned_and_state_survives_restart() {
        let d = std::env::temp_dir().join(format!("mcpmac-egress-{}", crate::rng::u64()));
        let e = crate::seq::new_boot_epoch_id();
        {
            let mut r = EgressRegistry::open(&d).unwrap();
            r.issued(&e, 1).unwrap();
            r.issued(&e, 2).unwrap();
            r.released(&e, 2).unwrap();
            r.may_tombstone(&e, 1).unwrap();
            assert!(r
                .may_tombstone(&e, 2)
                .unwrap_err()
                .is("TOMBSTONE_SLOT_RELEASED"));
            assert!(r
                .may_tombstone(&e, 3)
                .unwrap_err()
                .is("TOMBSTONE_SLOT_UNKNOWN"));
        }
        let r = EgressRegistry::open(&d).unwrap();
        assert!(r
            .may_tombstone(&e, 2)
            .unwrap_err()
            .is("TOMBSTONE_SLOT_RELEASED"));
        r.may_tombstone(&e, 1).unwrap();
        assert_eq!(r.released_in(&e, 0, 10), vec![2]);
        std::fs::write(d.join(format!("{e}.log")), "X 1\n").unwrap();
        assert!(EgressRegistry::open(&d)
            .unwrap_err()
            .is("EGRESS_LOG_CORRUPT"));
        std::fs::remove_dir_all(d).ok();
    }
}

#[cfg(test)]
#[path = "egress_persistence_tests.rs"]
mod persistence_tests;

#[cfg(test)]
#[path = "egress_replay_scan_tests.rs"]
mod replay_scan_tests;
