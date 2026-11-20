//! Compliance ledger state: replay rejection, per-chain ordering, a hard
//! capacity bound, and an optional hash-chained append-only journal
//! (DEFECT-F-92).
//!
//! # Chains
//! Frames are grouped by `nullifier_e`, which FS-705 defines as
//! `Poseidon2(DOM_NULL ‖ id_enclave ‖ e)`: one value per enclave per epoch,
//! constant across every frame of that epoch (the series verifier enforces
//! this, `rollup.rs` `SERIES_NULLIFIER_MISMATCH`). The nullifier is already a
//! public input, so keying on it links nothing an observer could not link
//! already, and frames from different hosts never interleave.
//!
//! Within a chain each new frame must extend the previous one exactly as
//! `ComplianceRollupProofV1::verify_series` requires of consecutive frames:
//! `s_start == prev.s_end + 1`, `used_in == prev.used_out`,
//! `J_prev == prev.J_curr`, same profile / policy / TUF snapshot root, and the
//! first frame of a chain starts at `used_in == 0`.
//!
//! # Replays
//! A byte-identical frame already recorded is reported as a duplicate and not
//! recorded again (an honest retry after a lost acknowledgement still gets a
//! 200 so the host's outbox can drop it). A different encoding of an already
//! covered slot range fails the chain rule (`SLOT_OVERLAP`).

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use enclave_zk_auditor::rollup::ComplianceRollupProofV1;
use serde::{Deserialize, Serialize};

/// Default maximum number of frames the ledger will hold.
pub const DEFAULT_MAX_FRAMES: usize = 100_000;
/// Default binary state directory. Its trusted parent must be provisioned by the operator.
pub const DEFAULT_STATE_DIR: &str = "/var/db/enclave/ledger";
/// Journal filename within a dedicated state directory.
pub const STATE_JOURNAL_NAME: &str = "frames.jsonl";
/// Absolute configuration ceiling, including replay allocations.
pub const HARD_MAX_FRAMES: usize = 1_000_000;
const MAX_JOURNAL_LINE: usize = 16 * 1024;

/// Record of a verified rollup frame accepted by the compliance ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedFrameSummary {
    /// Blake3 hash of the raw wire frame bytes.
    pub frame_digest: [u8; 32],
    /// Profile of the verified frame (L1, L2, or L3).
    pub profile: u8,
    /// Starting slot index.
    pub s_start: u64,
    /// Ending slot index (inclusive).
    pub s_end: u64,
    /// Whether this was an L3 constant-rate heartbeat cover frame.
    pub heartbeat: bool,
    /// Verifier key digest under which this frame was verified.
    pub vk_digest: [u8; 32],
    /// Cohort size committed in frame (if L3).
    pub cohort_size: Option<u64>,
    /// Chain key: the frame's epoch nullifier (hex).
    pub nullifier_e: String,
    /// QIF millibits entering the frame.
    pub used_in: u32,
    /// QIF millibits leaving the frame.
    pub used_out: u32,
    /// Journal commitment before the frame (hex).
    pub j_prev: String,
    /// Journal commitment after the frame (hex).
    pub j_curr: String,
    /// Policy digest (hex).
    pub policy_blake3: String,
    /// TUF snapshot root (hex).
    pub tuf_snapshot_root: String,
}

impl VerifiedFrameSummary {
    /// Summarise a verified frame.
    pub fn of(frame: &ComplianceRollupProofV1, frame_digest: [u8; 32], vk: [u8; 32]) -> Self {
        let p = &frame.public_inputs;
        Self {
            frame_digest,
            profile: frame.profile,
            s_start: frame.s_start,
            s_end: frame.s_end,
            heartbeat: frame.heartbeat.unwrap_or(false),
            vk_digest: vk,
            cohort_size: frame.cohort_size,
            nullifier_e: p.nullifier_e.clone(),
            used_in: p.used_in,
            used_out: p.used_out,
            j_prev: p.J_prev.clone(),
            j_curr: p.J_curr.clone(),
            policy_blake3: p.policy_blake3.clone(),
            tuf_snapshot_root: p.tuf_snapshot_root.clone(),
        }
    }
}

/// Outcome of offering a verified frame to the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Newly recorded.
    Recorded,
    /// Byte-identical to a frame already recorded; nothing changed.
    Duplicate,
}

/// The chain rule between the last recorded frame of a chain and a new one.
/// `prev == None` means the frame opens a new chain.
pub fn check_link(
    prev: Option<&VerifiedFrameSummary>,
    next: &VerifiedFrameSummary,
) -> EnclaveResult<()> {
    let Some(prev) = prev else {
        if next.used_in != 0 {
            fail!(
                EACCES,
                "QIF_INITIAL_NONZERO",
                "first frame of a chain has used_in {}",
                next.used_in
            );
        }
        return Ok(());
    };
    let expected = prev
        .s_end
        .checked_add(1)
        .ok_or_else(|| err!(EACCES, "SLOT_OVERFLOW"))?;
    if next.s_start < expected {
        fail!(
            EACCES,
            "SLOT_OVERLAP",
            "frame starts at {} but chain already covers up to {}",
            next.s_start,
            prev.s_end
        );
    }
    if next.s_start > expected {
        fail!(
            EACCES,
            "SLOT_GAP",
            "frame starts at {} but chain ended at {}",
            next.s_start,
            prev.s_end
        );
    }
    if next.used_in != prev.used_out {
        fail!(
            EACCES,
            "QIF_CHAIN_BREAK",
            "used_in {} != previous used_out {}",
            next.used_in,
            prev.used_out
        );
    }
    if next.j_prev != prev.j_curr {
        fail!(EACCES, "JOURNAL_CHAIN_BREAK");
    }
    if next.profile != prev.profile {
        fail!(EACCES, "SERIES_PROFILE_MISMATCH");
    }
    if next.policy_blake3 != prev.policy_blake3 {
        fail!(EACCES, "SERIES_POLICY_MISMATCH");
    }
    if next.tuf_snapshot_root != prev.tuf_snapshot_root {
        fail!(EACCES, "SERIES_TUF_MISMATCH");
    }
    Ok(())
}

/// One journal line: the summary plus the blake3 of the previous line.
#[derive(Debug, Serialize, Deserialize)]
struct JournalLine {
    prev: String,
    frame: VerifiedFrameSummary,
}

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Ledger state. All mutation goes through [`Ledger::admit`].
#[derive(Debug)]
pub struct Ledger {
    frames: Vec<VerifiedFrameSummary>,
    digests: HashSet<[u8; 32]>,
    tips: HashMap<String, usize>,
    max_frames: usize,
    journal: Option<(PathBuf, File)>,
    last_line_hash: String,
    write_failed: bool,
}

impl Ledger {
    /// An in-memory ledger (lost on restart) bounded to `max_frames`.
    pub fn in_memory(max_frames: usize) -> Self {
        Self {
            frames: Vec::new(),
            digests: HashSet::new(),
            tips: HashMap::new(),
            max_frames: max_frames.min(HARD_MAX_FRAMES),
            journal: None,
            last_line_hash: GENESIS.into(),
            write_failed: false,
        }
    }

    /// Open (or create, mode 0600) a persistent journal and replay it,
    /// re-checking the hash chain, replay set, chain rule and capacity. Any
    /// inconsistency refuses to open.
    pub fn open(path: &Path, max_frames: usize) -> EnclaveResult<Self> {
        if max_frames == 0 || max_frames > HARD_MAX_FRAMES {
            fail!(EINVAL, "LEDGER_CAPACITY_INVALID");
        }
        let mut ledger = Self::in_memory(max_frames);
        let (path, mut file) = open_locked(path)?;
        ledger.replay(&mut file)?;
        ledger.journal = Some((path, file));
        Ok(ledger)
    }

    /// Open the durable journal in an owned, mode-0700 state directory.
    ///
    /// The immediate parent must already exist, be owned by the effective user,
    /// and forbid group/other writes. Only the final directory is created;
    /// symlinks, wrong owners/modes and storage errors fail without falling back
    /// to memory. This does not detect deletion or a valid-prefix rollback by
    /// the storage owner; that requires an independently trusted head.
    pub fn open_state_dir(directory: &Path, max_frames: usize) -> EnclaveResult<Self> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        let parent = directory
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = std::fs::canonicalize(parent)
            .map_err(|e| err!(EIO, "LEDGER_STATE_PARENT", "{e}"))?;
        let meta = std::fs::metadata(&parent)
            .map_err(|e| err!(EIO, "LEDGER_STATE_PARENT", "{e}"))?;
        if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
            fail!(EACCES, "LEDGER_STATE_PARENT_UNTRUSTED");
        }
        let directory = parent.join(
            directory
                .file_name()
                .ok_or_else(|| err!(EINVAL, "LEDGER_STATE_PATH"))?,
        );
        match std::fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(err!(EIO, "LEDGER_STATE_CREATE", "{e}")),
        }
        let meta = std::fs::symlink_metadata(&directory)
            .map_err(|e| err!(EIO, "LEDGER_STATE_META", "{e}"))?;
        if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o7777 != 0o700 {
            fail!(EACCES, "LEDGER_STATE_UNTRUSTED");
        }
        // Persist the directory and its parent entry before any frame may be
        // acknowledged. Ledger::open separately syncs the journal and its entry.
        File::open(&directory)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| err!(EIO, "LEDGER_STATE_SYNC", "{e}"))?;
        File::open(&parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| err!(EIO, "LEDGER_STATE_PARENT_SYNC", "{e}"))?;
        Self::open(&directory.join(STATE_JOURNAL_NAME), max_frames)
    }

    fn replay(&mut self, file: &mut File) -> EnclaveResult<()> {
        file.seek(SeekFrom::Start(0))
            .map_err(|e| err!(EIO, "LEDGER_JOURNAL_READ", "{e}"))?;
        let mut reader = BufReader::new(file);
        let mut n = 0usize;
        loop {
            let mut bytes = Vec::new();
            let size = reader
                .by_ref()
                .take((MAX_JOURNAL_LINE + 1) as u64)
                .read_until(b'\n', &mut bytes)
                .map_err(|e| err!(EIO, "LEDGER_JOURNAL_READ", "{e}"))?;
            if size == 0 {
                break;
            }
            if size > MAX_JOURNAL_LINE {
                fail!(EINVAL, "LEDGER_JOURNAL_LINE_LIMIT");
            }
            if bytes.pop() != Some(b'\n') {
                fail!(EINVAL, "LEDGER_JOURNAL_PARTIAL");
            }
            let line = std::str::from_utf8(&bytes)
                .map_err(|e| err!(EINVAL, "LEDGER_JOURNAL_CORRUPT", "{e}"))?;
            let rec: JournalLine = serde_json::from_str(&line)
                .map_err(|e| err!(EINVAL, "LEDGER_JOURNAL_CORRUPT", "line {}: {e}", n + 1))?;
            if rec.prev != self.last_line_hash {
                fail!(
                    EINVAL,
                    "LEDGER_JOURNAL_CHAIN",
                    "line {} does not follow line {}",
                    n + 1,
                    n
                );
            }
            if self.insert(rec.frame)? == Admission::Duplicate {
                fail!(EINVAL, "LEDGER_JOURNAL_DUPLICATE", "line {}", n + 1);
            }
            self.last_line_hash = blake3::hash(line.as_bytes()).to_hex().to_string();
            n += 1;
        }
        Ok(())
    }

    /// Check and record one verified frame summary.
    pub fn admit(&mut self, summary: VerifiedFrameSummary) -> EnclaveResult<Admission> {
        if self.write_failed {
            fail!(EIO, "LEDGER_JOURNAL_FAILED");
        }
        if self.digests.contains(&summary.frame_digest) {
            return Ok(Admission::Duplicate);
        }
        self.check(&summary)?;
        if let Some((path, file)) = self.journal.as_mut() {
            let line = serde_json::to_string(&JournalLine {
                prev: self.last_line_hash.clone(),
                frame: summary.clone(),
            })
            .map_err(|e| err!(EIO, "LEDGER_JOURNAL_ENCODE", "{e}"))?;
            if line.len() + 1 > MAX_JOURNAL_LINE {
                fail!(EINVAL, "LEDGER_JOURNAL_LINE_LIMIT");
            }
            if let Err(e) = file
                .write_all(format!("{line}\n").as_bytes())
                .and_then(|()| file.sync_all())
            {
                // A partial append or uncertain durability cannot be followed by
                // more acknowledgements from this process. Reopen must validate.
                self.write_failed = true;
                return Err(err!(EIO, "LEDGER_JOURNAL_WRITE", "{}: {e}", path.display()));
            }
            self.last_line_hash = blake3::hash(line.as_bytes()).to_hex().to_string();
        }
        self.insert(summary)
    }

    fn check(&self, s: &VerifiedFrameSummary) -> EnclaveResult<()> {
        if [
            &s.nullifier_e,
            &s.j_prev,
            &s.j_curr,
            &s.policy_blake3,
            &s.tuf_snapshot_root,
        ]
        .iter()
        .any(|v| v.len() > 256)
        {
            fail!(EINVAL, "LEDGER_FIELD_LIMIT");
        }
        if self.frames.len() >= self.max_frames {
            fail!(
                ENOMEM,
                "LEDGER_FULL",
                "ledger holds its maximum of {} frames",
                self.max_frames
            );
        }
        check_link(self.tip(&s.nullifier_e), s)
    }

    fn insert(&mut self, s: VerifiedFrameSummary) -> EnclaveResult<Admission> {
        if self.digests.contains(&s.frame_digest) {
            return Ok(Admission::Duplicate);
        }
        self.check(&s)?;
        self.digests.insert(s.frame_digest);
        self.tips.insert(s.nullifier_e.clone(), self.frames.len());
        self.frames.push(s);
        Ok(Admission::Recorded)
    }

    /// Last recorded frame of the chain keyed by `nullifier_e`.
    pub fn tip(&self, nullifier_e: &str) -> Option<&VerifiedFrameSummary> {
        self.tips.get(nullifier_e).and_then(|&i| self.frames.get(i))
    }

    /// All recorded frames in admission order.
    pub fn frames(&self) -> &[VerifiedFrameSummary] {
        &self.frames
    }

    /// Path of the persistent journal, if any.
    pub fn journal_path(&self) -> Option<&Path> {
        self.journal.as_ref().map(|(p, _)| p.as_path())
    }
}

// Lock the descriptor used for BOTH replay and append. Separate handles,
// including in the same process, cannot accept from stale chain state.
fn open_locked(path: &Path) -> EnclaveResult<(PathBuf, File)> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = std::fs::canonicalize(parent).map_err(|e| err!(EIO, "LEDGER_PARENT", "{e}"))?;
    let meta = std::fs::metadata(&parent).map_err(|e| err!(EIO, "LEDGER_PARENT", "{e}"))?;
    if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
        fail!(EACCES, "LEDGER_PARENT_UNTRUSTED");
    }
    let path = parent.join(
        path.file_name()
            .ok_or_else(|| err!(EINVAL, "LEDGER_PATH"))?,
    );
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|e| err!(EIO, "LEDGER_JOURNAL_OPEN", "{e}"))?;
    let meta = file
        .metadata()
        .map_err(|e| err!(EIO, "LEDGER_JOURNAL_META", "{e}"))?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
    {
        fail!(EACCES, "LEDGER_JOURNAL_UNTRUSTED");
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        fail!(EACCES, "LEDGER_JOURNAL_LOCKED");
    }
    file.sync_all()
        .map_err(|e| err!(EIO, "LEDGER_JOURNAL_SYNC", "{e}"))?;
    File::open(&parent)
        .and_then(|dir| dir.sync_all())
        .map_err(|e| err!(EIO, "LEDGER_PARENT_SYNC", "{e}"))?;
    Ok((path, file))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sum(
        null: &str,
        s: (u64, u64),
        used: (u32, u32),
        j: (&str, &str),
        tag: u8,
    ) -> VerifiedFrameSummary {
        VerifiedFrameSummary {
            frame_digest: *blake3::hash(&[tag, s.0 as u8, null.as_bytes()[0]]).as_bytes(),
            profile: 2,
            s_start: s.0,
            s_end: s.1,
            heartbeat: false,
            vk_digest: [9; 32],
            cohort_size: None,
            nullifier_e: null.into(),
            used_in: used.0,
            used_out: used.1,
            j_prev: j.0.into(),
            j_curr: j.1.into(),
            policy_blake3: "p".into(),
            tuf_snapshot_root: "t".into(),
        }
    }

    fn f1() -> VerifiedFrameSummary {
        sum("n1", (1, 4), (0, 10), ("j0", "j1"), 1)
    }
    fn f2() -> VerifiedFrameSummary {
        sum("n1", (5, 8), (10, 25), ("j1", "j2"), 2)
    }

    fn reason(r: EnclaveResult<()>) -> String {
        r.map(|()| "OK".to_string()).unwrap_or_else(|e| e.reason)
    }

    #[test]
    fn link_rules() {
        assert_eq!(reason(check_link(None, &f1())), "OK");
        assert_eq!(reason(check_link(Some(&f1()), &f2())), "OK");
        let opens_nonzero = sum("n", (1, 1), (3, 3), ("a", "b"), 0);
        assert_eq!(
            reason(check_link(None, &opens_nonzero)),
            "QIF_INITIAL_NONZERO"
        );
        let cases = [
            (VerifiedFrameSummary { s_start: 4, ..f2() }, "SLOT_OVERLAP"),
            (VerifiedFrameSummary { s_start: 1, ..f2() }, "SLOT_OVERLAP"),
            (VerifiedFrameSummary { s_start: 6, ..f2() }, "SLOT_GAP"),
            (
                VerifiedFrameSummary { used_in: 9, ..f2() },
                "QIF_CHAIN_BREAK",
            ),
            (
                VerifiedFrameSummary {
                    j_prev: "jx".into(),
                    ..f2()
                },
                "JOURNAL_CHAIN_BREAK",
            ),
            (
                VerifiedFrameSummary { profile: 3, ..f2() },
                "SERIES_PROFILE_MISMATCH",
            ),
            (
                VerifiedFrameSummary {
                    policy_blake3: "q".into(),
                    ..f2()
                },
                "SERIES_POLICY_MISMATCH",
            ),
            (
                VerifiedFrameSummary {
                    tuf_snapshot_root: "u".into(),
                    ..f2()
                },
                "SERIES_TUF_MISMATCH",
            ),
        ];
        for (next, want) in cases {
            assert_eq!(reason(check_link(Some(&f1()), &next)), want);
        }
        let at_max = VerifiedFrameSummary {
            s_end: u64::MAX,
            ..f1()
        };
        assert_eq!(reason(check_link(Some(&at_max), &f2())), "SLOT_OVERFLOW");
    }

    #[test]
    fn duplicate_is_not_recorded_twice_and_reorder_is_refused() {
        let mut l = Ledger::in_memory(10);
        assert_eq!(l.admit(f1()).expect("f1"), Admission::Recorded);
        assert_eq!(l.admit(f1()).expect("dup"), Admission::Duplicate);
        assert_eq!(l.frames().len(), 1);
        assert_eq!(l.admit(f2()).expect("f2"), Admission::Recorded);
        assert_eq!(l.admit(f2()).expect("dup2"), Admission::Duplicate);
        assert_eq!(l.frames().len(), 2);
        // Out of order on a fresh ledger: f2 first cannot open a chain.
        let mut fresh = Ledger::in_memory(10);
        assert_eq!(fresh.admit(f2()).unwrap_err().reason, "QIF_INITIAL_NONZERO");
        assert!(
            fresh.frames().is_empty(),
            "refused frame must not be recorded"
        );
    }

    #[test]
    fn chains_are_independent() {
        let mut l = Ledger::in_memory(10);
        let g1 = sum("n2", (1, 2), (0, 1), ("k0", "k1"), 3);
        let g2 = sum("n2", (3, 3), (1, 1), ("k1", "k2"), 4);
        for f in [f1(), g1, f2(), g2] {
            assert_eq!(l.admit(f).expect("interleaved"), Admission::Recorded);
        }
        assert_eq!(l.tip("n1").map(|t| t.s_end), Some(8));
        assert_eq!(l.tip("n2").map(|t| t.s_end), Some(3));
    }

    #[test]
    fn capacity_is_a_hard_bound() {
        let mut l = Ledger::in_memory(1);
        l.admit(f1()).expect("f1");
        assert_eq!(l.admit(f2()).unwrap_err().reason, "LEDGER_FULL");
        // A replay of a recorded frame is still recognised when full.
        assert_eq!(l.admit(f1()).expect("dup"), Admission::Duplicate);
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ledger-f92-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("tmp");
        d.join("ledger.jsonl")
    }

    #[test]
    fn journal_survives_restart_and_keeps_replay_and_order_state() {
        let p = tmp("restart");
        {
            let mut l = Ledger::open(&p, 10).expect("open");
            l.admit(f1()).expect("f1");
        }
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&p).expect("meta").permissions(),
        );
        assert_eq!(mode & 0o777, 0o600);
        let mut l = Ledger::open(&p, 10).expect("reopen");
        assert_eq!(l.frames(), &[f1()]);
        assert_eq!(
            l.admit(f1()).expect("dup after restart"),
            Admission::Duplicate
        );
        assert_eq!(
            l.admit(VerifiedFrameSummary { s_start: 2, ..f2() })
                .unwrap_err()
                .reason,
            "SLOT_OVERLAP"
        );
        assert_eq!(l.admit(f2()).expect("f2"), Admission::Recorded);
        drop(l);
        assert_eq!(Ledger::open(&p, 10).expect("third open").frames().len(), 2);
        // The persisted capacity bound applies at load.
        assert_eq!(Ledger::open(&p, 1).unwrap_err().reason, "LEDGER_FULL");
    }

    #[test]
    fn tampered_journal_refuses_to_open() {
        let p = tmp("tamper");
        {
            let mut l = Ledger::open(&p, 10).expect("open");
            l.admit(f1()).expect("f1");
            l.admit(f2()).expect("f2");
        }
        let text = std::fs::read_to_string(&p).expect("read");
        let lines: Vec<&str> = text.lines().collect();
        // Drop the first line: the second no longer follows genesis.
        std::fs::write(&p, format!("{}\n", lines[1])).expect("write");
        assert_eq!(
            Ledger::open(&p, 10).unwrap_err().reason,
            "LEDGER_JOURNAL_CHAIN"
        );
        // Edit a field in place.
        std::fs::write(&p, text.replace("\"s_end\":4", "\"s_end\":3")).expect("write");
        let r = Ledger::open(&p, 10).unwrap_err().reason;
        assert!(r == "LEDGER_JOURNAL_CHAIN" || r == "SLOT_GAP", "{r}");
        std::fs::write(&p, "not json\n").expect("write");
        assert_eq!(
            Ledger::open(&p, 10).unwrap_err().reason,
            "LEDGER_JOURNAL_CORRUPT"
        );
    }
    #[test]
    fn second_writer_refused_then_restart_preserves_chain() {
        if let Some(path) = std::env::var_os("MCPMAC_F92_LOCK_CHILD") {
            assert_eq!(
                Ledger::open(Path::new(&path), 10).unwrap_err().reason,
                "LEDGER_JOURNAL_LOCKED"
            );
            return;
        }
        let p = tmp("writers");
        let mut first = Ledger::open(&p, 10).unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ledger::tests::second_writer_refused_then_restart_preserves_chain",
            ])
            .env("MCPMAC_F92_LOCK_CHILD", &p)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "{}",
            String::from_utf8_lossy(&child.stderr)
        );
        assert_eq!(
            Ledger::open(&p, 10).unwrap_err().reason,
            "LEDGER_JOURNAL_LOCKED"
        );
        first.admit(f1()).unwrap();
        drop(first);
        let mut second = Ledger::open(&p, 10).unwrap();
        assert_eq!(second.admit(f1()).unwrap(), Admission::Duplicate);
        second.admit(f2()).unwrap();
        drop(second);
        assert_eq!(Ledger::open(&p, 10).unwrap().frames().len(), 2);
    }

    #[test]
    fn replay_limits_and_untrusted_existing_files_fail() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let p = tmp("limits");
        drop(Ledger::open(&p, 10).unwrap());
        std::fs::write(&p, vec![b'x'; MAX_JOURNAL_LINE + 1]).unwrap();
        assert_eq!(
            Ledger::open(&p, 10).unwrap_err().reason,
            "LEDGER_JOURNAL_LINE_LIMIT"
        );
        std::fs::write(&p, b"{}").unwrap();
        assert_eq!(
            Ledger::open(&p, 10).unwrap_err().reason,
            "LEDGER_JOURNAL_PARTIAL"
        );
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            Ledger::open(&p, 10).unwrap_err().reason,
            "LEDGER_JOURNAL_UNTRUSTED"
        );
        let link = p.with_extension("link");
        symlink(&p, &link).unwrap();
        assert!(Ledger::open(&link, 10).is_err());
        assert!(Ledger::open(&p, HARD_MAX_FRAMES + 1).is_err());
    }
}
