//! GAP-10: UID 705 derives an epoch's witness itself.
//!
//! The prover no longer accepts slot contents, QIF deltas or journal lines
//! from its caller. For `(boot_epoch_id, s_start..=s_end)` it
//!
//! 1. reads the daemon journals read-only from the audit directory and
//!    verifies each hash chain (and that no journal shrank since the last
//!    epoch this process proved — truncation is `AUDIT_TRUNCATED`);
//! 2. keeps the governed lines of that epoch, i.e. lines stamped with the
//!    sequence authority's `boot_epoch_id` whose `payload.slot` equals their
//!    `rpc_seq_u64` and falls in the range;
//! 3. fetches UID 703's fold witnesses (`D_scrub`, `C_raw`, `H_ingress_mac`)
//!    for released vault slots over the authenticated 705→703 channel.
//!
//! Each slot then becomes exactly one of: a vault fold (703 witness, which
//! must be journaled by 703), an orchestrator fold (a UID 704 journal line,
//! carrying the QIF charge UID 704 recorded), or a tombstone that both
//! co-signers must still be willing to sign (each refuses a slot it released).

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use enclave_core::audit::{ChainAnchor, EnclaveAuditEnvelopeV1, JournalVerifier};
use enclave_core::daemon::DaemonId;
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Journals folded into `J_curr`, in fold order.
pub const JOURNALED: [DaemonId; 4] = [
    DaemonId::ModelRunner,
    DaemonId::SwarmSync,
    DaemonId::CustodyVault,
    DaemonId::AgentRuntime,
];

// This bounds read-ahead, not record length or retained witness bytes.
const JOURNAL_READ_BUFFER: usize = 8 * 1024;

/// One released vault slot as returned by UID 703 (`FetchWitness`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessFold {
    /// Slot.
    pub rpc_seq_u64: u64,
    /// `D_scrub`.
    #[serde(with = "serde_bytes")]
    pub scrubbed: Vec<u8>,
    /// `C_raw` (hex).
    pub c_raw: String,
    /// `H_ingress_mac` (hex).
    pub h_ingress_mac: String,
}

/// Governed journal content of one epoch range.
#[derive(Debug, Default)]
pub struct EpochJournal {
    /// Canonical lines per slot (fold order: daemon, then file order).
    pub lines: BTreeMap<u64, Vec<Vec<u8>>>,
    /// Slots UID 703 journaled.
    pub vault: BTreeMap<u64, ()>,
    /// Slots UID 704 journaled, with the QIF millibits it charged.
    pub ifc: BTreeMap<u64, u32>,
}

/// Read and verify the journals under `dir` for one epoch range.
///
/// `anchors` holds the last verified `(entries, tip)` per daemon and is
/// advanced on success, so a journal rewritten or truncated between epochs
/// is detected. Verification uses one opened regular nofollow descriptor and
/// each exact record is derived immediately after verification. Unselected
/// history is not retained; selected raw records are moved into the result.
/// Scratch memory scales with the largest record plus the fixed reader buffer,
/// and the result still scales with selected bytes. No journal/record cap or
/// constant process-memory/physical-footprint guarantee is implied.
pub fn read_epoch(
    dir: &Path,
    epoch: &str,
    s_start: u64,
    s_end: u64,
    anchors: &mut HashMap<u32, ChainAnchor>,
) -> EnclaveResult<EpochJournal> {
    read_epoch_after_verification(dir, epoch, s_start, s_end, anchors, |_| {})
}

// The private hook gives tests a deterministic path-replacement point after
// each record's verification and before its derivation. Production uses the
// no-op above; both the current owned record and unread tail must remain tied
// to the same opened descriptor when the live path changes at this point.
fn read_epoch_after_verification(
    dir: &Path,
    epoch: &str,
    s_start: u64,
    s_end: u64,
    anchors: &mut HashMap<u32, ChainAnchor>,
    mut after_verification: impl FnMut(&Path),
) -> EnclaveResult<EpochJournal> {
    use std::io::BufReader;
    use std::os::unix::fs::OpenOptionsExt;
    let mut out = EpochJournal::default();
    let mut next = HashMap::new();
    for d in JOURNALED {
        let path = dir
            .join(d.dir_name())
            .join(format!("{}-audit.jsonl", d.plist_suffix()));
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // A daemon that has not journaled yet has no file. That hides
                // nothing: its slots become tombstones, which UID 703 / UID 704
                // refuse to co-sign for any slot they released. A journal that
                // existed and vanished is tampering.
                if anchors.contains_key(&d.uid()) {
                    fail!(EACCES, "AUDIT_TRUNCATED", "{} disappeared", path.display());
                }
                continue;
            }
            Err(e) => return Err(err!(EIO, "AUDIT_OPEN", "{e}")),
        };
        if !file.metadata().map_err(|e| err!(EIO, "AUDIT_METADATA", "{e}"))?.is_file() {
            fail!(EACCES, "AUDIT_NOT_REGULAR");
        }
        // The reader owns this same descriptor until the entire chain and
        // prospective anchor have been checked. Never reopen the live path.
        let anchor = read_verified_records(
            BufReader::with_capacity(JOURNAL_READ_BUFFER, file),
            anchors.get(&d.uid()).copied(),
            |env, line| {
                after_verification(&path);
                if env.daemon_uid != d.uid() {
                    fail!(
                        EACCES,
                        "JOURNAL_FOREIGN_LINE",
                        "UID {} line in the UID {} journal",
                        env.daemon_uid,
                        d.uid()
                    );
                }
                let Some(slot) = env.payload.get("slot").and_then(|v| v.as_u64()) else {
                    return Ok(());
                };
                if env.boot_epoch_id != epoch || !(s_start..=s_end).contains(&slot) {
                    return Ok(());
                }
                if env.rpc_seq_u64 != slot {
                    fail!(
                        EACCES,
                        "JOURNAL_SLOT_MISMATCH",
                        "UID {} line claims slot {slot} at rpc_seq {}",
                        d.uid(),
                        env.rpc_seq_u64
                    );
                }
                match d {
                    DaemonId::CustodyVault => {
                        if out.vault.insert(slot, ()).is_some() {
                            fail!(EACCES, "JOURNAL_SLOT_DUPLICATE", "UID 703 slot {slot}");
                        }
                    }
                    DaemonId::AgentRuntime => {
                        let mb = journal_charge(&env.payload, slot)?;
                        if out.ifc.insert(slot, mb).is_some() {
                            fail!(EACCES, "JOURNAL_SLOT_DUPLICATE", "UID 704 slot {slot}");
                        }
                    }
                    _ => {}
                }
                // Keep the authenticated original bytes, without a second
                // retained per-line copy or any unselected journal history.
                out.lines.entry(slot).or_default().push(std::mem::take(line));
                Ok(())
            },
        )?;
        next.insert(d.uid(), anchor);
    }
    anchors.extend(next);
    Ok(out)
}

// `read_until` keeps only one growable raw record. Empty LF-separated records
// and a final record without LF have exactly the former byte-split semantics;
// CR and every other byte remain part of the authenticated canonical record.
fn read_verified_records(
    mut reader: impl std::io::BufRead,
    anchor: Option<ChainAnchor>,
    mut derive: impl FnMut(EnclaveAuditEnvelopeV1, &mut Vec<u8>) -> EnclaveResult<()>,
) -> EnclaveResult<ChainAnchor> {
    let mut verifier = JournalVerifier::new(anchor);
    let mut line = Vec::new();
    let mut verification_error = None;
    let mut semantic_error = None;
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)
            .map_err(|e| err!(EIO, "AUDIT_READ", "{e}"))? == 0
        {
            break;
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }
        // The former whole-file read reported I/O failure before any chain
        // failure. Drain the descriptor after a bad record to keep that order,
        // but never derive from or resume verification past that record.
        if verification_error.is_some() {
            continue;
        }
        let env = match verifier.push(&line) {
            Ok(env) => env,
            Err(error) => {
                verification_error = Some(error);
                continue;
            }
        };
        // Previously the whole chain was verified before the first semantic
        // check. Keep that failure ordering without buffering the journal:
        // defer the first semantic error while verifying every later record.
        if semantic_error.is_none() {
            if let Err(error) = derive(env, &mut line) {
                semantic_error = Some(error);
            }
        }
    }
    if let Some(error) = verification_error {
        return Err(error);
    }
    let summary = verifier.finish()?;
    if let Some(error) = semantic_error {
        return Err(error);
    }
    Ok(summary.anchor)
}

fn journal_charge(payload: &serde_json::Value, slot: u64) -> EnclaveResult<u32> {
    let event = payload.get("event").and_then(serde_json::Value::as_str)
        .ok_or_else(|| err!(EACCES, "JOURNAL_QIF_EVENT", "slot {slot}"))?;
    match (event, payload.get("qif_mb")) {
        // Old genuine output-sealing records are the sole missing-charge
        // compatibility case. They never reserve a QIF charge. New writers
        // emit explicit zero. Unknown or historical charged events cannot be
        // reconstructed by inventing a zero charge.
        ("TOOL_OUTPUT_SEALED", None) => Ok(0),
        ("TOOL_OUTPUT_SEALED", Some(value)) if value.as_u64() == Some(0) => Ok(0),
        ("TOOL_OUTPUT_SEALED", Some(_)) => fail!(EACCES, "JOURNAL_QIF_RANGE", "slot {slot}"),
        ("TOOL_CALL" | "DECLASSIFY_ENUM" | "DECLASSIFY_ENUM_FAILED" | "EXEC_TOOL", Some(value)) => {
            let mb = value.as_u64()
                .and_then(|mb| u32::try_from(mb).ok())
                .ok_or_else(|| err!(EACCES, "JOURNAL_QIF_RANGE", "slot {slot}"))?;
            Ok(mb)
        }
        ("TOOL_CALL" | "DECLASSIFY_ENUM" | "DECLASSIFY_ENUM_FAILED" | "EXEC_TOOL", None) =>
            fail!(EACCES, "JOURNAL_QIF_MISSING", "slot {slot}"),
        _ => fail!(EACCES, "JOURNAL_QIF_EVENT", "slot {slot}"),
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use enclave_core::audit::{AuditChain, AuditJournal};
    use serde_json::{json, Value};
    use std::cell::Cell;
    use std::io::{self, BufRead, Read};
    use std::path::PathBuf;
    use std::rc::Rc;

    fn scratch() -> PathBuf {
        let path = std::env::temp_dir().join(format!("depot-phase5-snapshot-{}", enclave_core::rng::u64()));
        std::fs::create_dir(&path).unwrap();
        path
    }
    fn path(dir: &Path, daemon: DaemonId) -> PathBuf {
        dir.join(daemon.dir_name()).join(format!("{}-audit.jsonl", daemon.plist_suffix()))
    }
    fn append(dir: &Path, daemon: DaemonId, epoch: &str, seq: u64, payload: Value) {
        AuditJournal::open(&path(dir, daemon), daemon, epoch.into()).unwrap()
            .append(seq, payload).unwrap();
    }

    fn write_records(dir: &Path, daemon: DaemonId, records: &[Vec<u8>]) {
        let journal = path(dir, daemon);
        std::fs::create_dir_all(journal.parent().unwrap()).unwrap();
        let mut bytes = Vec::new();
        for record in records {
            bytes.extend_from_slice(record);
            bytes.push(b'\n');
        }
        std::fs::write(journal, bytes).unwrap();
    }

    // Refuse to expose the next record until the previous one has reached its
    // derivation callback. A reader that buffers all history before deriving
    // cannot pass this test. Small fragments also split multibyte UTF-8.
    struct DerivationGatedReader {
        records: Vec<Vec<u8>>,
        record: usize,
        offset: usize,
        derived: Rc<Cell<usize>>,
    }

    impl Read for DerivationGatedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let available = self.fill_buf()?;
            let n = available.len().min(buf.len());
            buf[..n].copy_from_slice(&available[..n]);
            self.consume(n);
            Ok(n)
        }
    }

    impl BufRead for DerivationGatedReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            if self.derived.get() != self.record {
                return Err(io::Error::other("next record read before prior derivation"));
            }
            let Some(record) = self.records.get(self.record) else {
                return Ok(&[]);
            };
            Ok(&record[self.offset..(self.offset + 17).min(record.len())])
        }

        fn consume(&mut self, amount: usize) {
            self.offset += amount;
            if self.records.get(self.record).is_some_and(|record| self.offset == record.len()) {
                self.record += 1;
                self.offset = 0;
            }
        }
    }

    #[test]
    fn phase5_streaming_derives_before_reading_next_record_and_moves_exact_selected_bytes() {
        let epoch = enclave_core::seq::new_boot_epoch_id();
        let mut chain = AuditChain::new(DaemonId::AgentRuntime, epoch).unwrap();
        let records = [
            chain.next_line(1, json!({"event":"TOOL_CALL","slot":1,"qif_mb":7})).unwrap().1,
            chain.next_line(2, json!({"event":"TOOL_CALL","slot":2,"qif_mb":11,
                "detail":format!("{}{}", "x".repeat(9_000), "é🙂".repeat(17))})).unwrap().1,
            chain.next_line(3, json!({"event":"TOOL_CALL","slot":3,"qif_mb":13})).unwrap().1,
        ];
        assert!(records[1].len() > JOURNAL_READ_BUFFER);
        let expected_anchor = chain.anchor();
        let derived = Rc::new(Cell::new(0));
        let reader = DerivationGatedReader {
            records: records.iter().map(|record| {
                let mut terminated = record.clone();
                terminated.push(b'\n');
                terminated
            }).collect(),
            record: 0,
            offset: 0,
            derived: derived.clone(),
        };
        let mut selected = Vec::new();
        let anchor = read_verified_records(reader, None, |env, record| {
            let index = derived.get();
            assert_eq!(record.as_slice(), records[index].as_slice());
            assert_eq!(env.rpc_seq_u64, index as u64 + 1);
            if env.rpc_seq_u64 == 2 {
                selected.push(std::mem::take(record));
            }
            derived.set(index + 1);
            Ok(())
        }).unwrap();
        assert_eq!(derived.get(), 3);
        assert_eq!(selected, vec![records[1].clone()]);
        assert_eq!(anchor, expected_anchor);
        // The fixture deliberately owns its expected bytes. This proves
        // incremental consumption, not a physical process-memory ceiling.
    }

    #[test]
    fn phase5_streaming_preserves_empty_lines_final_record_and_complete_history_validation() {
        let dir = scratch();
        let epoch = enclave_core::seq::new_boot_epoch_id();
        let other_epoch = enclave_core::seq::new_boot_epoch_id();
        let mut chain = AuditChain::new(DaemonId::AgentRuntime, epoch.clone()).unwrap();
        let selected = chain.next_line(5, json!({"event":"TOOL_CALL","slot":5,"qif_mb":19,
            "detail":"z".repeat(9_000)})).unwrap().1;
        let ignored = chain.next_line_at(&other_epoch, 99,
            json!({"event":"IGNORED","slot":99})).unwrap().1;
        let expected_anchor = chain.anchor();
        let journal = path(&dir, DaemonId::AgentRuntime);
        std::fs::create_dir_all(journal.parent().unwrap()).unwrap();
        let mut bytes = b"\n\n".to_vec();
        bytes.extend_from_slice(&selected);
        bytes.extend_from_slice(b"\n\n");
        bytes.extend_from_slice(&ignored); // A final record need not end in LF.
        std::fs::write(&journal, &bytes).unwrap();
        let mut anchors = HashMap::new();
        let result = read_epoch(&dir, &epoch, 5, 5, &mut anchors).unwrap();
        assert_eq!(result.lines.len(), 1);
        assert_eq!(result.lines.get(&5), Some(&vec![selected]));
        assert_eq!(result.ifc.get(&5), Some(&19));
        assert_eq!(anchors[&DaemonId::AgentRuntime.uid()], expected_anchor);
        let before = anchors.clone();
        // CR is authenticated record content, even on an unselected suffix.
        let mut with_cr = bytes.clone();
        with_cr.push(b'\r');
        std::fs::write(&journal, with_cr).unwrap();
        assert!(read_epoch(&dir, &epoch, 5, 5, &mut anchors).unwrap_err().is("AUDIT_NON_CANONICAL"));
        assert_eq!(anchors, before);
        std::fs::write(&journal, bytes).unwrap();
        assert_eq!(read_epoch(&dir, &epoch, 5, 5, &mut anchors).unwrap().ifc.get(&5), Some(&19));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn phase5_streaming_verifies_ignored_suffix_before_semantic_errors_without_committing_anchors() {
        let dir = scratch();
        let epoch = enclave_core::seq::new_boot_epoch_id();
        let other_epoch = enclave_core::seq::new_boot_epoch_id();
        append(&dir, DaemonId::ModelRunner, &epoch, 1, json!({"event":"MODEL","slot":1}));
        let mut anchors = HashMap::new();
        read_epoch(&dir, &epoch, 1, 1, &mut anchors).unwrap();
        let before = anchors.clone();
        append(&dir, DaemonId::ModelRunner, &epoch, 2, json!({"event":"MODEL","slot":2}));
        let mut chain = AuditChain::new(DaemonId::AgentRuntime, epoch.clone()).unwrap();
        let bad_charge = chain.next_line(1, json!({"event":"TOOL_CALL","slot":1})).unwrap().1;
        let (mut suffix, valid_suffix) = chain.next_line_at(&other_epoch, 99,
            json!({"event":"IGNORED","slot":99})).unwrap();
        suffix.prev_blake3 = Some("0".repeat(64));
        let broken_suffix = enclave_core::jcs::to_jcs_bytes(&suffix).unwrap();
        write_records(&dir, DaemonId::AgentRuntime, &[bad_charge.clone(), broken_suffix]);
        assert!(read_epoch(&dir, &epoch, 1, 2, &mut anchors).unwrap_err().is("AUDIT_BLAKE3_CHAIN_BREAK"));
        assert_eq!(anchors, before);
        write_records(&dir, DaemonId::AgentRuntime, &[bad_charge, valid_suffix]);
        assert!(read_epoch(&dir, &epoch, 1, 2, &mut anchors).unwrap_err().is("JOURNAL_QIF_MISSING"));
        assert_eq!(anchors, before);
        let mut repaired = AuditChain::new(DaemonId::AgentRuntime, epoch.clone()).unwrap();
        let charged = repaired.next_line(1, json!({"event":"TOOL_CALL","slot":1,"qif_mb":17})).unwrap().1;
        let suffix = repaired.next_line_at(&other_epoch, 99,
            json!({"event":"IGNORED","slot":99})).unwrap().1;
        write_records(&dir, DaemonId::AgentRuntime, &[charged, suffix]);
        assert_eq!(read_epoch(&dir, &epoch, 1, 2, &mut anchors).unwrap().ifc.get(&1), Some(&17));
        assert_eq!(anchors[&DaemonId::ModelRunner.uid()].entries, 2);
        assert_eq!(anchors[&DaemonId::AgentRuntime.uid()], repaired.anchor());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn phase5_streaming_open_descriptor_survives_rename_symlink_and_unread_tail() {
        use std::os::unix::fs::symlink;
        let dir = scratch();
        let epoch = enclave_core::seq::new_boot_epoch_id();
        let mut chain = AuditChain::new(DaemonId::AgentRuntime, epoch.clone()).unwrap();
        let first = chain.next_line(1, json!({"event":"TOOL_CALL","slot":1,"qif_mb":23})).unwrap().1;
        let second = chain.next_line(2, json!({"event":"TOOL_CALL","slot":2,"qif_mb":29,
            "detail":"x".repeat(9_000)})).unwrap().1;
        // The second record extends past the first fixed BufReader fill, so
        // some original bytes remain unread on the descriptor at replacement.
        assert!(second.len() > JOURNAL_READ_BUFFER);
        let expected_anchor = chain.anchor();
        write_records(&dir, DaemonId::AgentRuntime, &[first.clone(), second.clone()]);
        let journal = path(&dir, DaemonId::AgentRuntime);
        let saved = dir.join("original-open-journal");
        let replacement = dir.join("replacement-journal");
        let mut alternate = AuditChain::new(DaemonId::AgentRuntime, epoch.clone()).unwrap();
        let alternate_line = alternate.next_line(1,
            json!({"event":"TOOL_CALL","slot":1,"qif_mb":97})).unwrap().1;
        std::fs::write(&replacement, alternate_line).unwrap();
        let mut replacements = 0;
        let mut anchors = HashMap::new();
        let result = read_epoch_after_verification(&dir, &epoch, 1, 2, &mut anchors, |p| {
            if p == journal && replacements == 0 {
                std::fs::rename(p, &saved).unwrap();
                symlink(&replacement, p).unwrap();
                replacements += 1;
            }
        }).unwrap();
        assert_eq!(replacements, 1);
        assert_eq!(result.ifc.get(&1), Some(&23));
        assert_eq!(result.ifc.get(&2), Some(&29));
        assert_eq!(result.lines.get(&1), Some(&vec![first]));
        assert_eq!(result.lines.get(&2), Some(&vec![second]));
        assert_eq!(anchors[&DaemonId::AgentRuntime.uid()], expected_anchor);
        let before = anchors.clone();
        assert!(read_epoch(&dir, &epoch, 1, 2, &mut anchors).unwrap_err().is("AUDIT_OPEN"));
        assert_eq!(anchors, before);
        std::fs::remove_file(&journal).unwrap();
        std::fs::rename(saved, &journal).unwrap();
        assert_eq!(read_epoch(&dir, &epoch, 1, 2, &mut anchors).unwrap().ifc.get(&2), Some(&29));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn phase5_streaming_read_failure_precedes_saved_chain_and_semantic_errors() {
        struct FailAfterPrefix(io::Cursor<Vec<u8>>);
        impl Read for FailAfterPrefix {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.0.position() == self.0.get_ref().len() as u64 {
                    return Err(io::Error::other("injected trailing read failure"));
                }
                self.0.read(buf)
            }
        }
        let epoch = enclave_core::seq::new_boot_epoch_id();
        let mut chain = AuditChain::new(DaemonId::AgentRuntime, epoch).unwrap();
        let mut bytes = chain.next_line(1, json!({"event":"TOOL_CALL","slot":1})).unwrap().1;
        bytes.extend_from_slice(b"\n{}\n");
        let mut derived = 0;
        let result = read_verified_records(io::BufReader::new(FailAfterPrefix(io::Cursor::new(bytes))),
            None, |_, _| {
                derived += 1;
                fail!(EACCES, "JOURNAL_QIF_MISSING");
            });
        assert!(result.unwrap_err().is("AUDIT_READ"));
        assert_eq!(derived, 1);
    }

    #[test]
    fn phase5_verified_snapshot_survives_path_swap_and_preserves_its_anchor() {
        let dir = scratch();
        let epoch = enclave_core::seq::new_boot_epoch_id();
        append(&dir, DaemonId::AgentRuntime, &epoch, 1, json!({"event":"TOOL_CALL","slot":1,"qif_mb":37}));
        let journal = path(&dir, DaemonId::AgentRuntime);
        let original = std::fs::read(&journal).unwrap();
        let mut anchors = HashMap::new();
        let baseline = read_epoch(&dir, &epoch, 1, 1, &mut anchors).unwrap();
        assert_eq!(baseline.ifc.get(&1), Some(&37));
        let before = anchors.clone();
        let mut swaps = 0;
        let snapshot = read_epoch_after_verification(&dir, &epoch, 1, 1, &mut anchors, |p| {
            if p == journal {
                swaps += 1;
                // Same byte count and valid JSON, but a different unauthenticated
                // charge. The old second path read derived this replacement.
                let text = std::str::from_utf8(&original).unwrap().replace("\"qif_mb\":37", "\"qif_mb\":99");
                std::fs::write(p, text).unwrap();
            }
        }).unwrap();
        assert_eq!(swaps, 1);
        assert_eq!(snapshot.ifc.get(&1), Some(&37));
        assert_eq!(snapshot.lines.get(&1), baseline.lines.get(&1));
        assert_eq!(anchors, before);
        assert!(read_epoch(&dir, &epoch, 1, 1, &mut anchors).unwrap_err().is("AUDIT_ANCHOR_MISMATCH"));
        assert_eq!(anchors, before);
        std::fs::write(&journal, &original).unwrap();
        assert_eq!(read_epoch(&dir, &epoch, 1, 1, &mut anchors).unwrap().ifc.get(&1), Some(&37));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn phase5_charge_types_missing_history_and_unknown_events_fail_without_advancing_any_anchor() {
        let dir = scratch();
        let epoch = enclave_core::seq::new_boot_epoch_id();
        append(&dir, DaemonId::ModelRunner, &epoch, 1, json!({"event":"MODEL","slot":1}));
        let mut anchors = HashMap::new();
        read_epoch(&dir, &epoch, 1, 1, &mut anchors).unwrap();
        let before = anchors.clone();
        // The first daemon advances in the next snapshot. A later UID 704
        // failure must roll back this prospective update too.
        append(&dir, DaemonId::ModelRunner, &epoch, 2, json!({"event":"MODEL","slot":2}));
        let bad = [
            (json!({"event":"TOOL_CALL","slot":1}), "JOURNAL_QIF_MISSING"),
            (json!({"event":"DECLASSIFY_ENUM","slot":1}), "JOURNAL_QIF_MISSING"),
            (json!({"event":"DECLASSIFY_ENUM_FAILED","slot":1}), "JOURNAL_QIF_MISSING"),
            (json!({"event":"TOOL_CALL","slot":1,"qif_mb":null}), "JOURNAL_QIF_RANGE"),
            (json!({"event":"TOOL_CALL","slot":1,"qif_mb":"37"}), "JOURNAL_QIF_RANGE"),
            (json!({"event":"TOOL_CALL","slot":1,"qif_mb":-1}), "JOURNAL_QIF_RANGE"),
            (json!({"event":"TOOL_CALL","slot":1,"qif_mb":1.5}), "JOURNAL_QIF_RANGE"),
            (json!({"event":"TOOL_CALL","slot":1,"qif_mb":true}), "JOURNAL_QIF_RANGE"),
            (json!({"event":"TOOL_CALL","slot":1,"qif_mb":u64::from(u32::MAX)+1}), "JOURNAL_QIF_RANGE"),
            (json!({"event":"TOOL_OUTPUT_SEALED","slot":1,"qif_mb":1}), "JOURNAL_QIF_RANGE"),
            (json!({"event":"TOOL_OUTPUT_SEALED","slot":1,"qif_mb":null}), "JOURNAL_QIF_RANGE"),
            (json!({"event":"UNREVIEWED_EVENT","slot":1,"qif_mb":0}), "JOURNAL_QIF_EVENT"),
            (json!({"slot":1,"qif_mb":0}), "JOURNAL_QIF_EVENT"),
        ];
        for (payload, expected) in bad {
            let journal = path(&dir, DaemonId::AgentRuntime);
            if journal.exists() { std::fs::remove_file(&journal).unwrap(); }
            append(&dir, DaemonId::AgentRuntime, &epoch, 1, payload.clone());
            let error = read_epoch(&dir, &epoch, 1, 2, &mut anchors).unwrap_err();
            assert!(error.is(expected), "{payload}: {error}");
            assert_eq!(anchors, before, "{payload}");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn phase5_explicit_charge_zero_boundary_and_legacy_sealed_records_are_usable() {
        let dir = scratch();
        let epoch = enclave_core::seq::new_boot_epoch_id();
        let values = [
            json!({"event":"TOOL_CALL","slot":1,"qif_mb":37}),
            json!({"event":"TOOL_CALL","slot":2,"qif_mb":0}),
            json!({"event":"DECLASSIFY_ENUM","slot":3,"qif_mb":u32::MAX}),
            json!({"event":"DECLASSIFY_ENUM_FAILED","slot":4,"qif_mb":11}),
            json!({"event":"TOOL_OUTPUT_SEALED","slot":5,"qif_mb":0}),
            json!({"event":"TOOL_OUTPUT_SEALED","slot":6}),
            // Historical explicit-charge fixture spelling remains supported;
            // it is never a missing-charge compatibility escape.
            json!({"event":"EXEC_TOOL","slot":7,"qif_mb":5}),
        ];
        for (index, payload) in values.into_iter().enumerate() {
            append(&dir, DaemonId::AgentRuntime, &epoch, index as u64 + 1, payload);
        }
        let mut anchors = HashMap::new();
        let parsed = read_epoch(&dir, &epoch, 1, 7, &mut anchors).unwrap();
        for (slot, charge) in [(1,37),(2,0),(3,u32::MAX),(4,11),(5,0),(6,0),(7,5)] {
            assert_eq!(parsed.ifc.get(&slot), Some(&charge));
        }
        assert_eq!(anchors[&DaemonId::AgentRuntime.uid()].entries, 7);
        // Parsing a valid u32 charge does not authorize exceeding the cap;
        // the production relation rejects it before generating proof bytes.
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn phase5_snapshot_refuses_links_nonregular_files_and_missing_anchored_history() {
        use std::os::unix::{ffi::OsStrExt, fs::symlink};
        let dir = scratch();
        let epoch = enclave_core::seq::new_boot_epoch_id();
        let journal = path(&dir, DaemonId::AgentRuntime);
        std::fs::create_dir_all(journal.parent().unwrap()).unwrap();
        let regular = dir.join("empty-regular");
        std::fs::write(&regular, b"").unwrap();
        let mut anchors = HashMap::new();
        assert!(read_epoch(&dir, &epoch, 1, 1, &mut anchors).unwrap().ifc.is_empty());
        symlink(&regular, &journal).unwrap();
        assert!(read_epoch(&dir, &epoch, 1, 1, &mut anchors).unwrap_err().is("AUDIT_OPEN"));
        std::fs::remove_file(&journal).unwrap();
        std::fs::create_dir(&journal).unwrap();
        assert!(read_epoch(&dir, &epoch, 1, 1, &mut anchors).unwrap_err().is("AUDIT_NOT_REGULAR"));
        std::fs::remove_dir(&journal).unwrap();
        let c_path = std::ffi::CString::new(journal.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert!(read_epoch(&dir, &epoch, 1, 1, &mut anchors).unwrap_err().is("AUDIT_NOT_REGULAR"));
        std::fs::remove_file(&journal).unwrap();
        append(&dir, DaemonId::AgentRuntime, &epoch, 1, json!({"event":"TOOL_CALL","slot":1,"qif_mb":37}));
        read_epoch(&dir, &epoch, 1, 1, &mut anchors).unwrap();
        let before = anchors.clone();
        std::fs::remove_file(&journal).unwrap();
        assert!(read_epoch(&dir, &epoch, 1, 1, &mut anchors).unwrap_err().is("AUDIT_TRUNCATED"));
        assert_eq!(anchors, before);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

/// Wire request on the dedicated 703→705 witness socket (GAP-10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessChannelRequest {
    /// Stream one or more witness folds from UID 703 to UID 705.
    StreamWitness {
        /// Epoch ID.
        boot_epoch_id: String,
        /// Folds.
        folds: Vec<WitnessFold>,
    },
    /// Query witnesses from UID 705.
    FetchWitness {
        /// Epoch ID.
        boot_epoch_id: String,
        /// Start slot.
        s_start: u64,
        /// End slot.
        s_end: u64,
    },
}

/// Wire response on the dedicated 703→705 witness socket (GAP-10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessChannelResponse {
    /// Acknowledged.
    Ack,
    /// Returned witnesses.
    Witness {
        /// Folds.
        folds: Vec<WitnessFold>,
        /// Next slot.
        next_slot: u64,
    },
}

// Keep the public wire types movable/destructurable. Only a fully decoded,
// not-yet-dispatched request needs this local owner across stop/admission.
struct DecodedWitnessRequest(Option<WitnessChannelRequest>);

impl DecodedWitnessRequest {
    fn into_request(mut self) -> WitnessChannelRequest {
        self.0.take().expect("decoded witness request is present")
    }
}

impl Drop for DecodedWitnessRequest {
    fn drop(&mut self) {
        if let Some(WitnessChannelRequest::StreamWitness { folds, .. }) = &mut self.0 {
            for fold in folds {
                fold.scrubbed.zeroize();
                fold.c_raw.zeroize();
                fold.h_ingress_mac.zeroize();
            }
        }
    }
}

// The listener invokes this only after peer and production admission checks.
// A failed insertion must propagate before any Ack is constructed.
pub(crate) fn dispatch_witness_request(
    svc: &crate::service::ZkService,
    req: WitnessChannelRequest,
) -> EnclaveResult<WitnessChannelResponse> {
    match req {
        WitnessChannelRequest::StreamWitness { boot_epoch_id, folds } => {
            svc.ingest_witnesses(&boot_epoch_id, folds)?;
            Ok(WitnessChannelResponse::Ack)
        }
        WitnessChannelRequest::FetchWitness { .. } => Ok(WitnessChannelResponse::Ack),
    }
}

/// Dedicated witness channel server loop (GAP-10), strict production policy.
pub fn serve_witness_channel(
    listener: std::os::unix::net::UnixListener,
    svc: std::sync::Arc<crate::service::ZkService>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    serve_witness_channel_with_admission(listener, svc, stop, || Ok(()));
}

/// Strict production wrapper; fatal listener errors are reported to stderr.
pub fn serve_witness_channel_with_admission(
    listener: std::os::unix::net::UnixListener,
    svc: std::sync::Arc<crate::service::ZkService>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    admission: impl Fn() -> enclave_core::error::EnclaveResult<()>,
) {
    if let Err(error) = serve_witness_channel_with_mode_and_admission(listener, svc, stop, false, admission) {
        eprintln!("witness channel stopped: {error}");
    }
}

/// Explicit trusted development policy. The daemon passes its parsed setting;
/// neither the socket path nor observed identity can enable this exception.
pub fn serve_witness_channel_with_mode_and_admission(
    listener: std::os::unix::net::UnixListener,
    svc: std::sync::Arc<crate::service::ZkService>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    dev_same_uid: bool,
    admission: impl Fn() -> enclave_core::error::EnclaveResult<()>,
) -> enclave_core::error::EnclaveResult<()> {
    let policy = if dev_same_uid {
        enclave_core::ipc::PeerPolicy::allow([enclave_core::ipc::geteuid()])
    } else { enclave_core::ipc::witness_channel_policy() };
    serve_witness_channel_inner(listener, svc, stop, admission, policy, enclave_core::ipc::FrameIoLimits::witness())
}

fn serve_witness_channel_inner(
    listener: std::os::unix::net::UnixListener,
    svc: std::sync::Arc<crate::service::ZkService>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    admission: impl Fn() -> enclave_core::error::EnclaveResult<()>,
    policy: enclave_core::ipc::PeerPolicy,
    frame_io: enclave_core::ipc::FrameIoLimits,
) -> enclave_core::error::EnclaveResult<()> {
    use enclave_core::ipc::{read_frame_timed, write_frame_timed};
    listener.set_nonblocking(true).map_err(|_| enclave_core::err!(EIO, "WITNESS_LISTENER_NONBLOCKING"))?;
    while !stop.load(std::sync::atomic::Ordering::SeqCst) {
        let (mut stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(2));
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(enclave_core::err!(EIO, "WITNESS_ACCEPT")),
        };
        let peer = match enclave_core::ipc::peer_credentials(&stream) {
            Ok(peer) => peer,
            Err(_) => continue,
        };
        if policy.check(&peer).is_err() { continue; }
        let request = match read_frame_timed(&mut stream, &frame_io) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let request = match ciborium::from_reader::<WitnessChannelRequest, _>(request.as_slice()) {
            Ok(request) => DecodedWitnessRequest(Some(request)),
            Err(_) => continue,
        };
        // Lifecycle stop is not a witness authority/release fence. It prevents
        // dispatch after a stop observed here; it cannot revoke an active call.
        if stop.load(std::sync::atomic::Ordering::SeqCst) { break; }
        if admission().is_err() { continue; }
        // Transfer straight into dispatch -> ingest's first-line wiping owner;
        // no fallible policy or state work may intervene after disarming.
        let response = match dispatch_witness_request(&svc, request.into_request()) {
            Ok(response) => response,
            Err(_) => continue,
        };
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        if ciborium::into_writer(&response, &mut *bytes).is_ok() {
            let _ = write_frame_timed(&mut stream, &bytes, &frame_io);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "witness_channel_tests.rs"]
mod channel_tests;
