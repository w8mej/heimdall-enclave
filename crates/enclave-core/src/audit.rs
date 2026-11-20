//! `EnclaveAuditEnvelopeV1` hash-chained journals (CORE-V3, F-024, F-039).
//!
//! Every line of `/var/log/enclave/*-audit.jsonl` is the RFC 8785 canonical
//! JSON of an envelope whose
//! * `prev_blake3`    = BLAKE3 over the previous line's exact bytes, and
//! * `prev_poseidon2` = Poseidon2(`MCPMac-Audit-Line-v1`, previous line bytes),
//!
//! with the all-zero digest as genesis. [`verify_journal`] recomputes both
//! chains, checks `log_seq_u64` contiguity and schema constraints, and — given
//! an off-host / SEP-signed [`ChainAnchor`] — detects tail truncation.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::daemon::DaemonId;
use crate::error::EnclaveResult;
use crate::poseidon2::{hash_bytes, Poseidon2Digest};
use crate::{err, fail};

/// Poseidon2 domain for journal-line hashing.
pub const AUDIT_LINE_DOMAIN: &[u8] = b"MCPMac-Audit-Line-v1";
/// Genesis digest (64 zero hex chars).
pub const GENESIS_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Schema floor for `ts_utc_ms` (2020-01-01).
pub const MIN_TS_UTC_MS: u64 = 1_577_836_800_000;

/// `EnclaveAuditEnvelopeV1`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnclaveAuditEnvelopeV1 {
    /// Always 1.
    pub v: u8,
    /// Emitting daemon UID.
    pub daemon_uid: u32,
    /// Boot epoch.
    pub boot_epoch_id: String,
    /// Per-journal line counter.
    pub log_seq_u64: u64,
    /// Cross-journal join key (shared across UID 701–704).
    pub rpc_seq_u64: u64,
    /// Wall-clock milliseconds.
    pub ts_utc_ms: u64,
    /// `spiffe://corporate.internal/enclave/uid/<uid>`.
    pub spiffe_id: String,
    /// v1.0 simulation field; v3.0 daemons omit it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub prev_sha256: Option<String>,
    /// BLAKE3 link.
    pub prev_blake3: Option<String>,
    /// Poseidon2 link.
    pub prev_poseidon2: Option<String>,
    /// Zero-PII payload.
    pub payload: Value,
}

/// Off-host / SEP-signed checkpoint of a journal tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainAnchor {
    /// Number of lines covered.
    pub entries: u64,
    /// BLAKE3 of the last covered line.
    pub tip_blake3: [u8; 32],
}

/// Result of a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalSummary {
    /// Lines verified.
    pub entries: u64,
    /// Tip BLAKE3 (hex).
    pub tip_blake3: String,
    /// Tip Poseidon2 (hex).
    pub tip_poseidon2: String,
    /// Anchor for this tip.
    pub anchor: ChainAnchor,
}

fn validate_spiffe(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("spiffe://") else {
        return false;
    };
    let Some((dom, path)) = rest.split_once('/') else {
        return false;
    };
    !dom.is_empty()
        && dom
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && !path.is_empty()
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
}

impl EnclaveAuditEnvelopeV1 {
    /// Schema-level validation.
    pub fn validate(&self) -> EnclaveResult<()> {
        if self.v != 1 {
            fail!(EINVAL, "AUDIT_BAD_VERSION");
        }
        crate::seq::validate_epoch_id(&self.boot_epoch_id)?;
        if self.ts_utc_ms < MIN_TS_UTC_MS {
            fail!(EINVAL, "AUDIT_BAD_TS");
        }
        if !validate_spiffe(&self.spiffe_id) {
            fail!(EINVAL, "AUDIT_BAD_SPIFFE_ID");
        }
        if !self.payload.is_object() {
            fail!(EINVAL, "AUDIT_PAYLOAD_NOT_OBJECT");
        }
        for h in [&self.prev_blake3, &self.prev_poseidon2, &self.prev_sha256]
            .into_iter()
            .flatten()
        {
            if h.len() != 64 || !h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                fail!(EINVAL, "AUDIT_BAD_DIGEST");
            }
        }
        Ok(())
    }
}

/// In-memory chain state (the writer side).
#[derive(Debug, Clone)]
pub struct ChainState {
    /// Lines written.
    pub entries: u64,
    /// Previous BLAKE3.
    pub prev_blake3: [u8; 32],
    /// Previous Poseidon2.
    pub prev_poseidon2: Poseidon2Digest,
}

impl ChainState {
    /// Genesis state.
    pub fn genesis() -> Self {
        Self {
            entries: 0,
            prev_blake3: [0; 32],
            prev_poseidon2: Poseidon2Digest::ZERO,
        }
    }
    fn advance(&mut self, line: &[u8]) {
        self.entries += 1;
        self.prev_blake3 = *blake3::hash(line).as_bytes();
        self.prev_poseidon2 = hash_bytes(AUDIT_LINE_DOMAIN, line);
    }
}

/// Builds envelopes and the exact canonical line bytes.
#[derive(Debug, Clone)]
pub struct AuditChain {
    daemon: DaemonId,
    boot_epoch_id: String,
    state: ChainState,
}

impl AuditChain {
    /// Fresh chain.
    pub fn new(daemon: DaemonId, boot_epoch_id: String) -> EnclaveResult<Self> {
        crate::seq::validate_epoch_id(&boot_epoch_id)?;
        Ok(Self {
            daemon,
            boot_epoch_id,
            state: ChainState::genesis(),
        })
    }
    /// Resume from an existing verified state.
    pub fn resume(daemon: DaemonId, boot_epoch_id: String, state: ChainState) -> Self {
        Self {
            daemon,
            boot_epoch_id,
            state,
        }
    }
    /// Current state.
    pub fn state(&self) -> &ChainState {
        &self.state
    }
    /// Append a payload and return `(envelope, canonical line bytes)`.
    pub fn next_line(
        &mut self,
        rpc_seq_u64: u64,
        payload: Value,
    ) -> EnclaveResult<(EnclaveAuditEnvelopeV1, Vec<u8>)> {
        let e = self.boot_epoch_id.clone();
        self.next_line_at(&e, rpc_seq_u64, payload)
    }
    /// As [`Self::next_line`], stamped with the governing `boot_epoch_id`
    /// of a slot issued by the sequence authority (UID 703, GAP-27).
    pub fn next_line_at(
        &mut self,
        boot_epoch_id: &str,
        rpc_seq_u64: u64,
        payload: Value,
    ) -> EnclaveResult<(EnclaveAuditEnvelopeV1, Vec<u8>)> {
        crate::seq::validate_epoch_id(boot_epoch_id)?;
        if !payload.is_object() {
            fail!(EINVAL, "AUDIT_PAYLOAD_NOT_OBJECT");
        }
        let env = EnclaveAuditEnvelopeV1 {
            v: 1,
            daemon_uid: self.daemon.uid(),
            boot_epoch_id: boot_epoch_id.to_owned(),
            log_seq_u64: self.state.entries + 1,
            rpc_seq_u64,
            ts_utc_ms: now_utc_ms().max(MIN_TS_UTC_MS),
            spiffe_id: self.daemon.spiffe_id(),
            prev_sha256: None,
            prev_blake3: Some(hex::encode(self.state.prev_blake3)),
            prev_poseidon2: Some(self.state.prev_poseidon2.to_hex()),
            payload,
        };
        let line = crate::jcs::to_jcs_bytes(&env)?;
        self.state.advance(&line);
        Ok((env, line))
    }
    /// Anchor for the current tip.
    pub fn anchor(&self) -> ChainAnchor {
        ChainAnchor {
            entries: self.state.entries,
            tip_blake3: self.state.prev_blake3,
        }
    }
}

/// Canonical bytes of an `AbortedPreEgressTombstone(slot, egress_released = false)`
/// that UID 703 **and** UID 704 must both sign (FS-705 §3.2.2, ADR-016).
pub fn tombstone_message(slot_rpc_seq: u64, boot_epoch_id: &str) -> Vec<u8> {
    let mut m = b"MCPMac-AbortedPreEgressTombstone-v1\0".to_vec();
    m.extend_from_slice(&slot_rpc_seq.to_be_bytes());
    m.extend_from_slice(boot_epoch_id.as_bytes());
    m.push(0); // egress_released = false
    m
}

/// Wall clock in ms.
pub fn now_utc_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Incremental verifier for exact, LF-free canonical journal records.
///
/// Each returned record has passed schema, canonical-byte, sequence and both
/// chain-link checks. The supplied anchor is a required historical prefix,
/// checked only once its entry is reached; it is not a new trust source.
/// Call [`Self::finish`] at end-of-input to reject a journal shorter than that
/// prefix. Callers must stage derived effects until finish succeeds.
/// A failed push permanently poisons this verifier: ignoring a malformed
/// record must never allow a valid-prefix summary to be certified afterward.
/// Scratch storage scales with the largest record, not the journal history.
#[derive(Debug)]
pub struct JournalVerifier {
    state: ChainState,
    anchor: Option<ChainAnchor>,
    anchor_hit: bool,
    failed: bool,
}

impl JournalVerifier {
    /// Start at genesis and require an optional previously authenticated prefix.
    pub fn new(anchor: Option<ChainAnchor>) -> Self {
        Self {
            state: ChainState::genesis(),
            anchor,
            anchor_hit: anchor.is_none_or(|a| a.entries == 0 && a.tip_blake3 == [0; 32]),
            failed: false,
        }
    }

    /// Verify the next exact record and return its checked envelope.
    /// The complete input and required historical anchor must still pass finish.
    /// Empty records are invalid here; file readers preserve their existing
    /// policy of skipping empty LF-delimited records before calling this method.
    pub fn push(&mut self, line: &[u8]) -> EnclaveResult<EnclaveAuditEnvelopeV1> {
        if self.failed {
            fail!(EACCES, "AUDIT_VERIFIER_FAILED");
        }
        self.failed = true;
        let envelope = self.push_record(line)?;
        self.failed = false;
        Ok(envelope)
    }

    fn push_record(&mut self, line: &[u8]) -> EnclaveResult<EnclaveAuditEnvelopeV1> {
        let n = self.state.entries.checked_add(1)
            .ok_or_else(|| err!(EACCES, "AUDIT_SEQ_OVERFLOW"))?;
        let env: EnclaveAuditEnvelopeV1 = serde_json::from_slice(line)
            .map_err(|e| err!(EINVAL, "AUDIT_LINE_PARSE", "line {n}: {e}"))?;
        env.validate()
            .map_err(|e| err!(EINVAL, "AUDIT_LINE_INVALID", "line {n}: {e}"))?;
        // Line bytes must be exactly canonical (no re-serialization ambiguity).
        let canon = crate::jcs::to_jcs_bytes(&env)?;
        if canon != line {
            fail!(EINVAL, "AUDIT_NON_CANONICAL", "line {n}");
        }
        if env.log_seq_u64 != n {
            fail!(
                EACCES,
                "AUDIT_SEQ_BREAK",
                "line {n} has log_seq {}",
                env.log_seq_u64
            );
        }
        if env.prev_blake3.as_deref() != Some(hex::encode(self.state.prev_blake3).as_str()) {
            fail!(EACCES, "AUDIT_BLAKE3_CHAIN_BREAK", "line {n}");
        }
        if env.prev_poseidon2.as_deref() != Some(self.state.prev_poseidon2.to_hex().as_str()) {
            fail!(EACCES, "AUDIT_POSEIDON2_CHAIN_BREAK", "line {n}");
        }
        self.state.advance(line);
        if let Some(a) = self.anchor {
            if a.entries == n {
                if a.tip_blake3 != self.state.prev_blake3 {
                    fail!(EACCES, "AUDIT_ANCHOR_MISMATCH", "line {n}");
                }
                self.anchor_hit = true;
            }
        }
        Ok(env)
    }

    /// Complete a fully consumed journal and certify its checked tip.
    /// Call this only after consuming the complete input. It consumes the
    /// verifier, preventing reuse of the same state after publishing a summary.
    pub fn finish(self) -> EnclaveResult<JournalSummary> {
        if self.failed {
            fail!(EACCES, "AUDIT_VERIFIER_FAILED");
        }
        if !self.anchor_hit {
            fail!(
                EACCES,
                "AUDIT_TRUNCATED",
                "journal shorter than anchored {} entries",
                self.anchor.map_or(0, |a| a.entries)
            );
        }
        Ok(JournalSummary {
            entries: self.state.entries,
            tip_blake3: hex::encode(self.state.prev_blake3),
            tip_poseidon2: self.state.prev_poseidon2.to_hex(),
            anchor: ChainAnchor {
                entries: self.state.entries,
                tip_blake3: self.state.prev_blake3,
            },
        })
    }
}

/// Verify a sequence of raw journal lines.
pub fn verify_lines<'a, I: IntoIterator<Item = &'a [u8]>>(
    lines: I,
    anchor: Option<ChainAnchor>,
) -> EnclaveResult<JournalSummary> {
    let mut verifier = JournalVerifier::new(anchor);
    for line in lines {
        verifier.push(line)?;
    }
    verifier.finish()
}

/// Verify a journal file.
pub fn verify_journal(path: &Path, anchor: Option<ChainAnchor>) -> EnclaveResult<JournalSummary> {
    let mut options=OpenOptions::new();options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A FIFO must not block verification/startup before fstat can reject
        // it. A leaf symlink must not redirect the authenticated journal.
        options.custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK);
    }
    let f=options.open(path).map_err(|e|err!(EIO,"AUDIT_OPEN","{e}"))?;
    require_regular_journal(&f)?;
    let mut verifier = JournalVerifier::new(anchor);
    let mut verification_error = None;
    for line in BufReader::new(f).split(b'\n') {
        let line = line.map_err(|e| err!(EIO, "AUDIT_READ", "{e}"))?;
        if !line.is_empty() && verification_error.is_none() {
            if let Err(error) = verifier.push(&line) {
                verification_error = Some(error);
            }
        }
    }
    // The old buffered reader completed I/O before checking records. Continue
    // reading after the first invalid record to preserve that error precedence,
    // without retaining subsequent journal history in memory.
    if let Some(error) = verification_error {
        return Err(error);
    }
    verifier.finish()
}

// Check the opened descriptor, rather than a racy path metadata probe. Some
// systems successfully fsync a FIFO; that cannot establish durable audit data.
fn require_regular_journal(file:&std::fs::File)->EnclaveResult<()> {
    let metadata=file.metadata().map_err(|e|err!(EIO,"AUDIT_METADATA","{e}"))?;
    if !metadata.is_file(){fail!(EACCES,"AUDIT_NOT_REGULAR");}
    Ok(())
}

/// Append-only journal file (`O_APPEND`, mode `0640`, `fsync` per line).
#[derive(Debug)]
pub struct AuditJournal {
    path: PathBuf,
    chain: AuditChain,
    // A failed write/fsync may have left a partial or complete line on disk.
    // Do not append again until reopening has verified the actual journal.
    failed: bool,
}

impl AuditJournal {
    /// Open (verifying any existing content first; a broken chain fails closed).
    pub fn open(path: &Path, daemon: DaemonId, boot_epoch_id: String) -> EnclaveResult<Self> {
        let existing=match std::fs::symlink_metadata(path) {
            Ok(_)=>true,
            Err(error) if error.kind()==std::io::ErrorKind::NotFound=>false,
            Err(error)=>return Err(err!(EIO,"AUDIT_METADATA","{error}")),
        };
        let state = if existing {
            let s = verify_journal(path, None)?;
            let mut prev_p = Poseidon2Digest::ZERO;
            if s.entries > 0 {
                prev_p = Poseidon2Digest::from_hex(&s.tip_poseidon2)
                    .ok_or_else(|| err!(EINVAL, "AUDIT_TIP"))?;
            }
            ChainState {
                entries: s.entries,
                prev_blake3: s.anchor.tip_blake3,
                prev_poseidon2: prev_p,
            }
        } else {
            if let Some(d) = path.parent() {
                std::fs::create_dir_all(d).map_err(|e| err!(EIO, "AUDIT_MKDIR", "{e}"))?;
            }
            ChainState::genesis()
        };
        crate::seq::validate_epoch_id(&boot_epoch_id)?;
        Ok(Self {
            path: path.to_owned(),
            chain: AuditChain::resume(daemon, boot_epoch_id, state),
            failed: false,
        })
    }

    /// Append one record.
    pub fn append(
        &mut self,
        rpc_seq_u64: u64,
        payload: Value,
    ) -> EnclaveResult<EnclaveAuditEnvelopeV1> {
        if self.failed {
            fail!(EIO, "AUDIT_WRITE_UNCERTAIN");
        }
        let mut next = self.chain.clone();
        let (env, line) = next.next_line(rpc_seq_u64, payload)?;
        let env = self.write_line(env, line)?;
        self.chain = next;
        Ok(env)
    }
    /// Append one record for a slot of the governing epoch (GAP-27).
    pub fn append_at(
        &mut self,
        boot_epoch_id: &str,
        rpc_seq_u64: u64,
        payload: Value,
    ) -> EnclaveResult<EnclaveAuditEnvelopeV1> {
        if self.failed {
            fail!(EIO, "AUDIT_WRITE_UNCERTAIN");
        }
        let mut next = self.chain.clone();
        let (env, line) = next.next_line_at(boot_epoch_id, rpc_seq_u64, payload)?;
        let env = self.write_line(env, line)?;
        self.chain = next;
        Ok(env)
    }
    fn write_line(
        &mut self,
        env: EnclaveAuditEnvelopeV1,
        mut line: Vec<u8>,
    ) -> EnclaveResult<EnclaveAuditEnvelopeV1> {
        line.push(b'\n');
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // 0640: the prover (UID 705) reads journals through the
            // `_enclave_journal_r` group of the per-daemon journal directory.
            opts.mode(0o640).custom_flags(libc::O_NOFOLLOW);
        }
        let result = (|| {
            let mut f = opts
                .open(&self.path)
                .map_err(|e| err!(EIO, "AUDIT_OPEN", "{e}"))?;
            require_regular_journal(&f)?;
            f.write_all(&line)
                .map_err(|e| err!(EIO, "AUDIT_WRITE", "{e}"))?;
            crate::fsutil::full_fsync(&f).map_err(|e| err!(EIO, "AUDIT_FSYNC", "{e}"))
        })();
        if let Err(error) = result {
            self.failed = true;
            return Err(error);
        }
        Ok(env)
    }

    /// Current anchor.
    pub fn anchor(&self) -> ChainAnchor {
        self.chain.anchor()
    }
    /// Path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn build(n: usize) -> (Vec<Vec<u8>>, ChainAnchor) {
        let mut c = AuditChain::new(DaemonId::SwarmSync, crate::seq::new_boot_epoch_id()).unwrap();
        let lines = (0..n)
            .map(|i| {
                c.next_line(i as u64, json!({"event": "resolve", "i": i}))
                    .unwrap()
                    .1
            })
            .collect();
        (lines, c.anchor())
    }

    #[test]
    fn incremental_anchor_is_a_required_prefix_and_allows_later_records() {
        let (lines, tip) = build(4);
        let prefix = ChainAnchor {
            entries: 2,
            tip_blake3: *blake3::hash(&lines[1]).as_bytes(),
        };
        let mut truncated = JournalVerifier::new(Some(prefix));
        let first = truncated.push(&lines[0]).unwrap();
        assert_eq!(first.log_seq_u64, 1);
        assert!(truncated.finish().unwrap_err().is("AUDIT_TRUNCATED"));
        let mut verifier = JournalVerifier::new(Some(prefix));
        for (index, line) in lines.iter().enumerate() {
            let envelope = verifier.push(line).unwrap();
            assert_eq!(envelope.log_seq_u64, index as u64 + 1);
            assert_eq!(crate::jcs::to_jcs_bytes(&envelope).unwrap(), *line);
        }
        let summary = verifier.finish().unwrap();
        assert_eq!(summary.entries, 4);
        assert_eq!(summary.anchor, tip);
        assert_eq!(summary.tip_blake3, hex::encode(tip.tip_blake3));
        assert_eq!(summary.tip_poseidon2, hash_bytes(AUDIT_LINE_DOMAIN, &lines[3]).to_hex());
        let mut wrong = JournalVerifier::new(Some(ChainAnchor {
            tip_blake3: [1; 32], ..prefix
        }));
        wrong.push(&lines[0]).unwrap();
        assert!(wrong.push(&lines[1]).unwrap_err().is("AUDIT_ANCHOR_MISMATCH"));
        assert!(wrong.finish().unwrap_err().is("AUDIT_VERIFIER_FAILED"));
        assert_eq!(JournalVerifier::new(None).finish().unwrap().entries, 0);
        assert!(JournalVerifier::new(Some(prefix)).finish().unwrap_err().is("AUDIT_TRUNCATED"));
    }

    #[test]
    fn incremental_invalid_record_poison_prevents_prefix_certification_or_retry() {
        let (lines, _) = build(2);
        let envelope: EnclaveAuditEnvelopeV1 = serde_json::from_slice(&lines[1]).unwrap();
        let mut attacks = vec![(b"{".to_vec(), "AUDIT_LINE_PARSE")];
        let mut noncanonical = lines[1].clone();
        noncanonical.push(b' ');
        attacks.push((noncanonical, "AUDIT_NON_CANONICAL"));
        for (field, reason) in [
            ("version", "AUDIT_LINE_INVALID"),
            ("sequence", "AUDIT_SEQ_BREAK"),
            ("blake3", "AUDIT_BLAKE3_CHAIN_BREAK"),
            ("poseidon2", "AUDIT_POSEIDON2_CHAIN_BREAK"),
        ] {
            let mut invalid = envelope.clone();
            match field {
                "version" => invalid.v = 2,
                "sequence" => invalid.log_seq_u64 = 3,
                "blake3" => invalid.prev_blake3 = Some(GENESIS_HEX.to_owned()),
                "poseidon2" => invalid.prev_poseidon2 = Some(GENESIS_HEX.to_owned()),
                _ => unreachable!(),
            }
            attacks.push((crate::jcs::to_jcs_bytes(&invalid).unwrap(), reason));
        }
        for (attack, reason) in attacks {
            let mut verifier = JournalVerifier::new(None);
            verifier.push(&lines[0]).unwrap();
            assert!(verifier.push(&attack).unwrap_err().is(reason), "{reason}");
            assert!(verifier.push(&lines[1]).unwrap_err().is("AUDIT_VERIFIER_FAILED"));
            assert!(verifier.finish().unwrap_err().is("AUDIT_VERIFIER_FAILED"));
        }
    }

    #[test]
    fn incremental_sequence_overflow_refuses_without_wrapping_or_certifying() {
        let (lines, _) = build(1);
        let mut verifier = JournalVerifier::new(None);
        verifier.state.entries = u64::MAX;
        assert!(verifier.push(&lines[0]).unwrap_err().is("AUDIT_SEQ_OVERFLOW"));
        assert!(verifier.finish().unwrap_err().is("AUDIT_VERIFIER_FAILED"));
    }

    #[test]
    fn streamed_file_preserves_empty_lines_unterminated_tail_and_anchor_refusal() {
        let (lines, anchor) = build(3);
        let dir = std::env::temp_dir().join(format!("mcpmac-audit-stream-{}", crate::rng::u64()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("audit");
        let mut bytes = vec![b'\n'];
        for (index, line) in lines.iter().enumerate() {
            bytes.extend_from_slice(line);
            if index != lines.len() - 1 { bytes.extend_from_slice(b"\n\n"); }
        }
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(verify_journal(&path, Some(anchor)).unwrap().anchor, anchor);
        let mut forged = bytes.clone();
        forged.push(b' ');
        std::fs::write(&path, forged).unwrap();
        assert!(verify_journal(&path, Some(anchor)).unwrap_err().is("AUDIT_NON_CANONICAL"));
        std::fs::write(&path, &lines[0]).unwrap();
        assert!(verify_journal(&path, Some(anchor)).unwrap_err().is("AUDIT_TRUNCATED"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn valid_chain_verifies() {
        let (lines, a) = build(20);
        let s = verify_lines(lines.iter().map(|l| l.as_slice()), Some(a)).unwrap();
        assert_eq!(s.entries, 20);
    }

    #[test]
    fn edit_delete_reorder_detected() {
        let (lines, _) = build(6);
        let mut edited = lines.clone();
        edited[2] = String::from_utf8(edited[2].clone())
            .unwrap()
            .replace("\"i\":2", "\"i\":9")
            .into_bytes();
        assert!(verify_lines(edited.iter().map(|l| l.as_slice()), None).is_err());
        let mut deleted = lines.clone();
        deleted.remove(3);
        assert!(verify_lines(deleted.iter().map(|l| l.as_slice()), None).is_err());
        let mut swapped = lines.clone();
        swapped.swap(1, 2);
        assert!(verify_lines(swapped.iter().map(|l| l.as_slice()), None).is_err());
    }

    #[test]
    fn tail_truncation_detected_only_with_anchor() {
        let (lines, a) = build(8);
        let trunc = &lines[..5];
        assert!(verify_lines(trunc.iter().map(|l| l.as_slice()), None).is_ok());
        assert!(verify_lines(trunc.iter().map(|l| l.as_slice()), Some(a))
            .unwrap_err()
            .is("AUDIT_TRUNCATED"));
    }

    #[test]
    fn poseidon2_link_is_independent_of_blake3_link() {
        // Forge a line that keeps prev_blake3 correct but corrupts prev_poseidon2.
        let (lines, _) = build(3);
        let mut env: EnclaveAuditEnvelopeV1 = serde_json::from_slice(&lines[1]).unwrap();
        env.prev_poseidon2 = Some(GENESIS_HEX.to_owned());
        let mut forged = lines.clone();
        forged[1] = crate::jcs::to_jcs_bytes(&env).unwrap();
        let e = verify_lines(forged.iter().map(|l| l.as_slice()), None).unwrap_err();
        assert!(e.is("AUDIT_POSEIDON2_CHAIN_BREAK"), "{e}");
    }

    #[test]
    fn file_journal_roundtrip_and_resume() {
        let dir = std::env::temp_dir().join(format!("mcpmac-audit-{}", crate::rng::u64()));
        let p = dir.join("cas-audit.jsonl");
        let epoch = crate::seq::new_boot_epoch_id();
        let mut j = AuditJournal::open(&p, DaemonId::SwarmSync, epoch.clone()).unwrap();
        for i in 0..5 {
            j.append(i, json!({"k": i})).unwrap();
        }
        drop(j);
        let mut j = AuditJournal::open(&p, DaemonId::SwarmSync, epoch).unwrap();
        j.append(5, json!({"k": 5})).unwrap();
        let s = verify_journal(&p, Some(j.anchor())).unwrap();
        assert_eq!(s.entries, 6);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn phase1_failed_append_retains_durable_anchor_and_requires_verified_reopen() {
        let dir = std::env::temp_dir().join(format!("mcpmac-audit-failure-{}", crate::rng::u64()));
        let path = dir.join("audit");
        let saved = dir.join("saved");
        let epoch = crate::seq::new_boot_epoch_id();
        let mut journal = AuditJournal::open(&path, DaemonId::SwarmSync, epoch.clone()).unwrap();
        journal.append(1, json!({"event":"first"})).unwrap();
        let durable = journal.anchor();
        std::fs::rename(&path, &saved).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(journal.append(2, json!({"event":"refused"})).unwrap_err().is("AUDIT_OPEN"));
        assert_eq!(journal.anchor(), durable);
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&saved, &path).unwrap();
        assert!(journal.append(3, json!({"event":"retry"})).unwrap_err().is("AUDIT_WRITE_UNCERTAIN"));
        assert!(journal.append_at(&epoch, 4, json!({"event":"retry-at"})).unwrap_err().is("AUDIT_WRITE_UNCERTAIN"));
        assert_eq!(verify_journal(&path, Some(durable)).unwrap().entries, 1);
        drop(journal);
        let mut reopened = AuditJournal::open(&path, DaemonId::SwarmSync, epoch).unwrap();
        reopened.append(5, json!({"event":"recovered"})).unwrap();
        assert_eq!(verify_journal(&path, Some(reopened.anchor())).unwrap().entries, 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn phase1_partial_write_latches_and_corrupt_tail_refuses_reopen() {
        const CHILD: &str = "MCPMAC_PHASE1_AUDIT_PARTIAL_CHILD";
        if let Some(dir) = std::env::var_os(CHILD) {
            let path = PathBuf::from(dir).join("audit");
            let epoch = crate::seq::new_boot_epoch_id();
            let mut journal = AuditJournal::open(&path, DaemonId::SwarmSync, epoch.clone()).unwrap();
            let durable = journal.anchor();
            // Limit only this owned child. Pipes used for its captured test
            // output are unaffected; the journal gets a real short write.
            unsafe {
                libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
                let limit = libc::rlimit { rlim_cur: 64, rlim_max: 64 };
                assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
            }
            assert!(journal.append(1, json!({"event":"partial"})).unwrap_err().is("AUDIT_WRITE"));
            assert_eq!(std::fs::metadata(&path).unwrap().len(), 64);
            assert_eq!(journal.anchor(), durable);
            assert!(journal.append(2, json!({"event":"retry"})).unwrap_err().is("AUDIT_WRITE_UNCERTAIN"));
            assert!(AuditJournal::open(&path, DaemonId::SwarmSync, epoch).unwrap_err().is("AUDIT_LINE_PARSE"));
            return;
        }
        let dir = std::env::temp_dir().join(format!("mcpmac-audit-partial-{}", crate::rng::u64()));
        std::fs::create_dir(&dir).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "audit::tests::phase1_partial_write_latches_and_corrupt_tail_refuses_reopen", "--nocapture"])
            .env(CHILD, &dir).output().unwrap();
        let _ = std::fs::remove_dir_all(dir);
        assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    }

    #[cfg(unix)]
    #[test]
    fn journal_rejects_existing_fifo_directory_and_leaf_symlink_before_read() {
        use std::os::unix::{ffi::OsStrExt,fs::symlink};
        let dir=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target").canonicalize().unwrap()
            .join(format!("audit-regularity-{}",crate::rng::u64()));
        std::fs::create_dir(&dir).unwrap();
        let fifo=dir.join("fifo");let c_path=std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe{libc::mkfifo(c_path.as_ptr(),0o600)},0);
        let directory=dir.join("directory");std::fs::create_dir(&directory).unwrap();
        let regular=dir.join("regular");std::fs::write(&regular,b"").unwrap();
        let link=dir.join("link");symlink(&regular,&link).unwrap();
        for path in [&fifo,&directory,&link] {
            assert!(verify_journal(path,None).is_err());
            assert!(AuditJournal::open(path,DaemonId::SwarmSync,crate::seq::new_boot_epoch_id()).is_err());
        }
        assert!(verify_journal(&fifo,None).unwrap_err().is("AUDIT_NOT_REGULAR"));
        assert!(verify_journal(&regular,None).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn journal_symlink_swap_never_writes_or_advances_anchor() {
        use std::os::unix::fs::symlink;
        let dir=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target").canonicalize().unwrap()
            .join(format!("audit-symlink-{}",crate::rng::u64()));
        std::fs::create_dir(&dir).unwrap();let path=dir.join("journal");let saved=dir.join("saved");
        let mut journal=AuditJournal::open(&path,DaemonId::SwarmSync,crate::seq::new_boot_epoch_id()).unwrap();
        journal.append(1,json!({"event":"durable"})).unwrap();let anchor=journal.anchor();
        std::fs::rename(&path,&saved).unwrap();let original=std::fs::read(&saved).unwrap();symlink(&saved,&path).unwrap();
        assert!(journal.append(2,json!({"event":"refused"})).unwrap_err().is("AUDIT_OPEN"));
        assert_eq!(std::fs::read(&saved).unwrap(),original);assert_eq!(journal.anchor(),anchor);
        assert!(journal.append(3,json!({"event":"retry"})).unwrap_err().is("AUDIT_WRITE_UNCERTAIN"));
        assert_eq!(verify_journal(&saved,Some(anchor)).unwrap().entries,1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn schema_example_header_is_well_formed() {
        let ex: EnclaveAuditEnvelopeV1 = serde_json::from_str(include_str!(
            "../../../schemas/examples/enclave-audit-envelope-v1.example.json"
        ))
        .unwrap();
        ex.validate().unwrap();
        let bad: Result<EnclaveAuditEnvelopeV1, _> = serde_json::from_str(include_str!(
            "../../../schemas/examples/invalid/enclave-audit-envelope-v1.invalid.iso-ts.json"
        ));
        assert!(bad.is_err() || bad.unwrap().validate().is_err());
    }
}
