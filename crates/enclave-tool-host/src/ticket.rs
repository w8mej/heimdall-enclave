//! Execution tickets for WASI / depot tool calls (GAP-04, GAP-18).
//!
//! Tools execute only with a single-use execution ticket issued by UID 704,
//! signed with UID 704's grant/policy key, binding arguments, row bound, and expiry.

pub use crate::replay::TicketReplayFilter;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};

/// Row interpretation selected by the trusted issuer and covered by its signature.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RowFormat {
    /// Each top-level JSON array element is one approved row.
    #[default]
    JsonArray,
    /// Each UTF-8 text line is one approved row (CR, LF and CRLF supported).
    Utf8Lines,
}

/// Execution ticket issued by UID 704 for a single tool call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionTicket {
    /// Unique ticket identifier (for replay protection).
    pub ticket_id: String,
    /// Target depot server name.
    pub server: String,
    /// Target tool name.
    pub tool_name: String,
    /// Hex-encoded BLAKE3 hash of JCS-canonical arguments.
    pub args_blake3: String,
    /// Maximum allowed rows returned (GAP-09).
    pub row_bound: u64,
    /// Issuance timestamp in UNIX epoch nanoseconds.
    pub issued_at_unix_ns: u64,
    /// Expiry timestamp in UNIX epoch nanoseconds.
    pub expires_at_unix_ns: u64,
    /// Digest of an issuer-approved precompiled native module; absent for depot calls.
    #[serde(default)]
    pub module_blake3: Option<[u8; 32]>,
    /// Issuer-selected output interpretation.
    #[serde(default)]
    pub row_format: RowFormat,
    /// Hex-encoded Ed25519 signature over ticket canonical fields.
    pub signature: String,
}

impl ExecutionTicket {
    /// Issue and sign a new execution ticket.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        signing_key: &SigningKey,
        ticket_id: String,
        server: String,
        tool_name: String,
        args_blake3: String,
        row_bound: u64,
        issued_at_unix_ns: u64,
        ttl_ns: u64,
    ) -> Self {
        let expires_at_unix_ns = issued_at_unix_ns.saturating_add(ttl_ns);
        let mut ticket = Self {
            ticket_id,
            server,
            tool_name,
            args_blake3,
            row_bound,
            issued_at_unix_ns,
            expires_at_unix_ns,
            module_blake3: None,
            row_format: RowFormat::JsonArray,
            signature: String::new(),
        };
        ticket.signature = hex::encode(signing_key.sign(&ticket.signing_bytes()).to_bytes());
        ticket
    }

    /// Issue a ticket authorizing exactly one trusted build artifact. The issuer
    /// must obtain this digest from its authenticated build/registry, not the request.
    pub fn for_module(mut self, signing_key: &SigningKey, module_blake3: [u8; 32]) -> Self {
        self.module_blake3 = Some(module_blake3);
        self.signature = hex::encode(signing_key.sign(&self.signing_bytes()).to_bytes());
        self
    }

    /// Select the row contract from authenticated tool metadata before issuance.
    pub fn with_row_format(mut self, signing_key: &SigningKey, format: RowFormat) -> Self {
        self.row_format = format;
        self.signature = hex::encode(signing_key.sign(&self.signing_bytes()).to_bytes());
        self
    }

    /// V2 canonical bytes: domain + length-prefixed strings + fixed-width typed fields.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut msg = b"depot-EXEC-TICKET-V2\0".to_vec();
        for value in [
            &self.ticket_id,
            &self.server,
            &self.tool_name,
            &self.args_blake3,
        ] {
            msg.extend_from_slice(&(value.len() as u64).to_be_bytes());
            msg.extend_from_slice(value.as_bytes());
        }
        for value in [
            self.row_bound,
            self.issued_at_unix_ns,
            self.expires_at_unix_ns,
        ] {
            msg.extend_from_slice(&value.to_be_bytes());
        }
        match self.module_blake3 {
            Some(digest) => {
                msg.push(1);
                msg.extend_from_slice(&digest);
            }
            None => msg.push(0),
        }
        msg.push(match self.row_format {
            RowFormat::JsonArray => 0,
            RowFormat::Utf8Lines => 1,
        });
        msg
    }

    /// Verify ticket signature, expiry, and arguments match.
    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        now_unix_ns: u64,
        expected_server: &str,
        expected_tool: &str,
        expected_args_blake3: &str,
    ) -> EnclaveResult<()> {
        if self.server != expected_server || self.tool_name != expected_tool {
            fail!(EACCES, "TICKET_TOOL_MISMATCH");
        }
        if self.args_blake3 != expected_args_blake3 {
            fail!(EACCES, "TICKET_ARGS_MISMATCH");
        }
        if self.ticket_id.is_empty()
            || self.ticket_id.len() > 256
            || self.server.len() > 256
            || self.tool_name.len() > 256
            || self.args_blake3.len() != 64
            || hex::decode(&self.args_blake3).map_or(true, |v| v.len() != 32)
        {
            fail!(EINVAL, "TICKET_FIELDS_INVALID");
        }
        if self.expires_at_unix_ns < self.issued_at_unix_ns
            || self.expires_at_unix_ns - self.issued_at_unix_ns > 3_600_000_000_000
            || now_unix_ns < self.issued_at_unix_ns
        {
            fail!(EACCES, "TICKET_TIME_INVALID");
        }
        if now_unix_ns > self.expires_at_unix_ns {
            fail!(EACCES, "TICKET_EXPIRED");
        }

        let sig_bytes = hex::decode(&self.signature).map_err(|_| err!(EINVAL, "TICKET_SIG_HEX"))?;
        let sig =
            Signature::from_slice(&sig_bytes).map_err(|_| err!(EINVAL, "TICKET_SIG_INVALID"))?;

        let msg = self.signing_bytes();
        verifying_key
            .verify(&msg, &sig)
            .map_err(|_| err!(EACCES, "TICKET_SIG_VERIFY_FAILED"))?;
        Ok(())
    }
}
