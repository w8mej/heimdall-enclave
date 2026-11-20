//! A2 15-minute biometric lease table (FS-703 §3.1, §4.1).
//!
//! A2 elevated session operations (cross-domain MCP joins, reading INTERNAL
//! schemas, refreshing L2 Biscuit capability leases) are granted a 15-minute
//! lease upon successful Touch ID authentication, scoped strictly to
//! `(caller_spiffe_id, target_namespace, biscuit_root_blake3)`.
//!
//! While a lease is valid, A2 operations evaluate `TouchIdCoreauthui` as
//! satisfied without prompting the user.
//!
//! The table is synchronously wiped on screen lock (`com.apple.screenIsLocked`)
//! and system sleep (`kIOMessageSystemWillSleep`), as well as explicit zeroization.

use std::collections::BTreeMap;

/// 15 minutes in nanoseconds: `15 * 60 * 1_000_000_000`.
pub const LEASE_DURATION_NS: u64 = 15 * 60 * 1_000_000_000;

/// Scope key for an A2 elevated session lease (FS-703 §4.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeaseKey {
    /// Calling agent SPIFFE identity.
    pub caller_spiffe_id: String,
    /// Destination namespace.
    pub target_namespace: String,
    /// Root biscuit token BLAKE3 digest.
    pub biscuit_root_blake3: [u8; 32],
}

/// A granted lease entry with continuous mach timestamps.
#[derive(Debug, Clone)]
pub struct LeaseEntry {
    /// Timestamp when Touch ID was verified.
    pub granted_at_mach_ns: u64,
    /// Expiration timestamp (`granted_at + 15 min`).
    pub expires_at_mach_ns: u64,
}

/// In-memory table of active A2 biometric leases.
#[derive(Debug, Default)]
pub struct LeaseTable {
    entries: BTreeMap<LeaseKey, LeaseEntry>,
}

impl LeaseTable {
    /// Create an empty lease table.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Check if a valid, unexpired lease exists.
    pub fn is_valid(
        &self,
        caller: &str,
        namespace: &str,
        biscuit_root: &[u8; 32],
        now_mach_ns: u64,
    ) -> bool {
        let key = LeaseKey {
            caller_spiffe_id: caller.to_string(),
            target_namespace: namespace.to_string(),
            biscuit_root_blake3: *biscuit_root,
        };
        if let Some(entry) = self.entries.get(&key) {
            now_mach_ns < entry.expires_at_mach_ns
        } else {
            false
        }
    }

    /// Grant or refresh a 15-minute lease.
    pub fn grant(
        &mut self,
        caller: &str,
        namespace: &str,
        biscuit_root: [u8; 32],
        now_mach_ns: u64,
    ) {
        let key = LeaseKey {
            caller_spiffe_id: caller.to_string(),
            target_namespace: namespace.to_string(),
            biscuit_root_blake3: biscuit_root,
        };
        let entry = LeaseEntry {
            granted_at_mach_ns: now_mach_ns,
            expires_at_mach_ns: now_mach_ns.saturating_add(LEASE_DURATION_NS),
        };
        self.entries.insert(key, entry);
    }

    /// Prune expired entries.
    pub fn prune(&mut self, now_mach_ns: u64) {
        self.entries
            .retain(|_, v| now_mach_ns < v.expires_at_mach_ns);
    }

    /// Revoke all leases (called on screen lock, sleep, tamper, zeroize).
    pub fn revoke_all(&mut self) {
        self.entries.clear();
    }

    /// Number of active leases at `now_mach_ns`.
    pub fn active_count(&self, now_mach_ns: u64) -> usize {
        self.entries
            .values()
            .filter(|v| now_mach_ns < v.expires_at_mach_ns)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_lifecycle_and_scoping() {
        let mut table = LeaseTable::new();
        let caller = "spiffe://corporate.internal/enclave/uid/704";
        let ns1 = "dev-billing";
        let ns2 = "prod-billing";
        let root1 = [1u8; 32];
        let root2 = [2u8; 32];
        let t0 = 1_000_000_000; // 1s

        assert!(!table.is_valid(caller, ns1, &root1, t0));

        table.grant(caller, ns1, root1, t0);
        assert!(table.is_valid(caller, ns1, &root1, t0));
        assert!(table.is_valid(caller, ns1, &root1, t0 + 10 * 60 * 1_000_000_000)); // 10 min

        // Scoped to namespace:
        assert!(!table.is_valid(caller, ns2, &root1, t0));

        // Scoped to biscuit root:
        assert!(!table.is_valid(caller, ns1, &root2, t0));

        // Scoped to caller:
        assert!(!table.is_valid("spiffe://other", ns1, &root1, t0));

        // Expiry at 15 minutes:
        let t_expired = t0 + LEASE_DURATION_NS + 1;
        assert!(!table.is_valid(caller, ns1, &root1, t_expired));

        // Re-grant and wipe:
        table.grant(caller, ns1, root1, t0);
        assert_eq!(table.active_count(t0), 1);
        table.revoke_all();
        assert_eq!(table.active_count(t0), 0);
        assert!(!table.is_valid(caller, ns1, &root1, t0));
    }
}
