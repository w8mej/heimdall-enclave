//! CaMeL/FIDES opaque SSA capability heap (FS-704 §3.2).
//!
//! The privileged planner never sees `C3`/`C4` or `T3` payload strings: it
//! receives `$v_i` / `$paste_k` handles whose [`IfcEnvelopeV1`] labels are
//! MAC-sealed under a per-boot key. Every transformation propagates
//! `ℓ(y) = ℓ_tool ⊔ ⨆ ℓ(x_j)` and `Entities(y) = ⋃ Entities(x_j)`, with
//! `|Entities| <= 64` (else `E2BIG`) and `Entities ≠ ∅` whenever `c >= C3`
//! (fallback artifact key + global unstructured pool).
//!
//! Handles (`$v_i`, `$paste_k`) are sequential **names, not capabilities**
//! (DEFECT-F-68): any admitted peer may name any live handle. Authorisation
//! never relies on handle secrecy; it relies on the MAC-verified label of
//! every named handle being joined into the decision's input label by the
//! PDP (and on the slot admission rule).

use std::collections::{BTreeSet, HashMap};

use enclave_core::error::EnclaveResult;
use enclave_core::ifc_envelope::{
    IfcEnvelopeV1, Origin, OriginKind, QifPool, VaultTier, MAX_ENTITY_FANIN,
};
use enclave_core::label::{Conf, Label, SlotKind, Taint};
use enclave_core::qif::fallback_artifact_key;
use enclave_core::secret::{SecretBytes, SecretKey32};
use enclave_core::{err, fail};

/// Own incoming private bytes before any fallible heap work. Successful storage
/// transfers the same allocation; every refusal keeps cleanup ownership here.
struct PendingPayload(Option<SecretBytes>);
impl PendingPayload {
    fn new(bytes: Vec<u8>) -> Self { Self(Some(SecretBytes::new(bytes))) }
    fn secret(&self) -> &SecretBytes { self.0.as_ref().expect("pending payload retained") }
    fn into_secret(mut self) -> SecretBytes { self.0.take().expect("pending payload retained") }
}
impl Drop for PendingPayload {
    fn drop(&mut self) {
        if let Some(secret) = &mut self.0 {
            secret.wipe();
            #[cfg(test)]
            capacity_tests::observe_pending_drop(secret);
            // SecretBytes still owns the allocation through its final Drop.
        }
    }
}

/// A stored value.
#[derive(Debug)]
pub struct HeapValue {
    /// Signed envelope.
    pub envelope: IfcEnvelopeV1,
    /// Payload (zeroized on drop; never handed to the planner).
    pub payload: SecretBytes,
    /// Whether the value came from an unstructured C3/C4 source.
    pub unstructured: bool,
}

/// The capability heap.
#[derive(Debug)]
pub struct CapabilityHeap {
    boot_key: SecretKey32,
    k_vault: SecretKey32,
    boot_epoch_id: String,
    next: u64,
    values: HashMap<String, HeapValue>,
    /// Maximum retained payload allocation bytes, including spare capacity.
    /// This is a payload budget, not a whole-process RSS bound; bulk tensors
    /// stay in UID 701 and are referenced by descriptor.
    pub max_payload_bytes: usize,
    resident: usize,
    /// Monotone provenance for caller-authored argument documents (F66).
    /// Releasing/wiping payloads cannot erase what admitted peers have observed.
    literal_exposure: Label,
}

/// Default payload budget (8 MiB of the 32 MiB ceiling).
pub const DEFAULT_HEAP_BUDGET: usize = 8 * 1024 * 1024;

impl CapabilityHeap {
    /// New heap for a boot epoch with a throwaway `K_vault` (tests; entity
    /// keys then differ per process).
    pub fn new(boot_epoch_id: String) -> Self {
        Self::with_vault_key(boot_epoch_id, SecretKey32::random())
    }

    /// Provenance floor for caller-authored arguments. All currently admitted
    /// peers share one exposure domain: their deployment does not establish
    /// independent, non-colluding plaintext and planner identities. The floor
    /// joins both lattice axes and never decreases during a heap's lifetime.
    pub fn literal_exposure(&self) -> Label {
        self.literal_exposure
    }

    /// Restore/raise trusted durable exposure. This never accepts a downgrade.
    pub fn raise_literal_exposure(&mut self, observed: Label) {
        self.literal_exposure = self.literal_exposure.join(observed);
    }

    /// New heap whose entity keys derive from a stable `K_vault`, so the
    /// persisted QIF ledger keeps charging the same entities (GAP-08).
    pub fn with_vault_key(boot_epoch_id: String, k_vault: SecretKey32) -> Self {
        Self {
            boot_key: SecretKey32::random(),
            k_vault,
            boot_epoch_id,
            next: 0,
            values: HashMap::new(),
            max_payload_bytes: DEFAULT_HEAP_BUDGET,
            resident: 0,
            literal_exposure: Label::DIRECTIVE,
        }
    }

    fn handle(&mut self, paste: bool) -> EnclaveResult<String> {
        let next = self
            .next
            .checked_add(1)
            .ok_or_else(|| err!(E2BIG, "HANDLE_ID_EXHAUSTED"))?;
        let h = if paste {
            format!("$paste_{}", self.next)
        } else {
            format!("$v_{}", self.next)
        };
        self.next = next;
        Ok(h)
    }

    fn store(
        &mut self,
        mut env: IfcEnvelopeV1,
        payload: PendingPayload,
        unstructured: bool,
    ) -> EnclaveResult<IfcEnvelopeV1> {
        let resident = self.resident.checked_add(payload.secret().allocation_bytes());
        if resident.is_none_or(|bytes| bytes > self.max_payload_bytes) {
            fail!(
                ENOMEM,
                "CAPABILITY_HEAP_FULL",
                "bulk payloads must stay in UID 701 and be passed by descriptor"
            );
        }
        env.payload_blake3 = Some(blake3::hash(payload.secret().expose()).to_hex().to_string());
        env.boot_epoch_id = Some(self.boot_epoch_id.clone());
        env.schema_version = Some("enclave.ifc.envelope.v1".into());
        env.validate()?;
        env.seal(&self.boot_key)?;
        self.raise_literal_exposure(env.label);
        self.resident = resident.expect("admitted retained allocation bytes");
        self.values.insert(
            env.handle.clone(),
            HeapValue {
                envelope: env.clone(),
                payload: payload.into_secret(),
                unstructured,
            },
        );
        Ok(env)
    }

    /// Ingest an depot tool output (always `T3`). `entity_ids` are canonical
    /// structured subject ids; if empty and `c >= C3`, the fallback artifact
    /// key for `source_uri` is used and the value joins the global pool.
    #[allow(clippy::too_many_arguments)]
    pub fn ingest_tool_output(
        &mut self,
        tool_name: &str,
        tools_list_blake3: &str,
        payload: Vec<u8>,
        c: Conf,
        entity_ids: &[String],
        source_uri: &str,
        vault_tier: VaultTier,
    ) -> EnclaveResult<IfcEnvelopeV1> {
        self.ingest_derived_tool_output(tool_name, tools_list_blake3, payload, c, entity_ids, source_uri, vault_tier, &[])
    }

    /// Trusted runtime output ingress retains every actual input entity and
    /// provenance edge while preserving the signed tool origin and C4 tier.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn ingest_derived_tool_output(
        &mut self,
        tool_name: &str,
        tools_list_blake3: &str,
        payload: Vec<u8>,
        c: Conf,
        entity_ids: &[String],
        source_uri: &str,
        vault_tier: VaultTier,
        parents: &[String],
    ) -> EnclaveResult<IfcEnvelopeV1> {
        let payload = PendingPayload::new(payload);
        let (label, parent_keys, parent_unstructured) = self.join(parents, Label::new(c, Taint::T3))?;
        let c=label.c;
        let dag=if parents.is_empty() {None} else {Some(self.provenance_dag(parents)?)};
        if entity_ids.len() > MAX_ENTITY_FANIN {
            fail!(E2BIG, "PROVENANCE_FANIN_EXCEEDED");
        }
        let mut keys: Vec<String> = entity_ids
            .iter()
            .map(|e| enclave_core::qif::entity_key(&self.k_vault, e))
            .collect();
        keys.sort();
        keys.dedup();
        let fallback = keys.is_empty() && c >= Conf::C3;
        if fallback {
            keys.push(fallback_artifact_key(
                &self.k_vault,
                source_uri,
                simhash_bucket(payload.secret().expose()),
            ));
        }
        keys.extend(parent_keys);
        keys.sort(); keys.dedup();
        if keys.len()>MAX_ENTITY_FANIN {fail!(E2BIG,"PROVENANCE_FANIN_EXCEEDED");}
        let unstructured=fallback || parent_unstructured;
        let h = self.handle(false)?;
        let env = IfcEnvelopeV1 {
            v: 1,
            schema_version: None,
            boot_epoch_id: None,
            handle: h,
            payload_blake3: None,
            value_type: Some("Bytes".into()),
            label: Label::new(c, Taint::T3),
            vault_tier: Some(vault_tier),
            entity_keys: keys,
            qif_pool: Some(if unstructured {
                QifPool::GlobalUnstructuredC3C424hPool
            } else {
                QifPool::EntityKey
            }),
            slot_kind: Some(SlotKind::BoundLiteral),
            provenance_parents: Some(parents.to_vec()),
            provenance_dag_blake3: dag,
            allowed_declassifiers: None,
            origin: Origin {
                kind: OriginKind::depotToolOutput,
                depot_tools_list_blake3: Some(tools_list_blake3.to_owned()),
                tool_name: Some(tool_name.to_owned()),
            },
            enclave_boot_mac: None,
        };
        self.store(env, payload, unstructured)
    }

    /// Ingest a `UserTurnV1` attachment as an opaque `(C3, T3)` `$paste_k`.
    pub fn ingest_attachment(
        &mut self,
        bytes: Vec<u8>,
        source_uri: &str,
    ) -> EnclaveResult<IfcEnvelopeV1> {
        let bytes = PendingPayload::new(bytes);
        let key = fallback_artifact_key(&self.k_vault, source_uri, simhash_bucket(bytes.secret().expose()));
        let h = self.handle(true)?;
        let env = IfcEnvelopeV1 {
            v: 1,
            schema_version: None,
            boot_epoch_id: None,
            handle: h,
            payload_blake3: None,
            value_type: Some("TextBlob".into()),
            label: Label::ATTACHMENT_DEFAULT,
            vault_tier: Some(VaultTier::None),
            entity_keys: vec![key],
            qif_pool: Some(QifPool::GlobalUnstructuredC3C424hPool),
            slot_kind: Some(SlotKind::BoundLiteral),
            provenance_parents: Some(vec![]),
            provenance_dag_blake3: None,
            allowed_declassifiers: None,
            origin: Origin {
                kind: OriginKind::UserAttachment,
                depot_tools_list_blake3: None,
                tool_name: None,
            },
            enclave_boot_mac: None,
        };
        self.store(env, bytes, true)
    }

    /// Look up and **verify** an envelope (forged / downgraded handles fail).
    pub fn get(&self, handle: &str) -> EnclaveResult<&HeapValue> {
        let v = self
            .values
            .get(handle)
            .ok_or_else(|| err!(EACCES, "HANDLE_FORGERY", "unknown handle {handle}"))?;
        v.envelope.verify_mac(&self.boot_key)?;
        Ok(v)
    }

    /// Verify an envelope presented back by the planner.
    pub fn verify_presented(&self, env: &IfcEnvelopeV1) -> EnclaveResult<()> {
        env.verify_mac(&self.boot_key)?;
        let stored = self.get(&env.handle)?;
        if &stored.envelope != env {
            fail!(
                EACCES,
                "HANDLE_FORGERY",
                "envelope differs from the heap copy"
            );
        }
        Ok(())
    }

    /// Joined label + entity set + unstructured flag over a set of handles.
    pub fn join(
        &self,
        handles: &[String],
        floor: Label,
    ) -> EnclaveResult<(Label, Vec<String>, bool)> {
        let mut l = floor;
        let mut ents: BTreeSet<String> = BTreeSet::new();
        let mut unstructured = false;
        for h in handles {
            let v = self.get(h)?;
            l = l.join(v.envelope.label);
            ents.extend(v.envelope.entity_keys.iter().cloned());
            unstructured |= v.unstructured;
            if ents.len() > MAX_ENTITY_FANIN {
                fail!(
                    E2BIG,
                    "PROVENANCE_FANIN_EXCEEDED",
                    "|E(input)| > {MAX_ENTITY_FANIN}"
                );
            }
        }
        Ok((l, ents.into_iter().collect(), unstructured))
    }

    /// Check slot admission for a tool call's arguments and return the max
    /// AST-slot taint rank.
    pub fn admit_slots(&self, args: &[(SlotKind, String)]) -> EnclaveResult<u8> {
        let mut max_ast = 0u8;
        for (slot, h) in args {
            let v = self.get(h)?;
            slot.admit(v.envelope.label)?;
            if *slot == SlotKind::AstStructural {
                max_ast = max_ast.max(v.envelope.label.t.rank());
            }
        }
        Ok(max_ast)
    }

    /// Wrap a derived value `y = f(x_1..x_k)` with the joined label.
    pub fn derive(
        &mut self,
        parents: &[String],
        tool_floor: Label,
        payload: Vec<u8>,
        value_type: &str,
    ) -> EnclaveResult<IfcEnvelopeV1> {
        let payload = PendingPayload::new(payload);
        let (l, ents, unstructured) = self.join(parents, tool_floor)?;
        if l.c >= Conf::C3 && ents.is_empty() {
            fail!(EPERM, "EMPTY_ENTITY_SET");
        }
        let dag = self.provenance_dag(parents)?;
        let h = self.handle(false)?;
        let origin_kind = if l.t == Taint::T3 {
            OriginKind::depotToolOutput
        } else {
            OriginKind::EnclaveVerified
        };
        let env = IfcEnvelopeV1 {
            v: 1,
            schema_version: None,
            boot_epoch_id: None,
            handle: h,
            payload_blake3: None,
            value_type: Some(value_type.to_owned()),
            label: l,
            vault_tier: None,
            entity_keys: ents,
            qif_pool: Some(if unstructured {
                QifPool::GlobalUnstructuredC3C424hPool
            } else {
                QifPool::EntityKey
            }),
            slot_kind: Some(SlotKind::BoundLiteral),
            provenance_parents: Some(parents.to_vec()),
            provenance_dag_blake3: Some(dag),
            allowed_declassifiers: None,
            origin: Origin {
                kind: origin_kind,
                depot_tools_list_blake3: None,
                tool_name: None,
            },
            enclave_boot_mac: None,
        };
        self.store(env, payload, unstructured)
    }

    /// `provenance_dag_blake3` for a derived value (DEFECT-F-68): binds the
    /// boot epoch and, per parent, its handle, payload hash and envelope MAC
    /// (per-boot key), so equal handle sequences in different boots or over
    /// different data never share a DAG hash.
    fn provenance_dag(&self, parents: &[String]) -> EnclaveResult<String> {
        let mut hh = blake3::Hasher::new();
        hh.update(b"depot-ProvenanceDag-v1\0");
        hh.update(self.boot_epoch_id.as_bytes());
        hh.update(&[0]);
        for p in parents {
            let env = &self.get(p)?.envelope;
            for part in [
                Some(env.handle.as_str()),
                env.payload_blake3.as_deref(),
                env.enclave_boot_mac.as_deref(),
            ] {
                hh.update(part.unwrap_or("").as_bytes());
                hh.update(&[0]);
            }
        }
        Ok(hh.finalize().to_hex().to_string())
    }

    /// Store a declassified scalar (`T2`, enclave-verified).
    pub fn store_declassified(
        &mut self,
        parent: &str,
        value: Vec<u8>,
        entity_keys: Vec<String>,
    ) -> EnclaveResult<IfcEnvelopeV1> {
        let value = PendingPayload::new(value);
        let h = self.handle(false)?;
        let env = IfcEnvelopeV1 {
            v: 1,
            schema_version: None,
            boot_epoch_id: None,
            handle: h,
            payload_blake3: None,
            value_type: Some("Enum".into()),
            label: Label::new(Conf::C2, Taint::T2),
            vault_tier: None,
            entity_keys,
            qif_pool: Some(QifPool::EntityKey),
            slot_kind: Some(SlotKind::BoundLiteral),
            provenance_parents: Some(vec![parent.to_owned()]),
            provenance_dag_blake3: None,
            allowed_declassifiers: None,
            origin: Origin {
                kind: OriginKind::EnclaveVerified,
                depot_tools_list_blake3: None,
                tool_name: Some("jev.enum".into()),
            },
            enclave_boot_mac: None,
        };
        self.store(env, value, false)
    }

    /// Payload access for enclave-internal sanitizers only (never the planner).
    pub fn payload(&self, handle: &str) -> EnclaveResult<&[u8]> {
        Ok(self.get(handle)?.payload.expose())
    }

    /// Release completed-turn handles without rotating keys or clearing unrelated
    /// values or QIF state (DEFECT-F-71). Validate the whole set first so an
    /// unknown/stale handle cannot cause a partial release. SecretBytes zeroizes
    /// each removed payload on drop; handle sequence numbers are never reused.
    pub fn release(&mut self, handles: &[String]) -> EnclaveResult<usize> {
        let unique: BTreeSet<&String> = handles.iter().collect();
        for handle in &unique {
            self.get(handle)?;
        }
        let mut released = 0;
        for handle in unique {
            if let Some(value) = self.values.remove(handle) {
                self.resident -= value.payload.allocation_bytes();
                released += 1;
            }
        }
        Ok(released)
    }

    /// Zeroize everything (`<5 ms` heap wipe on yank / lock).
    pub fn wipe(&mut self) {
        self.values.clear();
        self.resident = 0;
        self.boot_key = SecretKey32::random();
    }

    /// Number of live handles.
    pub fn len(&self) -> usize {
        self.values.len()
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

#[cfg(test)]
#[path = "heap_capacity_tests.rs"]
mod capacity_tests;

/// 64-bit SimHash bucket over byte 4-grams (near-duplicate unstructured
/// sources share one fallback key, so re-encoding cannot reset budgets).
pub fn simhash_bucket(data: &[u8]) -> u64 {
    let mut acc = [0i32; 64];
    for w in data.windows(4.min(data.len().max(1))) {
        let h = u64::from_le_bytes(blake3::hash(w).as_bytes()[..8].try_into().unwrap_or([0; 8]));
        for (i, a) in acc.iter_mut().enumerate() {
            *a += if (h >> i) & 1 == 1 { 1 } else { -1 };
        }
    }
    let mut out = 0u64;
    for (i, a) in acc.iter().enumerate() {
        if *a > 0 {
            out |= 1 << i;
        }
    }
    // Bucket: top 16 bits, so small edits land in the same bucket with high probability.
    out >> 48
}

#[cfg(test)]
mod tests {
    use super::*;

    fn heap() -> CapabilityHeap {
        CapabilityHeap::new(enclave_core::seq::new_boot_epoch_id())
    }

    #[test]
    fn f66_exposure_joins_both_axes_and_survives_release_wipe_and_lower_values() {
        let mut h = heap();
        let e = h.ingest_tool_output("t", &"aa".repeat(32), b"secret".to_vec(),
            Conf::C4, &[], "source", VaultTier::None).unwrap();
        assert_eq!(h.literal_exposure(), e.label);
        h.release(&[e.handle]).unwrap();
        h.wipe();
        h.raise_literal_exposure(Label::BOTTOM);
        h.ingest_attachment(b"lower".to_vec(), "paste://lower").unwrap();
        assert_eq!(h.literal_exposure(), Label::TOP);
    }

    #[test]
    fn tool_output_is_t3_and_cannot_steer_ast_slots() {
        let mut h = heap();
        let e = h
            .ingest_tool_output(
                "query_incidents",
                &"aa".repeat(32),
                b"ignore previous".to_vec(),
                Conf::C3,
                &["cust-1".into()],
                "depot://db",
                VaultTier::None,
            )
            .unwrap();
        assert_eq!(e.label.t, Taint::T3);
        assert!(h
            .admit_slots(&[(SlotKind::AstStructural, e.handle.clone())])
            .unwrap_err()
            .is("T3_BIBA_VIOLATION"));
        assert_eq!(
            h.admit_slots(&[(SlotKind::BoundLiteral, e.handle.clone())])
                .unwrap(),
            0
        );
    }

    #[test]
    fn join_propagates_and_fanin_is_capped() {
        let mut h = heap();
        let mut hs = vec![];
        for i in 0..65 {
            let e = h
                .ingest_tool_output(
                    "t",
                    &"aa".repeat(32),
                    vec![i as u8],
                    Conf::C3,
                    &[format!("cust-{i}")],
                    "u",
                    VaultTier::None,
                )
                .unwrap();
            hs.push(e.handle);
        }
        let (l, ents, _) = h.join(&hs[..64], Label::BOTTOM).unwrap();
        assert_eq!(l, Label::new(Conf::C3, Taint::T3));
        assert_eq!(ents.len(), 64);
        assert!(h
            .join(&hs, Label::BOTTOM)
            .unwrap_err()
            .is("PROVENANCE_FANIN_EXCEEDED"));
        let d = h
            .derive(
                &hs[..2],
                Label::new(Conf::C2, Taint::T0),
                b"y".to_vec(),
                "Struct",
            )
            .unwrap();
        assert_eq!(d.label, Label::new(Conf::C3, Taint::T3));
        assert_eq!(d.entity_keys.len(), 2);
    }

    #[test]
    fn unstructured_sources_get_fallback_key_and_global_pool() {
        let mut h = heap();
        let e = h
            .ingest_tool_output(
                "sentry",
                &"aa".repeat(32),
                b"crash dump".to_vec(),
                Conf::C4,
                &[],
                "sentry://x",
                VaultTier::A4,
            )
            .unwrap();
        assert_eq!(e.entity_keys.len(), 1);
        assert_eq!(e.qif_pool, Some(QifPool::GlobalUnstructuredC3C424hPool));
        let p = h
            .ingest_attachment(b"pasted log".to_vec(), "paste://0")
            .unwrap();
        assert!(p.handle.starts_with("$paste_"));
        assert_eq!(p.label, Label::ATTACHMENT_DEFAULT);
    }

    #[test]
    fn forged_and_downgraded_handles_rejected() {
        let mut h = heap();
        let e = h
            .ingest_tool_output(
                "t",
                &"aa".repeat(32),
                b"x".to_vec(),
                Conf::C3,
                &["a".into()],
                "u",
                VaultTier::None,
            )
            .unwrap();
        assert!(h.get("$v_99").unwrap_err().is("HANDLE_FORGERY"));
        let mut d = e.clone();
        d.label.t = Taint::T1;
        d.origin.kind = OriginKind::EnclaveVerified;
        assert!(h.verify_presented(&d).unwrap_err().is("HANDLE_FORGERY"));
        h.verify_presented(&e).unwrap();
        h.wipe();
        assert!(h.verify_presented(&e).is_err());
    }

    #[test]
    fn heap_budget_enforced() {
        let mut h = heap();
        h.max_payload_bytes = 10;
        assert!(h
            .ingest_attachment(vec![0u8; 11], "p")
            .unwrap_err()
            .is("CAPABILITY_HEAP_FULL"));
    }

    fn derived_dag(h: &mut CapabilityHeap, payload: &[u8]) -> String {
        let e = h
            .ingest_tool_output(
                "t",
                &"aa".repeat(32),
                payload.to_vec(),
                Conf::C2,
                &["a".into()],
                "u",
                VaultTier::None,
            )
            .unwrap();
        let d = h
            .derive(&[e.handle], Label::BOTTOM, b"y".to_vec(), "Struct")
            .unwrap();
        d.provenance_dag_blake3.unwrap()
    }

    #[test]
    fn f68_dag_hash_differs_across_boots_for_equal_handle_sequences() {
        // Same handle sequence ($v_0 -> $v_1), same payload, two boots.
        let a = derived_dag(&mut heap(), b"x");
        let b = derived_dag(&mut heap(), b"x");
        assert_ne!(a, b);
    }

    #[test]
    fn f68_dag_hash_binds_parent_payload() {
        let epoch = enclave_core::seq::new_boot_epoch_id();
        let key = SecretKey32::random();
        let mut h1 = CapabilityHeap::with_vault_key(epoch.clone(), key.clone());
        let mut h2 = CapabilityHeap::with_vault_key(epoch, key);
        // Equalise the per-boot MAC key so only the payload differs.
        h2.boot_key = h1.boot_key.clone();
        assert_ne!(derived_dag(&mut h1, b"x"), derived_dag(&mut h2, b"z"));
    }

    #[test]
    fn f68_dag_hash_is_deterministic_for_identical_inputs() {
        let epoch = enclave_core::seq::new_boot_epoch_id();
        let key = SecretKey32::random();
        let mut h1 = CapabilityHeap::with_vault_key(epoch.clone(), key.clone());
        let mut h2 = CapabilityHeap::with_vault_key(epoch, key);
        h2.boot_key = h1.boot_key.clone();
        assert_eq!(derived_dag(&mut h1, b"x"), derived_dag(&mut h2, b"x"));
    }
}

#[cfg(test)]
mod f71_tests {
    use super::*;
    #[test]
    fn exhausted_handle_ids_preserve_live_values_and_accounting() {
        let mut heap = CapabilityHeap::new("6f1c2c1e-3a54-4b8e-9d7a-0c4f5b6a7e81".into());
        let existing = heap
            .ingest_attachment(b"keep".to_vec(), "paste://keep")
            .unwrap();
        heap.next = u64::MAX;
        for _ in 0..2 {
            assert!(heap
                .ingest_attachment(b"new".to_vec(), "paste://new")
                .unwrap_err()
                .is("HANDLE_ID_EXHAUSTED"));
            assert_eq!(heap.next, u64::MAX);
            assert_eq!(heap.resident, 4);
            assert_eq!(heap.len(), 1);
            assert_eq!(heap.payload(&existing.handle).unwrap(), b"keep");
        }
    }
    #[test]
    fn f71_release_restores_budget_without_invalidating_unrelated_handles() {
        let mut heap = CapabilityHeap::new("6f1c2c1e-3a54-4b8e-9d7a-0c4f5b6a7e81".into());
        heap.max_payload_bytes = 12;
        let keep = heap
            .ingest_attachment(b"keep".to_vec(), "paste://keep")
            .unwrap();
        let old = heap
            .ingest_attachment(b"12345678".to_vec(), "paste://old")
            .unwrap();
        assert!(heap
            .ingest_attachment(b"x".to_vec(), "paste://full")
            .unwrap_err()
            .is("CAPABILITY_HEAP_FULL"));
        assert_eq!(
            heap.release(&[old.handle.clone(), old.handle.clone()])
                .unwrap(),
            1
        );
        assert_eq!(heap.payload(&keep.handle).unwrap(), b"keep");
        assert!(heap.get(&old.handle).unwrap_err().is("HANDLE_FORGERY"));
        for _ in 0..1000 {
            let next = heap
                .ingest_attachment(b"12345678".to_vec(), "paste://new")
                .unwrap();
            assert_ne!(old.handle, next.handle);
            assert_eq!(heap.release(&[next.handle]).unwrap(), 1);
        }
        assert_eq!(heap.resident, 4);
        assert_eq!(heap.len(), 1);
        assert_eq!(heap.payload(&keep.handle).unwrap(), b"keep");
    }
    #[test]
    fn f71_release_is_atomic_on_unknown_handles() {
        let mut heap = CapabilityHeap::new("6f1c2c1e-3a54-4b8e-9d7a-0c4f5b6a7e81".into());
        let keep = heap
            .ingest_attachment(b"keep".to_vec(), "paste://keep")
            .unwrap();
        assert!(heap
            .release(&[keep.handle.clone(), "$v_unknown".into()])
            .is_err());
        assert_eq!(heap.payload(&keep.handle).unwrap(), b"keep");
        assert_eq!(heap.release(&[]).unwrap(), 0);
    }
}
