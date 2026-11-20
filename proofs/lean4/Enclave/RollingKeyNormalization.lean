import Enclave.RollingQifRefinement

/-! First-occurrence normalization and the final push-back loop used by
`QifLedger::charge`. Keys name bucket identities; the reserved global key must
be disjoint from validated entity identities. Uniqueness is derived from
executable normalization, not assumed of the request. -/
namespace Enclave.RollingKeyNormalization

open Enclave.RollingQif Enclave.RollingQifRefinement

/-- Exact append-if-absent loop, preserving the first occurrence order. -/
def collect {α : Type} [DecidableEq α] : List α → List α → List α
  | acc, [] => acc
  | acc, key::rest => collect (if key ∈ acc then acc else acc++[key]) rest

theorem collect_preserves_membership {α : Type} [DecidableEq α] (acc raw : List α) (key : α) :
    key ∈ collect acc raw ↔ key ∈ acc ∨ key ∈ raw := by
  induction raw generalizing acc with
  | nil => simp [collect]
  | cons head rest ih =>
    simp only [collect]
    rw [ih]
    by_cases present : head ∈ acc
    · simp only [present,↓reduceIte,List.mem_cons]
      constructor
      · intro h; rcases h with old | tail
        · exact Or.inl old
        · exact Or.inr (Or.inr tail)
      · intro h; rcases h with old | rfl | tail
        · exact Or.inl old
        · exact Or.inl present
        · exact Or.inr tail
    · simp [present,List.mem_append,List.mem_singleton,List.mem_cons,or_assoc]

theorem collect_derives_unique_keys {α : Type} [DecidableEq α] (acc raw : List α) (unique : acc.Nodup) :
    (collect acc raw).Nodup := by
  induction raw generalizing acc with
  | nil => exact unique
  | cons key rest ih =>
    simp only [collect]
    split
    · exact ih _ unique
    · rename_i absent
      apply ih
      rw [List.nodup_append_comm]
      simpa using (List.nodup_cons.mpr ⟨absent,unique⟩)

def keys {α : Type} [DecidableEq α] (raw : List α) (pool : α) (needsPool : Bool) : List α :=
  collect [] raw ++ if needsPool then [pool] else []

theorem normalized_membership {α : Type} [DecidableEq α] (raw : List α) (pool key : α) (needsPool : Bool) :
    key ∈ keys raw pool needsPool ↔ key ∈ raw ∨ (needsPool=true ∧ key=pool) := by
  simp [keys,collect_preserves_membership]

theorem normalization_derives_nodup {α : Type} [DecidableEq α] (raw : List α) (pool : α) (needsPool : Bool)
    (reserved : pool ∉ raw) : (keys raw pool needsPool).Nodup := by
  have unique := collect_derives_unique_keys [] raw (by simp)
  have absent : pool ∉ collect [] raw := by
    simpa [collect_preserves_membership] using reserved
  cases needsPool
  · simpa [keys] using unique
  · simp only [keys,↓reduceIte]
    rw [List.nodup_append_comm]
    simpa using (List.nodup_cons.mpr ⟨absent,unique⟩)

/-- Every accepted entity name has the required prefix. The full production
hex/length validation is stronger than this sufficient disjointness condition. -/
theorem actual_reserved_pool_excluded (raw : List String)
    (validated : ∀ key ∈ raw, key.data.take 3="ek_".data) :
    "global_unstructured_c3_c4_24h_pool" ∉ raw := by
  intro member
  have impossible := validated "global_unstructured_c3_c4_24h_pool" member
  have rejected : "global_unstructured_c3_c4_24h_pool".data.take 3≠"ek_".data := by decide
  exact rejected impossible

theorem actual_string_key_normalization_unique (raw : List String) (needsPool : Bool)
    (validated : ∀ key ∈ raw, key.data.take 3="ek_".data) :
    (keys raw "global_unstructured_c3_c4_24h_pool" needsPool).Nodup :=
  normalization_derives_nodup raw _ needsPool (actual_reserved_pool_excluded raw validated)

/-- Native final for-loop, with one push_back for every list entry. -/
def pushLoop (buckets : Buckets) (now amount : Nat) : List Nat → Buckets
  | [] => buckets
  | key::rest => pushLoop (setBucket buckets key (buckets key++[(now,amount)])) now amount rest

theorem unique_push_loop_equals_membership_debit (buckets : Buckets) (now amount : Nat)
    (selected : List Nat) (unique : selected.Nodup) :
    pushLoop buckets now amount selected=debit buckets selected now amount := by
  induction selected generalizing buckets with
  | nil => funext key; simp [pushLoop,debit]
  | cons head rest ih =>
    rw [pushLoop,ih _ (List.nodup_cons.mp unique).2]
    funext key
    have absent := (List.nodup_cons.mp unique).1
    by_cases same : key=head
    · subst key
      simp [debit,setBucket,absent]
    · simp [debit,setBucket,same]

theorem normalized_native_loop_refines_debit (buckets : Buckets) (now amount : Nat)
    (raw : List Nat) (pool : Nat) (needsPool : Bool) (reserved : pool ∉ raw) :
    pushLoop buckets now amount (keys raw pool needsPool)=
      debit buckets (keys raw pool needsPool) now amount :=
  unique_push_loop_equals_membership_debit buckets now amount _
    (normalization_derives_nodup raw pool needsPool reserved)

/-- The raw loop really appends twice; skipping normalization is unsound. -/
theorem duplicate_raw_keys_cannot_skip_normalization :
    pushLoop (fun _ => []) 0 1 [1,1] 1 ≠ debit (fun _ => []) [1,1] 0 1 1 := by decide

end Enclave.RollingKeyNormalization
