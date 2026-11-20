import Enclave.ProtocolTrace

namespace Enclave.TufProtocol

def unique : List Nat → List Nat
  | [] => []
  | x::xs => if x ∈ unique xs then unique xs else x :: unique xs

theorem unique_nodup (xs : List Nat) : (unique xs).Nodup := by
  induction xs with
  | nil => simp [unique]
  | cons x xs ih =>
    simp only [unique]
    split
    · exact ih
    · simp_all

theorem mem_unique (x : Nat) (xs : List Nat) : x ∈ unique xs ↔ x ∈ xs := by
  induction xs generalizing x with
  | nil => simp [unique]
  | cons y ys ih =>
    simp only [unique]
    split
    · rename_i hy
      have hy' := (ih y).mp hy
      simp only [ih, List.mem_cons]
      constructor
      · exact fun h => Or.inr h
      · intro h; rcases h with h | h
        · simpa [h] using hy'
        · exact h
    · simp only [List.mem_cons, ih]

/-- Inputs are signature IDs whose signatures were checked over this exact body. -/
def threshold (authorized signatures : List Nat) (required : Nat) : Bool :=
  decide (0 < required ∧ required ≤
    (unique (signatures.filter (fun k => decide (k ∈ authorized)))).length)

theorem threshold_distinct_authorized (auth sigs : List Nat) (n : Nat)
    (h : threshold auth sigs n = true) :
    ∃ ks : List Nat, ks.Nodup ∧ n ≤ ks.length ∧ ∀ k ∈ ks, k ∈ auth ∧ k ∈ sigs := by
  refine ⟨unique (sigs.filter (fun k => decide (k ∈ auth))), unique_nodup _, ?_, ?_⟩
  · exact (of_decide_eq_true h).2
  · intro k hk
    have hh := (mem_unique k _).mp hk
    simp only [List.mem_filter, decide_eq_true_eq] at hh
    exact ⟨hh.2, hh.1⟩

structure Metadata where
  version : Nat
  body : List Nat
  expires : Nat
  deriving DecidableEq, Repr

def update (old next : Metadata) (now : Nat) : Option Metadata :=
  if old.version ≤ next.version ∧
      (next.version = old.version → next.body = old.body) ∧ now < next.expires then
    some next else none

theorem update_no_rollback_or_equivocation (old next result : Metadata) (now : Nat)
    (h : update old next now = some result) :
    old.version ≤ result.version ∧
    (result.version = old.version → result.body = old.body) ∧ now < result.expires := by
  unfold update at h
  split at h
  · rename_i hg; cases h; exact hg
  · contradiction

def rotate (old next : Metadata) (oldKeys newKeys signatures : List Nat)
    (oldThreshold newThreshold now : Nat) : Option Metadata :=
  if next.version = old.version + 1 ∧ now < next.expires ∧
      threshold oldKeys signatures oldThreshold = true ∧
      threshold newKeys signatures newThreshold = true then some next else none

theorem rotation_requires_both_thresholds (old next result : Metadata)
    (oldKeys newKeys signatures : List Nat) (a b now : Nat)
    (h : rotate old next oldKeys newKeys signatures a b now = some result) :
    result.version = old.version + 1 ∧
    threshold oldKeys signatures a = true ∧ threshold newKeys signatures b = true := by
  unfold rotate at h
  split at h
  · rename_i hg; cases h; exact ⟨hg.1, hg.2.2⟩
  · contradiction

inductive Role where | root | timestamp | snapshot | targets deriving DecidableEq, Repr

structure Reference where
  version : Nat
  length : Nat
  digest : Nat
  deriving DecidableEq, Repr

/-- Canonical semantic view of a parsed signed metadata body: the reference
is inside the authenticated body, never a caller-supplied side channel.
Production JSON decoding/canonicalization still needs its own bridge. -/
def decodeReference : List Nat → Option Reference
  | version::length::digest::_ => some ⟨version,length,digest⟩
  | _ => none

structure Bundle where
  root : Metadata
  timestamp : Metadata
  snapshot : Metadata
  targets : Metadata
  snapshotRef : Reference
  targetsRef : Reference
  deriving DecidableEq, Repr

def links (hash : List Nat → Nat) (reference : Reference) (metadata : Metadata) : Bool :=
  decide (reference.version=metadata.version ∧ reference.length=metadata.body.length ∧
    reference.digest=hash metadata.body)

structure Client where
  trusted : Bundle
  highTime : Nat
  deriving DecidableEq, Repr

/-- Keys and thresholds come from the current trusted root. `signatures` returns
only key IDs whose signatures verified over this exact role and body. The
cryptographic signature primitive is outside this protocol theorem. -/
def refresh (hash : List Nat → Nat) (keys : Role → List Nat) (quorum : Role → Nat)
    (signatures : Role → Metadata → List Nat) (s : Client) (next : Bundle) (now : Nat) : Option Client :=
  if s.highTime ≤ now ∧ next.root=s.trusted.root ∧ now<next.root.expires ∧
      update s.trusted.timestamp next.timestamp now = some next.timestamp ∧
      update s.trusted.snapshot next.snapshot now = some next.snapshot ∧
      update s.trusted.targets next.targets now = some next.targets ∧
      threshold (keys .timestamp) (signatures .timestamp next.timestamp) (quorum .timestamp) ∧
      threshold (keys .snapshot) (signatures .snapshot next.snapshot) (quorum .snapshot) ∧
      threshold (keys .targets) (signatures .targets next.targets) (quorum .targets) ∧
      links hash next.snapshotRef next.snapshot ∧ links hash next.targetsRef next.targets ∧
      decodeReference next.timestamp.body = some next.snapshotRef ∧
      decodeReference next.snapshot.body = some next.targetsRef then
    some ⟨next,now⟩ else none

theorem refresh_links_and_time (hash : List Nat → Nat) (keys : Role → List Nat)
    (quorum : Role → Nat) (signatures : Role → Metadata → List Nat)
    (s t : Client) (next : Bundle) (now : Nat)
    (ok : refresh hash keys quorum signatures s next now = some t) :
    s.highTime ≤ t.highTime ∧ now<t.trusted.root.expires ∧
    links hash t.trusted.snapshotRef t.trusted.snapshot = true ∧
    links hash t.trusted.targetsRef t.trusted.targets = true := by
  unfold refresh at ok
  split at ok
  · rename_i hg
    cases ok
    exact ⟨hg.1,hg.2.2.1,hg.2.2.2.2.2.2.2.2.2.1,hg.2.2.2.2.2.2.2.2.2.2.1⟩
  · contradiction

theorem refresh_versions_monotone (hash : List Nat → Nat) (keys : Role → List Nat)
    (quorum : Role → Nat) (signatures : Role → Metadata → List Nat)
    (s t : Client) (next : Bundle) (now : Nat)
    (ok : refresh hash keys quorum signatures s next now = some t) :
    s.trusted.root.version=t.trusted.root.version ∧
    s.trusted.timestamp.version≤t.trusted.timestamp.version ∧
    s.trusted.snapshot.version≤t.trusted.snapshot.version ∧
    s.trusted.targets.version≤t.trusted.targets.version := by
  unfold refresh at ok
  split at ok
  · rename_i hg
    cases ok
    exact ⟨congrArg (fun b : Metadata => b.version) hg.2.1.symm,
      (update_no_rollback_or_equivocation _ _ _ _ hg.2.2.2.1).1,
      (update_no_rollback_or_equivocation _ _ _ _ hg.2.2.2.2.1).1,
      (update_no_rollback_or_equivocation _ _ _ _ hg.2.2.2.2.2.1).1⟩
  · contradiction

abbrev RefreshEvent := Bundle × Nat
def refreshStep (hash : List Nat → Nat) (keys : Role → List Nat) (quorum : Role → Nat)
    (signatures : Role → Metadata → List Nat) (s : Client) (e : RefreshEvent) :=
  refresh hash keys quorum signatures s e.1 e.2

theorem refresh_history_no_clock_rollback (hash : List Nat → Nat) (keys : Role → List Nat)
    (quorum : Role → Nat) (signatures : Role → Metadata → List Nat)
    (s : Client) (events : List RefreshEvent) :
    s.highTime ≤ (Enclave.Protocol.run (refreshStep hash keys quorum signatures) s events).highTime := by
  exact Enclave.Protocol.run_invariant (refreshStep hash keys quorum signatures)
    (fun t => s.highTime≤t.highTime)
    (fun a e b ha hb => Nat.le_trans ha (refresh_links_and_time hash keys quorum signatures a b e.1 e.2 hb).1)
    s events (Nat.le_refl _)

end Enclave.TufProtocol
