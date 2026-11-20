import Enclave.ProtocolTrace

namespace Enclave.Authorization

structure Request where
  tool : Nat
  rows : Nat
  charge : Nat
  now : Nat
  deriving DecidableEq, Repr

structure Restriction where
  tools : List Nat
  maxRows : Nat
  maxCharge : Nat
  expires : Nat
  deriving DecidableEq, Repr

def accepts (r : Restriction) (q : Request) : Bool :=
  decide (q.tool ∈ r.tools ∧ q.rows ≤ r.maxRows ∧ q.charge ≤ r.maxCharge ∧ q.now ≤ r.expires)

/-- Each attenuation block is retained; permission is their intersection. -/
def tokenAllows (chain : List Restriction) (q : Request) : Bool :=
  !chain.isEmpty && chain.all (fun r => accepts r q)

def cedar (permits forbids : List (Request → Bool)) (q : Request) : Bool :=
  permits.any (fun p => p q) && !(forbids.any (fun p => p q))

def authorize (permits forbids : List (Request → Bool)) (chain : List Restriction)
    (q : Request) : Bool := cedar permits forbids q && tokenAllows chain q

theorem accepted_request_obeys_every_block (ps fs : List (Request → Bool))
    (rs : List Restriction) (q : Request) (h : authorize ps fs rs q = true) :
    ∀ r ∈ rs, q.tool ∈ r.tools ∧ q.rows ≤ r.maxRows ∧
      q.charge ≤ r.maxCharge ∧ q.now ≤ r.expires := by
  simp only [authorize, Bool.and_eq_true, tokenAllows, List.all_eq_true,
    Bool.not_eq_true] at h
  intro r hr
  have := h.2.2 r hr
  simpa [accepts] using this

theorem attenuation_never_widens (rs : List Restriction) (r : Restriction)
    (q : Request) (hn : rs ≠ []) (h : tokenAllows (rs ++ [r]) q = true) :
    tokenAllows rs q = true := by
  simp [tokenAllows, List.all_append, hn] at h ⊢
  exact h.1

theorem matching_forbid_denies (ps fs : List (Request → Bool))
    (rs : List Restriction) (q : Request) (f : Request → Bool)
    (hf : f ∈ fs) (hit : f q = true) : authorize ps fs rs q = false := by
  have hh : fs.any (fun p => p q) = true := List.any_eq_true.mpr ⟨f, hf, hit⟩
  simp [authorize, cedar, hh]

structure PolicyState where
  current : Nat
  previous : Option Nat
  swappedAt : Nat
  deriving DecidableEq, Repr

def bundleAccepted (s : PolicyState) (bundle now : Nat) : Bool :=
  decide (bundle = s.current ∨
    (s.previous = some bundle ∧ s.swappedAt ≤ now ∧ now - s.swappedAt ≤ 60000000000))

theorem expired_old_bundle_denied (s : PolicyState) (bundle now : Nat)
    (different : bundle ≠ s.current) (elapsed : s.swappedAt + 60000000000 < now) :
    bundleAccepted s bundle now = false := by
  simp only [bundleAccepted, decide_eq_false_iff_not]
  omega

end Enclave.Authorization
