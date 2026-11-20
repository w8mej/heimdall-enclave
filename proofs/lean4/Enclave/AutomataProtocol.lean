import Enclave.ProtocolTrace

namespace Enclave.AutomataProtocol

abbrev Transition := Nat → Nat → Option Nat

def run (δ : Transition) : Nat → List Nat → Option Nat
  | q, [] => some q
  | q, b::bs => do let next ← δ q b; run δ next bs

inductive Path (δ : Transition) : Nat → List Nat → Nat → Prop where
  | nil (q) : Path δ q [] q
  | cons {q r t b bs} : δ q b = some r → Path δ r bs t → Path δ q (b::bs) t

theorem executable_iff_path (δ : Transition) (q : Nat) (bs : List Nat) (t : Nat) :
    run δ q bs = some t ↔ Path δ q bs t := by
  induction bs generalizing q with
  | nil => simp only [run, Option.some.injEq]; constructor
           · intro h; subst t; exact .nil _
           · intro h; cases h; rfl
  | cons b bs ih =>
    cases hd : δ q b with
    | none =>
      simp [run, hd]
      intro h; cases h with | cons h _ => simp [hd] at h
    | some r =>
      simp only [run, hd]
      change run δ r bs = some t ↔ Path δ q (b::bs) t
      constructor
      · exact fun h => .cons hd ((ih r).mp h)
      · intro h
        cases h with
        | cons hr hp =>
          have eq := Option.some.inj (hd.symm.trans hr)
          subst r
          exact (ih _).mpr hp

theorem streaming_batch_equivalent (δ : Transition) (q : Nat) (xs ys : List Nat) :
    run δ q (xs ++ ys) = (run δ q xs).bind (fun r => run δ r ys) := by
  induction xs generalizing q with
  | nil => rfl
  | cons b bs ih =>
    cases h : δ q b <;> simp [run, h, ih]

def feasible (δ : Transition) (accept : Nat → Bool) (q : Nat) (xs : List (List Nat)) : Bool :=
  xs.any (fun bs => (run δ q bs).any accept)

theorem feasible_has_accepted_witness (δ : Transition) (accept : Nat → Bool)
    (q : Nat) (xs : List (List Nat)) (h : feasible δ accept q xs = true) :
    ∃ bs ∈ xs, ∃ t, Path δ q bs t ∧ accept t = true := by
  obtain ⟨bs, hm, ht⟩ := List.any_eq_true.mp h
  cases hr : run δ q bs with
  | none => simp [hr] at ht
  | some t => exact ⟨bs, hm, t, (executable_iff_path δ q bs t).mp hr, by simpa [hr] using ht⟩

def luhnDigit (double : Bool) (n : Nat) : Nat :=
  if double then if 2*n > 9 then 2*n-9 else 2*n else n

theorem luhn_digit_range (n : Nat) (h : n < 10) (double : Bool) :
    luhnDigit double n < 10 := by
  cases double <;> simp only [luhnDigit, Bool.false_eq_true, ↓reduceIte]
  · exact h
  · split <;> omega

end Enclave.AutomataProtocol
