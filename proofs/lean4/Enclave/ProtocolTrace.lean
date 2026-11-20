import Std

/-! Shared trace induction. Rejection leaves the state unchanged; success uses the
actual transition result. No invariant is stored in a state constructor. -/
namespace Enclave.Protocol

@[simp] theorem sum_append (xs ys : List Nat) : (xs ++ ys).sum = xs.sum + ys.sum := by
  induction xs with
  | nil => simp
  | cons x xs ih => simp [ih, Nat.add_assoc]

def run (step : S → E → Option S) : S → List E → S
  | s, [] => s
  | s, e :: es => run step ((step s e).getD s) es

theorem run_invariant (step : S → E → Option S) (P : S → Prop)
    (preserve : ∀ s e t, P s → step s e = some t → P t)
    (s : S) (es : List E) (initial : P s) : P (run step s es) := by
  induction es generalizing s with
  | nil => exact initial
  | cons e es ih =>
    apply ih
    cases h : step s e with
    | none => simpa [h] using initial
    | some t => simpa [h] using preserve s e t initial h

theorem run_append (step : S → E → Option S) (s : S) (xs ys : List E) :
    run step s (xs ++ ys) = run step (run step s xs) ys := by
  induction xs generalizing s with
  | nil => rfl
  | cons e es ih => exact ih _

end Enclave.Protocol
