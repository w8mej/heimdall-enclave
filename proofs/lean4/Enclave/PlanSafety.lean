import Enclave.ProtocolTrace

/-! A closed arithmetic/conditional fragment, with independent checker and
evaluator. It is intentionally not identified with the entire Starlark AST. -/
namespace Enclave.PlanSafety

inductive Ty where | num | flag deriving DecidableEq, Repr
inductive Value where | num (n : Nat) | flag (b : Bool) deriving DecidableEq, Repr
inductive Expr where
  | num (n : Nat) | flag (b : Bool)
  | add (a b : Expr) | less (a b : Expr) | ite (c a b : Expr)
  deriving DecidableEq, Repr

def valueType : Value → Ty | .num _ => .num | .flag _ => .flag

def check : Expr → Option Ty
  | .num _ => some .num
  | .flag _ => some .flag
  | .add a b => if check a = some .num ∧ check b = some .num then some .num else none
  | .less a b => if check a = some .num ∧ check b = some .num then some .flag else none
  | .ite c a b => do
    let t ← check a
    if check c = some .flag ∧ check b = some t then some t else none

def eval : Expr → Option Value
  | .num n => some (.num n)
  | .flag b => some (.flag b)
  | .add a b => do
    let .num x ← eval a | none
    let .num y ← eval b | none
    return .num (x+y)
  | .less a b => do
    let .num x ← eval a | none
    let .num y ← eval b | none
    return .flag (decide (x<y))
  | .ite c a b => do
    let .flag c ← eval c | none
    if c then eval a else eval b

theorem checker_progress_preservation (e : Expr) (t : Ty) (h : check e = some t) :
    ∃ v, eval e = some v ∧ valueType v = t := by
  induction e generalizing t with
  | num n => cases h; exact ⟨_, rfl, rfl⟩
  | flag b => cases h; exact ⟨_, rfl, rfl⟩
  | add a b ia ib =>
    simp only [check] at h
    split at h
    · rename_i hg
      cases h
      obtain ⟨va, ha, hta⟩ := ia _ hg.1
      obtain ⟨vb, hb, htb⟩ := ib _ hg.2
      cases va <;> cases vb <;> simp_all [eval, valueType]
    · contradiction
  | less a b ia ib =>
    simp only [check] at h
    split at h
    · rename_i hg
      cases h
      obtain ⟨va, ha, hta⟩ := ia _ hg.1
      obtain ⟨vb, hb, htb⟩ := ib _ hg.2
      cases va <;> cases vb <;> simp_all [eval, valueType]
    · contradiction
  | ite c a b ic ia ib =>
    cases ha : check a with
    | none => simp [check, ha] at h
    | some ta =>
      simp only [check, ha, Option.bind_some] at h
      change (if check c = some .flag ∧ check b = some ta then some ta else none) = some t at h
      split at h
      · rename_i hg
        cases h
        obtain ⟨vc, hc, htc⟩ := ic _ hg.1
        obtain ⟨va, hva, hta⟩ := ia _ ha
        obtain ⟨vb, hvb, htb⟩ := ib _ hg.2
        cases vc with
        | num n => contradiction
        | flag f => cases f <;> simp_all [eval]
      · contradiction

inductive Code where
  | skip | emit (tool : Nat) | seq (a b : Code) | repeat (n : Nat) (body : Code)
  deriving DecidableEq, Repr

def bounded : Code → Bool
  | .skip | .emit _ => true
  | .seq a b => bounded a && bounded b
  | .repeat n b => decide (n ≤ 16) && bounded b

def trace : Code → List Nat
  | .skip => [] | .emit n => [n]
  | .seq a b => trace a ++ trace b
  | .repeat n b => (List.replicate n (trace b)).flatten

def cost : Code → Nat
  | .skip => 0 | .emit _ => 1
  | .seq a b => cost a + cost b
  | .repeat n b => n * cost b

theorem trace_cost (c : Code) : (trace c).length = cost c := by
  induction c with
  | skip => rfl
  | emit _ => rfl
  | seq a b ia ib => simp [trace, cost, ia, ib]
  | «repeat» n b ib =>
    simp only [trace, cost]
    induction n with
    | zero => simp
    | succ n ih => simp [List.replicate_succ, ih, ib, Nat.succ_mul, Nat.add_comm]

end Enclave.PlanSafety
