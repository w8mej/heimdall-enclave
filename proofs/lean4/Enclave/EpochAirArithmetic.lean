import Enclave.ProtocolTrace

/-! KoalaBear modular arithmetic for the actual epoch AIR range equation.
This file also exhibits why the existing slack-only equation is insufficient.
It does not claim soundness of the auxiliary signature/hash AIRs. -/
namespace Enclave.EpochAirArithmetic

def modulus : Nat := 2130706433
def fieldEq (a b : Nat) : Bool := decide (a % modulus = b % modulus)

/-- cap - used = slack in the field, written without natural subtraction. -/
def slackEquation (cap used slack : Nat) : Bool := fieldEq cap (used+slack)

theorem range_equation_no_wrap (cap used slack : Nat)
    (hc : cap < 16384) (hu : used < 16384) (hs : slack < 16384)
    (he : slackEquation cap used slack = true) : used ≤ cap := by
  have hc' : cap < modulus := by unfold modulus; omega
  have hs' : used+slack < modulus := by unfold modulus; omega
  simp only [slackEquation, fieldEq, decide_eq_true_eq,
    Nat.mod_eq_of_lt hc', Nat.mod_eq_of_lt hs'] at he
  omega

/-- A kernel-checked counterexample to the production slack-only range claim. -/
theorem slack_only_allows_out_of_range_used :
    slackEquation 12000 (modulus-1) 12001 = true ∧ modulus-1 > 12000 := by decide

def transition (used delta next : Nat) : Bool := fieldEq next (used+delta)

theorem bounded_transition_is_integer_addition (used delta next : Nat)
    (hu : used < 16384) (hd : delta < 16384) (hn : next < 16384)
    (h : transition used delta next = true) : next = used+delta := by
  have ha : next < modulus := by unfold modulus; omega
  have hb : used+delta < modulus := by unfold modulus; omega
  simpa only [transition, fieldEq, decide_eq_true_eq,
    Nat.mod_eq_of_lt ha, Nat.mod_eq_of_lt hb] using h

end Enclave.EpochAirArithmetic
