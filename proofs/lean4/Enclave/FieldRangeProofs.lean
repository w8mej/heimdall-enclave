import Mathlib.Data.ZMod.Basic
import Mathlib.Tactic.NormNum
import Enclave.KoalaBearPrime
import Mathlib.Tactic.Ring
import Enclave.EpochAirArithmetic

namespace Enclave.FieldRangeProofs

abbrev P : Nat := 2130706433
instance : Fact (Nat.Prime P) := ⟨Enclave.KoalaBearPrime.koalaBear_prime⟩
instance : Fact (1 < P) := ⟨by decide⟩
abbrev F := ZMod P

theorem field_boolean_is_bit (b : F) (h : b*(b-1)=0) : b=0 ∨ b=1 := by
  rcases mul_eq_zero.mp h with h | h
  · exact Or.inl h
  · exact Or.inr (sub_eq_zero.mp h)

def naturalBits : List F → Nat
  | [] => 0
  | b::bs => b.val + 2 * naturalBits bs

def fieldBits : List F → F
  | [] => 0
  | b::bs => b + 2 * fieldBits bs

theorem bit_value_zero_or_one (b : F) (h : b*(b-1)=0) : b.val=0 ∨ b.val=1 := by
  rcases field_boolean_is_bit b h with rfl | rfl
  · exact Or.inl (by simp)
  · exact Or.inr (ZMod.val_one P)

theorem binary_natural_bound (bs : List F) (h : ∀ b ∈ bs, b*(b-1)=0) :
    naturalBits bs < 2^bs.length := by
  induction bs with
  | nil => simp [naturalBits]
  | cons b bs ih =>
    have hb := bit_value_zero_or_one b (h b (by simp))
    have ht := ih (fun x hx => h x (by simp [hx]))
    simp only [naturalBits, List.length_cons, Nat.pow_succ]
    omega

theorem field_bits_are_cast_natural (bs : List F) :
    fieldBits bs = (naturalBits bs : F) := by
  induction bs with
  | nil => rfl
  | cons b bs ih => simp [fieldBits, naturalBits, ih, ZMod.natCast_zmod_val]

theorem constrained_used_has_fourteen_bit_range (used : F) (bs : List F)
    (length : bs.length=14) (boolean : ∀ b ∈ bs, b*(b-1)=0)
    (decomposition : used=fieldBits bs) : used.val < 16384 := by
  have bound := binary_natural_bound bs boolean
  rw [length] at bound
  have small : naturalBits bs < P := by norm_num at bound ⊢; omega
  rw [decomposition, field_bits_are_cast_natural, ZMod.val_natCast_of_lt small]
  exact bound

theorem actual_field_slack_implies_integer_cap (cap used slack : F)
    (hu : used.val<16384) (hs : slack.val<16384)
    (equation : cap-used=slack) : used.val ≤ cap.val := by
  have eq : cap=used+slack := sub_eq_iff_eq_add.mp equation |>.trans (add_comm _ _)
  have sum_lt : used.val+slack.val < P := by unfold P; omega
  have castEq : cap = ((used.val+slack.val : Nat) : F) := by
    simpa only [Nat.cast_add, ZMod.natCast_zmod_val] using eq
  have valEq := congrArg ZMod.val castEq
  rw [ZMod.val_natCast_of_lt sum_lt] at valEq
  omega

end Enclave.FieldRangeProofs
