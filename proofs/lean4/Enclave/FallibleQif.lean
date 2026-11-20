import Enclave.AdaptiveBudget

/-! A fallible K-valued declassifier has K+1 public observations. Private
backend errors and invalid indices are coalesced into one error symbol before
crossing the trust boundary. Timing and external backend channels are outside
this value-channel theorem. -/
namespace Enclave.FallibleQif

set_option exponentiation.threshold 12001

/-- Symbol zero is the uniform error; successful values occupy 1..K. -/
def symbol (k : Nat) : Except Nat Nat → Fin (k+1)
  | .error _ => ⟨0,by omega⟩
  | .ok value => if bound : value<k then ⟨value+1,by omega⟩ else ⟨0,by omega⟩

theorem all_backend_errors_have_one_public_observation (k first second : Nat) :
    symbol k (.error first)=symbol k (.error second) := rfl

theorem invalid_index_is_the_same_public_error (k value privateError : Nat)
    (invalid : k≤value) : symbol k (.ok value)=symbol k (.error privateError) := by
  simp [symbol,show ¬value<k by omega]

theorem success_does_not_alias_failure (k value privateError : Nat) (valid : value<k) :
    symbol k (.ok value)≠symbol k (.error privateError) := by
  simp [symbol,valid,Fin.ext_iff]

theorem valid_outputs_remain_distinguishable (k first second : Nat)
    (firstValid : first<k) (secondValid : second<k) :
    symbol k (.ok first)=symbol k (.ok second) ↔ first=second := by
  simp [symbol,firstValid,secondValid,Fin.ext_iff]

def price (k : Nat) : Nat := Enclave.FractionalQif.price (k+1)

theorem charged_alphabet_includes_failure (k : Nat) :
    (k+1)^1000≤2^(price k) :=
  Enclave.FractionalQif.exact_price_never_undercharges (k+1)

theorem charging_only_two_values_undercharges_the_failure_channel :
    ¬(2+1:Nat)^1000≤2^(Enclave.FractionalQif.price 2) := by
  have binary : Enclave.FractionalQif.price 2=1000 := by
    simpa using Enclave.FractionalQif.power_of_two_exact_charge 1
  rw [binary]
  exact Nat.not_le_of_lt (Nat.pow_lt_pow_left (by decide : 2<3) (by decide : 1000≠0))

theorem full_window_permits_at_most_4095_values_plus_failure (k : Nat)
    (accepted : price k≤12000) : k≤4095 := by
  have cardinality := Enclave.FractionalQif.fractional_budget_implies_4096_bound [k+1]
  simp only [List.prod_cons,List.prod_nil,Nat.mul_one,List.map_cons,List.map_nil,
    List.sum_cons,List.sum_nil,Nat.add_zero] at cardinality
  have result := cardinality accepted
  omega

end Enclave.FallibleQif
