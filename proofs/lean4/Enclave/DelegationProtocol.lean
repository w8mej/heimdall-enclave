import Enclave.ProtocolTrace

/-! Linearized budget operations. Accounts represent exclusive residual slices,
not the sum of parent original grants (which would double-count delegation).
Tokens/signatures and concurrent implementation linearization are separate. -/
namespace Enclave.DelegationProtocol

structure State where
  accounts : List Nat
  spent : Nat
  calls : Nat
  deriving DecidableEq, Repr

def total (s : State) := s.accounts.sum + s.spent

inductive Event where
  | split (before after : List Nat) (balance allocation : Nat)
  | spend (before after : List Nat) (balance amount : Nat)
  | merge (before after : List Nat) (parent child : Nat)
  | call
  deriving DecidableEq, Repr

def step (s : State) : Event → Option State
  | .split pre post balance amount =>
    if s.accounts = pre ++ balance :: post ∧ amount ≤ balance then
      some {s with accounts := pre ++ (balance - amount) :: amount :: post}
    else none
  | .spend pre post balance amount =>
    if s.accounts = pre ++ balance :: post ∧ amount ≤ balance then
      some {s with accounts := pre ++ (balance - amount) :: post, spent := s.spent + amount}
    else none
  | .merge pre post parent child =>
    if s.accounts = pre ++ parent :: child :: post then
      some {s with accounts := pre ++ (parent + child) :: post}
    else none
  | .call => if s.calls < 64 then some {s with calls := s.calls + 1} else none

theorem step_conserves (s t : State) (e : Event) (h : step s e = some t) :
    total t = total s := by
  cases e <;> simp only [step] at h
  all_goals split at h
  all_goals first | contradiction | skip
  all_goals rename_i hg
  all_goals cases h
  all_goals dsimp only [total]
  all_goals try rw [hg.1]
  all_goals try rw [hg]
  all_goals simp only [Enclave.Protocol.sum_append, List.sum_cons]
  all_goals omega

theorem trace_conserves (s : State) (events : List Event) :
    total (Enclave.Protocol.run step s events) = total s := by
  exact Enclave.Protocol.run_invariant step (fun t => total t = total s)
    (fun a e b ha hb => (step_conserves a b e hb).trans ha) s events rfl

theorem step_calls_bounded (s t : State) (e : Event) (hs : s.calls ≤ 64)
    (h : step s e = some t) : t.calls ≤ 64 := by
  cases e <;> simp only [step] at h
  all_goals split at h
  all_goals first | contradiction | skip
  all_goals cases h
  all_goals simp only
  all_goals omega

theorem trace_calls_bounded (s : State) (events : List Event) (hs : s.calls ≤ 64) :
    (Enclave.Protocol.run step s events).calls ≤ 64 :=
  Enclave.Protocol.run_invariant step (fun s => s.calls ≤ 64)
    (fun a e b ha hb => step_calls_bounded a b e ha hb) s events hs

/-- Check machine-integer admissibility before translating natural arithmetic. -/
def signedSlice (delegated slice budget : Int) : Bool :=
  decide (0 ≤ delegated ∧ 0 ≤ slice ∧ delegated + slice ≤ budget ∧ budget ≤ 9223372036854775807)

theorem accepted_slice_no_overflow (d n b : Int) (h : signedSlice d n b = true) :
    0 ≤ d+n ∧ d+n ≤ 9223372036854775807 := by
  simp [signedSlice] at h
  omega

end Enclave.DelegationProtocol
