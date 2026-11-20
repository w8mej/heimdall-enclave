import Enclave.ProtocolTrace

/-! Per-entity atomic rolling-charge specification. Time advances to
max(previous, supplied) before pruning; rejection never debits a subset of the
requested entities. This model eagerly filters every bucket, whereas Rust
lazily removes an expired prefix from each visited bucket and stops validation
at the first failure. The lazy/eager correspondence, timestamp ordering,
key validation and signed machine arithmetic remain implementation obligations. -/
namespace Enclave.RollingQif

abbrev Bucket := List (Nat × Nat) -- charged-at, millibits
def used (b : Bucket) : Nat := (b.map Prod.snd).sum
def window : Nat := 86400000
def prune (b : Bucket) (now : Nat) := b.filter (fun e => decide (now-e.1 < window))

structure State where
  buckets : Nat → Bucket
  highTime : Nat

structure Charge where
  keys : List Nat
  amount : Nat
  now : Nat
  deriving DecidableEq, Repr

def pruned (s : State) (now : Nat) : State :=
  ⟨fun key => prune (s.buckets key) (max s.highTime now), max s.highTime now⟩

def charge (caps : Nat → Nat) (s : State) (request : Charge) : State × Bool :=
  let fresh := pruned s request.now
  if request.keys.all (fun key => decide (used (fresh.buckets key)+request.amount≤caps key)) then
    (⟨fun key => if key ∈ request.keys then
        (fresh.highTime,request.amount)::fresh.buckets key else fresh.buckets key,
      fresh.highTime⟩,true)
  else (fresh,false)

def Bounded (caps : Nat → Nat) (s : State) : Prop := ∀ key, used (s.buckets key)≤caps key

theorem prune_never_increases_usage (b : Bucket) (now : Nat) : used (prune b now)≤used b := by
  induction b with
  | nil => exact Nat.le_refl 0
  | cons e rest ih =>
    cases h : decide (now-e.1<window) <;> simp [prune,used,List.filter_cons,h] at * <;> omega

theorem charge_preserves_all_caps (caps : Nat → Nat) (s : State) (request : Charge)
    (safe : Bounded caps s) : Bounded caps (charge caps s request).1 := by
  unfold charge
  dsimp only
  split
  · rename_i admissible
    intro key
    by_cases selected : key ∈ request.keys
    · have cap := List.all_eq_true.mp admissible key selected
      simp only [decide_eq_true_eq] at cap
      simpa [selected,used,Nat.add_comm] using cap
    · simpa [selected,pruned] using
        Nat.le_trans (prune_never_increases_usage (s.buckets key) (max s.highTime request.now)) (safe key)
  · intro key
    exact Nat.le_trans (prune_never_increases_usage (s.buckets key) _) (safe key)

theorem rejected_charge_debits_no_entity (caps : Nat → Nat) (s : State) (request : Charge)
    (denied : (charge caps s request).2=false) :
    (charge caps s request).1=pruned s request.now := by
  unfold charge at denied ⊢
  dsimp only at denied ⊢
  split
  · rename_i admitted
    simp only [admitted, ↓reduceIte] at denied
    contradiction
  · rfl

theorem rollback_does_not_move_window_backwards (caps : Nat → Nat) (s : State) (request : Charge) :
    s.highTime≤(charge caps s request).1.highTime := by
  unfold charge
  dsimp only
  split <;> exact Nat.le_max_left _ _

def step (caps : Nat → Nat) (s : State) (c : Charge) : Option State := some (charge caps s c).1

theorem arbitrary_rolling_history_bounded (caps : Nat → Nat) (events : List Charge) :
    Bounded caps (Enclave.Protocol.run (step caps) ⟨fun _ => [],0⟩ events) := by
  exact Enclave.Protocol.run_invariant (step caps) (Bounded caps)
    (fun s c t hs ht => by cases ht; exact charge_preserves_all_caps caps s c hs)
    ⟨fun _ => [],0⟩ events (by simp [Bounded,used])

end Enclave.RollingQif
