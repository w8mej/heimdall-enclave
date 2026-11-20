import Enclave.ProtocolTrace

namespace Enclave.MerkleProtocol

inductive Tree : Nat → Type where
  | leaf (value : Nat) : Tree 0
  | node {h : Nat} (left right : Tree h) : Tree (h+1)

def root (compress : Nat → Nat → Nat) : Tree h → Nat
  | .leaf x => x
  | .node l r => compress (root compress l) (root compress r)

/-- Top-down paths; reversing this list gives the production bottom-up order. -/
def rebuild (compress : Nat → Nat → Nat) (leaf : Nat) : List (Bool × Nat) → Nat
  | [] => leaf
  | (right,sibling)::ps =>
    if right then compress sibling (rebuild compress leaf ps)
    else compress (rebuild compress leaf ps) sibling

def opening (compress : Nat → Nat → Nat) : Tree h → Nat → Option (Nat × List (Bool × Nat))
  | .leaf x, i => if i=0 then some (x,[]) else none
  | .node (h := h) l r, i =>
    if i < 2^h then do
      let (x,ps) ← opening compress l i
      return (x,(false,root compress r)::ps)
    else do
      let (x,ps) ← opening compress r (i-2^h)
      return (x,(true,root compress l)::ps)

theorem generated_opening_correct (compress : Nat → Nat → Nat) (tree : Tree h)
    (i x : Nat) (path : List (Bool × Nat)) (ok : opening compress tree i = some (x,path)) :
    path.length = h ∧ rebuild compress x path = root compress tree := by
  induction tree generalizing i x path with
  | leaf v =>
    simp only [opening] at ok
    split at ok
    · cases ok; exact ⟨rfl, rfl⟩
    · contradiction
  | @node height l r il ir =>
    simp only [opening] at ok
    split at ok
    · cases hl : opening compress l i with
      | none => simp [hl] at ok
      | some pair =>
        rcases pair with ⟨v,ps⟩
        simp only [hl] at ok
        have eq : (v,(false,root compress r)::ps) = (x,path) := Option.some.inj ok
        cases eq
        obtain ⟨hlen, hroot⟩ := il _ _ _ hl
        exact ⟨by simp [hlen], by simp [rebuild, root, hroot]⟩
    · cases hr : opening compress r (i-2^height) with
      | none => simp [hr] at ok
      | some pair =>
        rcases pair with ⟨v,ps⟩
        simp only [hr] at ok
        have eq : (v,(true,root compress l)::ps) = (x,path) := Option.some.inj ok
        cases eq
        obtain ⟨hlen, hroot⟩ := ir _ _ _ hr
        exact ⟨by simp [hlen], by simp [rebuild, root, hroot]⟩

def canonical (cohortSize index depth : Nat) : Bool :=
  decide (32 ≤ cohortSize ∧ cohortSize < 2130706433 ∧ index < cohortSize ∧
    cohortSize ≤ 2^depth ∧ (depth=0 ∨ 2^(depth-1) < cohortSize))

theorem padding_not_member (size index depth : Nat) (h : size ≤ index) :
    canonical size index depth = false := by simp [canonical]; omega

def leaves : Tree h → List Nat
  | .leaf x => [x]
  | .node l r => leaves l ++ leaves r

/-- An explicit compression collision, not an assumed hash-security Boolean. -/
def Collision (compress : Nat → Nat → Nat) : Prop :=
  ∃ a b c d, (a ≠ c ∨ b ≠ d) ∧ compress a b = compress c d

theorem reconstructed_leaf_is_member_or_collision (compress : Nat → Nat → Nat)
    (tree : Tree h) (x : Nat) (path : List (Bool × Nat))
    (hl : path.length=h) (hr : rebuild compress x path = root compress tree) :
    x ∈ leaves tree ∨ Collision compress := by
  induction tree generalizing x path with
  | leaf v =>
    cases path with
    | nil => exact Or.inl (by simpa [rebuild, root, leaves] using hr)
    | cons _ _ => simp at hl
  | node l r il ir =>
    cases path with
    | nil => simp at hl
    | cons pair ps =>
      rcases pair with ⟨direction,sibling⟩
      have hlen : ps.length = _ := Nat.succ.inj hl
      cases direction with
      | false =>
        have hh : compress (rebuild compress x ps) sibling = compress (root compress l) (root compress r) := hr
        by_cases he : rebuild compress x ps = root compress l ∧ sibling = root compress r
        · rcases il x ps hlen he.1 with member | collision
          · exact Or.inl (List.mem_append_left _ member)
          · exact Or.inr collision
        · refine Or.inr ⟨_,_,_,_,?_,hh⟩
          by_cases ha : rebuild compress x ps = root compress l
          · exact Or.inr (fun hb => he ⟨ha,hb⟩)
          · exact Or.inl ha
      | true =>
        have hh : compress sibling (rebuild compress x ps) = compress (root compress l) (root compress r) := hr
        by_cases he : sibling = root compress l ∧ rebuild compress x ps = root compress r
        · rcases ir x ps hlen he.2 with member | collision
          · exact Or.inl (List.mem_append_right _ member)
          · exact Or.inr collision
        · refine Or.inr ⟨_,_,_,_,?_,hh⟩
          by_cases ha : sibling = root compress l
          · exact Or.inr (fun hb => he ⟨ha,hb⟩)
          · exact Or.inl ha

theorem forged_nonmember_exhibits_collision (compress : Nat → Nat → Nat)
    (tree : Tree h) (x : Nat) (path : List (Bool × Nat))
    (hl : path.length=h) (hr : rebuild compress x path = root compress tree)
    (nonmember : x ∉ leaves tree) : Collision compress := by
  rcases reconstructed_leaf_is_member_or_collision compress tree x path hl hr with member | collision
  · exact False.elim (nonmember member)
  · exact collision

/-- The production verifier consumes siblings bottom-up and shifts the index
after each sibling. This executable definition follows that order. -/
def bottomUp (compress : Nat → Nat → Nat) : Nat → Nat → List Nat → Nat
  | value, _, [] => value
  | value, index, sibling::rest => bottomUp compress
      (if index % 2 = 0 then compress value sibling else compress sibling value)
      (index / 2) rest

def bottomPath : Nat → List Nat → List (Bool × Nat)
  | _, [] => []
  | index, sibling::rest => (decide (index % 2 ≠ 0),sibling)::bottomPath (index/2) rest

theorem rebuild_append_last (compress : Nat → Nat → Nat) (path : List (Bool × Nat))
    (direction : Bool) (sibling value : Nat) :
    rebuild compress value (path ++ [(direction,sibling)]) =
      rebuild compress (if direction then compress sibling value else compress value sibling) path := by
  induction path with
  | nil => cases direction <;> rfl
  | cons pair rest ih =>
    rcases pair with ⟨d,s⟩
    cases d <;> simp [rebuild, ih]

theorem bottom_up_matches_reversed_path (compress : Nat → Nat → Nat)
    (siblings : List Nat) (index value : Nat) :
    bottomUp compress value index siblings =
      rebuild compress value (bottomPath index siblings).reverse := by
  induction siblings generalizing index value with
  | nil => rfl
  | cons sibling rest ih =>
    simp only [bottomUp, bottomPath, List.reverse_cons, rebuild_append_last]
    by_cases h : index % 2 = 0 <;> simp [h, ih]

theorem bottom_path_length (index : Nat) (siblings : List Nat) :
    (bottomPath index siblings).length = siblings.length := by
  induction siblings generalizing index with
  | nil => rfl
  | cons s rest ih => simp [bottomPath, ih]

/-- The size commitment uses a separate domain. A forged size has an explicit
collision witness in that domain; no injectivity of a finite hash is assumed. -/
theorem changed_size_exhibits_commitment_collision (commit : Nat → Nat → Nat)
    (actualRaw claimedRaw actualSize claimedSize : Nat)
    (different : claimedSize ≠ actualSize)
    (accepted : commit claimedRaw claimedSize = commit actualRaw actualSize) :
    Collision commit := ⟨_,_,_,_,Or.inr different,accepted⟩

theorem bottom_up_nonmember_exhibits_collision (compress : Nat → Nat → Nat)
    (tree : Tree h) (value index : Nat) (siblings : List Nat)
    (depth : siblings.length=h)
    (accepted : bottomUp compress value index siblings = root compress tree)
    (outsider : value ∉ leaves tree) : Collision compress := by
  apply forged_nonmember_exhibits_collision compress tree value
    (bottomPath index siblings).reverse _ _ outsider
  · simp [bottom_path_length, depth]
  · rwa [← bottom_up_matches_reversed_path]

end Enclave.MerkleProtocol
