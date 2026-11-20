import Enclave.MerkleProtocol
import Enclave.TicketProtocol
import Mathlib.Data.Nat.ModEq
import Mathlib.Data.List.Nodup

/-! Index-specific Merkle binding. Membership somewhere in a tree is weaker
than binding to the claimed position. The theorem below recovers the actual
index bits consumed by the native bottom-up verifier and extracts an explicit
compression collision if an accepted value differs at that position. -/
namespace Enclave.MerkleIndexBinding

open Enclave.MerkleProtocol

def address : List Bool → Nat
  | [] => 0
  | direction::rest => (if direction then 2^rest.length else 0)+address rest

theorem address_bounded_by_path_width (path : List Bool) : address path<2^path.length := by
  induction path with
  | nil => decide
  | cons direction rest ih =>
    cases direction <;> simp only [address,List.length_cons,Bool.false_eq_true,↓reduceIte,
      Nat.zero_add,Nat.pow_succ] <;> omega

theorem address_append_last (path : List Bool) (direction : Bool) :
    address (path++[direction])=2*address path+(if direction then 1 else 0) := by
  induction path with
  | nil => cases direction <;> rfl
  | cons head rest ih =>
    cases head <;> simp [address,ih,Nat.pow_succ]
    omega

theorem native_path_address_is_index_modulo_width (index : Nat) (siblings : List Nat) :
    address ((bottomPath index siblings).reverse.map Prod.fst)=index % 2^siblings.length := by
  induction siblings generalizing index with
  | nil => simp [bottomPath,address,Nat.mod_one]
  | cons sibling rest ih =>
    simp only [bottomPath,List.reverse_cons,List.map_append,List.map_singleton,
      address_append_last,ih,List.length_cons,Nat.pow_succ]
    rw [Nat.mul_comm (2^rest.length) 2,Nat.mod_mul]
    have remainder := Nat.mod_lt index (by decide : 0<2)
    by_cases even : index%2=0
    · simp [even]
    · have odd : index%2=1 := by omega
      simp [even,odd,Nat.add_comm]

def atIndex : Tree h → Nat → Option Nat
  | .leaf value, index => if index=0 then some value else none
  | .node (h := height) left right, index =>
    if index<2^height then atIndex left index else atIndex right (index-2^height)

theorem matching_reconstruction_binds_exact_address_or_collision
    (compress : Nat → Nat → Nat) (tree : Tree h) (value : Nat)
    (path : List (Bool × Nat)) (depth : path.length=h)
    (accepted : rebuild compress value path=root compress tree) :
    atIndex tree (address (path.map Prod.fst))=some value ∨ Collision compress := by
  induction tree generalizing value path with
  | leaf actual =>
    cases path with
    | nil => exact Or.inl (by simpa [rebuild,root,atIndex,address] using accepted.symm)
    | cons _ _ => simp at depth
  | @node height left right leftIH rightIH =>
    cases path with
    | nil => simp at depth
    | cons pair rest =>
      rcases pair with ⟨direction,sibling⟩
      have restDepth : rest.length=height := Nat.succ.inj depth
      have bitsDepth : (rest.map Prod.fst).length=height := by simpa using restDepth
      have bitsBound := address_bounded_by_path_width (rest.map Prod.fst)
      rw [bitsDepth] at bitsBound
      cases direction with
      | false =>
        have equality : compress (rebuild compress value rest) sibling=
            compress (root compress left) (root compress right) := accepted
        by_cases same : rebuild compress value rest=root compress left ∧ sibling=root compress right
        · rcases leftIH value rest restDepth same.1 with bound | collision
          · exact Or.inl (by simpa [atIndex,address,bitsBound] using bound)
          · exact Or.inr collision
        · refine Or.inr ⟨_,_,_,_,?_,equality⟩
          tauto
      | true =>
        have equality : compress sibling (rebuild compress value rest)=
            compress (root compress left) (root compress right) := accepted
        by_cases same : sibling=root compress left ∧ rebuild compress value rest=root compress right
        · rcases rightIH value rest restDepth same.2 with bound | collision
          · have notLeft : ¬2^height+address (rest.map Prod.fst)<2^height := by omega
            exact Or.inl (by simpa [atIndex,address,bitsDepth,notLeft] using bound)
          · exact Or.inr collision
        · refine Or.inr ⟨_,_,_,_,?_,equality⟩
          tauto

theorem accepted_native_opening_binds_claimed_index_or_collision
    (compress : Nat → Nat → Nat) (tree : Tree h) (value index : Nat)
    (siblings : List Nat) (depth : siblings.length=h) (inRange : index<2^h)
    (accepted : bottomUp compress value index siblings=root compress tree) :
    atIndex tree index=some value ∨ Collision compress := by
  have binding := matching_reconstruction_binds_exact_address_or_collision compress tree value
    (bottomPath index siblings).reverse (by simp [bottom_path_length,depth])
    (by rwa [← bottom_up_matches_reversed_path])
  rw [native_path_address_is_index_modulo_width,depth,Nat.mod_eq_of_lt inRange] at binding
  exact binding

theorem wrong_value_at_claimed_index_exhibits_collision
    (compress : Nat → Nat → Nat) (tree : Tree h) (value actual index : Nat)
    (siblings : List Nat) (depth : siblings.length=h) (inRange : index<2^h)
    (accepted : bottomUp compress value index siblings=root compress tree)
    (actualValue : atIndex tree index=some actual) (different : value≠actual) :
    Collision compress := by
  rcases accepted_native_opening_binds_claimed_index_or_collision compress tree value index siblings
    depth inRange accepted with bound | collision
  · rw [actualValue] at bound
    exact False.elim (different (Option.some.inj bound).symm)
  · exact collision

theorem tree_leaf_count (tree : Tree h) : (leaves tree).length=2^h := by
  induction tree with
  | leaf _ => rfl
  | node left right ihLeft ihRight => simp [leaves,ihLeft,ihRight,Nat.pow_succ]; omega

theorem exact_index_matches_ordered_leaf_list (tree : Tree h) (index : Nat) :
    atIndex tree index=(leaves tree)[index]? := by
  induction tree generalizing index with
  | leaf value =>
    cases index <;> simp [atIndex,leaves]
  | node left right ihLeft ihRight =>
    simp only [atIndex,leaves,List.getElem?_append,tree_leaf_count]
    split
    · exact ihLeft index
    · exact ihRight _

/-- The top-down balanced constructor; a node contains exactly two equal
halves. A length check is required before accepting its result. -/
def build : (height : Nat) → List Nat → Tree height
  | 0, values => .leaf (values.headD 0)
  | height+1, values => .node (build height (values.take (2^height)))
      (build height (values.drop (2^height)))

theorem balanced_constructor_preserves_every_leaf (height : Nat) (values : List Nat)
    (sized : values.length=2^height) : leaves (build height values)=values := by
  induction height generalizing values with
  | zero =>
    cases values with
    | nil => simp at sized
    | cons head tail =>
      have empty : tail=[] := List.length_eq_zero.mp (by simpa using sized)
      subst tail
      rfl
  | succ height ih =>
    have halfBound : 2^height≤values.length := by rw [sized,Nat.pow_succ]; omega
    have leftLength : (values.take (2^height)).length=2^height := by simp [List.length_take,Nat.min_eq_left halfBound]
    have rightLength : (values.drop (2^height)).length=2^height := by
      simp only [List.length_drop,sized,Nat.pow_succ]; omega
    simp only [build,leaves,ih _ leftLength,ih _ rightLength,List.take_append_drop]

/-- Size is the number of actual members before zero-padding. Therefore an
accepted in-range position refers to an actual enrolled leaf, not a padding
leaf even when the padding digest equals a legitimate member's digest. -/
theorem padded_constructor_binds_actual_member_position (height size index : Nat)
    (members : List Nat) (sized : members.length=size) (fits : size≤2^height)
    (inRange : index<size) :
    atIndex (build height (members++List.replicate (2^height-size) 0)) index=members[index]? := by
  rw [exact_index_matches_ordered_leaf_list,balanced_constructor_preserves_every_leaf]
  · exact List.getElem?_append_left (by omega)
  · simp [sized]; omega

/-- The exact byte framing of `cohort::leaf`: u32 big-endian SEP-key length,
SEP bytes, then authenticator bytes. Hashing is a separate primitive. -/
def keyPairBytes (sep authenticator : List Nat) : List Nat :=
  Enclave.Tickets.beBytes 4 sep.length++(sep++authenticator)

def readKeyPair (bytes : List Nat) : Option (List Nat × List Nat) := do
  let (length,rest) ← Enclave.Tickets.readWord 4 bytes
  if length≤rest.length then some (rest.take length,rest.drop length) else none

theorem key_pair_framing_roundtrip (sep authenticator : List Nat)
    (lengthFitsU32 : sep.length<256^4) :
    readKeyPair (keyPairBytes sep authenticator)=some (sep,authenticator) := by
  simp [readKeyPair,keyPairBytes,Enclave.Tickets.readWord_write _ _ _ lengthFitsU32,
    List.take_append,List.drop_append]

theorem key_pair_encoding_injective (firstSep firstAuth secondSep secondAuth : List Nat)
    (firstLength : firstSep.length<256^4) (secondLength : secondSep.length<256^4)
    (sameBytes : keyPairBytes firstSep firstAuth=keyPairBytes secondSep secondAuth) :
    firstSep=secondSep ∧ firstAuth=secondAuth := by
  have first := key_pair_framing_roundtrip firstSep firstAuth firstLength
  rw [sameBytes,key_pair_framing_roundtrip secondSep secondAuth secondLength] at first
  have equality := Option.some.inj first
  exact ⟨(congrArg Prod.fst equality).symm,(congrArg Prod.snd equality).symm⟩

theorem different_key_pairs_sharing_leaf_exhibit_hash_collision
    (hashLeaf : List Nat → Nat) (firstSep firstAuth secondSep secondAuth : List Nat)
    (firstLength : firstSep.length<256^4) (secondLength : secondSep.length<256^4)
    (different : firstSep≠secondSep ∨ firstAuth≠secondAuth)
    (sameDigest : hashLeaf (keyPairBytes firstSep firstAuth)=hashLeaf (keyPairBytes secondSep secondAuth)) :
    ∃ first second, first≠second ∧ hashLeaf first=hashLeaf second := by
  refine ⟨_,_,?_,sameDigest⟩
  intro same
  have pairSame := key_pair_encoding_injective _ _ _ _ firstLength secondLength same
  tauto

/-- The native verifier first reconstructs the raw root, then applies the
separate size-commitment domain. Neither compression function is assumed
injective: failure of exact size or position binding yields a collision. -/
theorem size_committed_opening_binds_exact_index_or_collision
    (compress commit : Nat → Nat → Nat) (tree : Tree h)
    (value index actualSize claimedSize : Nat) (siblings : List Nat)
    (depth : siblings.length=h) (fits : actualSize≤2^h) (inClaim : index<claimedSize)
    (accepted : commit (bottomUp compress value index siblings) claimedSize=
      commit (root compress tree) actualSize) :
    (claimedSize=actualSize ∧ index<actualSize ∧ atIndex tree index=some value) ∨
      Collision compress ∨ Collision commit := by
  by_cases same : bottomUp compress value index siblings=root compress tree ∧ claimedSize=actualSize
  · have actualIndex : index<actualSize := by omega
    rcases accepted_native_opening_binds_claimed_index_or_collision compress tree value index siblings
        depth (by omega) same.1 with binding | collision
    · exact Or.inl ⟨same.2,actualIndex,binding⟩
    · exact Or.inr (Or.inl collision)
  · refine Or.inr (Or.inr ⟨_,_,_,_,?_,accepted⟩)
    tauto

/-- Repeating exactly the same enrolled key pair necessarily repeats a leaf
digest, independently of the hash's security. Therefore the native duplicate
digest check cannot count that repeated identity as two distinct members. -/
theorem unique_leaf_digests_exclude_repeated_key_pairs
    (hashLeaf : List Nat → Nat) (members : List (List Nat × List Nat))
    (unique : (members.map (fun keys => hashLeaf (keyPairBytes keys.1 keys.2))).Nodup) :
    members.Nodup := List.Nodup.of_map _ unique

end Enclave.MerkleIndexBinding
