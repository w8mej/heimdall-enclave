import Enclave.ProtocolTrace

namespace Enclave.DagProtocol

structure Node where
  parents : List Nat
  taint : Nat
  digest : List Nat
  deriving DecidableEq, Repr

def parentTaint (nodes : List Node) (parents : List Nat) : Nat :=
  parents.foldr (fun i acc => max ((nodes[i]?).map Node.taint |>.getD 0) acc) 0

theorem parent_bounded_by_join (nodes : List Node) (parents : List Nat) (i : Nat)
    (hi : i ∈ parents) : ((nodes[i]?).map Node.taint |>.getD 0) ≤ parentTaint nodes parents := by
  induction parents with
  | nil => contradiction
  | cons p ps ih =>
    simp only [List.mem_cons] at hi
    rcases hi with rfl | hi
    · exact Nat.le_max_left _ _
    · exact Nat.le_trans (ih hi) (Nat.le_max_right _ _)

def add (nodes : List Node) (parents : List Nat) (explicit : Nat) (digest : List Nat) :
    Option (List Node) :=
  if parents.all (fun p => decide (p < nodes.length)) ∧ parentTaint nodes parents ≤ explicit then
    some (nodes ++ [⟨parents, explicit, digest⟩]) else none

theorem accepted_parents_exist_and_precede (nodes result : List Node) (ps : List Nat)
    (t : Nat) (d : List Nat) (h : add nodes ps t d = some result) :
    ∀ i ∈ ps, i < nodes.length ∧ i < result.length := by
  unfold add at h
  split at h
  · rename_i hg
    cases h
    intro i hi
    have hp := List.all_eq_true.mp hg.1 i hi
    simp only [decide_eq_true_eq] at hp
    simp only [List.length_append, List.length_cons, List.length_nil]
    exact ⟨hp, by omega⟩
  · contradiction

theorem accepted_child_dominates_each_parent (nodes result : List Node) (ps : List Nat)
    (t : Nat) (d : List Nat) (h : add nodes ps t d = some result) :
    ∀ i ∈ ps, ((nodes[i]?).map Node.taint |>.getD 0) ≤ t := by
  unfold add at h
  split at h
  · rename_i hg
    exact fun i hi => Nat.le_trans (parent_bounded_by_join nodes ps i hi) hg.2
  · contradiction

inductive Ancestor (nodes : List Node) : Nat → Nat → Prop where
  | edge {a b : Nat} (hb : b < nodes.length) (h : a ∈ (nodes[b]).parents) : Ancestor nodes a b
  | trans {a b c} : Ancestor nodes a b → Ancestor nodes b c → Ancestor nodes a c

theorem ancestor_taint_monotone (nodes : List Node)
    (edges : ∀ (a b : Nat) (hb : b < nodes.length), a ∈ (nodes[b]).parents →
      ((nodes[a]?).map Node.taint |>.getD 0) ≤ (nodes[b]).taint)
    (a b : Nat) (h : Ancestor nodes a b) :
    ((nodes[a]?).map Node.taint |>.getD 0) ≤ ((nodes[b]?).map Node.taint |>.getD 0) := by
  induction h with
  | edge hb hm => simpa [List.getElem?_eq_getElem hb] using edges _ _ hb hm
  | trans _ _ ih₁ ih₂ => exact Nat.le_trans ih₁ ih₂

/-- A graph property derived from successful construction, rather than an
assumption supplied to the ancestor theorem. IDs are zero-based list positions. -/
def WellFormed (nodes : List Node) : Prop :=
  ∀ (i : Nat) (node : Node), nodes[i]? = some node → ∀ p ∈ node.parents,
    ∃ parent : Node, nodes[p]? = some parent ∧ p < i ∧ parent.taint ≤ node.taint

theorem empty_well_formed : WellFormed [] := by
  intro i node h
  simp at h

theorem add_preserves_well_formed (nodes result : List Node) (ps : List Nat)
    (t : Nat) (d : List Nat) (valid : WellFormed nodes)
    (ok : add nodes ps t d = some result) : WellFormed result := by
  unfold add at ok
  split at ok
  · rename_i guard
    cases ok
    intro i node hn p hp
    by_cases old : i < nodes.length
    · rw [List.getElem?_append_left old] at hn
      obtain ⟨parent, hparent, hlt, ht⟩ := valid i node hn p hp
      exact ⟨parent, by rw [List.getElem?_append_left (by omega)]; exact hparent, hlt, ht⟩
    · obtain ⟨hi, _⟩ := List.getElem?_eq_some_iff.mp hn
      have index : i = nodes.length := by simp only [List.length_append, List.length_singleton] at hi; omega
      subst i
      have equal : node = ⟨ps,t,d⟩ := by simpa [List.getElem?_append_right] using hn.symm
      rw [equal] at hp ⊢
      have before : p < nodes.length := by
        have hh := List.all_eq_true.mp guard.1 p hp
        simpa using hh
      refine ⟨nodes[p], ?_, before, ?_⟩
      · rw [List.getElem?_append_left before, List.getElem?_eq_getElem before]
      · have bound := Nat.le_trans (parent_bounded_by_join nodes ps p hp) guard.2
        simpa [List.getElem?_eq_getElem before] using bound
  · contradiction

abbrev BuildEvent := List Nat × Nat × List Nat
def buildStep (nodes : List Node) (e : BuildEvent) := add nodes e.1 e.2.1 e.2.2

theorem constructed_graph_well_formed (events : List BuildEvent) :
    WellFormed (Enclave.Protocol.run buildStep [] events) := by
  exact Enclave.Protocol.run_invariant buildStep WellFormed
    (fun s e t hs ht => add_preserves_well_formed s t e.1 e.2.1 e.2.2 hs ht)
    [] events empty_well_formed

theorem constructed_ancestor_taint_monotone (events : List BuildEvent) (a b : Nat)
    (path : Ancestor (Enclave.Protocol.run buildStep [] events) a b) :
    (((Enclave.Protocol.run buildStep [] events)[a]?).map Node.taint |>.getD 0) ≤
    (((Enclave.Protocol.run buildStep [] events)[b]?).map Node.taint |>.getD 0) := by
  apply ancestor_taint_monotone _ _ a b path
  intro p i hi hp
  obtain ⟨parent, hparent, _, ht⟩ := constructed_graph_well_formed events i
    ((Enclave.Protocol.run buildStep [] events)[i]) (List.getElem?_eq_getElem hi) p hp
  simpa [hparent] using ht

end Enclave.DagProtocol
