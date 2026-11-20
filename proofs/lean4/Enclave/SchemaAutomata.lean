import Enclave.AutomataProtocol
import Mathlib.Data.Fintype.Basic

/-! Independent language semantics and derivative recognition. The padding
constructor is zero-byte repetition, matching the production PAD contract.
Finite bounded JSON schemas need union, concatenation, literals and this PAD;
no unbounded user expression or general recursion is admitted. -/
namespace Enclave.SchemaAutomata

inductive Regex where
  | empty | eps | byte (b : Nat) | either (a b : Regex) | concat (a b : Regex) | padding
  deriving DecidableEq, Repr

def language : Regex → List Nat → Prop
  | .empty, _ => False
  | .eps, xs => xs=[]
  | .byte b, xs => xs=[b]
  | .either a b, xs => language a xs ∨ language b xs
  | .concat a b, xs => ∃ ys zs, xs=ys++zs ∧ language a ys ∧ language b zs
  | .padding, xs => ∀ b ∈ xs, b=0

def nullable : Regex → Bool
  | .empty | .byte _ => false
  | .eps | .padding => true
  | .either a b => nullable a || nullable b
  | .concat a b => nullable a && nullable b

theorem nullable_correct (r : Regex) : nullable r = true ↔ language r [] := by
  induction r with
  | empty => simp [nullable, language]
  | eps => simp [nullable, language]
  | byte _ => simp [nullable, language]
  | padding => simp [nullable, language]
  | either a b ia ib => simp [nullable, language, ia, ib]
  | concat a b ia ib =>
    simp only [nullable, Bool.and_eq_true, ia, ib, language]
    constructor
    · exact fun h => ⟨[],[],rfl,h⟩
    · rintro ⟨xs,ys,he,hx,hy⟩
      have hl := congrArg List.length he
      have hx0 : xs=[] := List.eq_nil_of_length_eq_zero (by simp at hl; omega)
      have hy0 : ys=[] := List.eq_nil_of_length_eq_zero (by simp at hl; omega)
      simpa [hx0,hy0] using And.intro hx hy

def derivative : Regex → Nat → Regex
  | .empty, _ | .eps, _ => .empty
  | .byte c, b => if b=c then .eps else .empty
  | .either a c, b => .either (derivative a b) (derivative c b)
  | .concat a c, b => .either (.concat (derivative a b) c)
      (if nullable a then derivative c b else .empty)
  | .padding, b => if b=0 then .padding else .empty

theorem derivative_correct (r : Regex) (b : Nat) (xs : List Nat) :
    language (derivative r b) xs ↔ language r (b::xs) := by
  induction r generalizing xs with
  | empty => simp [derivative, language]
  | eps => simp [derivative, language]
  | byte c => by_cases h : b=c <;> simp [derivative, language, h, List.cons.injEq]
  | either a c ia ic => simp [derivative, language, ia, ic]
  | padding => by_cases h : b=0 <;> simp [derivative, language, h]
  | concat a c ia ic =>
    constructor
    · intro h
      change language (.concat (derivative a b) c) xs ∨
        language (if nullable a then derivative c b else .empty) xs at h
      rcases h with h | h
      · obtain ⟨ys,zs,he,ha,hc⟩ := h
        exact ⟨b::ys,zs,by simp [he],(ia ys).mp ha,hc⟩
      · cases hn : nullable a with
        | false => simp [hn, language] at h
        | true =>
          have ha : language a [] := (nullable_correct a).mp hn
          have hc : language c (b::xs) := (ic xs).mp (by simpa [hn] using h)
          exact ⟨[],b::xs,rfl,ha,hc⟩
    · rintro ⟨ys,zs,he,ha,hc⟩
      cases ys with
      | nil =>
        have hn := (nullable_correct a).mpr ha
        have hz : zs=b::xs := by simpa using he.symm
        apply Or.inr
        change language (if nullable a then derivative c b else .empty) xs
        rw [hn]
        exact (ic xs).mpr (hz ▸ hc)
      | cons y ys =>
        have eq : b=y ∧ xs=ys++zs := by simpa using he
        rcases eq with ⟨rfl,ht⟩
        exact Or.inl ⟨ys,zs,ht,(ia ys).mpr ha,hc⟩

def accepts : Regex → List Nat → Bool
  | r, [] => nullable r
  | r, b::bs => accepts (derivative r b) bs

theorem accepts_iff_language (r : Regex) (xs : List Nat) :
    accepts r xs = true ↔ language r xs := by
  induction xs generalizing r with
  | nil => exact nullable_correct r
  | cons b bs ih => exact (ih _).trans (derivative_correct r b bs)

/-- A certificate relates actual DFA states to residual languages. The checker
must discharge these obligations for every byte/state; a filename or claimed
certificate is not evidence. -/
def Certificate (δ : Enclave.AutomataProtocol.Transition) (accept : Nat → Bool)
    (residual : Nat → Regex) : Prop :=
  (∀ q, accept q=nullable (residual q)) ∧
  (∀ q b, match δ q b with
    | none => derivative (residual q) b = .empty
    | some next => residual next = derivative (residual q) b)

theorem certified_dfa_recognizes_schema (δ : Enclave.AutomataProtocol.Transition)
    (accept : Nat → Bool) (residual : Nat → Regex) (cert : Certificate δ accept residual)
    (q : Nat) (xs : List Nat) :
    (Enclave.AutomataProtocol.run δ q xs).any accept = true ↔ language (residual q) xs := by
  induction xs generalizing q with
  | nil => simpa [Enclave.AutomataProtocol.run, cert.1] using nullable_correct (residual q)
  | cons b bs ih =>
    cases h : δ q b with
    | none =>
      have reject := cert.2 q b
      simp only [h] at reject
      simp only [Enclave.AutomataProtocol.run, h]
      change (false=true) ↔ language (residual q) (b::bs)
      simp only [Bool.false_eq_true, false_iff]
      intro hh
      have hd := (derivative_correct _ _ _).mpr hh
      rw [reject] at hd
      exact hd
    | some next =>
      have step := cert.2 q b
      simp only [h] at step
      simp only [Enclave.AutomataProtocol.run, h]
      change (Enclave.AutomataProtocol.run δ next bs).any accept = true ↔ _
      rw [ih next, step]
      exact derivative_correct _ _ _

/-- Finite certificate validation checks every state and every possible byte.
The only obligations are local syntactic equalities, which are executable.
There is no global recognition theorem hidden in a certificate field. -/
structure FiniteDfa (n : Nat) where
  next : Fin n → Fin 256 → Option (Fin n)
  accepting : Fin n → Bool
  residual : Fin n → Regex

def checkTransition (dfa : FiniteDfa n) (q : Fin n) (b : Fin 256) : Bool :=
  match dfa.next q b with
  | none => decide (derivative (dfa.residual q) b.val = .empty)
  | some next => decide (dfa.residual next = derivative (dfa.residual q) b.val)

def checkCertificate (dfa : FiniteDfa n) : Bool :=
  (List.finRange n).all (fun q =>
    decide (dfa.accepting q = nullable (dfa.residual q)) &&
      (List.finRange 256).all (checkTransition dfa q))

theorem certificate_checks_every_state_and_byte (dfa : FiniteDfa n)
    (checked : checkCertificate dfa = true) :
    (∀ q, dfa.accepting q=nullable (dfa.residual q)) ∧
    ∀ q b, match dfa.next q b with
      | none => derivative (dfa.residual q) b.val = .empty
      | some next => dfa.residual next = derivative (dfa.residual q) b.val := by
  have each (q : Fin n) := List.all_eq_true.mp checked q (List.mem_finRange q)
  simp only [Bool.and_eq_true, decide_eq_true_eq] at each
  refine ⟨fun q => (each q).1, ?_⟩
  intro q b
  have hb := List.all_eq_true.mp (each q).2 b (List.mem_finRange b)
  cases hn : dfa.next q b <;> simpa [checkTransition, hn] using hb

def finiteRun (dfa : FiniteDfa n) : Fin n → List (Fin 256) → Option (Fin n)
  | q, [] => some q
  | q, b::bs => (dfa.next q b).bind (fun next => finiteRun dfa next bs)

theorem checked_finite_certificate_recognizes_language (dfa : FiniteDfa n)
    (checked : checkCertificate dfa = true) (q : Fin n) (xs : List (Fin 256)) :
    (finiteRun dfa q xs).any dfa.accepting = true ↔
      language (dfa.residual q) (xs.map Fin.val) := by
  have certificate := certificate_checks_every_state_and_byte dfa checked
  induction xs generalizing q with
  | nil => simpa [finiteRun, certificate.1] using nullable_correct (dfa.residual q)
  | cons b bs ih =>
    cases h : dfa.next q b with
    | none =>
      have reject := certificate.2 q b
      simp only [h] at reject
      simp only [finiteRun, h]
      change (false=true) ↔ language (dfa.residual q) (b.val::bs.map Fin.val)
      simp only [Bool.false_eq_true, false_iff]
      intro accepted
      have hd := (derivative_correct _ _ _).mpr accepted
      rw [reject] at hd
      exact hd
    | some next =>
      have transition := certificate.2 q b
      simp only [h] at transition
      simp only [finiteRun, h]
      change (finiteRun dfa next bs).any dfa.accepting = true ↔
        language (dfa.residual q) (b.val::bs.map Fin.val)
      have tailCorrect := ih next
      rw [transition] at tailCorrect
      exact Iff.trans tailCorrect (derivative_correct _ _ _)

/-- A real cyclic certificate: arbitrary-length zero-byte padding, with every
nonzero byte rejected. Its acceptance and all 256 transitions are discharged. -/
def paddingDfa : FiniteDfa 1 where
  next := fun q b => if b.val=0 then some q else none
  accepting := fun _ => true
  residual := fun _ => .padding

theorem padding_certificate_checks : checkCertificate paddingDfa = true := by
  simp only [checkCertificate, List.all_eq_true, Bool.and_eq_true]
  intro q _
  refine ⟨rfl, ?_⟩
  intro b _
  by_cases h : b.val=0 <;> simp [checkTransition, paddingDfa, derivative, h]

theorem compiled_padding_iff_all_zero (xs : List (Fin 256)) :
    (finiteRun paddingDfa 0 xs).any paddingDfa.accepting = true ↔
      ∀ b ∈ xs, b.val=0 := by
  have h := checked_finite_certificate_recognizes_language paddingDfa padding_certificate_checks 0 xs
  simpa [paddingDfa, language, List.mem_map] using h

end Enclave.SchemaAutomata
