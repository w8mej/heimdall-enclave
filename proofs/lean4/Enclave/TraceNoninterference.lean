import Enclave.ProtocolTrace

/-! Two-run security for an explicit observable-command language. Secret state
affects secret computation; public decisions may read only public variables.
This is a value/trace theorem, not merely monotonicity of a label. -/
namespace Enclave.TraceIFC

structure Store where
  public : Nat → Nat
  secret : Nat → Nat

inductive Command where
  | emit (publicIndex : Nat)
  | secretWrite (index value : Nat)
  | publicWrite (index value : Nat)
  | branch (publicIndex : Nat) (yes no : Command)
  | seq (a b : Command)

def execute : Command → Store → Store × List Nat
  | .emit i, s => (s, [s.public i])
  | .secretWrite i v, s => ({s with secret := fun k => if k=i then v else s.secret k}, [])
  | .publicWrite i v, s => ({s with public := fun k => if k=i then v else s.public k}, [])
  | .branch i yes no, s => if s.public i = 0 then execute no s else execute yes s
  | .seq a b, s =>
    let (s₁, o₁) := execute a s
    let (s₂, o₂) := execute b s₁
    (s₂, o₁ ++ o₂)

theorem two_run_noninterference (c : Command) (a b : Store)
    (low : a.public = b.public) :
    (execute c a).1.public = (execute c b).1.public ∧
    (execute c a).2 = (execute c b).2 := by
  induction c generalizing a b with
  | emit i => simp [execute, low]
  | secretWrite i v => exact ⟨low, rfl⟩
  | publicWrite i v => simp [execute, low]
  | branch i yes no iy ino =>
    simp only [execute, low]
    split
    · exact ino a b low
    · exact iy a b low
  | seq c d ic id =>
    obtain ⟨hc, ho⟩ := ic a b low
    obtain ⟨hd, hp⟩ := id (execute c a).1 (execute c b).1 hc
    exact ⟨hd, by simp only [execute]; rw [ho, hp]⟩

/-- Unchecked input syntax includes explicit leaking operations. Security is
derived from checker acceptance, rather than exclusion by the input datatype. -/
inductive Raw where
  | emit (index : Nat)
  | emitSecret (index : Nat)
  | secretWrite (index value : Nat)
  | publicWrite (index value : Nat)
  | copySecretToPublic (source target : Nat)
  | branch (secretCondition : Bool) (index : Nat) (yes no : Raw)
  | seq (a b : Raw)
  deriving DecidableEq, Repr

def check : Raw → Option Command
  | .emit i => some (.emit i)
  | .emitSecret _ => none
  | .secretWrite i v => some (.secretWrite i v)
  | .publicWrite i v => some (.publicWrite i v)
  | .copySecretToPublic _ _ => none
  | .branch true _ _ _ => none
  | .branch false i a b => do return .branch i (←check a) (←check b)
  | .seq a b => do return .seq (←check a) (←check b)

def rawExecute : Raw → Store → Store × List Nat
  | .emit i, s => (s, [s.public i])
  | .emitSecret i, s => (s, [s.secret i])
  | .secretWrite i v, s => ({s with secret := fun k => if k=i then v else s.secret k}, [])
  | .publicWrite i v, s => ({s with public := fun k => if k=i then v else s.public k}, [])
  | .copySecretToPublic i j, s => ({s with public := fun k => if k=j then s.secret i else s.public k}, [])
  | .branch secret i yes no, s =>
    if (if secret then s.secret i else s.public i)=0 then rawExecute no s else rawExecute yes s
  | .seq a b, s =>
    let (s₁, o₁) := rawExecute a s
    let (s₂, o₂) := rawExecute b s₁
    (s₂, o₁ ++ o₂)

theorem checker_preserves_semantics (r : Raw) (c : Command) (h : check r = some c) (s : Store) :
    rawExecute r s = execute c s := by
  induction r generalizing c s with
  | emit i => cases h; rfl
  | emitSecret i => contradiction
  | secretWrite i v => cases h; rfl
  | publicWrite i v => cases h; rfl
  | copySecretToPublic i j => contradiction
  | branch secret i a b ia ib =>
    cases secret with
    | true => contradiction
    | false =>
      cases ha : check a with
      | none => simp [check, ha] at h
      | some ca =>
        cases hb : check b with
        | none => simp [check, ha, hb] at h
        | some cb =>
          have he : Command.branch i ca cb = c := by simpa [check, ha, hb] using h
          subst c
          simp only [rawExecute, Bool.false_eq_true, ↓reduceIte, execute]
          split
          · exact ib cb hb s
          · exact ia ca ha s
  | seq a b ia ib =>
    cases ha : check a with
    | none => simp [check, ha] at h
    | some ca =>
      cases hb : check b with
      | none => simp [check, ha, hb] at h
      | some cb =>
        have he : Command.seq ca cb = c := by simpa [check, ha, hb] using h
        subst c
        simp only [rawExecute, execute, ia ca ha s, ib cb hb]

theorem accepted_raw_trace_noninterference (r : Raw) (c : Command)
    (checked : check r = some c) (a b : Store) (low : a.public=b.public) :
    (rawExecute r a).1.public = (rawExecute r b).1.public ∧
    (rawExecute r a).2 = (rawExecute r b).2 := by
  rw [checker_preserves_semantics r c checked a, checker_preserves_semantics r c checked b]
  exact two_run_noninterference c a b low

end Enclave.TraceIFC
