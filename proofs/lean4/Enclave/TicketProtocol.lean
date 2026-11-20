import Enclave.ProtocolTrace

/-! Execution-ticket V2 byte encoding and durable replay semantics. Bytes are
represented by naturals; well-formed byte strings have values below 256.
Signature authenticity, hash collision resistance and durable transaction
semantics are external assumptions, not security conclusions in constructors. -/
namespace Enclave.Tickets

def leBytes : Nat → Nat → List Nat
  | 0, _ => []
  | k+1, n => n % 256 :: leBytes k (n / 256)

def fromLE : List Nat → Nat
  | [] => 0
  | b :: bs => b + 256 * fromLE bs

@[simp] theorem leBytes_length (k n : Nat) : (leBytes k n).length = k := by
  induction k generalizing n <;> simp [leBytes, *]

theorem fromLE_roundtrip (k n : Nat) (h : n < 256^k) :
    fromLE (leBytes k n) = n := by
  induction k generalizing n with
  | zero => simp at h; simp [fromLE, leBytes, h]
  | succ k ih =>
    have hq : n / 256 < 256^k := by
      apply (Nat.div_lt_iff_lt_mul (by decide : 0 < 256)).2
      simpa [Nat.pow_succ, Nat.mul_comm] using h
    simp only [leBytes, fromLE, ih _ hq]
    omega

def beBytes (k n : Nat) := (leBytes k n).reverse

def readWord (k : Nat) (bs : List Nat) : Option (Nat × List Nat) :=
  if k ≤ bs.length then some (fromLE (bs.take k).reverse, bs.drop k) else none

@[simp] theorem readWord_write (k n : Nat) (rest : List Nat) (h : n < 256^k) :
    readWord k (beBytes k n ++ rest) = some (n, rest) := by
  have hl : (beBytes k n).length = k := by simp [beBytes]
  have ht : (beBytes k n ++ rest).take k = beBytes k n := by
    exact List.take_left' hl
  have hd : (beBytes k n ++ rest).drop k = rest := by
    simpa only [hl, Nat.add_zero, List.drop_zero] using
      (List.drop_append (l₁ := beBytes k n) (l₂ := rest) 0)
  simp only [readWord, List.length_append, hl, Nat.le_add_right, ↓reduceIte, ht, hd]
  simp [beBytes, fromLE_roundtrip k n h]

def blob (bs : List Nat) := beBytes 8 bs.length ++ bs

def readBlob (bs : List Nat) : Option (List Nat × List Nat) := do
  let (n, rest) ← readWord 8 bs
  if n ≤ rest.length then some (rest.take n, rest.drop n) else none

@[simp] theorem readBlob_write (bs rest : List Nat) (h : bs.length < 256^8) :
    readBlob (blob bs ++ rest) = some (bs, rest) := by
  simp [blob, List.append_assoc, readBlob, readWord_write 8 bs.length _ h,
    List.take_append, List.drop_append]

structure Fields where
  id : List Nat
  server : List Nat
  tool : List Nat
  args : List Nat
  rows : Nat
  issued : Nat
  expires : Nat
  deriving DecidableEq, Repr

def Fields.bounded (t : Fields) : Prop :=
  t.id.length < 256^8 ∧ t.server.length < 256^8 ∧
  t.tool.length < 256^8 ∧ t.args.length < 256^8 ∧
  t.rows < 256^8 ∧ t.issued < 256^8 ∧ t.expires < 256^8

def encodeFields (t : Fields) : List Nat :=
  blob t.id ++ (blob t.server ++ (blob t.tool ++ (blob t.args ++
    (beBytes 8 t.rows ++ (beBytes 8 t.issued ++ beBytes 8 t.expires)))))

def decodeFields (bs : List Nat) : Option (Fields × List Nat) := do
  let (id, bs) ← readBlob bs
  let (server, bs) ← readBlob bs
  let (tool, bs) ← readBlob bs
  let (args, bs) ← readBlob bs
  let (rows, bs) ← readWord 8 bs
  let (issued, bs) ← readWord 8 bs
  let (expires, bs) ← readWord 8 bs
  return (⟨id, server, tool, args, rows, issued, expires⟩, bs)

theorem fields_roundtrip (t : Fields) (rest : List Nat) (h : t.bounded) :
    decodeFields (encodeFields t ++ rest) = some (t, rest) := by
  rcases h with ⟨h1,h2,h3,h4,h5,h6,h7⟩
  cases t
  simp [decodeFields, encodeFields, List.append_assoc, readBlob_write _ _ h1,
    readBlob_write _ _ h2, readBlob_write _ _ h3, readBlob_write _ _ h4,
    readWord_write _ _ _ h5, readWord_write _ _ _ h6, readWord_write _ _ _ h7]

theorem fields_encoding_injective (a b : Fields) (ha : a.bounded) (hb : b.bounded)
    (h : encodeFields a = encodeFields b) : a = b := by
  have ea := fields_roundtrip a [] ha
  have eb := fields_roundtrip b [] hb
  simp only [List.append_nil] at ea eb
  rw [h, eb] at ea
  exact (congrArg Prod.fst (Option.some.inj ea)).symm

structure Ticket where
  fields : Fields
  moduleDigest : Option (List Nat)
  lineRows : Bool
  deriving DecidableEq, Repr

def optionalDigest : Option (List Nat) → List Nat
  | none => [0]
  | some digest => 1 :: digest

def readDigest : List Nat → Option (Option (List Nat) × List Nat)
  | 0::rest => some (none, rest)
  | 1::rest => if 32 ≤ rest.length then some (some (rest.take 32), rest.drop 32) else none
  | _ => none

theorem digest_roundtrip (digest : Option (List Nat)) (rest : List Nat)
    (h : ∀ bs, digest = some bs → bs.length = 32) :
    readDigest (optionalDigest digest ++ rest) = some (digest, rest) := by
  cases digest with
  | none => rfl
  | some bs =>
    have hl := h bs rfl
    have ht := List.take_left' (l₂ := rest) hl
    have hd := List.drop_left' (l₂ := rest) hl
    simp [optionalDigest, readDigest, List.length_append, ← hl, ht, hd]

def body (t : Ticket) := encodeFields t.fields ++ optionalDigest t.moduleDigest ++
  [if t.lineRows then 1 else 0]

def domain : List Nat := "MCPMAC-EXEC-TICKET-V2\x00".toUTF8.data.toList.map UInt8.toNat
def signingBytes (t : Ticket) := domain ++ body t

def decodeBody (bs : List Nat) : Option Ticket := do
  let (fields, rest) ← decodeFields bs
  let (digest, rest) ← readDigest rest
  match rest with
  | [0] => return ⟨fields, digest, false⟩
  | [1] => return ⟨fields, digest, true⟩
  | _ => none

theorem ticket_roundtrip (t : Ticket) (hf : t.fields.bounded)
    (hm : ∀ bs, t.moduleDigest = some bs → bs.length = 32) :
    decodeBody (body t) = some t := by
  simp only [body, List.append_assoc, decodeBody,
    fields_roundtrip t.fields _ hf]
  change (do
    let (digest, rest) ← readDigest (optionalDigest t.moduleDigest ++ [if t.lineRows then 1 else 0])
    match rest with
    | [0] => return ⟨t.fields, digest, false⟩
    | [1] => return ⟨t.fields, digest, true⟩
    | _ => none) = some t
  rw [digest_roundtrip _ _ hm]
  cases t with
  | mk fields digest format => cases format <;> rfl

theorem signing_bytes_injective (a b : Ticket) (ha : a.fields.bounded) (hb : b.fields.bounded)
    (hma : ∀ bs, a.moduleDigest = some bs → bs.length = 32)
    (hmb : ∀ bs, b.moduleDigest = some bs → bs.length = 32)
    (h : signingBytes a = signingBytes b) : a = b := by
  have bodies : body a = body b := List.append_cancel_left h
  have da := ticket_roundtrip a ha hma
  rw [bodies, ticket_roundtrip b hb hmb] at da
  exact (Option.some.inj da).symm

structure Replay where
  used : List (Nat × Nat)
  lastTime : Nat
  capacity : Nat
  deriving DecidableEq, Repr

def consume (s : Replay) (id expiry now : Nat) : Option Replay :=
  let live := s.used.filter (fun x => decide (now ≤ x.2))
  if s.lastTime ≤ now ∧ now ≤ expiry ∧
      ¬ (live.any (fun x => x.1 == id)) ∧ live.length < s.capacity then
    some ⟨(id, expiry) :: live, now, s.capacity⟩
  else none

theorem consumption_recorded (s t : Replay) (id expiry now : Nat)
    (h : consume s id expiry now = some t) : (id, expiry) ∈ t.used := by
  unfold consume at h
  dsimp only at h
  split at h
  · cases h
    exact List.mem_cons_self ..
  · contradiction

theorem immediate_replay_denied (s t : Replay) (id expiry now : Nat)
    (h : consume s id expiry now = some t) : consume t id expiry now = none := by
  unfold consume at h
  dsimp only at h
  split at h
  · rename_i hg
    cases h
    simp [consume, hg.2.1]
  · contradiction

theorem consumption_capacity (s t : Replay) (id expiry now : Nat)
    (h : consume s id expiry now = some t) : t.used.length ≤ t.capacity := by
  unfold consume at h
  dsimp only at h
  split at h
  · rename_i hg
    cases h
    simp only [List.length_cons]
    omega
  · contradiction

theorem live_record_preserved (s t : Replay) (id expiry now old oldExpiry : Nat)
    (oldRecord : (old,oldExpiry) ∈ s.used) (live : now ≤ oldExpiry)
    (h : consume s id expiry now = some t) : (old,oldExpiry) ∈ t.used := by
  unfold consume at h
  dsimp only at h
  split at h
  · cases h
    simp only [List.mem_cons, List.mem_filter, decide_eq_true_eq]
    exact Or.inr ⟨oldRecord, live⟩
  · contradiction

theorem clock_rollback_denied (s : Replay) (id expiry now : Nat) (h : now < s.lastTime) :
    consume s id expiry now = none := by
  simp [consume, show ¬ s.lastTime ≤ now by omega]

theorem any_live_replay_denied (s : Replay) (id expiry oldExpiry now : Nat)
    (used : (id,oldExpiry) ∈ s.used) (live : now ≤ oldExpiry) :
    consume s id expiry now = none := by
  have hm : (id,oldExpiry) ∈ s.used.filter (fun x => decide (now ≤ x.2)) := by
    simp [List.mem_filter, used, live]
  have ha : (s.used.filter (fun x => decide (now ≤ x.2))).any (fun x => x.1 == id) = true :=
    List.any_eq_true.mpr ⟨(id,oldExpiry), hm, by simp⟩
  simp [consume, ha]

abbrev ReplayEvent := Nat × Nat × Nat -- identifier, expiry, trusted current time
def replayStep (s : Replay) (e : ReplayEvent) := consume s e.1 e.2.1 e.2.2

theorem consumed_record_or_clock_past_preserved (s t : Replay) (e : ReplayEvent)
    (old expiry : Nat) (inv : (old,expiry) ∈ s.used ∨ expiry < s.lastTime)
    (ok : replayStep s e = some t) : (old,expiry) ∈ t.used ∨ expiry < t.lastTime := by
  unfold replayStep consume at ok
  dsimp only at ok
  split at ok
  · rename_i hg
    cases ok
    rcases inv with record | past
    · by_cases live : e.2.2 ≤ expiry
      · exact Or.inl (by simp [List.mem_filter, record, live])
      · exact Or.inr (by simp only; omega)
    · exact Or.inr (by simp only; omega)
  · contradiction

theorem replay_after_arbitrary_history_denied (s t : Replay) (id expiry now later : Nat)
    (consumed : consume s id expiry now = some t) (events : List ReplayEvent) :
    consume (Enclave.Protocol.run replayStep t events) id expiry later = none := by
  have first : (id,expiry) ∈ t.used ∨ expiry < t.lastTime :=
    Or.inl (consumption_recorded s t id expiry now consumed)
  have inv := Enclave.Protocol.run_invariant replayStep
    (fun s => (id,expiry) ∈ s.used ∨ expiry < s.lastTime)
    (fun a e b ha hb => consumed_record_or_clock_past_preserved a b e id expiry ha hb)
    t events first
  rcases inv with record | past
  · by_cases live : later ≤ expiry
    · exact any_live_replay_denied _ id expiry expiry later record live
    · simp [consume, live]
  · by_cases rollback : later < (Enclave.Protocol.run replayStep t events).lastTime
    · exact clock_rollback_denied _ id expiry later rollback
    · have expired : ¬ later ≤ expiry := by omega
      simp [consume, expired]

structure Dispatch where
  server : List Nat
  tool : List Nat
  args : List Nat
  moduleDigest : Option (List Nat)
  lineRows : Bool
  deriving DecidableEq, Repr

def dispatchAllowed (signatureValid : Ticket → Bool) (t : Ticket) (expected : Dispatch)
    (now returnedRows : Nat) : Bool :=
  signatureValid t && decide (t.fields.server=expected.server ∧ t.fields.tool=expected.tool ∧
    t.fields.args=expected.args ∧ t.moduleDigest=expected.moduleDigest ∧
    t.lineRows=expected.lineRows ∧ t.fields.issued ≤ now ∧ now ≤ t.fields.expires ∧
    t.fields.expires-t.fields.issued ≤ 3600000000000 ∧ returnedRows ≤ t.fields.rows)

theorem dispatch_binds_independent_target_and_output (sig : Ticket → Bool) (t : Ticket)
    (expected : Dispatch) (now returned : Nat) (ok : dispatchAllowed sig t expected now returned = true) :
    t.fields.server=expected.server ∧ t.fields.tool=expected.tool ∧
    t.fields.args=expected.args ∧ t.moduleDigest=expected.moduleDigest ∧
    t.lineRows=expected.lineRows ∧ returned ≤ t.fields.rows := by
  simp only [dispatchAllowed, Bool.and_eq_true, decide_eq_true_eq] at ok
  exact ⟨ok.2.1,ok.2.2.1,ok.2.2.2.1,ok.2.2.2.2.1,ok.2.2.2.2.2.1,ok.2.2.2.2.2.2.2.2.2⟩

end Enclave.Tickets
