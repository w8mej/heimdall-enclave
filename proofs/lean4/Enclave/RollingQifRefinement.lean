import Enclave.RollingQif
import Enclave.AdaptiveBudget
import Init.Data.BitVec.Lemmas

/-! Refinement of the actual oldest-first bucket pruning algorithm. Lazy
storage is compared by its live observations, not by equality of stale entries.
The probability theorem concerns one charged entity over one live window;
it does not claim a lifetime bound after charges have expired. -/
namespace Enclave.RollingQifRefinement

open Enclave.RollingQif

def chronological (b : Bucket) : Prop := b.Pairwise (fun a c => a.1≤c.1)

/-- Same prefix-removal branch and stopping condition as `Bucket::prune`. -/
def prefixPrune : Bucket → Nat → Bucket
  | [], _ => []
  | entry::rest, now =>
    if window≤now-entry.1 then prefixPrune rest now else entry::rest

theorem prefix_prune_equals_live_filter (b : Bucket) (ordered : chronological b)
    (now : Nat) : prefixPrune b now=prune b now := by
  induction b with
  | nil => rfl
  | cons entry rest ih =>
    have sorted := List.pairwise_cons.mp ordered
    unfold prefixPrune
    split
    · rename_i expired
      simpa [prune,List.filter_cons,show ¬now-entry.1<window by omega]
        using ih sorted.2
    · rename_i live
      have allLive : ∀ x ∈ entry::rest, decide (now-x.1<window)=true := by
        intro x member
        rcases List.mem_cons.mp member with rfl | tail
        · simp only [decide_eq_true_eq]; omega
        · have earlier := sorted.1 x tail
          simp only [decide_eq_true_eq]; omega
      exact (List.filter_eq_self.mpr allLive).symm

theorem live_filter_preserves_chronology (b : Bucket) (ordered : chronological b)
    (now : Nat) : chronological (prune b now) :=
  ordered.sublist (List.filter_sublist _)

theorem prefix_prune_preserves_chronology (b : Bucket) (ordered : chronological b)
    (now : Nat) : chronological (prefixPrune b now) := by
  rw [prefix_prune_equals_live_filter b ordered now]
  exact live_filter_preserves_chronology b ordered now

theorem live_filter_idempotent (b : Bucket) (now : Nat) :
    prune (prune b now) now=prune b now := by
  simp [prune,List.filter_filter]

theorem later_filter_subsumes_earlier (b : Bucket) (earlier later : Nat)
    (forward : earlier≤later) : prune (prune b earlier) later=prune b later := by
  unfold prune
  rw [List.filter_filter]
  apply List.filter_congr
  intro entry _
  by_cases live : later-entry.1<window
  · have oldLive : earlier-entry.1<window := by omega
    simp [live,oldLive]
  · simp [live]

theorem reverse_live_filter (b : Bucket) (now : Nat) :
    prune b.reverse now=(prune b now).reverse := List.filter_reverse _ _

abbrev Buckets := Nat → Bucket

def setBucket (buckets : Buckets) (key : Nat) (bucket : Bucket) : Buckets :=
  fun k => if k=key then bucket else buckets k

def observe (buckets : Buckets) (now : Nat) : Buckets :=
  fun key => prune (buckets key) now

def Ordered (buckets : Buckets) : Prop := ∀ key, chronological (buckets key)

/-- Production preflight can prune a prefix of the requested keys before a
later rejection. No debit occurs in this phase. -/
def prepare (caps : Nat → Nat) (now amount : Nat) : Buckets → List Nat → Buckets × Bool
  | buckets, [] => (buckets,true)
  | buckets, key::rest =>
    let fresh := setBucket buckets key (prefixPrune (buckets key) now)
    if used (fresh key)+amount≤caps key then prepare caps now amount fresh rest
    else (fresh,false)

theorem prune_one_is_observationally_inert (buckets : Buckets) (key now : Nat)
    (ordered : Ordered buckets) :
    observe (setBucket buckets key (prefixPrune (buckets key) now)) now=
      observe buckets now := by
  funext k
  by_cases same : k=key
  · subst k
    simp [observe,setBucket,prefix_prune_equals_live_filter _ (ordered key),
      live_filter_idempotent]
  · simp [observe,setBucket,same]

theorem prune_one_preserves_order (buckets : Buckets) (key now : Nat)
    (ordered : Ordered buckets) :
    Ordered (setBucket buckets key (prefixPrune (buckets key) now)) := by
  intro k
  by_cases same : k=key
  · subst k
    simpa [setBucket] using prefix_prune_preserves_chronology _ (ordered key) now
  · simpa [setBucket,same] using ordered k

theorem prepare_preserves_order (caps : Nat → Nat) (now amount : Nat)
    (buckets : Buckets) (keys : List Nat) (ordered : Ordered buckets) :
    Ordered (prepare caps now amount buckets keys).1 := by
  induction keys generalizing buckets with
  | nil => exact ordered
  | cons key rest ih =>
    unfold prepare
    dsimp only
    split
    · exact ih _ (prune_one_preserves_order buckets key now ordered)
    · exact prune_one_preserves_order buckets key now ordered

theorem prepare_changes_no_live_observation (caps : Nat → Nat) (now amount : Nat)
    (buckets : Buckets) (keys : List Nat) (ordered : Ordered buckets) :
    observe (prepare caps now amount buckets keys).1 now=observe buckets now := by
  induction keys generalizing buckets with
  | nil => rfl
  | cons key rest ih =>
    unfold prepare
    dsimp only
    split
    · exact (ih _ (prune_one_preserves_order buckets key now ordered)).trans
        (prune_one_is_observationally_inert buckets key now ordered)
    · exact prune_one_is_observationally_inert buckets key now ordered

theorem prepare_agrees_with_all_live_cap_checks (caps : Nat → Nat) (now amount : Nat)
    (buckets : Buckets) (keys : List Nat) (ordered : Ordered buckets) :
    (prepare caps now amount buckets keys).2=
      keys.all (fun key => decide (used (prune (buckets key) now)+amount≤caps key)) := by
  induction keys generalizing buckets with
  | nil => rfl
  | cons key rest ih =>
    have observation := prune_one_is_observationally_inert buckets key now ordered
    have checks : rest.all (fun k => decide
        (used (prune (setBucket buckets key (prefixPrune (buckets key) now) k) now)+amount≤caps k))=
        rest.all (fun k => decide (used (prune (buckets k) now)+amount≤caps k)) := by
      have same := congrArg (fun observed : Buckets =>
        rest.all (fun k => decide (used (observed k)+amount≤caps k))) observation
      exact same
    simp only [prepare,List.all_cons]
    rw [show setBucket buckets key (prefixPrune (buckets key) now) key=
      prune (buckets key) now by simp [setBucket,prefix_prune_equals_live_filter _ (ordered key)]]
    split
    · rename_i allowed
      rw [ih _ (prune_one_preserves_order buckets key now ordered),checks]
      simp [allowed]
    · rename_i denied
      simp [denied]

/-- One debit per normalized key, in the oldest-first order used by VecDeque.
The caller's key normalization must exclude duplicates. -/
def debit (buckets : Buckets) (keys : List Nat) (now amount : Nat) : Buckets :=
  fun key => if key ∈ keys then buckets key ++ [(now,amount)] else buckets key

def nativeCharge (caps : Nat → Nat) (s : State) (request : Charge) : State × Bool :=
  let now := max s.highTime request.now
  let checked := prepare caps now request.amount s.buckets request.keys
  if checked.2 then
    (⟨debit checked.1 request.keys now request.amount,now⟩,true)
  else (⟨checked.1,now⟩,false)

/-- Projection discards only observationally expired storage, and reverses the
oldest-first native sequence to the newest-first abstract sequence. -/
def project (s : State) : State :=
  ⟨fun key => (prune (s.buckets key) s.highTime).reverse,s.highTime⟩

theorem abstract_clock_projection (s : State) (now : Nat) :
    pruned (project s) now=
      ⟨fun key => (prune (s.buckets key) (max s.highTime now)).reverse,
        max s.highTime now⟩ := by
  unfold pruned project
  congr 1
  funext key
  rw [reverse_live_filter,later_filter_subsumes_earlier _ _ _ (Nat.le_max_left _ _)]

/-- Universal accepted/denied and post-state observation correspondence. It
covers arbitrary key lists, including failure after earlier keys were pruned.
This is an algorithm-refinement theorem, not a proof of the Rust compiler. -/
theorem native_charge_refines_eager_settlement (caps : Nat → Nat) (s : State)
    (request : Charge) (ordered : Ordered s.buckets) :
    (project (nativeCharge caps s request).1,(nativeCharge caps s request).2)=
      charge caps (project s) request := by
  have prepared := prepare_changes_no_live_observation caps
    (max s.highTime request.now) request.amount s.buckets request.keys ordered
  have checks := prepare_agrees_with_all_live_cap_checks caps
    (max s.highTime request.now) request.amount s.buckets request.keys ordered
  unfold nativeCharge charge
  rw [abstract_clock_projection]
  dsimp only
  rw [checks]
  have reversedUsage (bucket : Bucket) : used bucket.reverse=used bucket := by
    simp [used,List.map_reverse,List.sum_reverse]
  simp only [reversedUsage]
  split
  · apply Prod.ext
    · unfold project
      dsimp only
      congr 1
      funext key
      have same := congrFun prepared key
      by_cases selected : key ∈ request.keys
      · simp only [debit,selected,↓reduceIte,prune,List.filter_append,
          List.filter_cons,Nat.sub_self] at *
        simpa [window,List.reverse_append,List.reverse_cons] using
          congrArg (fun b : Bucket => (b ++ [(max s.highTime request.now,request.amount)]).reverse) same
      · simpa [debit,selected] using congrArg List.reverse same
    · rfl
  · apply Prod.ext
    · unfold project
      dsimp only
      congr 1
      funext key
      exact congrArg List.reverse (congrFun prepared key)
    · rfl

def Entries (predicate : Nat × Nat → Prop) (buckets : Buckets) : Prop :=
  ∀ key entry, entry ∈ buckets key → predicate entry

theorem prefix_prune_only_removes_entries (b : Bucket) (now : Nat) :
    ∀ entry ∈ prefixPrune b now, entry ∈ b := by
  induction b with
  | nil => simp [prefixPrune]
  | cons head rest ih =>
    unfold prefixPrune
    split
    · intro entry member
      exact List.mem_cons_of_mem head (ih entry member)
    · exact fun _ member => member

theorem prepare_preserves_entries (predicate : Nat × Nat → Prop)
    (caps : Nat → Nat) (now amount : Nat) (buckets : Buckets) (keys : List Nat)
    (safe : Entries predicate buckets) :
    Entries predicate (prepare caps now amount buckets keys).1 := by
  induction keys generalizing buckets with
  | nil => exact safe
  | cons key rest ih =>
    have freshSafe : Entries predicate
        (setBucket buckets key (prefixPrune (buckets key) now)) := by
      intro k entry member
      by_cases same : k=key
      · subst k
        simp only [setBucket,↓reduceIte] at member
        exact safe key entry (prefix_prune_only_removes_entries _ _ entry member)
      · exact safe k entry (by simpa [setBucket,same] using member)
    unfold prepare
    dsimp only
    split
    · exact ih _ freshSafe
    · exact freshSafe

def WellFormed (s : State) : Prop :=
  Ordered s.buckets ∧ Entries (fun entry => entry.1≤s.highTime) s.buckets

theorem debit_preserves_chronology (buckets : Buckets) (keys : List Nat)
    (now amount : Nat) (ordered : Ordered buckets)
    (times : Entries (fun entry => entry.1≤now) buckets) :
    Ordered (debit buckets keys now amount) := by
  intro key
  by_cases selected : key ∈ keys
  · simp only [debit,selected,↓reduceIte,chronological,List.pairwise_append]
    refine ⟨ordered key,by simp,?_⟩
    intro a ha b hb
    have same : b=(now,amount) := by simpa using hb
    subst b
    exact times key a ha
  · simpa [debit,selected] using ordered key

theorem native_charge_preserves_well_formedness (caps : Nat → Nat) (s : State)
    (request : Charge) (valid : WellFormed s) :
    WellFormed (nativeCharge caps s request).1 := by
  have ordered := prepare_preserves_order caps (max s.highTime request.now)
    request.amount s.buckets request.keys valid.1
  have times := prepare_preserves_entries (fun entry => entry.1≤s.highTime)
    caps (max s.highTime request.now) request.amount s.buckets request.keys valid.2
  have freshTimes : Entries (fun entry => entry.1≤max s.highTime request.now)
      (prepare caps (max s.highTime request.now) request.amount s.buckets request.keys).1 := by
    intro key entry member
    exact (times key entry member).trans (Nat.le_max_left _ _)
  unfold nativeCharge
  dsimp only
  split
  · constructor
    · exact debit_preserves_chronology _ _ _ _ ordered freshTimes
    · intro key entry member
      by_cases selected : key ∈ request.keys
      · simp only [debit,selected,↓reduceIte,List.mem_append,List.mem_singleton] at member
        rcases member with old | rfl
        · exact freshTimes key entry old
        · exact Nat.le_refl _
      · exact freshTimes key entry (by simpa [debit,selected] using member)
  · exact ⟨ordered,freshTimes⟩

def nativeStep (caps : Nat → Nat) (s : State) (request : Charge) : Option State :=
  some (nativeCharge caps s request).1

theorem native_histories_well_formed (caps : Nat → Nat) (events : List Charge) :
    WellFormed (Enclave.Protocol.run (nativeStep caps) ⟨fun _ => [],0⟩ events) :=
  Enclave.Protocol.run_invariant (nativeStep caps) WellFormed
    (fun s request t hs ht => by
      cases ht
      exact native_charge_preserves_well_formedness caps s request hs)
    ⟨fun _ => [],0⟩ events (by simp [WellFormed,Ordered,chronological,Entries])

theorem arbitrary_native_history_refines_eager_history (caps : Nat → Nat)
    (s : State) (events : List Charge) (valid : WellFormed s) :
    project (Enclave.Protocol.run (nativeStep caps) s events)=
      Enclave.Protocol.run (step caps) (project s) events := by
  induction events generalizing s with
  | nil => rfl
  | cons request rest ih =>
    have agreement : project (nativeCharge caps s request).1=
        (charge caps (project s) request).1 := congrArg Prod.fst
      (native_charge_refines_eager_settlement caps s request valid.1)
    have tail := ih (nativeCharge caps s request).1
      (native_charge_preserves_well_formedness caps s request valid)
    rw [agreement] at tail
    simpa only [Enclave.Protocol.run,nativeStep,Option.getD_some,step] using tail

theorem arbitrary_native_history_live_usage_bounded (caps : Nat → Nat)
    (events : List Charge) (key : Nat) :
    let final := Enclave.Protocol.run (nativeStep caps) ⟨fun _ => [],0⟩ events
    used (prune (final.buckets key) final.highTime)≤caps key := by
  have simulation := arbitrary_native_history_refines_eager_history caps
    ⟨fun _ => [],0⟩ events (by simp [WellFormed,Ordered,chronological,Entries])
  have safety := arbitrary_rolling_history_bounded caps events key
  have empty : project ⟨fun _ => [],0⟩=⟨fun _ => [],0⟩ := rfl
  rw [empty] at simulation
  rw [← simulation] at safety
  simpa [project,used,List.map_reverse,List.sum_reverse] using safety

/-- Bounded nonnegative charges cannot wrap the actual 64-bit addition or set
its sign bit. Decoding the result as a signed integer gives the mathematical
sum. This is a bit-vector result, not merely equality between two casts. -/
theorem accepted_machine_addition_is_exact (used amount cap : Nat)
    (bounded : used+amount≤cap) (capBound : cap≤12000) :
    (used:Int)+(amount:Int)≤9223372036854775807 ∧
      (BitVec.ofNat 64 used+BitVec.ofNat 64 amount).toInt=(used:Int)+(amount:Int) := by
  have usedFits : used<2^64 := by norm_num; omega
  have amountFits : amount<2^64 := by norm_num; omega
  have sumFits : used+amount<2^64 := by norm_num; omega
  have unsigned : (BitVec.ofNat 64 used+BitVec.ofNat 64 amount).toNat=used+amount := by
    simp only [BitVec.toNat_add,BitVec.toNat_ofNat,Nat.mod_eq_of_lt usedFits,
      Nat.mod_eq_of_lt amountFits,Nat.mod_eq_of_lt sumFits]
  constructor
  · exact_mod_cast (show used+amount≤9223372036854775807 by omega)
  · have nonnegativeEncoding : 2*(used+amount)<2^64 := by norm_num; omega
    rw [BitVec.toInt_eq_toNat_cond,unsigned,if_pos nonnegativeEncoding]
    simp

end Enclave.RollingQifRefinement
