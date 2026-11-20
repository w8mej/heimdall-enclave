import Enclave.EpochAirCorrespondence
import Mathlib.Data.Finset.Max

/-! Slot coverage derived from the actual extracted AIR constraints. Active
rows form one nonempty prefix and their sequence column equals their position
in the prime field. A native trace-height bound prevents modular wrap when
lifting that sequence to natural slot offsets. Auxiliary AIR relations remain
outside this accounting theorem. -/
namespace Enclave.EpochAirSlotCoverage

open Enclave.FieldRangeProofs Enclave.EpochAirCorrespondence
open Enclave.EpochAirExtracted (c3 c5 c6 c52 c53 c54 c57 c58 c59 c61)

/-- `make_public_values` reduces both u32 limbs into KoalaBear. The radix
2^32 reduces to 33554430, exactly the constant in extracted polynomial 52. -/
theorem two_limb_encoding_reconstructs_absolute_sequence (sequence : Nat) :
    ((sequence%4294967296:Nat):F)+33554430*((sequence/4294967296:Nat):F)=(sequence:F) := by
  have radix : (4294967296:F)=33554430 := by
    apply ZMod.val_injective P
    change 4294967296 % P=33554430 % P
    norm_num [P]
  have reconstruction := congrArg (fun n : Nat => (n:F)) (Nat.mod_add_div sequence 4294967296)
  simpa only [Nat.cast_add,Nat.cast_mul,radix] using reconstruction

theorem encoded_absolute_endpoints_satisfy_actual_span_constraint
    (e : Enclave.EpochAirExtracted.Env) (start finish : Nat) (ordered : start≤finish)
    (startLow : e.public 52=((start%4294967296:Nat):F))
    (startHigh : e.public 53=((start/4294967296:Nat):F))
    (endLow : e.public 54=((finish%4294967296:Nat):F))
    (endHigh : e.public 55=((finish/4294967296:Nat):F))
    (span : e.public 0=((finish-start:Nat):F)) : c52 e=0 := by
  rw [c52,startLow,startHigh,endLow,endHigh,span,Nat.cast_sub ordered]
  have difference :
      ((finish%4294967296:Nat):F)-((start%4294967296:Nat):F)+
        33554430*(((finish/4294967296:Nat):F)-((start/4294967296:Nat):F))=
        (finish:F)-(start:F) := by
    calc
      _ = (((finish%4294967296:Nat):F)+33554430*((finish/4294967296:Nat):F))-
          (((start%4294967296:Nat):F)+33554430*((start/4294967296:Nat):F)) := by ring
      _ = _ := by rw [two_limb_encoding_reconstructs_absolute_sequence,
        two_limb_encoding_reconstructs_absolute_sequence]
  exact sub_eq_zero.mpr difference

theorem actual_active_row_has_exactly_one_slot_kind (rows : Nat → Nat → F)
    (public : Nat → F) (last i : Nat) (valid : ValidTrace rows public last)
    (inTrace : i≤last) (active : rows i 0=1) :
    (rows i 2=1 ∧ rows i 3=0) ∨ (rows i 2=0 ∧ rows i 3=1) := by
  have current := valid i inTrace
  have foldBit := field_boolean_is_bit (rows i 2) (by
    simpa only [Enclave.EpochAirExtracted.constraint,Enclave.EpochAirExtracted.c1,
      rowEnv,Nat.add_zero] using current ⟨1,by decide⟩)
  have tombBit := field_boolean_is_bit (rows i 3) (by
    simpa only [Enclave.EpochAirExtracted.constraint,Enclave.EpochAirExtracted.c2,
      rowEnv,Nat.add_zero] using current ⟨2,by decide⟩)
  have equation := current ⟨3,by decide⟩
  change c3 (rowEnv rows public last i)=0 at equation
  simp only [c3,rowEnv,Nat.add_zero,active,one_mul,sub_eq_zero] at equation
  rcases foldBit with zero | one <;> rcases tombBit with zeroT | oneT <;> simp_all

theorem actual_tombstones_have_zero_charge (rows : Nat → Nat → F)
    (public : Nat → F) (last i : Nat) (valid : ValidTrace rows public last)
    (inTrace : i≤last) (tombstone : rows i 3=1) : rows i 4=0 := by
  have equation := valid i inTrace ⟨5,by decide⟩
  change c5 (rowEnv rows public last i)=0 at equation
  simpa only [c5,rowEnv,Nat.add_zero,tombstone,one_mul] using equation

theorem actual_padding_has_zero_charge (rows : Nat → Nat → F)
    (public : Nat → F) (last i : Nat) (valid : ValidTrace rows public last)
    (inTrace : i≤last) (padding : rows i 0=0) : rows i 4=0 := by
  have equation := valid i inTrace ⟨6,by decide⟩
  change c6 (rowEnv rows public last i)=0 at equation
  simpa only [c6,rowEnv,Nat.add_zero,padding,sub_zero,one_mul] using equation

theorem actual_active_is_boolean (rows : Nat → Nat → F) (public : Nat → F)
    (last i : Nat) (valid : ValidTrace rows public last) (inTrace : i≤last) :
    rows i 0=0 ∨ rows i 0=1 := by
  apply field_boolean_is_bit
  exact valid i inTrace ⟨0,by decide⟩

theorem actual_first_row_is_active (rows : Nat → Nat → F) (public : Nat → F)
    (last : Nat) (valid : ValidTrace rows public last) : rows 0 0=1 := by
  have equation := valid 0 (Nat.zero_le _) ⟨53,by decide⟩
  change c53 (rowEnv rows public last 0)=0 at equation
  simpa [c53,rowEnv,sub_eq_zero] using equation

theorem actual_active_next_requires_active_current (rows : Nat → Nat → F)
    (public : Nat → F) (last i : Nat) (valid : ValidTrace rows public last)
    (transition : i<last) (nextActive : rows (i+1) 0=1) : rows i 0=1 := by
  have equation := valid i (by omega) ⟨58,by decide⟩
  change c58 (rowEnv rows public last i)=0 at equation
  simp only [c58,rowEnv,transition,↓reduceIte,one_mul,Nat.add_zero,nextActive] at equation
  exact (sub_eq_zero.mp equation).symm

theorem actual_active_rows_have_position_sequence (rows : Nat → Nat → F)
    (public : Nat → F) (last i : Nat) (valid : ValidTrace rows public last)
    (inTrace : i≤last) (active : rows i 0=1) : rows i 1=(i:F) := by
  induction i with
  | zero =>
    have equation := valid 0 (Nat.zero_le _) ⟨54,by decide⟩
    change c54 (rowEnv rows public last 0)=0 at equation
    simpa [c54,rowEnv] using equation
  | succ i ih =>
    have previous := actual_active_next_requires_active_current rows public last i valid (by omega) active
    have previousSeq := ih (by omega) previous
    have equation := valid i (by omega) ⟨59,by decide⟩
    change c59 (rowEnv rows public last i)=0 at equation
    simp only [c59,rowEnv,show i<last by omega,↓reduceIte,one_mul,Nat.add_zero,
      active,previousSeq] at equation
    have linear := sub_eq_zero.mp equation
    rw [sub_eq_iff_eq_add] at linear
    simpa [Nat.cast_add,Nat.cast_one,add_comm] using linear

theorem actual_active_prefix (rows : Nat → Nat → F) (public : Nat → F)
    (last endRow : Nat) (valid : ValidTrace rows public last) (endInTrace : endRow≤last)
    (endActive : rows endRow 0=1) (i : Nat) (beforeEnd : i≤endRow) : rows i 0=1 := by
  induction endRow with
  | zero =>
    have same : i=0 := by omega
    simpa [same] using endActive
  | succ endRow ih =>
    by_cases same : i=endRow+1
    · simpa [same] using endActive
    · exact ih (by omega)
        (actual_active_next_requires_active_current rows public last endRow valid (by omega) endActive)
        (by omega)

theorem actual_last_active_sequence_is_public_span (rows : Nat → Nat → F)
    (public : Nat → F) (last endRow : Nat) (valid : ValidTrace rows public last)
    (inTrace : endRow≤last) (active : rows endRow 0=1)
    (finalActive : ∀ j, endRow<j → j≤last → rows j 0≠1) : rows endRow 1=public 0 := by
  by_cases lastRow : endRow=last
  · subst endRow
    have equation := valid last (Nat.le_refl _) ⟨57,by decide⟩
    change c57 (rowEnv rows public last last)=0 at equation
    simpa [c57,rowEnv,active,sub_eq_zero] using equation
  · have transition : endRow<last := by omega
    have nextZero : rows (endRow+1) 0=0 := by
      rcases actual_active_is_boolean rows public last (endRow+1) valid (by omega) with zero | one
      · exact zero
      · exact False.elim (finalActive (endRow+1) (by omega) (by omega) one)
    have equation := valid endRow (by omega) ⟨61,by decide⟩
    change c61 (rowEnv rows public last endRow)=0 at equation
    simpa [c61,rowEnv,transition,active,nextZero,sub_eq_zero] using equation

theorem actual_trace_covers_every_public_slot_exactly_once (rows : Nat → Nat → F)
    (public : Nat → F) (last : Nat) (valid : ValidTrace rows public last)
    (heightBelowPrime : last<P) :
    (public 0).val≤last ∧
    (∀ i≤last, rows i 0=1 ↔ i≤(public 0).val) ∧
    (∀ i≤last, rows i 0=1 → (rows i 1).val=i) := by
  let activeRows := (Finset.range (last+1)).filter (fun i => rows i 0=1)
  have nonempty : activeRows.Nonempty := by
    refine ⟨0,?_⟩
    simp only [activeRows,Finset.mem_filter,Finset.mem_range]
    exact ⟨by omega,actual_first_row_is_active rows public last valid⟩
  let endRow := activeRows.max' nonempty
  have endMember := Finset.max'_mem activeRows nonempty
  have endFacts : endRow≤last ∧ rows endRow 0=1 := by
    change endRow∈activeRows at endMember
    simpa only [activeRows,Finset.mem_filter,Finset.mem_range,Nat.lt_succ_iff] using endMember
  have maximal : ∀ j, endRow<j → j≤last → rows j 0≠1 := by
    intro j later inTrace active
    have member : j∈activeRows := by simp [activeRows,show j<last+1 by omega,active]
    have bound := Finset.le_max' activeRows j member
    change j≤endRow at bound
    omega
  have sequence := actual_active_rows_have_position_sequence rows public last endRow valid endFacts.1 endFacts.2
  have span := actual_last_active_sequence_is_public_span rows public last endRow valid endFacts.1 endFacts.2 maximal
  have naturalEnd : endRow=(public 0).val := by
    have equality := congrArg ZMod.val (sequence.symm.trans span)
    simpa [ZMod.val_natCast_of_lt (show endRow<P by omega)] using equality
  refine ⟨by omega,?_,?_⟩
  · intro i inTrace
    constructor
    · intro active
      by_contra after
      exact maximal i (by omega) inTrace active
    · intro before
      exact actual_active_prefix rows public last endRow valid endFacts.1 endFacts.2 i (by omega)
  · intro i inTrace active
    have sequence := actual_active_rows_have_position_sequence rows public last i valid inTrace active
    exact sequence ▸ ZMod.val_natCast_of_lt (show i<P by omega)

/-- Existence and uniqueness are consequences of the actual constraints, rather
than hypotheses supplied by a caller. Padding rows cannot witness a slot. -/
theorem every_public_offset_has_exactly_one_active_row (rows : Nat → Nat → F)
    (public : Nat → F) (last : Nat) (valid : ValidTrace rows public last)
    (heightBelowPrime : last<P) (offset : Nat) (inSpan : offset≤(public 0).val) :
    ∃! i, i≤last ∧ rows i 0=1 ∧ (rows i 1).val=offset := by
  obtain ⟨spanBound,activePrefix,sequence⟩ :=
    actual_trace_covers_every_public_slot_exactly_once rows public last valid heightBelowPrime
  have inTrace : offset≤last := by omega
  have active := (activePrefix offset inTrace).2 inSpan
  refine ⟨offset,⟨inTrace,active,sequence offset inTrace active⟩,?_⟩
  intro i facts
  have position := sequence i facts.1 facts.2.1
  exact position.symm.trans facts.2.2

theorem active_sequence_values_are_injective (rows : Nat → Nat → F)
    (public : Nat → F) (last : Nat) (valid : ValidTrace rows public last)
    (heightBelowPrime : last<P) (i j : Nat) (hi : i≤last) (hj : j≤last)
    (ai : rows i 0=1) (aj : rows j 0=1) (sameSequence : rows i 1=rows j 1) : i=j := by
  have coverage := actual_trace_covers_every_public_slot_exactly_once rows public last valid heightBelowPrime
  have same := congrArg ZMod.val sameSequence
  rwa [coverage.2.2 i hi ai,coverage.2.2 j hj aj] at same

theorem padding_preserves_final_active_budget (rows : Nat → Nat → F)
    (public : Nat → F) (last : Nat) (valid : ValidTrace rows public last)
    (heightBelowPrime : last<P) (i : Nat) (inTrace : i≤last)
    (afterActivePrefix : (public 0).val ≤ i) :
    (rows i 5).val=(rows ((public 0).val) 5).val := by
  have coverage := actual_trace_covers_every_public_slot_exactly_once rows public last valid heightBelowPrime
  induction i with
  | zero =>
    have spanZero : (public 0).val=0 := by omega
    rw [spanZero]
  | succ i ih =>
    by_cases atEnd : i+1=(public 0).val
    · rw [atEnd]
    · have earlier : (public 0).val ≤ i := by omega
      have padding : rows (i+1) 0=0 := by
        rcases actual_active_is_boolean rows public last (i+1) valid inTrace with zero | active
        · exact zero
        · have inside := (coverage.2.1 (i+1) inTrace).1 active
          omega
      have noCharge := actual_padding_has_zero_charge rows public last (i+1) valid inTrace padding
      have accounting := actual_transition_integer_accounting rows public last i valid (by omega)
      rw [noCharge] at accounting
      simpa only [ZMod.val_zero,Nat.add_zero,ih (by omega) earlier] using accounting

/-- Padding contributes no charge, so the integer accounting sum ranges over
exactly the public slots, rather than the potentially longer padded trace. -/
theorem actual_epoch_accounts_exactly_the_public_slots (rows : Nat → Nat → F)
    (public : Nat → F) (last : Nat) (valid : ValidTrace rows public last)
    (heightBelowPrime : last<P) (inputRange : (public 2).val<16384) :
    (public 3).val=(public 2).val+
      ((List.range ((public 0).val+1)).map (fun i => (rows i 4).val)).sum ∧
      (public 3).val≤(public 1).val := by
  have coverage := actual_trace_covers_every_public_slot_exactly_once rows public last valid heightBelowPrime
  have accounting := actual_trace_integer_sum rows public last valid inputRange (public 0).val coverage.1
  have padding := padding_preserves_final_active_budget rows public last valid heightBelowPrime last
    (Nat.le_refl _) coverage.1
  have final := valid last (Nat.le_refl _) ⟨56,by decide⟩
  change Enclave.EpochAirExtracted.c56 (rowEnv rows public last last)=0 at final
  have output : rows last 5=public 3 := by
    simpa [Enclave.EpochAirExtracted.c56,rowEnv,sub_eq_zero] using final
  rw [output] at padding
  exact ⟨padding.trans accounting,
    (actual_epoch_full_integer_accounting rows public last valid inputRange).2⟩

/-- Plonky3 0.8 bounds the committed degree by KoalaBear's two-adicity (24).
The hiding configuration removes one degree bit for the base row domain, so
this bound also conservatively covers its selector domain. -/
theorem supported_degree_prevents_sequence_wrap (degreeBits last : Nat)
    (supported : degreeBits≤24) (traceHeight : last<2^degreeBits) : last<P := by
  have width := pow_le_pow_right₀ (by decide : (1:Nat)≤2) supported
  norm_num at width
  unfold P
  omega

/-- Native statement checks bound the absolute span and encode it as public
value 0. Combining that encoding with the actual constraints covers the entire
absolute interval, including intervals crossing either u32 limb boundary. -/
theorem native_bounded_trace_covers_absolute_interval
    (rows : Nat → Nat → F) (public : Nat → F) (last degreeBits start finish : Nat)
    (valid : ValidTrace rows public last) (degreeSupported : degreeBits≤24)
    (traceHeight : last<2^degreeBits) (ordered : start≤finish)
    (spanBound : finish-start<1048576) (encodedSpan : public 0=((finish-start:Nat):F))
    (sequence : Nat) (afterStart : start≤sequence) (beforeFinish : sequence≤finish) :
    ∃! i, i≤last ∧ rows i 0=1 ∧ start+(rows i 1).val=sequence := by
  have spanBelowPrime : finish-start<P := by unfold P; omega
  have spanValue : (public 0).val=finish-start := by
    rw [encodedSpan,ZMod.val_natCast_of_lt spanBelowPrime]
  have offsetBound : sequence-start≤(public 0).val := by rw [spanValue]; omega
  obtain ⟨i,facts,unique⟩ := every_public_offset_has_exactly_one_active_row rows public last valid
    (supported_degree_prevents_sequence_wrap degreeBits last degreeSupported traceHeight)
    (sequence-start) offsetBound
  refine ⟨i,⟨facts.1,facts.2.1,by omega⟩,?_⟩
  intro j other
  exact unique j ⟨other.1,other.2.1,by omega⟩

end Enclave.EpochAirSlotCoverage
