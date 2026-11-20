import Enclave.BibaNoninterference
import Enclave.QifBound
import Enclave.ProbabilisticQif

namespace Enclave.AssuranceModelTest

def heapA : CapHeap :=
  ⟨fun h => if h == 17 then [1] else [3],
   fun h => ⟨.C3, if h == 99 then .T3 else .T1⟩⟩
def heapB : CapHeap :=
  ⟨fun h => if h == 17 then [1] else [4], heapA.label⟩
def heapChangedTrusted : CapHeap := ⟨fun _ => [2], heapA.label⟩
def trustedCall : StructuralDataCall := ⟨.HeapRef 17, [.Concat (.HeapRef 17) (.Const [7])]⟩
def untrustedCall : StructuralDataCall := ⟨.HeapRef 99, []⟩

theorem trusted_structure_admitted : checkStructuralCalls heapA [trustedCall] = true := by decide
theorem untrusted_structure_rejected : checkStructuralCalls heapA [untrustedCall] = false := by decide
theorem untrusted_payload_change_preserves_trace :
    evaluatedStructuralTrace heapA [trustedCall] = evaluatedStructuralTrace heapB [trustedCall] := by decide
theorem trusted_payload_changes_trace :
    evaluatedStructuralTrace heapA [trustedCall] ≠ evaluatedStructuralTrace heapChangedTrusted [trustedCall] := by decide

theorem twelve_bits_has_4096_transcripts : (chargedTranscripts [4, 4, 4]).length = 4096 := by
  rw [entropy_bounded]
  decide

theorem zero_cost_deterministic_queries : (chargedTranscripts [0, 0]).length = 1 := by decide

theorem thirteen_bits_not_admitted : ¬ValidChargedChannel [13] := by
  intro h
  have hb := h.budget_bounded
  simp [chargedMillibits, totalChargedBits, QIF_CAP_MB] at hb

def weightedRows : List (WeightedObservation 4) :=
  [⟨⟨0, by decide⟩, 50⟩, ⟨⟨1, by decide⟩, 40⟩,
   ⟨⟨2, by decide⟩, 60⟩, ⟨⟨3, by decide⟩, 30⟩]

theorem computed_prior_is_actual_maximum : priorMass weightedRows = 60 := by decide
theorem computed_posterior_uses_table :
    posteriorVulnerability (channelOfRows 4 weightedRows (by decide)) = 180 := by decide

end Enclave.AssuranceModelTest
