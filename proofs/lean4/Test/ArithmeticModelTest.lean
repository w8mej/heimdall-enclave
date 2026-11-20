import Enclave.AuditChain
import Enclave.BaoStreamVerification
import Enclave.DpopBinding

namespace Enclave.ArithmeticModelTest

-- Changing two coordinates defeats the linear code despite coordinate injectivity.
theorem entry_linear_collision : linearEntryCode 7 0 0 false = linearEntryCode 0 0 31 false := by decide

def streamA : List BaoChunk := [⟨0, 10007⟩, ⟨1, 0⟩]
def streamB : List BaoChunk := [⟨0, 0⟩, ⟨1, 1⟩]

theorem different_streams_same_linear_root :
    streamA ≠ streamB ∧ linearChunkCode streamA = linearChunkCode streamB := by decide

theorem both_colliding_streams_pass_model_check :
    verifyBaoStream 10007 2 streamA = true ∧ verifyBaoStream 10007 2 streamB = true := by decide

theorem parent_linear_collision : linearParentCode 10007 0 = linearParentCode 0 31 := by decide

theorem token_prefix_contains_raw_token : modelTokenPrefix "secret" = "sha256:secret" := by rfl

end Enclave.ArithmeticModelTest
