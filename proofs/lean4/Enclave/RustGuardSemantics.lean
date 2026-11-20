import Enclave.TransportStartup
import Lean.Elab.Tactic.Omega

/-! Semantics of the deliberately small extracted guard fragment. Lengths are
mathematical naturals; Rust inputs inhabit their native machine ranges. This is
not a Rust frontend or a semantics for allocation, cryptography, I/O or panics.
The source checker discloses its trusted translation and primitive boundaries. -/
namespace Enclave.RustGuardSemantics

abbrev Profile := Enclave.TransportStartup.Profile

structure Failure where
  errno : String
  reason : String
  deriving DecidableEq, Repr

def usize64 (n : Int) : Nat := (n % (18446744073709551616 : Int)).toNat

theorem positive_c_int_cast_exact (n : Int) (positive : 0 < n)
    (bounded : n ≤ 2147483647) : usize64 n = n.toNat := by
  unfold usize64
  rw [Int.emod_eq_of_lt (by omega) (by omega)]

def checked64 (a b : Nat) : Option Nat :=
  if a + b ≤ 18446744073709551615 then some (a + b) else none

def asciiAlphanumeric (b : UInt8) : Bool :=
  decide (48 ≤ b.toNat ∧ b.toNat ≤ 57 ∨ 65 ≤ b.toNat ∧ b.toNat ≤ 90 ∨
    97 ≤ b.toNat ∧ b.toNat ≤ 122)

def asciiDigit (b : UInt8) : Bool := decide (48 ≤ b.toNat ∧ b.toNat ≤ 57)

end Enclave.RustGuardSemantics
