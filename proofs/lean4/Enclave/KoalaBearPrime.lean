import Mathlib.Data.ZMod.Basic
import Mathlib.NumberTheory.LucasPrimality

/-!
# Kernel-checked KoalaBear primality certificate

The pinned Mathlib `norm_num` prime extension builds a deeply nested trial-division
proof for this 31-bit prime and exceeds Lean 4.14's kernel recursion bound. This
Lucas certificate uses the complete factorization `P - 1 = 2^24 * 127` and witness
3. Every modular square/product is checked by ordinary kernel reduction (`decide`);
no native decision, primality assumption or increased recursion limit is used.
The named intermediate residues keep the certificate's proof depth bounded.
-/
namespace Enclave.KoalaBearPrime

theorem koalaBear_prime : Nat.Prime 2130706433 := by
  have h0 : (3 : ZMod 2130706433)^1 = 3 := by decide
  have h1 : (3 : ZMod 2130706433)^2 = 9 := by
    calc
      _ = ((3 : ZMod 2130706433)^1)^2 := by rw [← pow_mul]
      _ = 9 := by rw [h0]; decide
  have h2 : (3 : ZMod 2130706433)^4 = 81 := by
    calc
      _ = ((3 : ZMod 2130706433)^2)^2 := by rw [← pow_mul]
      _ = 81 := by rw [h1]; decide
  have h3 : (3 : ZMod 2130706433)^8 = 6561 := by
    calc
      _ = ((3 : ZMod 2130706433)^4)^2 := by rw [← pow_mul]
      _ = 6561 := by rw [h2]; decide
  have h4 : (3 : ZMod 2130706433)^16 = 43046721 := by
    calc
      _ = ((3 : ZMod 2130706433)^8)^2 := by rw [← pow_mul]
      _ = 43046721 := by rw [h3]; decide
  have h5 : (3 : ZMod 2130706433)^32 = 202438999 := by
    calc
      _ = ((3 : ZMod 2130706433)^16)^2 := by rw [← pow_mul]
      _ = 202438999 := by rw [h4]; decide
  have h6 : (3 : ZMod 2130706433)^64 = 1016389529 := by
    calc
      _ = ((3 : ZMod 2130706433)^32)^2 := by rw [← pow_mul]
      _ = 1016389529 := by rw [h5]; decide
  have h7 : (3 : ZMod 2130706433)^128 = 1112399510 := by
    calc
      _ = ((3 : ZMod 2130706433)^64)^2 := by rw [← pow_mul]
      _ = 1112399510 := by rw [h6]; decide
  have h8 : (3 : ZMod 2130706433)^256 = 925288330 := by
    calc
      _ = ((3 : ZMod 2130706433)^128)^2 := by rw [← pow_mul]
      _ = 925288330 := by rw [h7]; decide
  have h9 : (3 : ZMod 2130706433)^512 = 1368166559 := by
    calc
      _ = ((3 : ZMod 2130706433)^256)^2 := by rw [← pow_mul]
      _ = 1368166559 := by rw [h8]; decide
  have h10 : (3 : ZMod 2130706433)^1024 = 1178470116 := by
    calc
      _ = ((3 : ZMod 2130706433)^512)^2 := by rw [← pow_mul]
      _ = 1178470116 := by rw [h9]; decide
  have h11 : (3 : ZMod 2130706433)^2048 = 1220923943 := by
    calc
      _ = ((3 : ZMod 2130706433)^1024)^2 := by rw [← pow_mul]
      _ = 1220923943 := by rw [h10]; decide
  have h12 : (3 : ZMod 2130706433)^4096 = 1356258691 := by
    calc
      _ = ((3 : ZMod 2130706433)^2048)^2 := by rw [← pow_mul]
      _ = 1356258691 := by rw [h11]; decide
  have h13 : (3 : ZMod 2130706433)^8192 = 591038889 := by
    calc
      _ = ((3 : ZMod 2130706433)^4096)^2 := by rw [← pow_mul]
      _ = 591038889 := by rw [h12]; decide
  have h14 : (3 : ZMod 2130706433)^16384 = 919906353 := by
    calc
      _ = ((3 : ZMod 2130706433)^8192)^2 := by rw [← pow_mul]
      _ = 919906353 := by rw [h13]; decide
  have h15 : (3 : ZMod 2130706433)^32768 = 435958235 := by
    calc
      _ = ((3 : ZMod 2130706433)^16384)^2 := by rw [← pow_mul]
      _ = 435958235 := by rw [h14]; decide
  have h16 : (3 : ZMod 2130706433)^65536 = 2072804047 := by
    calc
      _ = ((3 : ZMod 2130706433)^32768)^2 := by rw [← pow_mul]
      _ = 2072804047 := by rw [h15]; decide
  have h17 : (3 : ZMod 2130706433)^131072 = 555809599 := by
    calc
      _ = ((3 : ZMod 2130706433)^65536)^2 := by rw [← pow_mul]
      _ = 555809599 := by rw [h16]; decide
  have h18 : (3 : ZMod 2130706433)^262144 = 749749968 := by
    calc
      _ = ((3 : ZMod 2130706433)^131072)^2 := by rw [← pow_mul]
      _ = 749749968 := by rw [h17]; decide
  have h19 : (3 : ZMod 2130706433)^524288 = 14471777 := by
    calc
      _ = ((3 : ZMod 2130706433)^262144)^2 := by rw [← pow_mul]
      _ = 14471777 := by rw [h18]; decide
  have h20 : (3 : ZMod 2130706433)^1048576 = 932825293 := by
    calc
      _ = ((3 : ZMod 2130706433)^524288)^2 := by rw [← pow_mul]
      _ = 932825293 := by rw [h19]; decide
  have h21 : (3 : ZMod 2130706433)^2097152 = 338912181 := by
    calc
      _ = ((3 : ZMod 2130706433)^1048576)^2 := by rw [← pow_mul]
      _ = 338912181 := by rw [h20]; decide
  have h22 : (3 : ZMod 2130706433)^4194304 = 297594125 := by
    calc
      _ = ((3 : ZMod 2130706433)^2097152)^2 := by rw [← pow_mul]
      _ = 297594125 := by rw [h21]; decide
  have h23 : (3 : ZMod 2130706433)^8388608 = 69130339 := by
    calc
      _ = ((3 : ZMod 2130706433)^4194304)^2 := by rw [← pow_mul]
      _ = 69130339 := by rw [h22]; decide
  have h24 : (3 : ZMod 2130706433)^16777216 = 1828256994 := by
    calc
      _ = ((3 : ZMod 2130706433)^8388608)^2 := by rw [← pow_mul]
      _ = 1828256994 := by rw [h23]; decide
  have h25 : (3 : ZMod 2130706433)^33554432 = 1982637648 := by
    calc
      _ = ((3 : ZMod 2130706433)^16777216)^2 := by rw [← pow_mul]
      _ = 1982637648 := by rw [h24]; decide
  have h26 : (3 : ZMod 2130706433)^67108864 = 1016433197 := by
    calc
      _ = ((3 : ZMod 2130706433)^33554432)^2 := by rw [← pow_mul]
      _ = 1016433197 := by rw [h25]; decide
  have h27 : (3 : ZMod 2130706433)^134217728 = 923786832 := by
    calc
      _ = ((3 : ZMod 2130706433)^67108864)^2 := by rw [← pow_mul]
      _ = 923786832 := by rw [h26]; decide
  have h28 : (3 : ZMod 2130706433)^268435456 = 1636791605 := by
    calc
      _ = ((3 : ZMod 2130706433)^134217728)^2 := by rw [← pow_mul]
      _ = 1636791605 := by rw [h27]; decide
  have h29 : (3 : ZMod 2130706433)^536870912 = 1441630889 := by
    calc
      _ = ((3 : ZMod 2130706433)^268435456)^2 := by rw [← pow_mul]
      _ = 1441630889 := by rw [h28]; decide
  have h30 : (3 : ZMod 2130706433)^1073741824 = 2061576094 := by
    calc
      _ = ((3 : ZMod 2130706433)^536870912)^2 := by rw [← pow_mul]
      _ = 2061576094 := by rw [h29]; decide
  have full0 : (3 : ZMod 2130706433)^50331648 = 1044068769 := by
    calc
      _ = (3 : ZMod 2130706433)^16777216 * (3 : ZMod 2130706433)^33554432 := by rw [← pow_add]
      _ = 1044068769 := by rw [h24, h25]; decide
  have full1 : (3 : ZMod 2130706433)^117440512 = 1434391678 := by
    calc
      _ = (3 : ZMod 2130706433)^50331648 * (3 : ZMod 2130706433)^67108864 := by rw [← pow_add]
      _ = 1434391678 := by rw [full0, h26]; decide
  have full2 : (3 : ZMod 2130706433)^251658240 = 1758221443 := by
    calc
      _ = (3 : ZMod 2130706433)^117440512 * (3 : ZMod 2130706433)^134217728 := by rw [← pow_add]
      _ = 1758221443 := by rw [full1, h27]; decide
  have full3 : (3 : ZMod 2130706433)^520093696 = 26808122 := by
    calc
      _ = (3 : ZMod 2130706433)^251658240 * (3 : ZMod 2130706433)^268435456 := by rw [← pow_add]
      _ = 26808122 := by rw [full2, h28]; decide
  have full4 : (3 : ZMod 2130706433)^1056964608 = 819825795 := by
    calc
      _ = (3 : ZMod 2130706433)^520093696 * (3 : ZMod 2130706433)^536870912 := by rw [← pow_add]
      _ = 819825795 := by rw [full3, h29]; decide
  have full5 : (3 : ZMod 2130706433)^2130706432 = 1 := by
    calc
      _ = (3 : ZMod 2130706433)^1056964608 * (3 : ZMod 2130706433)^1073741824 := by rw [← pow_add]
      _ = 1 := by rw [full4, h30]; decide
  have half0 : (3 : ZMod 2130706433)^25165824 = 345726642 := by
    calc
      _ = (3 : ZMod 2130706433)^8388608 * (3 : ZMod 2130706433)^16777216 := by rw [← pow_add]
      _ = 345726642 := by rw [h23, h24]; decide
  have half1 : (3 : ZMod 2130706433)^58720256 = 1935687324 := by
    calc
      _ = (3 : ZMod 2130706433)^25165824 * (3 : ZMod 2130706433)^33554432 := by rw [← pow_add]
      _ = 1935687324 := by rw [half0, h25]; decide
  have half2 : (3 : ZMod 2130706433)^125829120 = 1483545991 := by
    calc
      _ = (3 : ZMod 2130706433)^58720256 * (3 : ZMod 2130706433)^67108864 := by rw [← pow_add]
      _ = 1483545991 := by rw [half1, h26]; decide
  have half3 : (3 : ZMod 2130706433)^260046848 = 1883686423 := by
    calc
      _ = (3 : ZMod 2130706433)^125829120 * (3 : ZMod 2130706433)^134217728 := by rw [← pow_add]
      _ = 1883686423 := by rw [half2, h27]; decide
  have half4 : (3 : ZMod 2130706433)^528482304 = 197692886 := by
    calc
      _ = (3 : ZMod 2130706433)^260046848 * (3 : ZMod 2130706433)^268435456 := by rw [← pow_add]
      _ = 197692886 := by rw [half3, h28]; decide
  have half5 : (3 : ZMod 2130706433)^1065353216 = 2130706432 := by
    calc
      _ = (3 : ZMod 2130706433)^528482304 * (3 : ZMod 2130706433)^536870912 := by rw [← pow_add]
      _ = 2130706432 := by rw [half4, h29]; decide
  apply lucas_primality 2130706433 (3 : ZMod 2130706433) full5
  intro q hq hd
  have factors : q = 2 ∨ q = 127 := by
    have h : q ∣ 2^24 * 127 := by simpa only [show 2130706433-1 = 2^24*127 by decide] using hd
    rcases hq.dvd_mul.mp h with h | h
    · exact Or.inl ((Nat.prime_dvd_prime_iff_eq hq Nat.prime_two).mp (hq.dvd_of_dvd_pow h))
    · exact Or.inr ((Nat.prime_dvd_prime_iff_eq hq (by decide : Nat.Prime 127)).mp h)
  rcases factors with rfl | rfl
  · simpa only [show (2130706433-1)/2 = 1065353216 by decide, half5] using (by decide : (2130706432 : ZMod 2130706433) ≠ 1)
  · simpa only [show (2130706433-1)/127 = 16777216 by decide, h24] using (by decide : (1828256994 : ZMod 2130706433) ≠ 1)

end Enclave.KoalaBearPrime
