//! Field facts for `R_epoch`, with an independent irreducibility proof of the
//! quintic modulus `X^5 + X^2 - 1` over KoalaBear.

/// The KoalaBear prime.
pub const P: u64 = (1u64 << 31) - (1u64 << 24) + 1;
/// Extension degree.
pub const EXT_DEGREE: u32 = 5;

/// Size of the challenge field: `5 * log2(p)` bits, not proof-system security.
pub fn extension_bits() -> f64 {
    EXT_DEGREE as f64 * (P as f64).log2()
}

fn mulmod5(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
    let mut r = [0u128; 9];
    for i in 0..5 {
        for j in 0..5 {
            r[i + j] = (r[i + j] + a[i] as u128 * b[j] as u128) % P as u128;
        }
    }
    // X^5 = 1 - X^2.
    for d in (5..9).rev() {
        let c = r[d];
        if c != 0 {
            r[d] = 0;
            r[d - 5] = (r[d - 5] + c) % P as u128;
            r[d - 3] = (r[d - 3] + P as u128 - c) % P as u128;
        }
    }
    [
        r[0] as u64,
        r[1] as u64,
        r[2] as u64,
        r[3] as u64,
        r[4] as u64,
    ]
}

fn powmod5(mut b: [u64; 5], mut e: u64) -> [u64; 5] {
    let mut r = [1, 0, 0, 0, 0];
    while e > 0 {
        if e & 1 == 1 {
            r = mulmod5(&r, &b);
        }
        b = mulmod5(&b, &b);
        e >>= 1;
    }
    r
}

/// Irreducibility of `f = X^5 + X^2 - 1` over `F_p`, by a Rabin-style argument:
/// `X^{p^5} ≡ X (mod f)` holds iff every irreducible factor of `f` has degree
/// dividing 5 and `f` is squarefree (`X^{p^5} - X` is the squarefree product
/// of all monic irreducibles of degree 1 or 5). So `f` is either irreducible
/// or a product of five distinct linear factors; the latter is exactly the
/// case `X^p ≡ X (mod f)`. Hence `f` is irreducible ⇔
/// `X^{p^5} ≡ X ∧ X^p ≢ X (mod f)`.
pub fn quintic_is_irreducible() -> bool {
    let x = [0, 1, 0, 0, 0];
    let mut y = x;
    for _ in 0..5 {
        y = powmod5(y, P);
    }
    y == x && powmod5(x, P) != x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quintic_extension_is_a_field_with_154_9_bits() {
        assert!(quintic_is_irreducible());
        assert!(
            (extension_bits() - 154.9).abs() < 0.1,
            "{}",
            extension_bits()
        );
        // The quartic extension would give < 128 bits (rejected by FS-705).
        assert!(4.0 * (P as f64).log2() < 128.0);
    }
    #[test]
    fn engine_challenge_uses_the_independently_checked_modulus() {
        use crate::zk::engine::{Challenge, Val};
        use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
        assert_eq!(Val::ORDER_U32 as u64, P);
        assert_eq!(
            <Challenge as BasedVectorSpace<Val>>::DIMENSION,
            EXT_DEGREE as usize
        );
        let x =
            Challenge::from_basis_coefficients_fn(|i| if i == 1 { Val::ONE } else { Val::ZERO });
        assert_eq!(x.exp_u64(5) + x.square(), Challenge::ONE);
        for n in 1..20u64 {
            let a = [n, n + 1, n + 2, n + 3, n + 4];
            let b = [n + 5, n + 6, n + 7, n + 8, n + 9];
            let aa = Challenge::from_basis_coefficients_fn(|i| Val::from_u64(a[i]));
            let bb = Challenge::from_basis_coefficients_fn(|i| Val::from_u64(b[i]));
            let actual: Vec<u64> = (aa * bb)
                .as_basis_coefficients_slice()
                .iter()
                .map(|v: &Val| v.as_canonical_u32() as u64)
                .collect();
            assert_eq!(actual.as_slice(), mulmod5(&a, &b).as_slice());
        }
    }
}
