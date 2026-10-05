//! Minimal 256-bit unsigned integer, big-endian byte order.
//!
//! Only what consensus needs: `floor((2^256 - 1) / d)` and comparison against a
//! target. Integer only — SPEC.md forbids floating point in consensus.

use crate::error::{Error, Result};

/// Difficulty ceiling. Keeps the long-division remainder `rem < d <= 2^96`, so
/// `rem * 2 + 1` cannot overflow a 128-bit accumulator in any implementation.
pub const MAX_DIFFICULTY: u128 = 1u128 << 96;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct U256(pub [u8; 32]); // big-endian

impl U256 {
    pub const MAX: U256 = U256([0xff; 32]);
    pub const ZERO: U256 = U256([0u8; 32]);

    pub fn from_u128_be(v: u128) -> U256 {
        let mut b = [0u8; 32];
        b[16..].copy_from_slice(&v.to_be_bytes());
        U256(b)
    }

    pub fn from_be_bytes(b: [u8; 32]) -> U256 {
        U256(b)
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }

    /// Exact `floor((2^256 - 1) / d)` by 256-step binary long division.
    ///
    /// Invariant: before each step `rem < d`, so `rem * 2 + 1` stays well
    /// inside `u128` because `d <= MAX_DIFFICULTY = 2^96`.
    pub fn max_div_u128(d: u128) -> Result<U256> {
        if d == 0 {
            return Err(Error::InvalidDifficulty(0));
        }
        if d > MAX_DIFFICULTY {
            return Err(Error::TargetOverflow(d));
        }
        let mut rem: u128 = 0;
        let mut q = [0u8; 32];
        // Dividend is 2^256 - 1: every bit is 1, MSB (bit 255) first.
        for bit in (0..256).rev() {
            rem = rem * 2 + 1;
            let qb = if rem >= d {
                rem -= d;
                1u8
            } else {
                0u8
            };
            if qb == 1 {
                q[31 - bit / 8] |= 1u8 << (bit % 8);
            }
        }
        Ok(U256(q))
    }

    /// Lossy for large values; display/debugging only.
    pub fn saturating_as_u128(&self) -> u128 {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&self.0[16..]);
        u128::from_be_bytes(buf)
    }
}

/// `target(d) = floor((2^256 - 1) / d)` — SPEC.md §4.
pub fn target_for_difficulty(d: u128) -> Result<U256> {
    U256::max_div_u128(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Schoolbook 256x128 multiply, little-endian 64-bit limbs.
    /// Returns 6 limbs; limbs 4 and 5 carry anything past 2^256.
    fn mul_256x128(q: [u64; 4], d: u128) -> [u64; 6] {
        let d = [d as u64, (d >> 64) as u64];
        let mut res = [0u64; 6];
        for i in 0..4 {
            let mut carry: u128 = 0;
            for j in 0..2 {
                let t = (q[i] as u128) * (d[j] as u128) + (res[i + j] as u128) + carry;
                res[i + j] = t as u64;
                carry = t >> 64;
            }
            // res[i+2] is still zero when iteration i begins.
            res[i + 2] = carry as u64;
        }
        res
    }

    fn to_limbs(v: &U256) -> [u64; 4] {
        let mut l = [0u64; 4];
        for i in 0..4 {
            let mut w = [0u8; 8];
            w.copy_from_slice(&v.0[i * 8..(i + 1) * 8]);
            l[3 - i] = u64::from_be_bytes(w);
        }
        l
    }

    fn max_limbs() -> [u64; 4] {
        [u64::MAX; 4]
    }

    #[test]
    fn difficulty_one_gives_max_target() {
        assert_eq!(target_for_difficulty(1).unwrap(), U256::MAX);
    }

    #[test]
    fn difficulty_two_halves_exactly() {
        let t = target_for_difficulty(2).unwrap();
        // (2^256 - 1) / 2 == 2^255 - 1, because 2^256 - 1 is odd.
        let mut expect = [0xffu8; 32];
        expect[0] = 0x7f;
        assert_eq!(t, U256(expect));
    }

    /// q = floor((2^256-1)/d) must satisfy q*d <= 2^256-1 < (q+1)*d.
    #[test]
    fn quotient_is_exact_floor() {
        for d in [
            1u128,
            2,
            3,
            7,
            10,
            999,
            1_000_000,
            1 << 40,
            1 << 64,
            (1 << 64) + 1,
            1 << 80,
            MAX_DIFFICULTY,
        ] {
            let q = U256::max_div_u128(d).unwrap();

            let prod = mul_256x128(to_limbs(&q), d);
            assert_eq!((prod[4], prod[5]), (0, 0), "q*d overflowed 2^256 for d={d}");
            assert!(
                prod[..4] <= max_limbs()[..],
                "q*d must fit in 2^256-1 for d={d}"
            );
            if q == U256::MAX {
                // (q+1) wraps; (2^256)*d > 2^256-1 holds by construction.
                continue;
            }

            let mut l = to_limbs(&q);
            let mut carry: u128 = 1;
            for limb in l.iter_mut() {
                let t = *limb as u128 + carry;
                *limb = t as u64;
                carry = t >> 64;
                if carry == 0 {
                    break;
                }
            }
            let prod2 = mul_256x128(l, d);
            let over = prod2[4] > 0 || prod2[..4] > max_limbs()[..];
            assert!(over, "(q+1)*d must exceed 2^256-1 for d={d}");
        }
    }

    #[test]
    fn target_is_monotonic_decreasing() {
        let mut prev = target_for_difficulty(1).unwrap();
        assert_eq!(prev, U256::MAX);
        for d in [2u128, 10, 1000, 100_000, 1 << 40, 1 << 80] {
            let t = target_for_difficulty(d).unwrap();
            assert!(t < prev, "target must shrink as difficulty grows (d={d})");
            prev = t;
        }
    }

    #[test]
    fn rejects_out_of_range_difficulty() {
        assert!(matches!(
            target_for_difficulty(0),
            Err(Error::InvalidDifficulty(0))
        ));
        assert!(matches!(
            target_for_difficulty(MAX_DIFFICULTY + 1),
            Err(Error::TargetOverflow(_))
        ));
    }

    /// target(2^k) == 2^(256-k) - 1, i.e. exactly k leading zero bits.
    #[test]
    fn power_of_two_difficulty_gives_exact_leading_zero_bits() {
        for k in 1..=32u32 {
            let d = 1u128 << k;
            let t = target_for_difficulty(d).unwrap();
            let full_zero_bytes = (k / 8) as usize;
            let partial = (k % 8) as u8;
            let mut expect = [0u8; 32];
            for b in expect.iter_mut().skip(full_zero_bytes) {
                *b = 0xff;
            }
            if partial != 0 {
                expect[full_zero_bytes] = 0xffu8 >> partial;
            }
            assert_eq!(t, U256(expect), "k={k}");
        }
    }
}
