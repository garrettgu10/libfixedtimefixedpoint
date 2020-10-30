#include "ftfp.h"
#include "internal.h"

FIX_INLINE int8_t fix_is_neg_i(fixed op1) {
  return FIX_IS_NEG(op1);
}
FIX_INLINE int8_t fix_is_nan_i(fixed op1) {
  return FIX_IS_NAN(op1);
}
FIX_INLINE int8_t fix_is_inf_pos_i(fixed op1) {
  return FIX_IS_INF_POS(op1);
}
FIX_INLINE int8_t fix_is_inf_neg_i(fixed op1) {
  return FIX_IS_INF_NEG(op1);
}
FIX_INLINE int8_t fix_eq_i(fixed op1, fixed op2) {
  return FIX_EQ(op1, op2);
}
FIX_INLINE int8_t fix_eq_nan_i(fixed op1, fixed op2) {
  return FIX_EQ_NAN(op1, op2);
}
FIX_INLINE int8_t fix_ne_i(fixed op1, fixed op2) {
  return !FIX_EQ(op1, op2);
}

FIX_INLINE int8_t fix_cmp_i(fixed op1, fixed op2) {
  uint32_t nans = !!(FIX_IS_NAN(op1) | FIX_IS_NAN(op2));

  uint32_t pos1 = !FIX_IS_NEG(op1);
  uint32_t pos2 = !FIX_IS_NEG(op2);

  uint32_t gt = (  FIX_IS_INF_POS(op1)  & (!FIX_IS_INF_POS(op2))) |
                ((!FIX_IS_INF_NEG(op1)) &   FIX_IS_INF_NEG(op2));
  uint32_t lt = ((!FIX_IS_INF_POS(op1)) &   FIX_IS_INF_POS(op2)) |
                  (FIX_IS_INF_NEG(op1)  & (!FIX_IS_INF_NEG(op2)));

  gt |= (!lt) & (pos1 & (!pos2));
  lt |= (!gt) & ((!pos1) & pos2);

  uint32_t cmp_gt = ((fixed) (op1) > (fixed) (op2));
  uint32_t cmp_lt = ((fixed) (op1) < (fixed) (op2));

  int8_t result =
    MASK_UNLESS( nans, 1 ) |
    MASK_UNLESS( !nans,
        MASK_UNLESS( gt, 1) |
        MASK_UNLESS( lt, -1) |
        MASK_UNLESS(!(gt|lt),
          MASK_UNLESS(cmp_gt, 1) |
          MASK_UNLESS(cmp_lt, -1)));
  return result;
}

FIX_INLINE uint8_t fix_le_i(fixed op1, fixed op2) {
  uint32_t nans = !!(FIX_IS_NAN(op1) | FIX_IS_NAN(op2));
  int8_t result = fix_cmp_i(op1, op2);

  return MASK_UNLESS(!nans, result <= 0);
}

FIX_INLINE uint8_t fix_ge_i(fixed op1, fixed op2) {
  uint32_t nans = !!(FIX_IS_NAN(op1) | FIX_IS_NAN(op2));
  int8_t result = fix_cmp_i(op1, op2);

  return MASK_UNLESS(!nans, result >= 0);
}

FIX_INLINE uint8_t fix_lt_i(fixed op1, fixed op2) {
  uint32_t nans = !!(FIX_IS_NAN(op1) | FIX_IS_NAN(op2));
  int8_t result = fix_cmp_i(op1, op2);

  return MASK_UNLESS(!nans, result < 0);
}

FIX_INLINE uint8_t fix_gt_i(fixed op1, fixed op2) {
  uint32_t nans = !!(FIX_IS_NAN(op1) | FIX_IS_NAN(op2));
  int8_t result = fix_cmp_i(op1, op2);

  return MASK_UNLESS(!nans, result > 0);
}


FIX_INLINE fixed fix_neg_i(fixed op1){
  // Flip our infs
  // NaN is still NaN
  // Because we're two's complement, FIX_MIN has no inverse. Make it positive
  // infinity...
  uint8_t isinfpos = FIX_IS_INF_NEG(op1) | (op1 == FIX_MIN);
  uint8_t isinfneg = FIX_IS_INF_POS(op1);
  uint8_t isnan = FIX_IS_NAN(op1);

  // 2s comp negate the data bits
  fixed tempresult = FIX_DATA_BITS(((~op1) + 4));

  // Combine
  return FIX_IF_NAN(isnan) |
    FIX_IF_INF_POS(isinfpos & (!isnan)) |
    FIX_IF_INF_NEG(isinfneg & (!isnan)) |
    FIX_DATA_BITS(tempresult);
}

FIX_INLINE fixed fix_abs_i(fixed op1){
  uint8_t isinfpos = FIX_IS_INF_POS(op1);
  uint8_t isinfneg = FIX_IS_INF_NEG(op1);
  uint8_t isnan = FIX_IS_NAN(op1);

  fixed tempresult = MASK_UNLESS(FIX_TOP_BIT(~op1),                  op1       ) |
                     MASK_UNLESS(FIX_TOP_BIT( op1), FIX_DATA_BITS(((~op1) + 4)));

  /* check for FIX_MIN */
  isinfpos |= (!(isinfpos | isinfneg)) & (!!FIX_TOP_BIT(op1)) & (op1 == tempresult);

  return FIX_IF_NAN(isnan) |
    FIX_IF_INF_POS((isinfpos | isinfneg) & (!isnan)) |
    FIX_DATA_BITS(tempresult);
}

FIX_INLINE fixed fix_add_i(fixed op1, fixed op2) {
  uint8_t isnan;
  uint8_t isinfpos;
  uint8_t isinfneg;

  fixed tempresult;

  isnan = FIX_IS_NAN(op1) | FIX_IS_NAN(op2);
  isinfpos = FIX_IS_INF_POS(op1) | FIX_IS_INF_POS(op2);
  isinfneg = FIX_IS_INF_NEG(op1) | FIX_IS_INF_NEG(op2);

  tempresult = op1 + op2;

  // check if we're overflowing: adding two positive numbers that results in a
  // 'negative' number:
  //   if both inputs are positive (top bit == 0) and the result is 'negative'
  //   (top bit nonzero)
  isinfpos |= ((FIX_TOP_BIT(op1) | FIX_TOP_BIT(op2)) == 0x0)
    & (FIX_TOP_BIT(tempresult) != 0x0);

  // check if there's negative infinity overflow
  isinfneg |= ((FIX_TOP_BIT(op1) & FIX_TOP_BIT(op2)) == FIX_TOP_BIT_MASK)
    & (FIX_TOP_BIT(tempresult) == 0x0);

  // Force infpos to win in cases where it is unclear
  isinfneg &= !isinfpos;

  // do some horrible bit-ops to make result into what we want

  return FIX_IF_NAN(isnan) |
    FIX_IF_INF_POS(isinfpos & (!isnan)) |
    FIX_IF_INF_NEG(isinfneg & (!isnan)) |
    FIX_DATA_BITS(tempresult);
}

FIX_INLINE fixed fix_sub_i(fixed op1, fixed op2) {
  return fix_add_i(op1,fix_neg_i(op2));
}

/* Here's what we want here (N is nonzero normal)
 *  op1    op2     result
 * -----------------------
 *   N      N        N
 *   0      N        0
 *
 *   N      0       Inf
 *  -N      0      -Inf
 *  Inf     0       Inf
 * -Inf     0      -Inf
 *  NaN     0       NaN
 *
 *   0  +/-Inf       0
 *   0      N        0
 *   0     NaN      NaN
 *
 *  Inf    Inf      Inf
 *   N     Inf       0
 *   0     Inf       0
 *  Nan    Inf      NaN
 */
FIX_INLINE fixed fix_div_i(fixed op1, fixed op2) {
  uint8_t isinf = 0;

  fixed tempresult = fix_div_64(op1, op2, &isinf); //fix_div_64 already inlined

  uint8_t divbyzero = op2 == FIX_ZERO;

  uint8_t isinfop1 = (FIX_IS_INF_NEG(op1) | FIX_IS_INF_POS(op1));
  uint8_t isinfop2 = (FIX_IS_INF_NEG(op2) | FIX_IS_INF_POS(op2));

  uint8_t isnegop1 = FIX_IS_INF_NEG(op1) | (FIX_IS_NEG(op1) & !isinfop1);
  uint8_t isnegop2 = FIX_IS_INF_NEG(op2) | (FIX_IS_NEG(op2) & !isinfop2);

  uint8_t isnan = FIX_IS_NAN(op1) | FIX_IS_NAN(op2) | ((op1 == FIX_ZERO) & (op2 == FIX_ZERO));

  isinf = (isinf | isinfop1) & (!isnan);
  uint8_t isinfpos = (isinf & !(isnegop1 ^ isnegop2)) | (divbyzero & !isnegop1);
  uint8_t isinfneg = (isinf & (isnegop1 ^ isnegop2)) | (divbyzero & isnegop1);

  uint8_t iszero = (!(isinfop1)) & isinfop2;

  return FIX_IF_NAN(isnan) |
    FIX_IF_INF_POS(isinfpos & (!isnan) & (!iszero)) |
    FIX_IF_INF_NEG(isinfneg & (!isnan) & (!iszero)) |
    MASK_UNLESS(!iszero, FIX_DATA_BITS(tempresult));
}


FIX_INLINE fixed fix_mul_i(fixed op1, fixed op2) {

  uint8_t isinfop1 = (FIX_IS_INF_NEG(op1) | FIX_IS_INF_POS(op1));
  uint8_t isinfop2 = (FIX_IS_INF_NEG(op2) | FIX_IS_INF_POS(op2));
  uint8_t isnegop1 = FIX_IS_INF_NEG(op1) | (FIX_IS_NEG(op1) & !isinfop1);
  uint8_t isnegop2 = FIX_IS_INF_NEG(op2) | (FIX_IS_NEG(op2) & !isinfop2);

  uint8_t isnan = FIX_IS_NAN(op1) | FIX_IS_NAN(op2);
  uint8_t isinf = 0;

  uint8_t iszero = (op1 == FIX_ZERO) | (op2 == FIX_ZERO);

  fixed tmp = ROUND_TO_EVEN(FIX_MUL_64(op1, op2, isinf), FIX_FLAG_BITS) << FIX_FLAG_BITS;

  isinf = (!iszero) & (isinfop1 | isinfop2 | isinf) & (!isnan);

  uint8_t isinfpos = isinf & !(isnegop1 ^ isnegop2);
  uint8_t isinfneg = isinf & (isnegop1 ^ isnegop2);

  return FIX_IF_NAN(isnan) |
    FIX_IF_INF_POS(isinfpos & (!isnan)) |
    FIX_IF_INF_NEG(isinfneg & (!isnan)) |
    FIX_DATA_BITS(tmp);
}

FIX_INLINE fixed fix_floor_i(fixed op1) {
  uint8_t isinfpos = FIX_IS_INF_POS(op1);
  uint8_t isinfneg = FIX_IS_INF_NEG(op1);
  uint8_t isnan = FIX_IS_NAN(op1);

  fixed tempresult = op1 & ~((1ull << (FIX_POINT_BITS))-1);

  return FIX_IF_NAN(isnan) |
    FIX_IF_INF_POS(isinfpos & (!isnan)) |
    FIX_IF_INF_NEG(isinfneg & (!isnan)) |
    FIX_DATA_BITS(tempresult);
}

FIX_INLINE fixed fix_ceil_i(fixed op1) {
  uint8_t isinfpos = FIX_IS_INF_POS(op1);
  uint8_t isinfneg = FIX_IS_INF_NEG(op1);
  uint8_t isnan = FIX_IS_NAN(op1);
  uint8_t ispos = !FIX_IS_NEG(op1);

  fixed frac_mask = (((fixed) 1) << (FIX_POINT_BITS))-1;

  fixed tempresult = (op1 & ~frac_mask) +
    MASK_UNLESS(!!(op1 & frac_mask),  (((fixed) 1) << (FIX_POINT_BITS)));

  // If we used to be positive and we wrapped around, switch to INF_POS.
  isinfpos |= ((tempresult == FIX_MIN) & ispos);

  return FIX_IF_NAN(isnan) |
    FIX_IF_INF_POS(isinfpos & (!isnan)) |
    FIX_IF_INF_NEG(isinfneg & (!isnan)) |
    FIX_DATA_BITS(tempresult);
}

//fixed fix_sin_fast_i(fixed op1) {
//  uint8_t isinfpos;
//  uint8_t isinfneg;
//  uint8_t isnan;
//
//  isinfpos = FIX_IS_INF_POS(op1);
//  isinfneg = FIX_IS_INF_NEG(op1);
//  isnan = FIX_IS_NAN(op1);
//
//  /* Math:
//   *
//   * See http://www.coranac.com/2009/07/sines/ for a great overview.
//   *
//   * Fifth order taylor approximation:
//   *
//   *   Sin_5(x) = ax - bx^3 + cx^5
//   *
//   * where:
//   *
//   *   a = 1.569718634 (almost but not quite pi/2)
//   *   b = 2a - (5/2)
//   *   c = a - (3/2)
//   *   Constants minimise least-squared error (according to Coranac).
//   *
//   * Simplify for computation:
//   *
//   *   Sin_5(x) = az - bz^3 + cz^5
//   *            = z(a + (-bz^2 + cz^4))
//   *            = z(a + z^2(cz^2 - b))
//   *            = z(a - z^2(b - cz^2))
//   *
//   *   where z = x / (tau/4).
//   *
//   */
//
//  uint32_t circle_frac = fix_circle_frac_i(op1);
//
//  /* for sin, we need to map the circle frac [0,4) to [-1, 1]:
//   *
//   * Z' =    2 - Z       { if 1 <= z < 3
//   *         Z           { otherwise
//   *
//   * zp =                                   # bits: xx.2.28
//   *         (1<<31) - circle_frac { if 1 <= circle_frac[29:28] < 3
//   *         circle_frac           { otherwise
//   */
//  uint32_t top_bits_differ = ((circle_frac >> 28) & 0x1) ^ ((circle_frac >> 29) & 0x1);
//  uint32_t zp = MASK_UNLESS(top_bits_differ, (1<<29) - circle_frac) |
//                MASK_UNLESS(!top_bits_differ, SIGN_EXTEND_64(circle_frac, 30));
//
//  uint32_t zp2 = MUL_2x28(zp, zp);
//
//  uint32_t a = 0x64764525; // a = 1.569718634; "0x%08x"%(a*2**30)"
//  uint32_t b = 0x28ec8a4a; // "0x%08x"%((2*a - (5/2.)) *2**30)
//  uint32_t c = 0x04764525; // "0x%08x"%((a - (3/2.)) *2**30)
//
//  uint32_t result =
//    MUL_2x28(zp,
//        (a - MUL_2x28(zp2,
//                          b - MUL_2x28(c, zp2))));
//
//  // result is xx.2.28, shift over into fixed, sign extend to full result
//  return FIX_IF_NAN(isnan) |
//    FIX_IF_INF_POS(isinfpos & (!isnan)) |
//    FIX_IF_INF_NEG(isinfneg & (!isnan)) |
//    convert_228_to_fixed(result);
//}

FIX_INLINE fixed fix_convert_from_int64_i(int64_t i) {
  fixed_signed fnint = (fixed_signed) i;
  uint8_t isinfpos = (fnint >= ((fixed_signed) FIX_INT_MAX));
  uint8_t isinfneg = (fnint < (-((fixed_signed) FIX_INT_MAX)));

  fixed f = ((fixed_signed) i) << (FIX_POINT_BITS);

  return FIX_IF_INF_POS(isinfpos) |
         FIX_IF_INF_NEG(isinfneg) |
         MASK_UNLESS(!(isinfpos | isinfneg), f);
}


FIX_INLINE int64_t fix_convert_to_int64_i(fixed op1) {
  return FIX_ROUND_INT64(op1);
}
FIX_INLINE int64_t fix_round_up_int64_i(fixed op1) {
  return FIX_ROUND_UP_INT64(op1);
}
FIX_INLINE int64_t fix_ceil64_i(fixed op1) {
  return FIX_CEIL64(op1);
}
FIX_INLINE int64_t fix_floor64_i(fixed op1) {
  return FIX_FLOOR64(op1);
}