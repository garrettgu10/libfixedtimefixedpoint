#include "ftfp.h"
#include "ftfp_inline.h"
#include "internal.h"
#include <math.h>

#include <stdint.h>

int8_t fix_is_neg(fixed op1) {
  return fix_is_neg_i(op1);
}
int8_t fix_is_nan(fixed op1) {
  return fix_is_nan_i(op1);
}
int8_t fix_is_inf_pos(fixed op1) {
  return fix_is_inf_pos_i(op1);
}
int8_t fix_is_inf_neg(fixed op1) {
  return fix_is_inf_neg_i(op1);
}
int8_t fix_eq(fixed op1, fixed op2) {
  return fix_eq_i(op1, op2);
}
int8_t fix_eq_nan(fixed op1, fixed op2) {
  return fix_eq_nan_i(op1, op2);
}
int8_t fix_ne(fixed op1, fixed op2) {
  return fix_ne_i(op1, op2);
}

int8_t fix_cmp(fixed op1, fixed op2) {
  return fix_cmp_i(op1, op2);
}

uint8_t fix_le(fixed op1, fixed op2) {
  return fix_le_i(op1, op2);
}

uint8_t fix_ge(fixed op1, fixed op2) {
  return fix_ge_i(op1, op2);
}

uint8_t fix_lt(fixed op1, fixed op2) {
  return fix_lt_i(op1, op2);
}

uint8_t fix_gt(fixed op1, fixed op2) {
  return fix_gt_i(op1, op2);
}

fixed fix_neg(fixed op1){
  return fix_neg_i(op1);
}

fixed fix_abs(fixed op1){
  return fix_abs_i(op1);
}

fixed fix_sub(fixed op1, fixed op2) {
  return fix_sub_i(op1, op2);
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
fixed fix_div(fixed op1, fixed op2) {
  return fix_div_i(op1, op2);
}

fixed fix_mul(fixed op1, fixed op2) {
  return fix_mul_i(op1, op2);
}

fixed fix_add(fixed op1, fixed op2) {
  return fix_add_i(op1, op2);
}

fixed fix_floor(fixed op1) {
  return fix_floor_i(op1);
}

fixed fix_ceil(fixed op1) {
  return fix_ceil_i(op1);
}

//fixed fix_sin_fast(fixed op1) {
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
//  uint32_t circle_frac = fix_circle_frac(op1);
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

fixed fix_convert_from_int64(int64_t i) {
  return fix_convert_from_int64_i(i);
}


int64_t fix_convert_to_int64(fixed op1) {
  return fix_convert_to_int64_i(op1);
}
int64_t fix_round_up_int64(fixed op1) {
  return fix_round_up_int64_i(op1);
}
int64_t fix_ceil64(fixed op1) {
  return fix_ceil64_i(op1);
}
int64_t fix_floor64(fixed op1) {
  return fix_floor64_i(op1);
}

void fix_print(fixed f) {
  char buf[FIX_PRINT_BUFFER_SIZE];
  fix_sprint(buf, f);
  printf("%s", buf);
}
void fix_println(fixed f) {
  fix_print(f);
  printf("\n");
}
