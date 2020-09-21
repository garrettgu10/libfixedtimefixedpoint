
#include "ftfp.h"
#include "internal.h"
#include <math.h>

#include <stdint.h>



fixed fix_convert_from_double(double d) {
  uint64_t bits = *(uint64_t*) &d;
  uint32_t exponent_base = ((bits >> 52) & 0x7ff);
  uint64_t mantissa_base = (bits & ((1ull <<52)-1));
  uint8_t d_is_zero = (exponent_base == 0) & (mantissa_base == 0);

  uint32_t exponent = exponent_base - 1023;
  uint32_t sign = bits >> 63;

  /* note that this breaks with denorm numbers. However, we'll shift those all
   * away with the exponent later */
  uint64_t mantissa = mantissa_base | MASK_UNLESS_64(!d_is_zero, (1ull << 52));

  int32_t shift = 52 - (FIX_FRAC_BITS) - exponent;

  fixed result = FIX_ALL_BIT_MASK & (
      MASK_UNLESS((shift >= 2) & (shift <  64), ((ROUND_TO_EVEN(mantissa,shift)) << FIX_FLAG_BITS)) |
      MASK_UNLESS (shift == 1                 , (ROUND_TO_EVEN_ONE_BIT(mantissa) << FIX_FLAG_BITS)) |
      MASK_UNLESS((shift <= 0) & (shift > -64), (mantissa << (-shift + 2))));

  /* If there are any integer bits that we shifted off into oblivion, the double
   * is outside our range. Generate INF... */
  uint8_t lostbits = MASK_UNLESS(shift <= 0, mantissa != (result >> (-shift+2)));

  /* use IEEE 754 definition of INF */
  uint8_t isinf = (exponent_base == 0x7ff) & (mantissa_base == 0);

  /* If we lost any bits by shifting, kill it. */
  isinf |= lostbits;

  /* Since doubles have a sign bit and we're two's complement, the other
   * INFINITY case is if the double is >= FIX_INT_MAX and positive, or >
   * FIX_INT_MAX and negative. */
  isinf |= ((result >= FIX_TOP_BIT_MASK) & !sign);
  isinf |= ((result >  FIX_TOP_BIT_MASK) &  sign);

  uint8_t isinfpos = (sign == 0) & isinf;
  uint8_t isinfneg = (sign != 0) & isinf;
  uint8_t isnan = (exponent_base == 0x7ff) && (mantissa_base != 0);

  fixed result_neg = fix_neg(result);

  return
    FIX_IF_NAN(isnan) |
    FIX_IF_INF_POS(isinfpos & !isnan) |
    FIX_IF_INF_NEG(isinfneg & !isnan) |
    MASK_UNLESS(!sign, FIX_DATA_BITS(result)) |
    MASK_UNLESS(sign, FIX_DATA_BITS(result_neg));
}

double fix_convert_to_double(fixed op1) {
  uint8_t isinfpos = FIX_IS_INF_POS(op1);
  uint8_t isinfneg = FIX_IS_INF_NEG(op1);
  uint8_t isnan = FIX_IS_NAN(op1);
  uint8_t exception = isinfpos | isinfneg | isnan;

  // Doubles don't use two's complement. Record the sign and flip back into positive land...
  uint64_t sign = FIX_IS_NEG(op1);
  op1 = fix_abs(op1);

  uint32_t log2op1 = uint64_log2(op1);

  int32_t shift = 53 - 1 - log2op1;

  uint64_t mantissa = ((1ull << 52) - 1) & (
      MASK_UNLESS(shift >= 0, ((uint64_t) op1) << shift) |
      MASK_UNLESS(shift < 0, ((uint64_t) op1) >> (-shift)));
  uint64_t exponent = MASK_UNLESS_64(op1 != (fixed) 0, log2op1 - FIX_POINT_BITS + 1023);

  // We would include
  //  MASK_UNLESS( isinfpos | isinfneg , 0 ),
  // but that's implied by masking everything else.
  mantissa =
    MASK_UNLESS_64( isnan, 1 ) |
    MASK_UNLESS_64(!exception, mantissa );

  sign =
    MASK_UNLESS_64( isinfneg, 1ull ) |
    MASK_UNLESS_64(!exception, sign );

  exponent =
    MASK_UNLESS_64( exception, 0x7ff) |
    MASK_UNLESS_64(!exception, exponent);

  uint64_t result = (sign << 63) |
    (exponent << 52) |
    (mantissa);

  double d = *(double*) &result;
  return d;
}