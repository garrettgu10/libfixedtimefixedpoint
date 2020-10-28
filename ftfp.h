#ifndef ftfp_h
#define ftfp_h

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#include "base.h"

/*
 * TODO:
 * arccos
 * arctan
 * arcsin
 */

#define REPEAT_1(x) x
#define REPEAT_2(x) REPEAT_1(x) x
#define REPEAT_3(x) REPEAT_2(x) x
#define REPEAT_4(x) REPEAT_3(x) x
#define REPEAT_5(x) REPEAT_4(x) x
#define REPEAT_6(x) REPEAT_5(x) x
#define REPEAT_7(x) REPEAT_6(x) x
#define REPEAT_8(x) REPEAT_7(x) x
#define REPEAT_9(x) REPEAT_8(x) x
#define REPEAT_10(x) REPEAT_9(x) x
#define REPEAT_11(x) REPEAT_10(x) x
#define REPEAT_12(x) REPEAT_11(x) x
#define REPEAT_13(x) REPEAT_12(x) x
#define REPEAT_14(x) REPEAT_13(x) x
#define REPEAT_15(x) REPEAT_14(x) x
#define REPEAT_16(x) REPEAT_15(x) x
#define REPEAT_17(x) REPEAT_16(x) x
#define REPEAT_18(x) REPEAT_17(x) x
#define REPEAT_19(x) REPEAT_18(x) x
#define REPEAT_20(x) REPEAT_19(x) x
#define REPEAT_21(x) REPEAT_20(x) x
#define REPEAT_22(x) REPEAT_21(x) x
#define REPEAT_23(x) REPEAT_22(x) x
#define REPEAT_24(x) REPEAT_23(x) x
#define REPEAT_25(x) REPEAT_24(x) x
#define REPEAT_26(x) REPEAT_25(x) x
#define REPEAT_27(x) REPEAT_26(x) x
#define REPEAT_28(x) REPEAT_27(x) x
#define REPEAT_29(x) REPEAT_28(x) x
#define REPEAT_30(x) REPEAT_29(x) x
#define REPEAT_31(x) REPEAT_30(x) x
#define REPEAT_32(x) REPEAT_31(x) x
#define REPEAT_33(x) REPEAT_32(x) x
#define REPEAT_34(x) REPEAT_33(x) x
#define REPEAT_35(x) REPEAT_34(x) x
#define REPEAT_36(x) REPEAT_35(x) x
#define REPEAT_37(x) REPEAT_36(x) x
#define REPEAT_38(x) REPEAT_37(x) x
#define REPEAT_39(x) REPEAT_38(x) x
#define REPEAT_40(x) REPEAT_39(x) x
#define REPEAT_41(x) REPEAT_40(x) x
#define REPEAT_42(x) REPEAT_41(x) x
#define REPEAT_43(x) REPEAT_42(x) x
#define REPEAT_44(x) REPEAT_43(x) x
#define REPEAT_45(x) REPEAT_44(x) x
#define REPEAT_46(x) REPEAT_45(x) x
#define REPEAT_47(x) REPEAT_46(x) x
#define REPEAT_48(x) REPEAT_47(x) x
#define REPEAT_49(x) REPEAT_48(x) x
#define REPEAT_50(x) REPEAT_49(x) x
#define REPEAT_51(x) REPEAT_50(x) x
#define REPEAT_52(x) REPEAT_51(x) x
#define REPEAT_53(x) REPEAT_52(x) x
#define REPEAT_54(x) REPEAT_53(x) x
#define REPEAT_55(x) REPEAT_54(x) x
#define REPEAT_56(x) REPEAT_55(x) x
#define REPEAT_57(x) REPEAT_56(x) x
#define REPEAT_58(x) REPEAT_57(x) x
#define REPEAT_59(x) REPEAT_58(x) x
#define REPEAT_60(x) REPEAT_59(x) x
#define REPEAT_61(x) REPEAT_60(x) x
#define REPEAT_62(x) REPEAT_61(x) x
#define REPEAT_63(x) REPEAT_62(x) x
#define REPEAT_64(x) REPEAT_63(x) x
#define CONCAT(x, y) x ## y
#define REPEAT_N(x) CONCAT(REPEAT_, x)

#define FIX_NORMAL   ((fixed) 0x0)
#define FIX_NAN      ((fixed) 0x1)
#define FIX_INF_POS  ((fixed) 0x2)
#define FIX_INF_NEG  ((fixed) 0x3)

// Useful constants
#define FIX_EPSILON     ((fixed) (1 << FIX_FLAG_BITS))
#define FIX_EPSILON_NEG ((fixed) ~((1 << FIX_FLAG_BITS)-1))
#define FIX_ZERO        ((fixed) 0)

#define FIX_MAX     FIX_DATA_BITS((fixed) (((fixed) 1) << (FIX_BITS-1)) -1)
#define FIX_MIN     FIX_DATA_BITS((fixed) ((fixed) 1) << (FIX_BITS-1))

int8_t fix_is_neg(fixed op1);
int8_t fix_is_nan(fixed op1);
int8_t fix_is_inf_pos(fixed op1);
int8_t fix_is_inf_neg(fixed op1);

/* Returns true if the numbers are equal (NaNs are always unequal.) */
int8_t fix_eq(fixed op1, fixed op2);

/* Returns true if the numbers are equal (and also if they are both NaN) */
int8_t fix_eq_nan(fixed op1, fixed op2);

/* Returns true if the numbers are unequal (NaNs are always unequal.) */
int8_t fix_ne(fixed op1, fixed op2);

/* Returns:
 *   -1 if op1 < op2
 *    0 if they are equal
 *    1 if op1 > op2 (or either is * NaN)
 */
int8_t fix_cmp(fixed op1, fixed op2);

uint8_t fix_le(fixed op1, fixed op2);
uint8_t fix_ge(fixed op1, fixed op2);

uint8_t fix_lt(fixed op1, fixed op2);
uint8_t fix_gt(fixed op1, fixed op2);

fixed fix_neg(fixed op1);
fixed fix_abs(fixed op1);

fixed fix_add(fixed op1, fixed op2);
fixed fix_sub(fixed op1, fixed op2);
fixed fix_mul(fixed op1, fixed op2);
fixed fix_div(fixed op1, fixed op2);

fixed fix_floor(fixed op1);
fixed fix_ceil(fixed op1);

fixed fix_exp(fixed op1);
fixed fix_ln(fixed op1);
fixed fix_log2(fixed op1);
fixed fix_log10(fixed op1);

fixed fix_sqrt(fixed op1);

/* Computes x^y.
 *
 * Note that this is undefined when x < 0 and y is not an integer, and will
 * return NaN.
 */
fixed fix_pow(fixed x, fixed y);


/* Accurate to 2^-57. */
fixed fix_sin(fixed op1);
fixed fix_cos(fixed op1);
fixed fix_tan(fixed op1);

/* Uses a polynomial approximation of sin. Very quick, but less accurate at the
 * edges. */
//fixed fix_sin_fast(fixed op1);

/* Defining these using macros so FTFP can be compiled with no fp */
fixed  fix_convert_from_double_internal(uint64_t d);
uint64_t fix_convert_to_double_internal(fixed op1);

#define fix_convert_from_double(d) \
  fix_convert_from_double_internal((union {double d; uint64_t i;}){ .d = (d) }.i)
#define fix_convert_to_double(f) \
  ((union {double d; uint64_t i;}){ .i = fix_convert_to_double_internal(f) }.d)

fixed  fix_convert_from_int64(int64_t i);

/* Round to integers */
int64_t fix_convert_to_int64(fixed op1);
int64_t fix_round_up_int64(fixed op1);
int64_t fix_ceil64(fixed op1);
int64_t fix_floor64(fixed op1);

/* Prints the fixed into a buffer in base 10. The buffer must be at least FIX_PRINT_BUFFER_SIZE
 * characters long. */
void fix_sprint(char* buffer, fixed f);
void fix_sprint_nospecial(char* buffer, fixed f);

/* Prints a fixed to STDOUT. */
void fix_print(fixed f);
void fix_println(fixed f);

#endif
