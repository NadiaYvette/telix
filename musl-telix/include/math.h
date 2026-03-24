#ifndef MATH_H
#define MATH_H

/* Constants. */
#define M_PI        3.14159265358979323846
#define M_E         2.71828182845904523536
#define M_LN2       0.69314718055994530942
#define M_LOG2E     1.44269504088896340736
#define M_SQRT2     1.41421356237309504880
#define M_LN10      2.30258509299404568402
#define M_LOG10E    0.43429448190325182765
#define M_PI_2      1.57079632679489661923
#define M_PI_4      0.78539816339744830962
#define M_1_PI      0.31830988618379067154
#define M_2_PI      0.63661977236758134308

/* Special values — use compiler builtins. */
#define HUGE_VAL    __builtin_huge_val()
#define INFINITY    __builtin_inf()
#define NAN         __builtin_nan("")

/* Classification macros. */
#define FP_NAN       0
#define FP_INFINITE  1
#define FP_ZERO      2
#define FP_SUBNORMAL 3
#define FP_NORMAL    4

#define fpclassify(x) __builtin_fpclassify(FP_NAN, FP_INFINITE, FP_NORMAL, \
                                            FP_SUBNORMAL, FP_ZERO, (x))
#define isinf(x)      __builtin_isinf(x)
#define isnan(x)      __builtin_isnan(x)
#define isfinite(x)   __builtin_isfinite(x)
#define isnormal(x)   __builtin_isnormal(x)
#define signbit(x)    __builtin_signbit(x)

/* Function declarations.
 *
 * NOTE: With -mgeneral-regs-only on aarch64 the compiler cannot generate
 * code that passes or returns doubles in FP registers.  These declarations
 * exist so that headers compile, but the functions are NOT defined.
 * Any translation unit that actually calls them must be compiled WITHOUT
 * -mgeneral-regs-only.
 */
double fabs(double);
double ceil(double);
double floor(double);
double sqrt(double);
double fmod(double, double);
double pow(double, double);
double log(double);
double log2(double);
double log10(double);
double exp(double);
double exp2(double);
double sin(double);
double cos(double);
double tan(double);
double atan(double);
double atan2(double, double);
double round(double);
double trunc(double);
double copysign(double, double);
double frexp(double, int *);
double ldexp(double, int);
double modf(double, double *);
double fmax(double, double);
double fmin(double, double);

float fabsf(float);
float ceilf(float);
float floorf(float);
float sqrtf(float);
float roundf(float);
float truncf(float);

#endif /* MATH_H */
