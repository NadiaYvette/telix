/* Minimal C locale for Telix. Always "C" / POSIX. */
#include <locale.h>

static char c_locale[] = "C";
static char empty[] = "";
static char dot[] = ".";

static struct lconv c_lconv = {
    .decimal_point = dot,
    .thousands_sep = empty,
    .grouping = empty,
    .int_curr_symbol = empty,
    .currency_symbol = empty,
    .mon_decimal_point = empty,
    .mon_thousands_sep = empty,
    .mon_grouping = empty,
    .positive_sign = empty,
    .negative_sign = empty,
    .int_frac_digits = 127,
    .frac_digits = 127,
    .p_cs_precedes = 127,
    .p_sep_by_space = 127,
    .n_cs_precedes = 127,
    .n_sep_by_space = 127,
    .p_sign_posn = 127,
    .n_sign_posn = 127,
};

char *setlocale(int category, const char *locale) {
    (void)category;
    (void)locale;
    return c_locale;
}

struct lconv *localeconv(void) {
    return &c_lconv;
}
