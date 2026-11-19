/* fmpz_mpoly_set_str_pretty: the multivariate polynomial expression parser.
   Input: byte 0 = number of variables (1..4), byte 1 = monomial order, rest = expression. */
#include <flint/flint.h>
#include <flint/fmpz_mpoly.h>
#include "common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const ordering_t ords[3] = {ORD_LEX, ORD_DEGLEX, ORD_DEGREVLEX};
    static const char *names[4] = {"x", "y", "z", "t"};

    if (size < 2)
        return -1;

    slong nvars = 1 + data[0] % 4;
    char *s = mayhem_cstr(data + 2, size - 2);
    int ok = -1;

    if (mayhem_big_exponent(s) || mayhem_zero_denominator(s))
    {
        free(s);
        return -1;
    }

    fmpz_mpoly_ctx_t ctx;
    fmpz_mpoly_t a, b;
    fmpz_mpoly_ctx_init(ctx, nvars, ords[data[1] % 3]);
    fmpz_mpoly_init(a, ctx);
    fmpz_mpoly_init(b, ctx);

    if (fmpz_mpoly_set_str_pretty(a, s, names, ctx) == 0)
    {
        char *t = fmpz_mpoly_get_str_pretty(a, names, ctx);
        if (fmpz_mpoly_set_str_pretty(b, t, names, ctx) != 0 || !fmpz_mpoly_equal(a, b, ctx))
            flint_abort();
        flint_free(t);
        ok = 0;
    }

    fmpz_mpoly_clear(a, ctx);
    fmpz_mpoly_clear(b, ctx);
    fmpz_mpoly_ctx_clear(ctx);
    free(s);
    flint_cleanup();
    return ok;
}
