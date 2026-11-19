/* gr_set_str: the generic-rings expression parser (gr_generic_set_str_expr in
   src/gr_generic/set_str_expr.c). It is GR_METHOD_SET_STR's default, so it is the string
   parser behind gr_set_str for every context that has no parser of its own (fmpq, nmod,
   fmpz_mod here), and the fallback of those that do (fmpz, the polynomial rings, acb, qqbar).
   Input: byte 0 selects the context, the rest is the string. The context is created and
   cleared for each input, so nothing carries over between inputs. */
#include <stdio.h>
#include <flint/flint.h>
#include <flint/fmpz.h>
#include <flint/mpoly.h>
#include <flint/fmpz_mpoly_q.h>
#include <flint/gr.h>
#include "common.h"

#define NCTX 12

/* exact rings: an element parsed back from its own printed form must be equal to it */
static int init_ctx(gr_ctx_t ctx, int which, int *exact)
{
    fmpz_t n;
    *exact = 1;
    switch (which)
    {
        case 0: gr_ctx_init_fmpz(ctx); return 1;
        case 1: gr_ctx_init_fmpq(ctx); return 1;
        case 2: return gr_ctx_init_nmod(ctx, 101) == GR_SUCCESS;
        case 3:
            fmpz_init(n);
            fmpz_set_str(n, "340282366920938463463374607431768211507", 10);  /* 2^128 + 51, prime */
            gr_ctx_init_fmpz_mod(ctx, n);
            fmpz_clear(n);
            return 1;
        case 4: gr_ctx_init_fmpzi(ctx); return 1;
        case 5: gr_ctx_init_fmpz_poly(ctx); return 1;
        case 6: gr_ctx_init_fmpq_poly(ctx); return 1;
        case 7: gr_ctx_init_fmpz_mpoly(ctx, 2, ORD_LEX); return 1;
        case 8: gr_ctx_init_fmpz_mpoly_q(ctx, 2, ORD_DEGREVLEX); return 1;
        case 9: *exact = 0; gr_ctx_init_real_arb(ctx, 64); return 1;
        case 10: *exact = 0; gr_ctx_init_complex_acb(ctx, 64); return 1;
        default: *exact = 0; gr_ctx_init_real_float_arf(ctx, 64); return 1;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return -1;

    char *s = mayhem_cstr(data + 1, size - 1);
    gr_ctx_t ctx;
    int exact, ok = -1;
    if (!init_ctx(ctx, data[0] % NCTX, &exact))
    {
        free(s);
        return -1;
    }

    /* nothing bounds sizes in the parser (security.md): a literal exponent, nested powers,
       "me<e>" or fac/gamma/zeta of a big argument are requests for terabytes in an exact
       ring, not parser bugs (common.h); the floating-point contexts (arb, acb, arf) hold
       "1e999999999" or "fac(1e99)" in a few words */
    if (mayhem_big_exponent(s) || (exact && (mayhem_big_sci_exponent(s) || mayhem_big_function(s))))
    {
        gr_ctx_clear(ctx);
        free(s);
        return -1;
    }

    gr_ptr x = gr_heap_init(ctx);
    gr_ptr y = gr_heap_init(ctx);

    if (gr_set_str(x, s, ctx) == GR_SUCCESS)
    {
        char *t;
        if (gr_get_str(&t, x, ctx) == GR_SUCCESS)
        {
            /* upstream's gr_test_get_set_str (src/gr/test_ring.c), run on every ring by
               gr_test_ring: when the printed form of x reads back, it must not be unequal
               to x. A printed form the parser declines is not a failure there either. */
            if (exact && gr_set_str(y, t, ctx) == GR_SUCCESS && gr_equal(x, y, ctx) == T_FALSE)
            {
                fprintf(stderr, "get_set_str: context %d, input \"%s\" prints as \"%s\", "
                        "which reads back unequal\n", data[0] % NCTX, s, t);
                flint_abort();
            }
            flint_free(t);
        }
        ok = 0;
    }

    gr_heap_clear(x, ctx);
    gr_heap_clear(y, ctx);
    gr_ctx_clear(ctx);
    free(s);
    flint_cleanup();
    return ok;
}
