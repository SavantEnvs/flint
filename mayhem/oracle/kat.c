/* Known-answer probe for the code the fuzz targets exercise: prints one "KAT name value"
   line per check; mayhem/test.sh compares the lines with the values worked out by hand. */
#include <stdio.h>
#include <flint/flint.h>
#include <flint/ulong_extras.h>
#include <flint/fmpz.h>
#include <flint/fmpz_poly.h>
#include <flint/fmpq.h>
#include <flint/fmpq_poly.h>
#include <flint/fmpz_mpoly.h>
#include <flint/arb.h>

int main(void)
{
    ulong n;
    int e;

    n = 1701; /* 3^5 * 7 */
    e = n_remove(&n, 3);
    printf("KAT n_remove %d %lu\n", e, n);
    n = UWORD_MAX; /* 3*5*17*257*641*65537*6700417 */
    e = n_remove(&n, 641);
    printf("KAT n_remove_big %d %lu\n", e, n);
    n = UWORD(1) << 63;
    e = n_remove2_precomp(&n, 2, n_precompute_inverse(2));
    printf("KAT n_remove2 %d %lu\n", e, n);

    {
        fmpz_t x, f, r;
        fmpz_init(x); fmpz_init(f); fmpz_init(r);
        fmpz_set_ui(x, 1); fmpz_mul_2exp(x, x, 100);
        fmpz_mul_ui(x, x, 10935); /* 3^7 * 5 */
        fmpz_set_ui(f, 2);
        slong v = fmpz_remove(r, x, f);
        printf("KAT fmpz_remove %ld ", v); fmpz_print(r); printf("\n");

        fmpz_set_str(x, "-ff", 16);
        printf("KAT fmpz_set_str16 "); fmpz_print(x); printf("\n");
        fmpz_set_str(x, "zz", 62);
        printf("KAT fmpz_set_str62 "); fmpz_print(x); printf("\n");
        fmpz_set_str(x, "123456789012345678901234567890", 10);
        char *s = fmpz_get_str(NULL, 36, x);
        printf("KAT fmpz_get_str36 %s\n", s);
        flint_free(s);
        printf("KAT fmpz_set_str_bad %d\n", fmpz_set_str(x, "12x", 10));
        fmpz_clear(x); fmpz_clear(f); fmpz_clear(r);
    }

    {
        fmpz_poly_t g, h, f, q;
        fmpz_poly_init(g); fmpz_poly_init(h); fmpz_poly_init(f); fmpz_poly_init(q);
        fmpz_poly_set_str(g, "2  1 1");   /* x + 1 */
        fmpz_poly_set_str(h, "3  1 1 1"); /* x^2 + x + 1 */
        fmpz_poly_pow(f, g, 3);
        fmpz_poly_mul(f, f, h);
        slong v = fmpz_poly_remove(q, f, g);
        char *s = fmpz_poly_get_str(q);
        printf("KAT fmpz_poly_remove %ld %s\n", v, s);
        flint_free(s);
        fmpz_poly_set_str(f, "3  1 -2 3");
        fmpz_t y, z;
        fmpz_init_set_ui(y, 2); fmpz_init(z);
        fmpz_poly_evaluate_fmpz(z, f, y);
        printf("KAT fmpz_poly_set_str "); fmpz_print(z); printf("\n");
        printf("KAT fmpz_poly_set_str_bad %d\n", fmpz_poly_set_str(f, "x 1"));
        fmpz_clear(y); fmpz_clear(z);
        fmpz_poly_clear(g); fmpz_poly_clear(h); fmpz_poly_clear(f); fmpz_poly_clear(q);
    }

    {
        fmpq_poly_t p;
        fmpq_poly_init(p);
        fmpq_poly_set_str(p, "3  1/2 0 -3/4");
        char *s = fmpq_poly_get_str(p);
        printf("KAT fmpq_poly_set_str %s\n", s);
        flint_free(s);
        fmpq_poly_clear(p);

        fmpq_t q;
        fmpq_init(q);
        fmpq_set_str(q, "-6/8", 10);
        fmpq_canonicalise(q);
        printf("KAT fmpq_set_str "); fmpq_print(q); printf("\n");
        fmpq_clear(q);
    }

    {
        fmpz_mpoly_ctx_t ctx;
        fmpz_mpoly_t p;
        const char *vars[] = {"x", "y"};
        fmpz_mpoly_ctx_init(ctx, 2, ORD_LEX);
        fmpz_mpoly_init(p, ctx);
        int r = fmpz_mpoly_set_str_pretty(p, "x^2*y + 3*y - 1", vars, ctx);
        char *s = fmpz_mpoly_get_str_pretty(p, vars, ctx);
        printf("KAT fmpz_mpoly_set_str_pretty %d %ld %s\n", r, (long) fmpz_mpoly_length(p, ctx), s);
        flint_free(s);
        fmpz_mpoly_clear(p, ctx);
        fmpz_mpoly_ctx_clear(ctx);
    }

    {
        arb_t x;
        arb_init(x);
        int r = arb_set_str(x, "0.375", 64);
        printf("KAT arb_set_str %d %d ", r, arb_contains_si(x, 0));
        arf_printd(arb_midref(x), 10);
        printf("\n");
        arb_clear(x);
    }

    flint_cleanup();
    return 0;
}
