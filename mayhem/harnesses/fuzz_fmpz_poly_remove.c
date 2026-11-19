/* fmpz_poly_remove: the largest power of g dividing f.
   Input: [1 byte e][1 byte len_g][len_g int16 coeffs][1 byte len_h][len_h int16 coeffs].
   Both g and h itself and f = h * g^e are passed as f. */
#include <flint/flint.h>
#include <flint/fmpz.h>
#include <flint/fmpz_poly.h>
#include "common.h"

static int read_poly(fmpz_poly_t p, const uint8_t **d, size_t *size)
{
    if (*size < 1)
        return -1;
    slong len = *(*d)++ % 17;
    (*size)--;
    if (*size < (size_t) len * 2)
        return -1;
    fmpz_poly_zero(p);
    for (slong i = 0; i < len; i++)
    {
        int16_t c;
        memcpy(&c, *d, 2);
        *d += 2;
        fmpz_poly_set_coeff_si(p, i, c);
    }
    *size -= (size_t) len * 2;
    return 0;
}

static void check_remove(const fmpz_poly_t f, const fmpz_poly_t g, slong at_least)
{
    fmpz_poly_t q, pw, prod, d;
    fmpz_poly_init(q);
    fmpz_poly_init(pw);
    fmpz_poly_init(prod);
    fmpz_poly_init(d);

    slong k = fmpz_poly_remove(q, f, g);

    fmpz_poly_pow(pw, g, (ulong) k);
    fmpz_poly_mul(prod, q, pw);
    if ((k < at_least && !fmpz_poly_is_zero(f)) || !fmpz_poly_equal(prod, f))
        flint_abort();
    /* k is maximal: g does not divide the quotient (the zero polynomial is divisible by anything) */
    if (!fmpz_poly_is_zero(q) && fmpz_poly_divides(d, q, g))
        flint_abort();

    fmpz_poly_clear(q);
    fmpz_poly_clear(pw);
    fmpz_poly_clear(prod);
    fmpz_poly_clear(d);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return -1;
    ulong e = data[0] % 8;
    data++;
    size--;

    fmpz_poly_t g, h, f;
    fmpz_poly_init(g);
    fmpz_poly_init(h);
    fmpz_poly_init(f);

    int ok = -1;
    if (read_poly(g, &data, &size) == 0 && read_poly(h, &data, &size) == 0
        /* docs: poly2 must not be zero or +-1 (an exception is raised) */
        && !fmpz_poly_is_zero(g) && !(g->length == 1 && (fmpz_is_pm1(g->coeffs))))
    {
        check_remove(h, g, 0);
        fmpz_poly_pow(f, g, e);
        fmpz_poly_mul(f, f, h);
        check_remove(f, g, (slong) e);
        ok = 0;
    }

    fmpz_poly_clear(g);
    fmpz_poly_clear(h);
    fmpz_poly_clear(f);
    flint_cleanup();
    return ok;
}
