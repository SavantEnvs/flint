/* fmpz_poly_set_str / fmpq_poly_set_str: the polynomial
   string parsers ("<len>  <c0> <c1> ..."), and fmpz_poly_q_set_str, which reads one such
   fmpz_poly string or two separated by '/'. Input: byte 0 selects the parser. */
#include <flint/flint.h>
#include <flint/fmpz_poly.h>
#include <flint/fmpq_poly.h>
#include <flint/fmpz_poly_q.h>
#include "common.h"

/* fmpz_poly_q_set_str cuts the string at the first '/' and hands each side to
   fmpz_poly_set_str, so each side carries that parser's contract (above). Its documentation
   (doc/src/fmpz_poly_q) also says that a denominator describing the zero polynomial raises an
   exception, so such a denominator is left out too: it is the documented behaviour. */
static inline int mayhem_poly_q_str_contract(const char *s)
{
    const char *slash = strchr(s, '/');
    if (slash == NULL)
        return mayhem_poly_str_contract(s);
    size_t m = (size_t) (slash - s);
    char *num = (char *) malloc(m + 1);
    memcpy(num, s, m);
    num[m] = '\0';
    int ok = mayhem_poly_str_contract(num) && mayhem_poly_str_contract(slash + 1);
    free(num);
    if (ok)
    {
        /* the zero polynomial is "0", or any length whose coefficients are all zero */
        fmpz_poly_t d;
        fmpz_poly_init(d);
        if (fmpz_poly_set_str(d, slash + 1) == 0 && fmpz_poly_is_zero(d))
            ok = 0;
        fmpz_poly_clear(d);
    }
    return ok;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return -1;

    int which = data[0] % 3;
    char *s = mayhem_cstr(data + 1, size - 1);
    int ok = -1;

    if (which == 2)
    {
        if (!mayhem_poly_q_str_contract(s))
        {
            free(s);
            return -1;
        }
    }
    else if (!mayhem_poly_str_contract(s) || (which == 1 && mayhem_zero_denominator_tokens(s)))
    {
        free(s);
        return -1;
    }

    if (which == 0)
    {
        fmpz_poly_t a, b;
        fmpz_poly_init(a);
        fmpz_poly_init(b);
        if (fmpz_poly_set_str(a, s) == 0)
        {
            char *t = fmpz_poly_get_str(a);
            if (fmpz_poly_set_str(b, t) != 0 || !fmpz_poly_equal(a, b))
                flint_abort();
            flint_free(t);
            ok = 0;
        }
        fmpz_poly_clear(a);
        fmpz_poly_clear(b);
    }
    else if (which == 1)
    {
        fmpq_poly_t a, b;
        fmpq_poly_init(a);
        fmpq_poly_init(b);
        if (fmpq_poly_set_str(a, s) == 0)
        {
            /* canonical only if every coefficient is in lowest terms (documented) */
            fmpq_poly_canonicalise(a);
            char *t = fmpq_poly_get_str(a);
            if (fmpq_poly_set_str(b, t) != 0 || !fmpq_poly_equal(a, b))
                flint_abort();
            flint_free(t);
            ok = 0;
        }
        fmpq_poly_clear(a);
        fmpq_poly_clear(b);
    }
    else
    {
        fmpz_poly_q_t a, b;
        fmpz_poly_q_init(a);
        fmpz_poly_q_init(b);
        if (fmpz_poly_q_set_str(a, s) == 0)
        {
            char *t = fmpz_poly_q_get_str(a);
            if (fmpz_poly_q_set_str(b, t) != 0 || !fmpz_poly_q_equal(a, b))
                flint_abort();
            flint_free(t);
            ok = 0;
        }
        fmpz_poly_q_clear(a);
        fmpz_poly_q_clear(b);
    }

    free(s);
    flint_cleanup();
    return ok;
}
