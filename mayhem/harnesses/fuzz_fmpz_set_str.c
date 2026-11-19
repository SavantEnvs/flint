/* fmpz_set_str / fmpq_set_str: the integer and rational string parsers.
   Input: byte 0 selects the base (2..62), the rest is the string. */
#include <flint/flint.h>
#include <flint/fmpz.h>
#include <flint/fmpq.h>
#include "common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return -1;

    int base = 2 + data[0] % 61;
    char *s = mayhem_cstr(data + 1, size - 1);

    int ok = -1;
    fmpz_t z, w;
    fmpz_init(z);
    fmpz_init(w);

    if (fmpz_set_str(z, s, base) == 0)
    {
        char *t = fmpz_get_str(NULL, base, z);
        if (fmpz_set_str(w, t, base) != 0 || !fmpz_equal(z, w))
            flint_abort();
        flint_free(t);
        ok = 0;
    }

    fmpq_t q, r;
    fmpq_init(q);
    fmpq_init(r);

    if (fmpq_set_str(q, s, base) == 0 && !fmpz_is_zero(fmpq_denref(q)))
    {
        /* fmpq_set_str, like mpq_set_str, does not canonicalise (documented) */
        fmpq_canonicalise(q);
        char *t = fmpq_get_str(NULL, base, q);
        if (fmpq_set_str(r, t, base) != 0 || !fmpq_equal(q, r))
            flint_abort();
        flint_free(t);
        ok = 0;
    }

    fmpq_clear(q);
    fmpq_clear(r);
    fmpz_clear(z);
    fmpz_clear(w);
    free(s);
    flint_cleanup();
    return ok;
}
