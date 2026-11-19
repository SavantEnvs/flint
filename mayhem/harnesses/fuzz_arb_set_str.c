/* arb_set_str: the real-ball parser (decimal literals, "[m +/- r]" balls).
   Input: bytes 0-1 = working precision, the rest is the string. */
#include <flint/flint.h>
#include <flint/arb.h>
#include "common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
        return -1;

    slong prec = 2 + ((data[0] | (data[1] << 8)) % 2048);
    char *s = mayhem_cstr(data + 2, size - 2);
    int ok = -1;

    arb_t x, y;
    arb_init(x);
    arb_init(y);

    if (arb_set_str(x, s, prec) == 0)
    {
        char *t = arb_get_str(x, 20, 0);
        /* the printed ball always contains the value it was printed from */
        if (arb_is_finite(x) && arb_set_str(y, t, prec) == 0 && !arb_overlaps(x, y))
            flint_abort();
        flint_free(t);
        ok = 0;
    }

    arb_clear(x);
    arb_clear(y);
    free(s);
    flint_cleanup();
    return ok;
}
