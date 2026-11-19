/* arb_load_str, arf_load_str and mag_load_str: the readers for stored values written by
   the matching *_dump_str (hexadecimal mantissa and exponent, separated by spaces;
   doc/src/arb/index.md, doc/src/arf/index.md). Each documents a nonzero return on a
   format error. Input: byte 0 selects the reader, the rest is the string. A value that
   loads is dumped again and must load back exactly. */
#include <flint/flint.h>
#include <flint/arf.h>
#include <flint/mag.h>
#include <flint/arb.h>
#include "common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return -1;

    char *s = mayhem_cstr(data + 1, size - 1);
    int ok = -1;
    char *t;

    switch (data[0] % 3)
    {
        case 0:
        {
            arb_t x, y;
            arb_init(x);
            arb_init(y);
            if (arb_load_str(x, s) == 0)
            {
                t = arb_dump_str(x);
                if (arb_load_str(y, t) != 0 || !arb_equal(x, y))
                    flint_abort();
                flint_free(t);
                ok = 0;
            }
            arb_clear(x);
            arb_clear(y);
            break;
        }
        case 1:
        {
            arf_t x, y;
            arf_init(x);
            arf_init(y);
            if (arf_load_str(x, s) == 0)
            {
                t = arf_dump_str(x);
                if (arf_load_str(y, t) != 0 || !arf_equal(x, y))
                    flint_abort();
                flint_free(t);
                ok = 0;
            }
            arf_clear(x);
            arf_clear(y);
            break;
        }
        default:
        {
            mag_t x, y;
            mag_init(x);
            mag_init(y);
            if (mag_load_str(x, s) == 0)
            {
                t = mag_dump_str(x);
                if (mag_load_str(y, t) != 0 || !mag_equal(x, y))
                    flint_abort();
                flint_free(t);
                ok = 0;
            }
            mag_clear(x);
            mag_clear(y);
            break;
        }
    }

    free(s);
    flint_cleanup();
    return ok;
}
