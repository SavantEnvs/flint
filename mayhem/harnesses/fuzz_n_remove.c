/* n_remove / n_remove2_precomp / fmpz_remove: strip the largest power of p from n.
   Input: [8 bytes n][8 bytes p][1 byte limb count a][1 byte limb count b][a limbs op][b limbs f]. */
#include <flint/flint.h>
#include <flint/ulong_extras.h>
#include <flint/fmpz.h>
#include "common.h"

static void check_split(const fmpz_t orig, const fmpz_t rop, const fmpz_t f, slong v)
{
    fmpz_t pw, prod;
    fmpz_init(pw);
    fmpz_init(prod);
    fmpz_pow_ui(pw, f, (ulong) v);
    fmpz_mul(prod, rop, pw);
    if (!fmpz_equal(prod, orig))
        flint_abort();
    if (!fmpz_is_zero(rop) && fmpz_divisible(rop, f))
        flint_abort();
    fmpz_clear(pw);
    fmpz_clear(prod);
}

static void read_fmpz(fmpz_t out, const uint8_t *p, slong limbs)
{
    ulong buf[16];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, p, (size_t) limbs * sizeof(ulong));
    fmpz_set_ui_array(out, buf, limbs);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 18)
        return -1;

    ulong n, p;
    memcpy(&n, data, 8);
    memcpy(&p, data + 8, 8);
    slong la = 1 + data[16] % 4, lb = 1 + data[17] % 2;
    const uint8_t *rest = data + 18;
    size -= 18;

    /* docs: n_remove requires n != 0 and p > 1; fmpz_remove requires f >= 2 */
    if (n == 0 || p < 2 || size < (size_t) (la + lb) * sizeof(ulong))
        return -1;

    ulong m = n;
    int e = n_remove(&m, p);

    fmpz_t on, om, fp;
    fmpz_init_set_ui(on, n);
    fmpz_init_set_ui(om, m);
    fmpz_init_set_ui(fp, p);
    check_split(on, om, fp, e);

    ulong m2 = n;
    int e2 = n_remove2_precomp(&m2, p, n_precompute_inverse(p));
    if (e2 != e || m2 != m)
        flint_abort();

    fmpz_t op, f, rop;
    fmpz_init(op);
    fmpz_init(f);
    fmpz_init(rop);
    read_fmpz(op, rest, la);
    read_fmpz(f, rest + la * sizeof(ulong), lb);
    if (fmpz_cmp_ui(f, 2) >= 0)
    {
        slong v = fmpz_remove(rop, op, f);
        check_split(op, rop, f, v);
    }

    fmpz_clear(on);
    fmpz_clear(om);
    fmpz_clear(fp);
    fmpz_clear(op);
    fmpz_clear(f);
    fmpz_clear(rop);
    flint_cleanup();
    return 0;
}
