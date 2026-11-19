/* ecpp_cert_set_str: the reader for elliptic-curve primality certificates, in FLINT's
   labelled format ("ecpp certificate, k steps\n[0] n = ...") or PARI/GP's
   ([[N, t, s, a, [x, y]], ...]); doc/src/ecpp/index.md: "Returns 1 on success, and 0,
   leaving an empty certificate, if the string is malformed". A certificate is exactly the
   kind of data that comes from someone else, to be checked with ecpp_verify, so a
   certificate that reads is then verified against its own n_0, written back in the format
   it was read in, and must read back to the same steps (the PARI format does not carry D,
   upstream's t-cert_str). Input: the whole string. */
#include <flint/flint.h>
#include <flint/fmpz.h>
#include <flint/ecpp.h>
#include "common.h"

static int same_step(const ecpp_step_struct *a, const ecpp_step_struct *b, int pari)
{
    return fmpz_equal(a->n, b->n) && fmpz_equal(a->a, b->a) && fmpz_equal(a->b, b->b)
        && fmpz_equal(a->m, b->m) && fmpz_equal(a->q, b->q) && fmpz_equal(a->x, b->x)
        && fmpz_equal(a->y, b->y) && (pari || a->D == b->D);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *s = mayhem_cstr(data, size);
    ecpp_cert_t cert, cert2;
    int ok = -1;

    ecpp_cert_init(cert);
    ecpp_cert_init(cert2);
    if (ecpp_cert_set_str(cert, s))
    {
        const char *p = s;
        while (*p == ' ' || *p == '\n' || *p == '\t' || *p == '\r')
            p++;
        int pari = (*p == '[');
        fmpz_t n;
        fmpz_init_set(n, cert->steps[0].n);
        (void) ecpp_verify(cert, n);
        fmpz_clear(n);

        char *t = ecpp_cert_get_str(cert, pari ? ECPP_CERT_FORMAT_PARI : ECPP_CERT_FORMAT_FLINT);
        if (!ecpp_cert_set_str(cert2, t) || cert2->num != cert->num)
            flint_abort();
        for (slong i = 0; i < cert->num; i++)
            if (!same_step(cert->steps + i, cert2->steps + i, pari))
                flint_abort();
        flint_free(t);
        ok = 0;
    }
    ecpp_cert_clear(cert);
    ecpp_cert_clear(cert2);
    free(s);
    flint_cleanup();
    return ok;
}
