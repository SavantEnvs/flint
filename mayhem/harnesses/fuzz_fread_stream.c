/* Stream readers for integers and polynomials: fmpz_fread (decimal, via mpz_inp_str),
   fmpz_inp_raw (GMP's binary mpz format), fmpz_poly_fread and fmpq_poly_fread
   ("<len>  <c0> <c1> ..." read with mpz_inp_str/mpq_inp_str), nmod_poly_fread
   ("<len> <modulus>  <c0> <c1> ..." read with fscanf) and fmpz_mod_poly_fread
   ("<len> <modulus>  <c0> ...", the format of fmpz_mod_poly_fprint). Input: byte 0 selects
   the reader, the rest is the stream. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <flint/flint.h>
#include <flint/fmpz.h>
#include <flint/fmpz_poly.h>
#include <flint/fmpq_poly.h>
#include <flint/nmod_poly.h>
#include <flint/fmpz_mod.h>
#include <flint/fmpz_mod_poly.h>
#include "common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
        return -1;

    int which = data[0] % 6;
    const uint8_t *body = data + 1;
    size_t blen = size - 1;
    int ok = -1;

    if (which == 3)
    {
        /* mpz_inp_raw: 4-byte big-endian byte count, then the magnitude; a count of
           gigabytes is a request for gigabytes (sizes are unchecked, see security.md) */
        if (blen < 4)
            return -1;
        uint32_t n = ((uint32_t) body[0] << 24) | ((uint32_t) body[1] << 16)
                   | ((uint32_t) body[2] << 8) | body[3];
        if ((int32_t) n > 4096 || (int32_t) n < -4096)
            return -1;
    }
    else if (which != 0)
    {
        /* The polynomial readers take the length first (mpz_inp_str, or fscanf "%wd" for
           nmod_poly and fmpz_mod_poly: leading whitespace, an optional sign, decimal
           digits) and allocate it before reading any coefficient: an announced length of
           billions is a request for gigabytes (security.md: the parsers "trust the sizes in
           their input"), so a positive length is kept to 4096. Its magnitude is bounded the
           same way when it is negative: fmpz_poly_fread deliberately throws on a length that
           does not fit a slong (src/fmpz_poly/io.c), and fscanf's behaviour on an
           out-of-range "%wd" is undefined (C11 7.21.6.2p10). Nothing else is filtered: a
           small negative length, a missing or short coefficient list and arbitrary separators
           all reach the reader. */
        size_t i = 0;
        while (i < blen && isspace(body[i]))
            i++;
        if (i < blen && (body[i] == '-' || body[i] == '+'))
            i++;
        long len = 0;
        for (; i < blen && body[i] >= '0' && body[i] <= '9'; i++)
            if ((len = 10 * len + (body[i] - '0')) > 4096)
                return -1;
        /* fmpq_poly_fread reads each coefficient with mpq_inp_str; a literal zero
           denominator is undefined in GMP and then divides by zero */
        if (which == 2 && mayhem_zero_den_range((const char *) body, (const char *) body + blen, 0))
            return -1;
    }

    FILE *f = fmemopen((void *) body, blen, "rb");
    if (f == NULL)
        return -1;

    if (which == 0)
    {
        fmpz_t z;
        fmpz_init(z);
        if (fmpz_fread(f, z) == 1)
            ok = 0;
        fmpz_clear(z);
    }
    else if (which == 1)
    {
        fmpz_poly_t p;
        fmpz_poly_init(p);
        if (fmpz_poly_fread(f, p) > 0)
            ok = 0;
        fmpz_poly_clear(p);
    }
    else if (which == 2)
    {
        fmpq_poly_t p;
        fmpq_poly_init(p);
        if (fmpq_poly_fread(f, p) > 0)
            ok = 0;
        fmpq_poly_clear(p);
    }
    else if (which == 4)
    {
        /* reinitialises the polynomial with the modulus it reads */
        nmod_poly_t p;
        nmod_poly_init(p, 2);
        if (nmod_poly_fread(f, p) > 0)
            ok = 0;
        nmod_poly_clear(p);
    }
    else if (which == 5)
    {
        /* sets the context's modulus to the one it reads (documented: at least 2) */
        fmpz_mod_ctx_t ctx;
        fmpz_mod_poly_t p;
        fmpz_mod_ctx_init_ui(ctx, 2);
        fmpz_mod_poly_init(p, ctx);
        if (fmpz_mod_poly_fread(f, p, ctx) > 0)
            ok = 0;
        fmpz_mod_poly_clear(p, ctx);
        fmpz_mod_ctx_clear(ctx);
    }
    else
    {
        fmpz_t z;
        fmpz_init(z);
        if (fmpz_inp_raw(z, f) > 0)
            ok = 0;
        fmpz_clear(z);
    }

    fclose(f);
    flint_cleanup();
    return ok;
}
