#ifndef MAYHEM_COMMON_H
#define MAYHEM_COMMON_H

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* NUL-terminated copy of the fuzzer bytes, so the library's C-string parsers
   see exactly the input (they cannot be handed a non-terminated buffer). */
static inline char *mayhem_cstr(const uint8_t *data, size_t size)
{
    char *s = (char *) malloc(size + 1);
    if (size)
        memcpy(s, data, size);
    s[size] = '\0';
    return s;
}

/* Contract of the "<len>  <c0> <c1> ..." polynomial strings: the announced
   length is a plain number, bounded so that it cannot request terabytes, and
   the string really holds that many space-separated coefficients (upstream's
   doc/src/guide/correctness/security.md documents that the parsers read past
   the end of a string that does not, and allocate the announced length
   unchecked; see there). Mirrors the scan in _fmpz_poly_set_str. */
static inline int mayhem_poly_str_contract(const char *s)
{
    char *end;
    if (s[0] < '0' || s[0] > '9')
        return 0;
    long len = strtol(s, &end, 10);
    if (len < 0 || len > 4096)
        return 0;
    if (len == 0)
        return 1;
    const char *p = strchr(s, ' ');
    if (p == NULL)
        return 0;
    p++;
    for (long i = 0; i < len; i++)
    {
        if (*p == '\0')
            return 0;
        for (p++; *p != ' ' && *p != '\0'; p++)
            ;
    }
    return 1;
}

/* A literal zero divisor ("/0", "/-00", "/\t0", "/0\n0"). mpq_set_str leaves a zero denominator
   undefined (GMP manual) and the polynomial parsers then divide by it (SIGFPE); the pretty-printed
   parsers throw "Divide by zero". The harnesses leave such inputs out; a divisor that only
   evaluates to zero ("x/(y-y)") still reaches the library. Each '/' in [s, end) is read the way the
   GMP routine that reads the denominator reads it: with ws_in_digits (mpz_set_str) any isspace
   character is skipped wherever it occurs, inside the digits too, then signs, then the digits up to
   the first other character; without it (mpz_inp_str) the digits must follow the '/' directly and
   end at the first other character. */
static inline int mayhem_zero_den_range(const char *s, const char *end, int ws_in_digits)
{
    for (const char *p = s; p < end; p++)
    {
        if (*p != '/')
            continue;
        const char *q = p + 1;
        while (q < end && ((ws_in_digits && isspace((unsigned char) *q)) || *q == '+' || *q == '-'))
            q++;
        int digits = 0, nonzero = 0;
        for (; q < end && ((*q >= '0' && *q <= '9') || (ws_in_digits && isspace((unsigned char) *q))); q++)
        {
            if (!isspace((unsigned char) *q))
            {
                digits = 1;
                nonzero |= (*q != '0');
            }
        }
        if (digits && !nonzero)
            return 1;
    }
    return 0;
}

/* fmpq_set_str and the pretty-printed parsers hand the whole string to mpz_set_str-style readers. */
static inline int mayhem_zero_denominator(const char *s)
{
    return mayhem_zero_den_range(s, s + strlen(s), 1);
}

/* _fmpq_poly_set_str cuts the coefficients at ' ' only and gives each token to mpq_set_str, so a
   denominator never extends past a ' ': the scan runs inside each ' '-separated token. */
static inline int mayhem_zero_denominator_tokens(const char *s)
{
    const char *end = s + strlen(s);
    for (const char *a = s; a <= end;)
    {
        const char *b = a;
        while (b < end && *b != ' ')
            b++;
        if (mayhem_zero_den_range(a, b, 1))
            return 1;
        a = b + 1;
    }
    return 0;
}

/* Sizes are not bounded anywhere in the expression parsers (upstream's
   doc/src/guide/correctness/security.md), and they evaluate what they read exactly: "a^e" is
   a to the power e, so the size of a value multiplies by e. The harnesses keep the product of
   the exponents that apply to any one subexpression at 99, the same as one two-digit exponent:
   "(x+1)^99" is read, "((x^9)^9)" too, but "((2^99)^99)^99" is a request for gigabytes
   (2^(99^5) asked for 2.8 GB), and so is a power tower "50^8^50" or an exponent that is itself
   an expression ("2^(99*99*99)", "2^99e9"). An exponent must therefore be a signed literal of
   one or two digits, optionally in one pair of parentheses, followed by an operator, ')' or
   the end. */
static inline long mayhem_pow_literal(const char *p, const char **after)
{
    const char *q = p + 1;
    int paren = 0;
    while (*q == ' ' || *q == '+' || *q == '-')
        q++;
    if (*q == '(')
    {
        paren = 1;
        for (q++; *q == ' ' || *q == '+' || *q == '-'; q++)
            ;
    }
    int n = 0;
    long v = 0;
    for (; q[n] >= '0' && q[n] <= '9'; n++)
    {
        if (n == 2)   /* more than two digits: refuse before accumulating */
            return -1;
        v = 10 * v + (q[n] - '0');
    }
    if (n < 1)
        return -1;
    for (q += n; *q == ' '; q++)
        ;
    if (paren)
    {
        if (*q != ')')
            return -1;
        for (q++; *q == ' '; q++)
            ;
    }
    if (*q != '\0' && *q != ')' && *q != '+' && *q != '-' && *q != '*' && *q != '/')
        return -1;
    *after = q;
    return v;
}

static inline int mayhem_big_exponent(const char *s)
{
    long group[64];      /* largest exponent product inside each open parenthesis */
    int d = 0, after_group = 0;
    long closed = 1;     /* product of the group that was just closed */
    group[0] = 1;
    for (const char *p = s; *p; p++)
    {
        if (*p == ' ')
            continue;
        if (*p == '(')
        {
            if (d == 63)
                return 1;
            group[++d] = 1;
            after_group = 0;
        }
        else if (*p == ')')
        {
            closed = d > 0 ? group[d--] : 1;
            if (closed > group[d])
                group[d] = closed;
            after_group = 1;
        }
        else if (*p == '^')
        {
            const char *after;
            long e = mayhem_pow_literal(p, &after);
            if (e < 0)
                return 1;
            long v = (after_group ? closed : 1) * (e > 1 ? e : 1);
            if (v > 99)
                return 1;
            if (v > group[d])
                group[d] = v;
            p = after - 1;
            after_group = 0;
        }
        else
            after_group = 0;
    }
    return 0;
}

/* gr_set_str also reads the functions fac, gamma and zeta (gr_generic/set_str_expr.c). In an
   exact ring fac(n) has n*log(n) bits, and gamma and zeta at integers are factorials and
   Bernoulli numbers, so their argument is the same unbounded size request ("fac11e9" asked for
   4 GB). The gr harness takes them only on an unsigned literal of at most three digits, or a
   signed one in parentheses: "fac 999", "fac(-12)". */
static inline int mayhem_big_function(const char *s)
{
    static const char *const names[] = { "fac", "gamma", "zeta" };
    for (int i = 0; i < 3; i++)
    {
        size_t len = strlen(names[i]);
        for (const char *p = strstr(s, names[i]); p != NULL; p = strstr(p + 1, names[i]))
        {
            const char *q = p + len;
            int paren = 0;
            /* a sign after the name widens the argument: "fac+3^2" is fac(9) */
            while (*q == ' ')
                q++;
            if (*q == '(')
            {
                paren = 1;
                for (q++; *q == ' ' || *q == '+' || *q == '-'; q++)
                    ;
            }
            int n = 0;
            while (q[n] >= '0' && q[n] <= '9')
                n++;
            if (n < 1 || n > 3 || isalnum((unsigned char) q[n]) || q[n] == '.' || q[n] == '_')
                return 1;
            if (paren)
            {
                for (q += n; *q == ' '; q++)
                    ;
                if (*q != ')')
                    return 1;
            }
        }
    }
    return 0;
}

/* A decimal literal with a scientific exponent ("4e-9337444873") is, in an exact ring,
   the exact rational 4/10^9337444873: the same unbounded size request as a big "^". */
static inline int mayhem_big_sci_exponent(const char *s)
{
    for (const char *p = s; *p; p++)
    {
        if ((*p != 'e' && *p != 'E') || p == s || !((p[-1] >= '0' && p[-1] <= '9') || p[-1] == '.'))
            continue;
        const char *q = p + 1;
        if (*q == '+' || *q == '-')
            q++;
        int n = 0;
        while (q[n] >= '0' && q[n] <= '9')
            n++;
        if (n > 4)
            return 1;
    }
    return 0;
}

#endif
