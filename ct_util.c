//  ct_util.c

//  === Generic constant time utilities.

#include "ct_util.h"

//  returns true for equal strings, false for non-equal strings

bool ct_equal(const volatile void *a, const volatile void *b, size_t len)
{
    size_t i;
    uint32_t r;

    r = 0;
    for (i = 0; i < len; i++) {
        r |= ((const uint8_t *)a)[i] ^ ((const uint8_t *)b)[i];
    }
    return (((-r) >> 31) & 1) ^ 1;
}

//  conditional move. b = 1: move x to r, b = 0: don't move, just process

void ct_cmov(volatile uint8_t *r, const volatile uint8_t *x, size_t len,
             uint8_t b)
{
    size_t i;

    b = -b;
    for (i = 0; i < len; i++) {
        r[i] ^= b & (x[i] ^ r[i]);
    }
}
