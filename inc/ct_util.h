//  ct_util.h

//  === Generic constant time utilities.

#ifndef _CT_UTIL_H_
#define _CT_UTIL_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

//  returns true for equal strings, false for non-equal strings
bool ct_equal(const volatile void *a, const volatile void *b, size_t len);

//  conditional move. b = 1: move x to r, b = 0: don't move, just process
void ct_cmov(volatile uint8_t *r, const volatile uint8_t *x, size_t len,
             uint8_t b);

//  copy memory
void ct_memcpy(volatile void *dest, const volatile void *src, size_t len);

//  _CT_UTIL_H_
#endif

