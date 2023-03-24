//  sha3_t.h

//  === SHA3 (FIPS 202) related prototypes and shared functions.

#ifndef _PQHM_SHA3_H_
#define _PQHM_SHA3_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "plat_local.h"

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_224_RATE 144
#define SHA3_256_RATE 136
#define SHA3_384_RATE 104
#define SHA3_512_RATE 72

#define SHA3_PAD 0x06
#define SHAKE_PAD 0x1F


//  === Incremental interface for FIPS 202 functions ===

typedef struct {
    uint8_t b[200];
    uint64_t s[25];
    size_t r, i;
} sha3_t;

//  Initialize the Keccak constant for algorithm-specific rate "r".

void sha3_init(sha3_t* kec, size_t r);

//  Absorb "mlen" bytes from "m" into the Keccak context "kec".

void sha3_absorb(sha3_t* kec, const uint8_t* m, size_t mlen);

//  Move from absorb phase to squeeze phase and add a padding byte "p".

void sha3_pad(sha3_t* kec, uint8_t p);

//  Squeeze "hlen" bytes to address "h" from Keccak context "kec".

void sha3_squeeze(sha3_t* kec, uint8_t* h, size_t hlen);

//  Clear sensitive information from the Keccak context "kec."

void sha3_clear(sha3_t* kec);

//  === Single-call SHA3 hash interface ===

void sha3_hash(uint8_t* h, size_t hlen, const uint8_t* m, size_t mlen);

#define sha3_224(h, m, mlen) sha3_hash(h, 28, m, mlen)
#define sha3_256(h, m, mlen) sha3_hash(h, 32, m, mlen)
#define sha3_384(h, m, mlen) sha3_hash(h, 48, m, mlen)
#define sha3_512(h, m, mlen) sha3_hash(h, 64, m, mlen)

//  === Single-call SHAKE XOF interface ===

void shake_xof(uint8_t* h, size_t hlen, const uint8_t* m, size_t mlen,
               size_t r);

#define shake128(h, hlen, m, mlen) shake_xof(h, hlen, m, mlen, SHAKE128_RATE)
#define shake256(h, hlen, m, mlen) shake_xof(h, hlen, m, mlen, SHAKE256_RATE)

#ifdef __cplusplus
}
#endif

//  _PQHM_SHA3_H_
#endif
