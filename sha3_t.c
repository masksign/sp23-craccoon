//  sha3_t.c

//  === Common wrappers for  SHA3 (FIPS 202) functionality.

#include <string.h>

#include "sha3_t.h"
#include "keccakf1600.h"

//  Initialize the Keccak context "kec" for algorithm-specific rate "r".

void sha3_init(sha3_t* kec, size_t r)
{
    keccak_clear(kec->s);
    kec->i = 0;
    kec->r = r;
}

//  Absorb "mlen" bytes from "m" into the Keccak context "kec".

void sha3_absorb(sha3_t* kec, const uint8_t* m, size_t mlen)
{
    size_t l;

    l = kec->r - kec->i;
    if (mlen < l) {
        memcpy(kec->b + kec->i, m, mlen);
        kec->i += mlen;
        return;
    }
    if (kec->i > 0) {
        memcpy(kec->b + kec->i, m, l);
        keccak_xorbytes(kec->s, kec->b, kec->r);
        keccak_f1600(kec->s);
        mlen -= l;
        m += l;
        kec->i = 0;
    }
    while (mlen >= kec->r) {
        keccak_xorbytes(kec->s, m, kec->r);
        keccak_f1600(kec->s);
        mlen -= kec->r;
        m += kec->r;
    }
    memcpy(kec->b, m, mlen);
    kec->i = mlen;
}

//  Move from absorb phase to squeeze phase and add a padding byte "p".

void sha3_pad(sha3_t* kec, uint8_t p)
{
    kec->b[kec->i++] = p;
    memset(kec->b + kec->i, 0, kec->r - kec->i);
    kec->b[kec->r - 1] |= 0x80;
    keccak_xorbytes(kec->s, kec->b, kec->r);
    kec->i = kec->r;
}

//  Squeeze "hlen" bytes to address "h" from Keccak context "kec".

void sha3_squeeze(sha3_t* kec, uint8_t* h, size_t hlen)
{
    size_t l;

    while (hlen > 0) {
        if (kec->i >= kec->r) {
            keccak_f1600(kec->s);
            keccak_extract(kec->s, kec->b, kec->r);
            kec->i = 0;
        }
        l = kec->r - kec->i;
        if (hlen <= l) {
            memcpy(h, kec->b + kec->i, hlen);
            kec->i += hlen;
            return;
        }
        memcpy(h, kec->b + kec->i, l);
        h += l;
        hlen -= l;
        kec->i += l;
    }
}

//  Clear sensitive information from the Keccak context "kec."

void sha3_clear(sha3_t* kec)
{
    memset(kec, 0, sizeof(sha3_t));
}

//  init, absorb and pad

void keccak_absorb(uint64_t* st, size_t r, const uint8_t* m, size_t mlen,
                   uint8_t p)
{
    uint8_t buf[200];

    //  clear state
    keccak_clear(st);

    //  full blocks
    while (mlen >= r) {
        keccak_xorbytes(st, m, r);
        keccak_f1600(st);
        mlen -= r;
        m += r;
    }

    //  padding
    memcpy(buf, m, mlen);
    buf[mlen++] = p;
    memset(buf + mlen, 0, r - mlen);
    buf[r - 1] |= 0x80;
    keccak_xorbytes(st, buf, r);
}

//  single-call hash

void sha3_hash(uint8_t* h, size_t hlen, const uint8_t* m, size_t mlen)
{
    uint64_t st[25];
    uint8_t buf[64];

    keccak_absorb(st, 200 - 2 * hlen, m, mlen, SHA3_PAD);
    keccak_f1600(st);
    keccak_extract(st, buf, 8 * ((hlen + 7) / 8));
    memcpy(h, buf, hlen);
}

//  shake xof (r < 200 needs to be divisible by 8)

void shake_xof(uint8_t* h, size_t hlen, const uint8_t* m, size_t mlen, size_t r)
{
    uint64_t st[25];
    uint8_t buf[r];

    keccak_absorb(st, r, m, mlen, SHAKE_PAD);

    while (hlen >= r) {
        keccak_f1600(st);
        keccak_extract(st, h, r);
        h += r;
        hlen -= r;
    }
    if (hlen > 0) {
        keccak_f1600(st);
        keccak_extract(st, buf, r);
        memcpy(h, buf, hlen);
    }
}
