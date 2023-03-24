//  test_main.c

//  === Raccoon testing main

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "raccoon.h"
#include "mont64.h"
#include "plat_local.h"
#include "polyr.h"

//  Fake random number generator

static int64_t debug_seedq = 0;

/*
    linear congurential generator: x' = (x + c) * g  (mod q)

    q = 549824583172097
    c = 314159265358979
    g = 123456790123
*/

static inline int64_t debug_randq()
{
    debug_seedq = mont64_cadd(
        mont64_mulq(
            debug_seedq + 314159265358979LL,
            471255603307124LL),  // Montgomery representation: (2^64 * g) % q
                RACC_Q );

    return debug_seedq;
}

//  [debug] Trivial PRNG for testing purposes.

void randombytes(uint8_t *d, size_t d_sz)
{
    size_t i;

    for (i = 0; i < d_sz; i++) {
        d[i] = debug_randq() & 0xFF;
    }
}

//  [debug] sample a polynomial

void random_poly(int64_t *v)
{
    size_t i;

    for (i = 0; i < RACC_N; i++) {
        v[i] = debug_randq();
    }
}

//  [debug] additive remask of two polynommials

void remask_poly(int64_t *v0, int64_t *v1)
{
    size_t i;
    int64_t x;

    for (i = 0; i < RACC_N; i++) {
        x = debug_randq();
        v0[i] = mont64_csub(v0[i] + x, RACC_Q);
        v1[i] = mont64_cadd(v1[i] - x, RACC_Q);
    }
}

//  [debug] polynomial (mod q) checksum of matrices/vectors

int64_t debug_qsum(const char *lab, const void *m, size_t d1, size_t d2)
{
    size_t i;
    const int64_t *v = (const int64_t *)m;
    int64_t s;

    s = 31337;
    for (i = 0; i < (d1 * d2 * RACC_N); i++) {
        s = (RACC_Q + 3 * s + v[i]) % RACC_Q;
    }
    printf("%s[%zu][%zu][%u]: %lu\n", lab, d1, d2, RACC_N, s);

    return s;
}

//  [debug] dump a hex stpolyr

void debug_hex(const char *lab, const uint8_t *d, size_t d_sz)
{
    size_t i;
    printf("%s: ", lab);
    for (i = 0; i < d_sz; i++) {
        printf("%02x", d[i]);
    }
    printf("\n");
}

//  standard library process time

static inline double cpu_clock_secs()
{
    return ((double)clock()) / ((double)CLOCKS_PER_SEC);
}

//  [debug] inverse-ntt and compute checksum of matrices/vectors

int64_t debug_intt_qsum(const char *lab, const void *m, size_t d1, size_t d2)
{
    size_t i, j;
    const int64_t *v = (const int64_t *)m;
    int64_t t[RACC_N];
    int64_t s;

    s = 31337;
    for (i = 0; i < (d1 * d2); i++) {

        for (j = 0; j < RACC_N; j++) {  //  copy a polynomial
            t[j] = v[i * RACC_N + j];
        }
        polyr_intt(t);        //    inverse-NTT
        polyr_smul(t, t, 1);  //    Montgomery scaling

        for (j = 0; j < RACC_N; j++) {
            s = (RACC_Q + 3 * s + t[j]) % RACC_Q;
        }
    }
    printf("%s[%zu][%zu][%u]: %lu\n", lab, d1, d2, RACC_N, s);

    return s;
}

//  === raccoon_ref.c

void racc_keygen_ref(racc_pk_t *pk, racc_sk_t *sk);
void racc_sign_ref(racc_sig_t *sig, const uint8_t *msg, size_t mlen, racc_sk_t *sk);
bool racc_verify_ref(const racc_sig_t *sig, const uint8_t *msg, size_t mlen,
                     const racc_pk_t *pk);

int main()
{
    size_t i, iter = 100;
    const uint8_t msg[] = "abc";
    size_t mlen = 3;
    double ts, to;
    uint64_t cc;
    bool rsp;

    racc_pk_t pk;    // public key
    racc_sk_t sk;    // secret key
    racc_sig_t sig;  // signature

    //  === keygen
    printf("=== KeyGen ===\n");
    debug_seedq = 1;

    racc_keygen_ref(&pk, &sk);
    debug_hex("A_seed", pk.a_seed, RACC_SEC);
    debug_qsum("t", pk.t, 1, RACC_K);
    debug_intt_qsum("s", sk.s, RACC_ELL, RACC_D);

    //  === sign
    printf("=== Sign ===\n");
    debug_seedq = 2;

    racc_sign_ref(&sig, msg, mlen, &sk);
    debug_hex("c_hash", sig.ch, RACC_SEC);
    debug_intt_qsum("z", sig.z, 1, RACC_ELL);
    debug_qsum("h", sig.h, 1, RACC_K);

    //  === verify
    printf("=== Verify ===\n");

    rsp = racc_verify_ref(&sig, msg, mlen, &pk);
    printf("Verification: %s\n", rsp ? "True" : "False");

    printf("=== Check Main ===\n");

    racc_keygen(&pk, &sk);
    racc_sign(&sig, msg, mlen, &sk);
    rsp = racc_verify(&sig, msg, mlen, &pk);
    printf("Verification: %s\n", rsp ? "True" : "False");

    printf("=== Bench ===\n");

#ifndef RACC_BENCH
    to = 1.0;  //   timeout threshold (seconds)
#else
    to = RACC_BENCH ;
#endif
    printf("Raccoon-%d_%d\n", 8 * RACC_SEC, RACC_D);

    iter = 16;
    do {
        iter *= 2;
        ts = cpu_clock_secs();
        cc = plat_get_cycle();

        for (i = 0; i < iter; i++) {
            racc_keygen(&pk, &sk);
        }
        cc = plat_get_cycle() - cc;
        ts = cpu_clock_secs() - ts;
        fflush(stdout);
    } while (ts < to);
    printf("\tKeyGen() %5zu: %8.3f ms  %8lu cyc\n",
            iter, 1000.0 * ts / ((double)iter), cc / iter);

    iter = 16;
    do {
        iter *= 2;
        racc_keygen(&pk, &sk);
        ts = cpu_clock_secs();
        cc = plat_get_cycle();

        for (i = 0; i < iter; i++) {
            racc_sign(&sig, msg, mlen, &sk);
        }
        cc = plat_get_cycle() - cc;
        ts = cpu_clock_secs() - ts;
    } while (ts < to);
    printf("\t  Sign() %5zu: %8.3f ms  %8lu cyc\n",
        iter, 1000.0 * ts / ((double)iter), cc / iter);

    iter = 16;
    do {
        iter *= 2;
        racc_keygen(&pk, &sk);
        racc_sign(&sig, msg, mlen, &sk);
        ts = cpu_clock_secs();
        cc = plat_get_cycle();

        //  repeats the same verify..
        for (i = 0; i < iter; i++) {
            rsp = racc_verify(&sig, msg, mlen, &pk);
        }
        cc = plat_get_cycle() - cc;
        ts = cpu_clock_secs() - ts;
    } while (ts < to);
    printf("\t Verif() %5zu: %8.3f ms  %8lu cyc\n",
        iter, 1000.0 * ts / ((double)iter), cc / iter);

    return 0;
}
