//  raccoon.c

//  === Raccoon signature scheme
//  This code diverges from Python reference; order of operations, NTT.

#include <string.h>

#include "plat_local.h"
#include "raccoon.h"
#include "sha3_t.h"
#include "polyr.h"
#include "mont64.h"
#include "ct_util.h"

//  disable SNI refresh
//#define FAST_REFRESH

//  [debug] these are instantiated by "fake" random functions in test_main.c

void randombytes(uint8_t *d, size_t d_sz);
void random_poly(int64_t *v);
void remask_poly(int64_t *v0, int64_t *v1);


//  create the A matrix

static void xof_sample(int64_t *a, size_t n, const uint8_t *a_seed,
                       size_t a_seed_sz)
{
    size_t i;
    uint8_t buf[8];
    int64_t x;
    sha3_t kec;

    sha3_init(&kec, SHAKE256_RATE);
    sha3_absorb(&kec, a_seed, a_seed_sz);
    sha3_pad(&kec, SHAKE_PAD);

    memset(buf, 0, sizeof(buf));  //    holds bytes from XOF

    for (i = 0; i < n; i++) {
        do {
            sha3_squeeze(&kec, buf, (RACC_LGQ + 7) / 8);
            x = get64u_le(buf) & RACC_QMSK;
        } while (x >= RACC_Q);
        a[i] = x;
    }
    sha3_clear(&kec);
}

//  hash w vector into a challenge

static void racc_challenge_hash(uint8_t h[RACC_SEC], const uint8_t *m,
                                size_t msz, const int64_t w[RACC_K][RACC_N])
{
    size_t i, j;
    uint8_t buf[8];
    sha3_t kec;

    sha3_init(&kec, SHAKE256_RATE);

    for (i = 0; i < RACC_K; i++) {
        for (j = 0; j < RACC_N; j++) {
            put64u_le(buf, w[i][j]);
            sha3_absorb(&kec, buf, (RACC_LGW + 7) / 8);
        }
    }
    sha3_absorb(&kec, m, msz);
    sha3_pad(&kec, SHAKE_PAD);
    sha3_squeeze(&kec, h, RACC_SEC);
    sha3_clear(&kec);
}

//  create a challenge polynomial frin a hash

static void racc_challenge_poly(int64_t cp[RACC_N], const uint8_t ch[RACC_SEC])
{
    sha3_t kec;
    uint8_t buf[2];
    size_t i, j;
    int64_t x;

    sha3_init(&kec, SHAKE256_RATE);
    sha3_absorb(&kec, ch, RACC_SEC);
    sha3_pad(&kec, SHAKE_PAD);

    for (i = 0; i < RACC_N; i++) {
        cp[i] = 0;
    }

    j = 0;
    while (j < RACC_W) {
        sha3_squeeze(&kec, buf, 2);
        i = get16u_le(buf);
        x = i & 1;
        i = (i >> 1) & (RACC_N - 1);
        if (cp[i] == 0) {
            cp[i] = 2 * x - 1;
            j++;
        }
    }
    sha3_clear(&kec);
}

//  collapse shares

static void racc_decode(int64_t r[RACC_N], const int64_t m[][RACC_N],
                        size_t d, int64_t q)
{
    size_t i;

    polyr_addm(r, m[0], m[1], q);
    for (i = 2; i < d; i++) {
        polyr_addm(r, r, m[i], q);
    }
}

/*
    Adaptation of a quasilinear refresh gadget over a masked polynomial.
    Based on Algorithm 6/7: "IOS refresh gadget" in
    http://www.matthieurivain.com/files/habilitation-thesis.pdf
    This algorithm is proven IOS in the eprint version of [GPRV21],
    and SNI in http://www.theses.fr/2021UPASG095.
*/

//  note: this function is recursive but uses data in-place
//  write-over leakage is likely to contradict the physical SNI assumption.

#ifndef FAST_REFRESH

static void zero_encoding(int64_t z[][RACC_N], size_t d)
{
    size_t i, d2 = d / 2;

    if (d == 2) {
        random_poly(z[0]);
        polyr_negm(z[1], z[0], RACC_Q);
    } else {
        zero_encoding(z, d2);
        zero_encoding(&z[d2], d2);
        for (i = 0; i < d2; i++) {
            remask_poly(z[i], z[i + d2]);
        }
    }
}

static void racc_refresh(int64_t r[][RACC_N], size_t d)
{
    size_t i;
    int64_t z[2 * RACC_D][RACC_N];  //  large

    zero_encoding(z, d);
    for (i = 0; i < d; i++) {
        polyr_addq(r[i], r[i], z[i]);
    }
}

#else

//  faster "TI" refresh gadget (not SNI)

static void racc_refresh(int64_t r[][RACC_N], size_t d)
{
    size_t i;

    for (i = 1; i < d; i++) {
        remask_poly(r[i - 1], r[i]);
    }
}

#endif

//  doubles the order to 2d

static void orderswitch(int64_t r[][RACC_N],
                        const int64_t a[][RACC_N], size_t d)
{
    size_t i;

    for (i = 0; i < d; i++) {
        polyr_copy(r[i], a[i]);
        polyr_zero(r[d + i]);
    }
    racc_refresh(r, 2 * d);
}

//  check norms: false on failure

static bool racc_norm_check(const int64_t h[RACC_K][RACC_N])
{
    size_t i, j;
    int64_t x, n2;
    bool ok;

    n2 = 0;
    ok = true;

    for (i = 0; i < RACC_K; i++) {
        for (j = 0; j < RACC_N; j++) {
            x = h[i][j];
            n2 += x * x;
            ok = ok && (x <= RACC_BOO) && (x >= -RACC_BOO);
        }
    }
    return ok && (n2 <= RACC_B22);
}

//  === racc_keygen ===
//  Generate a public-secret keypair ("pk", "sk").

void racc_keygen(racc_pk_t *pk, racc_sk_t *sk)
{
    size_t i, j, k;
    int64_t ma[RACC_K][RACC_ELL][RACC_N];
    int64_t mt[RACC_D][RACC_N];
    int64_t mt2[2 * RACC_D][RACC_N];

    randombytes(pk->a_seed, RACC_SEC);

    //  --- 1.  A <- R_q^(k*ell)

    xof_sample((int64_t *)ma, RACC_K * RACC_ELL * RACC_N,
                pk->a_seed, RACC_SEC);

    //  --- 2.  [[s]] <- (R_q^ell)^d

    for (i = 0; i < RACC_ELL; i++) {
        for (j = 0; j < RACC_D; j++) {
            random_poly(sk->s[i][j]);
        }
    }

    //  --- 3.  [[t]] := A * [[s]]

    for (i = 0; i < RACC_K; i++) {
        for (j = 0; j < RACC_D; j++) {
            polyr_cmul(mt[j], sk->s[0][j], ma[i][0]);
            for (k = 1; k < RACC_ELL; k++) {
                polyr_mula(mt[j], sk->s[k][j], ma[i][k], mt[j]);
            }
            polyr_intt(mt[j]);
        }

    //  --- 4.  [[t]] <- OrderSwitch_d->2d([[t]])

        orderswitch(mt2, mt, RACC_D);

    //  --- 5.  [[t]] := ApproxShift_q->qt([[t]])

        for (j = 0; j < 2 * RACC_D; j++) {
            polyr_round(mt2[j], mt2[j], RACC_LPT, RACC_CTT, RACC_QT);
        }

    //  --- 6.  t := Decode(t)

        racc_decode(pk->t[i], mt2, 2 * RACC_D, RACC_QT);
    }

    //  insert the public key into the secret key

    memcpy(&sk->pk, pk, sizeof(racc_pk_t));
}

//  === racc_sign ===
//  Create a detached signature "sig" of message "msg" of "mlen" bytes
//  using secret key "sk" (which is not const, due to masking refresh.)

void racc_sign(racc_sig_t *sig, const uint8_t *msg,
                size_t mlen, racc_sk_t *sk)
{
    size_t i, j, k;
    int64_t ma[RACC_K][RACC_ELL][RACC_N];
    int64_t mr[RACC_ELL][RACC_D][RACC_N];
    int64_t mz[RACC_D][RACC_N];
    int64_t mw[RACC_K][RACC_D][RACC_N];
    int64_t t[RACC_N], u[RACC_N];
    int64_t vw[RACC_K][RACC_N];
    int64_t c_poly[RACC_N];

    //  generate public matrix A from A_seed
    xof_sample((int64_t *)ma, RACC_K * RACC_ELL * RACC_N, sk->pk.a_seed,
               RACC_SEC);

    do {

        //  --- 1.  [[r]] <= (R_q^ell)^d

        for (i = 0; i < RACC_ELL; i++) {
            for (j = 0; j < RACC_D; j++) {
                random_poly(mr[i][j]);
            }
        }

        //  --- 2.  [[u]] := A * [[r]]      ( mw holds [[u]] )

        for (i = 0; i < RACC_K; i++) {
            for (j = 0; j < RACC_D; j++) {
                polyr_cmul(mw[i][j], mr[0][j], ma[i][0]);
                for (k = 1; k < RACC_ELL; k++) {
                    polyr_mula(mw[i][j], mr[k][j], ma[i][k], mw[i][j]);
                }
                polyr_intt(mw[i][j]);
            }

        //  --- 3.  [[u]] <- Refresh([[u]])

            racc_refresh(mw[i], RACC_D);

        //  --- 4.  [[w]] <= ApproxShift_{q->qw}([[u]])

            for (j = 0; j < RACC_D; j++) {
                polyr_round(mw[i][j], mw[i][j], RACC_LPW, RACC_CTW, RACC_QW);
            }

        //  --- 5.  w := Decode([[w]])

            racc_decode(vw[i], mw[i], RACC_D, RACC_QW);
        }

        //  --- 6.  Chash := H(w, msg)

        racc_challenge_hash(sig->ch, msg, mlen, vw);

        //  --- 7.  Cpoly := ChalPoly(Chash)

        racc_challenge_poly(c_poly, sig->ch);
        polyr_fntt(c_poly);

        //  --- 8.  [[s]] <- Refresh([[s]])

        for (i = 0; i < RACC_ELL; i++) {

            racc_refresh(sk->s[i], RACC_D);

        //  --- 9.  [[r]] <- Refresh([[r]])

            racc_refresh(mr[i], RACC_D);

        //  --- 10. [[z]] := Cpoly * [[s]] + [[r]]

            for (j = 0; j < RACC_D; j++) {
                polyr_cmul(t, sk->s[i][j], c_poly);
                polyr_smul(u, mr[i][j], 1);  // Montgomery scaling
                polyr_addq(mz[j], t, u);
            }

        //  --- 11. z := Decode([[z]])

            racc_decode(sig->z[i], mz, RACC_D, RACC_Q);

        //  Montgomery scaling; equivalent to NTT(NTT^-1(z)) buf faster

            polyr_smul(sig->z[i], sig->z[i], MONT_RR);
        }

        //  --- 12. y := A*z - p_t * Cpoly * t

        for (i = 0; i < RACC_K; i++) {
            polyr_cmul(t, ma[i][0], sig->z[0]);
            for (j = 1; j < RACC_ELL; j++) {
                polyr_mula(t, ma[i][j], sig->z[j], t);
            }
            polyr_shlm(u, sk->pk.t[i], RACC_LPT, RACC_Q);
            polyr_fntt(u);
            polyr_cmul(u, u, c_poly);
            polyr_subq(t, t, u);
            polyr_intt(t);

            //  --- 13. yT := |y|q->wq

            polyr_shrm(t, t, RACC_LPW, RACC_QW);

            //  --- 14. h := w - yT

            polyr_subm(t, vw[i], t, RACC_QW);
            polyr_center(sig->h[i], t, RACC_QW);
        }

    } while (!racc_norm_check(sig->h));  // restart on bound failure
}

//  === racc_verify ===
//  Verify that the signature "sig" is valid for "msg" of "mlen" bytes.
//  if returns true: signature is valid. if false: signature is invalid.

bool racc_verify(const racc_sig_t *sig, const uint8_t *msg, size_t mlen,
                 const racc_pk_t *pk)
{
    size_t i, j;
    int64_t ma[RACC_K][RACC_ELL][RACC_N];
    int64_t c_poly[RACC_N];
    uint8_t c_hchk[RACC_SEC];
    int64_t vw[RACC_K][RACC_N];
    int64_t t[RACC_N], u[RACC_N];

    //  we check the norms of h first. this is a "formatting" issue
    //  --- 5. if (||h||2 > B2) or (||h||inf > Boo) .. reject

    if (!racc_norm_check(sig->h)) {
        return false;
    }

    //  --- 1.  Cpoly := ChalPoly(Chash)

    racc_challenge_poly(c_poly, sig->ch);
    polyr_fntt(c_poly);

    //  compute A

    xof_sample((int64_t *)ma, RACC_K * RACC_ELL * RACC_N,
                pk->a_seed, RACC_SEC);

    for (i = 0; i < RACC_K; i++) {

        //  --- 2.  y = A * z - p_t * Cpoly * t

        polyr_cmul(t, ma[i][0], sig->z[0]);             //  A * z ..
        for (j = 1; j < RACC_ELL; j++) {
            polyr_mula(t, ma[i][j], sig->z[j], t);
        }
        polyr_intt(t);

        polyr_shlm(u, pk->t[i], RACC_LPT, RACC_Q);      //  .. - p_t * t ..
        polyr_fntt(u);
        polyr_cmul(u, u, c_poly);
        polyr_intt(u);
        polyr_subq(t, t, u);

        //  --- 3.  w' = |y|q->wq + h

        polyr_shrm(t, t, RACC_LPW, RACC_QW);
        polyr_nonneg(u, sig->h[i], RACC_QW);
        polyr_addm(vw[i], t, u, RACC_QW);
    }

    //  --- 4. C'hash := H(w', msg)

    racc_challenge_hash(c_hchk, msg, mlen, vw);

    //  --- 5. ... or (Chash != C'hash)

    return ct_equal(c_hchk, sig->ch, RACC_SEC);
}

