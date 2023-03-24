//  raccoon.h

//  === Raccoon signature scheme -- parameters and prototypes.

#ifndef _RACCOON_H_
#define _RACCOON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "raccoon_par.h"

//  === Internal structures ===
//  note: no serialization at the moment

//  raccoon public key

typedef struct {
    uint8_t a_seed[RACC_SEC];
    int64_t t[RACC_K][RACC_N];
} racc_pk_t;

//  raccoon secret key

typedef struct {
    racc_pk_t pk;                               //  copy of public key
    int64_t s[RACC_ELL][RACC_D][RACC_N];        //  in RACC_D shares
} racc_sk_t;

//  raccoon signature

typedef struct {
    uint8_t ch[RACC_SEC];  //   challenge hash
    int64_t h[RACC_K][RACC_N];
    int64_t z[RACC_ELL][RACC_N];
} racc_sig_t;

//  === API ===

//  Generate a public-secret keypair ("pk", "sk").

void racc_keygen(racc_pk_t *pk, racc_sk_t *sk);

//  Create a detached signature "sig" of message "msg" of "mlen" bytes
//  using secret key "sk" (which is not const, due to masking refresh.)

void racc_sign(racc_sig_t *sig, const uint8_t *msg, size_t mlen, racc_sk_t *sk);

//  Verify that the signature "sig" is valid for "msg" of "mlen" bytes.
//  if returns true: signature is valid. if false: signature is invalid.

bool racc_verify(const racc_sig_t *sig, const uint8_t *msg, size_t mlen,
                 const racc_pk_t *pk);

#ifdef __cplusplus
}
#endif

//  _RACCOON_H_
#endif
