#ifndef NTTRU_KEM_H
#define NTTRU_KEM_H

#include "nttru-params.h"
#include "nttru-poly.h"
int nttru_keygen(nttru_poly *hhat, nttru_poly *fhat, const unsigned char coins[NTTRU_N]);
void nttru_encrypt(nttru_poly *chat,
                   const nttru_poly *hhat,
                   const nttru_poly *m,
                   const unsigned char coins[NTTRU_N/2]);
void nttru_decrypt(nttru_poly *m,
                   const nttru_poly *chat,
                   const nttru_poly *fhat);
int nttru_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int nttru_crypto_kem_enc(unsigned char *c, unsigned char *k, const unsigned char *pk);
int nttru_crypto_kem_dec(unsigned char *k, const unsigned char *c, const unsigned char *sk);

#endif
