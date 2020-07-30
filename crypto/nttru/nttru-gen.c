#include <stdio.h>
#include "internal/cryptlib.h"
#include "nttru-locl.h"
#include "nttru-params.h"
#include "nttru-kem.h"
#include "openssl/evp.h"
#include "openssl/rand.h"

static int nttru_builtin_keygen(NTTRU *nttru);

/*
 * NB: this wrapper would normally be placed in nttru_lib.c and the static
 * implementation would probably be in nttru_eay.c. Nonetheless, is kept here
 * so that we don't introduce a new linker dependency. Eg. any application
 * that wasn't previously linking object code related to key-generation won't
 * have to now just because key-generation is part of NTTRU_METHOD.
 */
int nttru_generate_key_ex(NTTRU *nttru)
{
    if (nttru->meth->nttru_keygen != NULL)
        return nttru->meth->nttru_keygen(nttru);
    return nttru_builtin_keygen(nttru);
}

static int nttru_builtin_keygen(NTTRU *nttru)
{
    if (nttru == NULL)
        return 0;

    nttru->public_key_size = NTTRU_PUBLICKEYBYTES;
    nttru->private_key_size = NTTRU_SECRETKEYBYTES;

    nttru->public_key = OPENSSL_zalloc(nttru->public_key_size);
    if (nttru->public_key == NULL) {
        return 0;
    }
    nttru->private_key = OPENSSL_zalloc(nttru->private_key_size);
    if (nttru->private_key == NULL) {
        OPENSSL_free(nttru->public_key);
        return 0;
    }
    // Command Output
    if (nttru_crypto_kem_keypair(nttru->public_key, nttru->private_key) != 0)
      return 0;

    return 1;
}

// Returns size of the cipher text on success and a negative number
// on failure
int nttru_encapsulate(const NTTRU *nttru, uint8_t *ss, uint8_t **ct) {
    if (nttru == NULL)
        return -1;
    if (nttru->public_key == NULL)
        return -1;

    *ct = OPENSSL_zalloc(NTTRU_CIPHERTEXTBYTES);
    if (*ct == NULL)
      return -1;

    if (nttru_crypto_kem_enc(*ct, ss, nttru->public_key) != 0)
       return -1;
    return NTTRU_CIPHERTEXTBYTES;
}

// Returns 1 if ok, otherwise negative number
int nttru_decapsulate(const NTTRU *nttru, uint8_t *ss, const uint8_t *ct) {
    if (nttru == NULL)
        return -1;
    if (nttru->private_key == NULL)
        return -1;
    if (nttru_crypto_kem_dec(ss, ct, nttru->private_key) != 0)
      return -1;
    return 1;
}
