#include <stdio.h>
#include "internal/cryptlib.h"
#include "kyber-locl.h"
#include "kyber-params.h"
#include "kyber-indcpa.h"
#include "kyber-verify.h"
#include "openssl/evp.h"
#include "openssl/rand.h"

static int kyber_builtin_keygen(Kyber *kyber, int mode);

KyberParams generate_kyber_params(const int kyber_k) {
    KyberParams params;
    params.polyvecbytes = kyber_k * KYBER_POLYBYTES;

    switch (kyber_k) {
        case 2:
            params.polycompressedbytes = 96;
            params.polyveccompressedbytes = kyber_k * 320;
            break;
        case 3:
            params.polycompressedbytes = 128;
            params.polyveccompressedbytes = kyber_k * 320;
            break;
        case 4:
            params.polycompressedbytes = 160;
            params.polyveccompressedbytes = kyber_k * 352;
            break;
        default:
            break;
    }

    params.k = kyber_k;
    params.indcpa_publickeybytes = params.polyvecbytes + KYBER_SYMBYTES;
    params.indcpa_secretkeybytes = params.polyvecbytes;

    params.publickeybytes =  params.indcpa_publickeybytes;
    params.secretkeybytes =  params.indcpa_secretkeybytes + params.indcpa_publickeybytes + 2*KYBER_SYMBYTES;
    params.ciphertextbytes = params.polyveccompressedbytes + params.polycompressedbytes;
    params.eta = 2;

    return params;
}

/*
 * NB: this wrapper would normally be placed in kyber_lib.c and the static
 * implementation would probably be in kyber_eay.c. Nonetheless, is kept here
 * so that we don't introduce a new linker dependency. Eg. any application
 * that wasn't previously linking object code related to key-generation won't
 * have to now just because key-generation is part of KYBER_METHOD.
 */
int kyber_generate_key_ex(Kyber *kyber, int mode)
{
    if (kyber->meth->kyber_keygen != NULL)
        return kyber->meth->kyber_keygen(kyber, mode);

    return kyber_builtin_keygen(kyber, mode);
}

static int kyber_builtin_keygen(Kyber *kyber, const int mode)
{
    if (kyber == NULL)
        return 0;

    if (mode != 2 && mode != 3 && mode != 4)
        return 0;

    KyberParams params = generate_kyber_params(mode);
    kyber->mode = mode;

    kyber->public_key_size = params.publickeybytes;
    kyber->private_key_size = params.secretkeybytes;

    kyber->public_key = OPENSSL_zalloc(kyber->public_key_size);
    if (kyber->public_key == NULL) {
        return 0;
    }
    kyber->private_key = OPENSSL_zalloc(kyber->private_key_size);
    if (kyber->private_key == NULL) {
        OPENSSL_free(kyber->public_key);
        return 0;
    }

    // Command Output
    indcpa_keypair(kyber->public_key, kyber->private_key,
            params.k, params.polyvecbytes, params.eta);
    for (size_t i = 0; i < params.indcpa_publickeybytes; i++) {
        kyber->private_key[i+params.indcpa_secretkeybytes] = kyber->public_key[i];
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        return 0;
    }

    // TODO: Error checking
    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(mdctx, kyber->public_key, kyber->public_key_size);
    EVP_DigestFinal_ex(mdctx,
            kyber->private_key+kyber->private_key_size-2*KYBER_SYMBYTES, NULL);
    EVP_MD_CTX_free(mdctx);

    /* Value z for pseudo-random output on reject */
    // TODO: Error checking
    RAND_bytes(kyber->private_key+kyber->private_key_size-KYBER_SYMBYTES,
            KYBER_SYMBYTES);

    return 1;
}

// Returns size of the cipher text on success and a negative number
// on failure
int kyber_encapsulate(const Kyber *kyber, uint8_t *ss, uint8_t **ct) {
    KyberParams params;

    /* Will contain key, coins */
    uint8_t  kr[2*KYBER_SYMBYTES];
    uint8_t buf[2*KYBER_SYMBYTES];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        return -1;
    }
    if (kyber == NULL)
        return -1;

    if (kyber->mode != 2 && kyber->mode != 3 && kyber->mode != 4)
        return -1;

    if (kyber->public_key == NULL)
        return -1;

    // Parameter Generation
    params = generate_kyber_params(kyber->mode);

    *ct = OPENSSL_zalloc(params.ciphertextbytes);
    if (*ct == NULL)
        return -1;

    // Create secret data from RNG
    RAND_bytes(buf, KYBER_SYMBYTES);

    /* Don't release system RNG output */
    // TODO: Error checking
    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(mdctx, buf, KYBER_SYMBYTES);
    EVP_DigestFinal_ex(mdctx, buf, NULL);

    /* Multitarget countermeasure for coins + contributory KEM */
    // TODO: Error checking
    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(mdctx, kyber->public_key, params.publickeybytes);
    EVP_DigestFinal_ex(mdctx, buf+KYBER_SYMBYTES, NULL);

    // TODO: Error checking
    EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(mdctx, buf, 2*KYBER_SYMBYTES);
    EVP_DigestFinal_ex(mdctx, kr, NULL);

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc(*ct, buf,
               kyber->public_key,
               kr+KYBER_SYMBYTES, params.k,
               params.polyveccompressedbytes,
               params.eta,
               params.polyvecbytes,
               params.polycompressedbytes);

    /* overwrite coins in kr with H(c) */
    // TODO: Error checking
    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(mdctx, *ct, params.ciphertextbytes);
    EVP_DigestFinal_ex(mdctx, kr+KYBER_SYMBYTES, NULL);

    /* hash concatenation of pre-k and H(c) to k */
    // TODO: Error checking
    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(mdctx, kr, 2*KYBER_SYMBYTES);
    EVP_DigestFinal_ex(mdctx, ss, NULL);

    EVP_MD_CTX_free(mdctx);

    return params.ciphertextbytes;
}

// Returns 1 if ok, otherwise negative number
int kyber_decapsulate(const Kyber *kyber, uint8_t *ss, const uint8_t *ct) {
    KyberParams params;
    size_t i;
    int fail;
    uint8_t buf[2*KYBER_SYMBYTES];
    /* Will contain key, coins, qrom-hash */
    uint8_t kr[2*KYBER_SYMBYTES];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        return -1;
    }

    if (kyber == NULL)
        return -1;

    if (kyber->mode != 2 && kyber->mode != 3 && kyber->mode != 4)
        return -1;

    if (kyber->private_key == NULL)
        return -1;

    // Parameter Generation
    params = generate_kyber_params(kyber->mode);

    const unsigned char *pk = kyber->private_key+params.indcpa_secretkeybytes;
    unsigned char cmp[params.ciphertextbytes];

    /* indcpa_dec(buf, ct, kyber->private_key, params.k, */
    /*            params.polyveccompressedbytes, params.eta); */

    indcpa_dec(buf, ct, kyber->private_key, params.k,
               params.polyveccompressedbytes, params.polycompressedbytes);

    /* Multitarget countermeasure for coins + contributory KEM */
    for(i = 0; i < KYBER_SYMBYTES; i++) {
      /* Save hash by storing H(pk) in sk */
      buf[KYBER_SYMBYTES+i] = kyber->private_key[params.secretkeybytes-2*KYBER_SYMBYTES+i];
    }

    EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(mdctx, buf, 2*KYBER_SYMBYTES);
    EVP_DigestFinal_ex(mdctx, kr, NULL);

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES, params.k,
               params.polyveccompressedbytes,
               params.eta,
               params.polyvecbytes,
               params.polycompressedbytes);

    fail = kyber_verify(ct, cmp, params.ciphertextbytes);

    /* overwrite coins in kr with H(c)  */
    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(mdctx, ct, params.ciphertextbytes);
    EVP_DigestFinal_ex(mdctx, kr+KYBER_SYMBYTES, NULL);

    /* Overwrite pre-k with z on re-encryption failure */
    kyber_cmov(kr, kyber->private_key+params.secretkeybytes-KYBER_SYMBYTES,
            KYBER_SYMBYTES, fail);

    /* hash concatenation of pre-k and H(c) to k */
    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(mdctx, kr, 2*KYBER_SYMBYTES);
    EVP_DigestFinal_ex(mdctx, ss, NULL);

    EVP_MD_CTX_free(mdctx);

    return 1;
}
