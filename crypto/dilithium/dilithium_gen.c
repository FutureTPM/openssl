#include <stdio.h>
#include "internal/cryptlib.h"
#include "dilithium_locl.h"
#include "dilithium-params.h"
#include "dilithium-sign.h"
#include "dilithium-packing.h"
#include "openssl/evp.h"
#include "openssl/rand.h"

static int dilithium_builtin_keygen(Dilithium *dilithium, int mode);

DilithiumParams generate_dilithium_params(const int mode) {
    DilithiumParams params;

    switch(mode) {
        case 1:
            params.k = 3;
            params.l = 2;
            params.eta = 7;
            params.setabits = 4;
            params.beta = 375;
            params.omega = 64;
            break;
        case 2:
            params.k = 4;
            params.l = 3;
            params.eta = 6;
            params.setabits = 4;
            params.beta = 325;
            params.omega = 80;
            break;
        case 3:
            params.k = 5;
            params.l = 4;
            params.eta = 5;
            params.setabits = 4;
            params.beta = 275;
            params.omega = 96;
            break;
        case 4:
            params.k = 6;
            params.l = 5;
            params.eta = 3;
            params.setabits = 3;
            params.beta = 175;
            params.omega = 120;
            break;
        default:
            // A call to this function should be protected against invalid
            // dilithium modes
            break;
    }

    params.pol_size_packed     = ((DILITHIUM_N * DILITHIUM_QBITS) / 8);
    params.polt1_size_packed   = ((DILITHIUM_N * (DILITHIUM_QBITS - DILITHIUM_D)) / 8);
    params.polt0_size_packed   = ((DILITHIUM_N * DILITHIUM_D) / 8);
    params.poleta_size_packed  = ((DILITHIUM_N * params.setabits) / 8);
    params.polz_size_packed    = ((DILITHIUM_N * (DILITHIUM_QBITS - 3)) / 8);
    params.polw1_size_packed   = ((DILITHIUM_N * 4) / 8);
    params.polveck_size_packed = (params.k * params.pol_size_packed);
    params.polvecl_size_packed = (params.l * params.pol_size_packed);

    params.crypto_publickeybytes =
        (DILITHIUM_SEEDBYTES + params.k * params.polt1_size_packed);
    params.crypto_secretkeybytes =
        2*DILITHIUM_SEEDBYTES + (params.l + params.k) *
         params.poleta_size_packed + DILITHIUM_CRHBYTES +
         params.k * params.polt0_size_packed;
    params.crypto_bytes = params.l * params.polz_size_packed +
            (params.omega + params.k) + (DILITHIUM_N/8 + 8);

    return params;
}

/*
 * NB: this wrapper would normally be placed in dilithium_lib.c and the static
 * implementation would probably be in dilithium_eay.c. Nonetheless, is kept here
 * so that we don't introduce a new linker dependency. Eg. any application
 * that wasn't previously linking object code related to key-generation won't
 * have to now just because key-generation is part of DILITHIUM_METHOD.
 */
int dilithium_generate_key_ex(Dilithium *dilithium, int mode)
{
    if (dilithium->meth->dilithium_keygen != NULL)
        return dilithium->meth->dilithium_keygen(dilithium, mode);

    return dilithium_builtin_keygen(dilithium, mode);
}

static int dilithium_builtin_keygen(Dilithium *dilithium, const int mode)
{
    unsigned int i;
    unsigned char seedbuf[3*DILITHIUM_SEEDBYTES];
    unsigned char tr[DILITHIUM_CRHBYTES];
    const unsigned char *rho, *rhoprime, *key;
    uint16_t nonce = 0;
    dilithium_polyvecl mat[6]; // MAX K in Dilithium
    dilithium_polyvecl s1, s1hat;
    dilithium_polyveck s2, t, t1, t0;
    EVP_MD_CTX *mdctx = NULL;

    if (dilithium == NULL)
        return 0;

    if (mode != 1 && mode != 2 && mode != 3 && mode != 4)
        return 0;

    DilithiumParams params = generate_dilithium_params(mode);
    dilithium->mode = mode;

    dilithium->public_key_size = params.crypto_publickeybytes;
    dilithium->private_key_size = params.crypto_secretkeybytes;

    dilithium->public_key = OPENSSL_zalloc(dilithium->public_key_size);
    if (dilithium->public_key == NULL) {
        return 0;
    }
    dilithium->private_key = OPENSSL_zalloc(dilithium->private_key_size);
    if (dilithium->private_key == NULL) {
        OPENSSL_free(dilithium->public_key);
        return 0;
    }

    /* Expand 32 bytes of randomness into rho, rhoprime and key */
    RAND_bytes(seedbuf, 3*DILITHIUM_SEEDBYTES);
    rho = seedbuf;
    rhoprime = seedbuf + DILITHIUM_SEEDBYTES;
    key = seedbuf + 2*DILITHIUM_SEEDBYTES;

    /* Expand matrix */
    dilithium_expand_mat(mat, rho, params.k, params.l);

    /* Sample short vector s1 and s2 */
    for(i = 0; i < params.l; ++i)
        dilithium_poly_uniform_eta(&s1.vec[i], rhoprime, nonce++, params.eta,
              params.setabits);
    for(i = 0; i < params.k; ++i)
        dilithium_poly_uniform_eta(&s2.vec[i], rhoprime, nonce++, params.eta,
              params.setabits);

    /* Matrix-vector multiplication */
    s1hat = s1;
    dilithium_polyvecl_ntt(&s1hat, params.l);
    for(i = 0; i < params.k; ++i) {
      dilithium_polyvecl_pointwise_acc_invmontgomery(&t.vec[i], &mat[i], &s1hat,
              params.l);
      dilithium_poly_reduce(&t.vec[i]);
      dilithium_poly_invntt_montgomery(&t.vec[i]);
    }

    /* Add error vector s2 */
    dilithium_polyveck_add(&t, &t, &s2, params.k);

    /* Extract t1 and write public key */
    dilithium_polyveck_freeze(&t, params.k);
    dilithium_polyveck_power2round(&t1, &t0, &t, params.k);
    dilithium_pack_pk(dilithium->public_key,
            rho, &t1, params.k, params.polt1_size_packed);

    /* Compute CRH(rho, t1) and write secret key */
    // TODO: Error checking
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL);
    EVP_DigestUpdate(mdctx, dilithium->public_key, dilithium->public_key_size);
    EVP_DigestFinalXOF(mdctx, tr, DILITHIUM_CRHBYTES);
    EVP_MD_CTX_free(mdctx);

    dilithium_pack_sk(dilithium->private_key,
            rho, key, tr, &s1, &s2, &t0,
            params.k, params.l, params.poleta_size_packed,
            params.polt0_size_packed, params.eta);

    return 1;
}
