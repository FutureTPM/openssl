#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/dilithium.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include "internal/x509_int.h"
#include "dilithium_locl.h"
#include "dilithium-params.h"
#include "dilithium-polyvec.h"
#include "dilithium-poly.h"
#include "dilithium-packing.h"
#include "dilithium-sign.h"

int int_dilithium_sign(const unsigned char *m, unsigned int m_len,
             unsigned char *sigret, unsigned int *siglen, const Dilithium *dilithium)
{
    DilithiumParams params;
    unsigned long long i;
    unsigned int n;
    unsigned char seedbuf[2*DILITHIUM_SEEDBYTES + 3*DILITHIUM_CRHBYTES];
    unsigned char *rho, *key_, *mu, *tr, *rhoprime;
    uint16_t nonce = 0;
    dilithium_poly c, chat;
    dilithium_polyvecl mat[6], s1, y, yhat, z; // Max K in Dilithium
    dilithium_polyveck t0, s2, w0, w, w1;
    dilithium_polyveck h, ct0, cs2;
    int ret = 0;
    EVP_MD_CTX *mdctx = NULL;

    if (m == NULL || m_len == 0 || sigret == NULL || siglen == NULL) {
        goto err;
    }

    params = generate_dilithium_params(dilithium->mode);

    rho = seedbuf;
    tr = rho + DILITHIUM_SEEDBYTES;
    key_ = tr + DILITHIUM_CRHBYTES;
    mu = key_ + DILITHIUM_SEEDBYTES;
    rhoprime = mu + DILITHIUM_CRHBYTES;
    dilithium_unpack_sk(rho, key_, tr, &s1, &s2, &t0,
            dilithium->private_key, params.k,
            params.l, params.poleta_size_packed, params.polt0_size_packed,
            params.eta);

    /* Copy tr and message into the sm buffer,
     * backwards since m and sm can be equal in SUPERCOP API */
    for(i = 1; i <= m_len; ++i)
      sigret[params.crypto_bytes + m_len - i] = m[m_len - i];
    for(i = 0; i < DILITHIUM_CRHBYTES; ++i)
      sigret[params.crypto_bytes - DILITHIUM_CRHBYTES + i] = tr[i];

    /* Compute CRH(tr, msg) */
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL);
    EVP_DigestUpdate(mdctx, sigret + params.crypto_bytes - DILITHIUM_CRHBYTES, DILITHIUM_CRHBYTES + m_len);
    EVP_DigestFinalXOF(mdctx, mu, DILITHIUM_CRHBYTES);

    EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL);
    EVP_DigestUpdate(mdctx, key_, DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES);
    EVP_DigestFinalXOF(mdctx, rhoprime, DILITHIUM_CRHBYTES);
    EVP_MD_CTX_free(mdctx);

    /* Expand matrix and transform vectors */
    dilithium_expand_mat(mat, rho, params.k, params.l);
    dilithium_polyvecl_ntt(&s1, params.l);
    dilithium_polyveck_ntt(&s2, params.k);
    dilithium_polyveck_ntt(&t0, params.k);

rej:

    /* Sample intermediate vector y */
    for(i = 0; i < params.l; ++i)
      dilithium_poly_uniform_gamma1m1(&y.vec[i], rhoprime, nonce++);

    /* Matrix-vector multiplication */
    yhat = y;
    dilithium_polyvecl_ntt(&yhat, params.l);
    for(i = 0; i < params.k; ++i) {
      dilithium_polyvecl_pointwise_acc_invmontgomery(&w.vec[i], &mat[i], &yhat,
              params.l);
      dilithium_poly_reduce(&w.vec[i]);
      dilithium_poly_invntt_montgomery(&w.vec[i]);
    }

    /* Decompose w and call the random oracle */
    dilithium_polyveck_csubq(&w, params.k);
    dilithium_polyveck_decompose(&w1, &w0, &w, params.k);
    dilithium_challenge(&c, mu, &w1, params.k, params.polw1_size_packed);
    chat = c;
    dilithium_poly_ntt(&chat);

    /* Check that subtracting cs2 does not change high bits of w and low bits
    * do not reveal secret information */
    for(i = 0; i < params.k; ++i) {
        dilithium_poly_pointwise_invmontgomery(&cs2.vec[i], &chat, &s2.vec[i]);
        dilithium_poly_invntt_montgomery(&cs2.vec[i]);
    }
    dilithium_polyveck_sub(&w0, &w0, &cs2, params.k);
    dilithium_polyveck_freeze(&w0, params.k);
    if(dilithium_polyveck_chknorm(&w0, DILITHIUM_GAMMA2 - params.beta, params.l))
        goto rej;

    /* Compute z, reject if it reveals secret */
    for(i = 0; i < params.l; ++i) {
      dilithium_poly_pointwise_invmontgomery(&z.vec[i], &chat, &s1.vec[i]);
      dilithium_poly_invntt_montgomery(&z.vec[i]);
    }
    dilithium_polyvecl_add(&z, &z, &y, params.l);
    dilithium_polyvecl_freeze(&z, params.l);
    if(dilithium_polyvecl_chknorm(&z, DILITHIUM_GAMMA1 - params.beta, params.l))
      goto rej;

    /* Compute hints for w1 */
    for(i = 0; i < params.k; ++i) {
      dilithium_poly_pointwise_invmontgomery(&ct0.vec[i], &chat, &t0.vec[i]);
      dilithium_poly_invntt_montgomery(&ct0.vec[i]);
    }

    dilithium_polyveck_csubq(&ct0, params.k);
    if(dilithium_polyveck_chknorm(&ct0, DILITHIUM_GAMMA2, params.k))
      goto rej;

    dilithium_polyveck_add(&w0, &w0, &ct0, params.k);
    dilithium_polyveck_csubq(&w0, params.k);
    n = dilithium_polyveck_make_hint(&h, &w0, &w1, params.k);
    if(n > params.omega)
      goto rej;

    /* Write signature */
    dilithium_pack_sig(sigret, &z, &h,
            &c, params.k, params.l, params.polz_size_packed, params.omega);

    *siglen = m_len + params.crypto_bytes;

    ret = 1;

err:
    return ret;
}

int int_dilithium_verify(const unsigned char *m, unsigned int m_len,
                   const unsigned char *sigbuf, unsigned int siglen, const Dilithium *dilithium)
{
    DilithiumParams params;
    unsigned long long i;
    unsigned char rho[DILITHIUM_SEEDBYTES];
    unsigned char mu[DILITHIUM_CRHBYTES], *decrypt_buf = NULL;
    size_t decrypt_buf_len = 0;
    dilithium_poly c, chat, cp;
    dilithium_polyvecl mat[6], z; // Max K for Dilithium
    dilithium_polyveck t1, w1, h, tmp1, tmp2;
    int ret = 0;
    EVP_MD_CTX *mdctx = NULL;

    if ((siglen - m_len) != (size_t)Dilithium_sig_size(dilithium)) {
        Dilithiumerr(DILITHIUM_F_INT_DILITHIUM_VERIFY, DILITHIUM_R_WRONG_SIGNATURE_LENGTH);
        return 0;
    }

    if (m == NULL || sigbuf == NULL) {
        goto err;
    }

    /* Recover the encoded digest. */
    decrypt_buf = OPENSSL_malloc(siglen);
    if (decrypt_buf == NULL) {
        Dilithiumerr(DILITHIUM_F_INT_DILITHIUM_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    params = generate_dilithium_params(dilithium->mode);

    decrypt_buf_len = siglen - params.crypto_bytes;

    dilithium_unpack_pk(rho, &t1, dilithium->public_key, params.k,
            params.polt1_size_packed);
    if (dilithium_unpack_sig(&z, &h, &c, sigbuf, params.k, params.l,
                params.polz_size_packed, params.omega)) {
        goto err;
    }
    if(dilithium_polyvecl_chknorm(&z, DILITHIUM_GAMMA1 - params.beta, params.l)) {
        goto err;
    }

    /* Compute CRH(CRH(rho, t1), msg) using m as "playground" buffer */
    if(sigbuf != decrypt_buf)
      for(i = 0; i < decrypt_buf_len; ++i)
        decrypt_buf[params.crypto_bytes + i] = sigbuf[params.crypto_bytes + i];

    // TODO
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL);
    EVP_DigestUpdate(mdctx, dilithium->public_key, params.crypto_publickeybytes);
    EVP_DigestFinalXOF(mdctx, decrypt_buf + params.crypto_bytes - DILITHIUM_CRHBYTES, DILITHIUM_CRHBYTES);

    EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL);
    EVP_DigestUpdate(mdctx, decrypt_buf + params.crypto_bytes - DILITHIUM_CRHBYTES, DILITHIUM_CRHBYTES + decrypt_buf_len);
    EVP_DigestFinalXOF(mdctx, mu, DILITHIUM_CRHBYTES);
    EVP_MD_CTX_free(mdctx);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    dilithium_expand_mat(mat, rho, params.k, params.l);
    dilithium_polyvecl_ntt(&z, params.l);
    for(i = 0; i < params.k; ++i)
        dilithium_polyvecl_pointwise_acc_invmontgomery(&tmp1.vec[i], &mat[i],
                &z, params.l);

    chat = c;
    dilithium_poly_ntt(&chat);
    dilithium_polyveck_shiftl(&t1, params.k);
    dilithium_polyveck_ntt(&t1, params.k);
    for(i = 0; i < params.k; ++i)
        dilithium_poly_pointwise_invmontgomery(&tmp2.vec[i], &chat, &t1.vec[i]);

    dilithium_polyveck_sub(&tmp1, &tmp1, &tmp2, params.k);
    dilithium_polyveck_reduce(&tmp1, params.k);
    dilithium_polyveck_invntt_montgomery(&tmp1, params.k);

    /* Reconstruct w1 */
    dilithium_polyveck_csubq(&tmp1, params.k);
    dilithium_polyveck_use_hint(&w1, &tmp1, &h, params.k);

    /* Call random oracle and verify challenge */
    dilithium_challenge(&cp, mu, &w1, params.k, params.polw1_size_packed);

    for(i = 0; i < DILITHIUM_N; ++i)
        if(c.coeffs[i] != cp.coeffs[i]) {
            goto err;
        }

    /* All good, copy msg, return 0 */
    for(i = 0; i < decrypt_buf_len; ++i)
        decrypt_buf[i] = sigbuf[params.crypto_bytes + i];

    if (memcmp(m, decrypt_buf, m_len)) {
        goto err;
    }

    ret = 1;

err:
    OPENSSL_clear_free(decrypt_buf, siglen);
    return ret;
}

int Dilithium_verify(const unsigned char *m, unsigned int m_len,
               const unsigned char *sigbuf, unsigned int siglen, const Dilithium *dilithium)
{

    if (dilithium->meth->dilithium_verify) {
        return dilithium->meth->dilithium_verify(m, m_len, sigbuf, siglen, dilithium);
    }

    return int_dilithium_verify(m, m_len, sigbuf, siglen, dilithium);
}

int Dilithium_sign(const unsigned char *m, unsigned int m_len,
             unsigned char *sigret, unsigned int *siglen, const Dilithium *dilithium) {
    if (dilithium->meth->dilithium_sign) {
        return dilithium->meth->dilithium_sign(m, m_len, sigret, siglen, dilithium);
    }

    return int_dilithium_sign(m, m_len, sigret, siglen, dilithium);
}
