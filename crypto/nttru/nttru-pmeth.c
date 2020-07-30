#include "internal/constant_time_locl.h"

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/nttru.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include "internal/evp_int.h"
#include "nttru-locl.h"

/* NTTRU pkey context structure */

typedef struct {
    /* Key gen parameters */
    uint8_t *public_key;
    int public_key_size;
} NTTRU_PKEY_CTX;

static int pkey_nttru_init(EVP_PKEY_CTX *ctx)
{
    NTTRU_PKEY_CTX *rctx = OPENSSL_zalloc(sizeof(*rctx));

    if (rctx == NULL)
        return 0;
    rctx->public_key_size = 0;
    rctx->public_key = NULL;

    ctx->data = rctx;

    return 1;
}

static int pkey_nttru_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    NTTRU_PKEY_CTX *dctx, *sctx;

    if (!pkey_nttru_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;

    dctx->public_key_size = sctx->public_key_size;

    if (sctx->public_key) {
        dctx->public_key = OPENSSL_memdup(sctx->public_key, sctx->public_key_size);
        if (!dctx->public_key)
            return 0;
    } else {
        dctx->public_key = NULL;
    }

    return 1;
}

static void pkey_nttru_cleanup(EVP_PKEY_CTX *ctx)
{
    NTTRU_PKEY_CTX *rctx = ctx->data;
    if (rctx) {
        if (rctx->public_key) {
            OPENSSL_free(rctx->public_key);
        }
        OPENSSL_free(rctx);
    }
}

static int pkey_nttru_encrypt(EVP_PKEY_CTX *ctx,
                            unsigned char *out, size_t *outlen,
                            const unsigned char *in, size_t inlen)
{
    int ret;

    ret = nttru_public_encrypt(inlen, in, out, ctx->pkey->pkey.nttru);

    if (ret < 0)
        return ret;
    *outlen = ret;
    return 1;
}

static int pkey_nttru_decrypt(EVP_PKEY_CTX *ctx,
                            unsigned char *out, size_t *outlen,
                            const unsigned char *in, size_t inlen)
{
    int ret;

    ret = nttru_private_decrypt(inlen, in, out, ctx->pkey->pkey.nttru);
    *outlen = constant_time_select_s(constant_time_msb_s(ret), *outlen, ret);
    ret = constant_time_select_int(constant_time_msb(ret), ret, 1);
    return ret;
}

static int pkey_nttru_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
  //NTTRU_PKEY_CTX *rctx = ctx->data;

    switch (type) {
        case EVP_PKEY_CTRL_NTTRU_KEYGEN_MODE:
            if (p1 < 2 || p1 > 4) {
                NTTRUerr(NTTRU_F_PKEY_NTTRU_CTRL, NTTRU_R_BAD_MODE_VALUE);
                return -2;
            }
            return 1;
        default:
            return -2;
    }
}

static int pkey_nttru_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    NTTRU *nttru = NULL;
    // NTTRU_PKEY_CTX *rctx = ctx->data;
    int ret = 1;

    nttru = nttru_new();
    if (nttru == NULL)
        return 0;
    if (!ossl_assert(EVP_PKEY_assign_NTTRU(pkey, nttru))) {
        nttru_free(nttru);
        return 0;
    }

    return ret ? nttru_generate_key_ex(nttru) : 0;
}

const EVP_PKEY_METHOD nttru_pkey_meth = {
    EVP_PKEY_NTTRU,
    EVP_PKEY_FLAG_AUTOARGLEN,
    pkey_nttru_init,
    pkey_nttru_copy,
    pkey_nttru_cleanup,

    0, 0,

    0,
    pkey_nttru_keygen,

    0,
    0,

    0,
    0,

    0,
    0,

    0, 0, 0, 0,

    0,
    pkey_nttru_encrypt,

    0,
    pkey_nttru_decrypt,

    0, 0,

    pkey_nttru_ctrl
};
