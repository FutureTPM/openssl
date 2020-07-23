#include "internal/constant_time_locl.h"

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/kyber.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include "internal/evp_int.h"
#include "kyber-locl.h"

/* Kyber pkey context structure */

typedef struct {
    /* Key gen parameters */
    int mode;
    uint8_t *public_key;
    int public_key_size;
} KYBER_PKEY_CTX;

static int pkey_kyber_init(EVP_PKEY_CTX *ctx)
{
    KYBER_PKEY_CTX *rctx = OPENSSL_zalloc(sizeof(*rctx));

    if (rctx == NULL)
        return 0;
    rctx->mode = 2; // Default mode
    rctx->public_key_size = 0;
    rctx->public_key = NULL;

    ctx->data = rctx;

    return 1;
}

static int pkey_kyber_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    KYBER_PKEY_CTX *dctx, *sctx;

    if (!pkey_kyber_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;

    dctx->mode = sctx->mode;
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

static void pkey_kyber_cleanup(EVP_PKEY_CTX *ctx)
{
    KYBER_PKEY_CTX *rctx = ctx->data;
    if (rctx) {
        if (rctx->public_key) {
            OPENSSL_free(rctx->public_key);
        }
        OPENSSL_free(rctx);
    }
}

static int pkey_kyber_encrypt(EVP_PKEY_CTX *ctx,
                            unsigned char *out, size_t *outlen,
                            const unsigned char *in, size_t inlen)
{
    int ret;

    ret = kyber_public_encrypt(inlen, in, out, ctx->pkey->pkey.kyber);

    if (ret < 0)
        return ret;
    *outlen = ret;
    return 1;
}

static int pkey_kyber_decrypt(EVP_PKEY_CTX *ctx,
                            unsigned char *out, size_t *outlen,
                            const unsigned char *in, size_t inlen)
{
    int ret;

    ret = kyber_private_decrypt(inlen, in, out, ctx->pkey->pkey.kyber);
    *outlen = constant_time_select_s(constant_time_msb_s(ret), *outlen, ret);
    ret = constant_time_select_int(constant_time_msb(ret), ret, 1);
    return ret;
}

static int pkey_kyber_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    KYBER_PKEY_CTX *rctx = ctx->data;

    switch (type) {
        case EVP_PKEY_CTRL_KYBER_KEYGEN_MODE:
            if (p1 < 2 || p1 > 4) {
                Kybererr(KYBER_F_PKEY_KYBER_CTRL, KYBER_R_BAD_MODE_VALUE);
                return -2;
            }
            rctx->mode = p1;
            return 1;
        default:
            return -2;
    }
}

static int pkey_kyber_ctrl_str(EVP_PKEY_CTX *ctx,
                             const char *type, const char *value)
{
    if (value == NULL) {
        Kybererr(KYBER_F_PKEY_KYBER_CTRL_STR, KYBER_R_VALUE_MISSING);
        return 0;
    }
    if (strcmp(type, "kyber_mode") == 0) {
        int mode;

        if (strcmp(value, "2") == 0) {
            mode = 2;
        } else if (strcmp(value, "3") == 0) {
            mode = 3;
        } else if (strcmp(value, "4") == 0) {
            mode = 4;
        } else {
            Kybererr(KYBER_F_PKEY_KYBER_CTRL_STR, KYBER_R_BAD_MODE_VALUE);
            return -2;
        }
        return EVP_PKEY_CTX_set_kyber_mode(ctx, mode);
    }

    return -2;
}

static int pkey_kyber_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    Kyber *kyber = NULL;
    KYBER_PKEY_CTX *rctx = ctx->data;
    int ret = 1;

    kyber = kyber_new();
    if (kyber == NULL)
        return 0;
    if (!ossl_assert(EVP_PKEY_assign_Kyber(pkey, kyber))) {
        kyber_free(kyber);
        return 0;
    }

    return ret ? kyber_generate_key_ex(kyber, rctx->mode) : 0;
}

const EVP_PKEY_METHOD kyber_pkey_meth = {
    EVP_PKEY_KYBER,
    EVP_PKEY_FLAG_AUTOARGLEN,
    pkey_kyber_init,
    pkey_kyber_copy,
    pkey_kyber_cleanup,

    0, 0,

    0,
    pkey_kyber_keygen,

    0,
    0,

    0,
    0,

    0,
    0,

    0, 0, 0, 0,

    0,
    pkey_kyber_encrypt,

    0,
    pkey_kyber_decrypt,

    0, 0,

    pkey_kyber_ctrl,
    pkey_kyber_ctrl_str
};
