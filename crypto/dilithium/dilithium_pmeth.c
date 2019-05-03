#include "internal/constant_time_locl.h"

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/dilithium.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include "internal/evp_int.h"
#include "dilithium_locl.h"

/* Dilithium pkey context structure */

typedef struct {
    /* Key gen parameters */
    int mode;
    uint8_t *public_key;
    int public_key_size;
} DILITHIUM_PKEY_CTX;

static int pkey_dilithium_init(EVP_PKEY_CTX *ctx)
{
    DILITHIUM_PKEY_CTX *rctx = OPENSSL_zalloc(sizeof(*rctx));

    if (rctx == NULL)
        return 0;
    rctx->mode = 3; // Default mode
    rctx->public_key_size = 0;
    rctx->public_key = NULL;

    ctx->data = rctx;

    return 1;
}

static int pkey_dilithium_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    DILITHIUM_PKEY_CTX *dctx, *sctx;

    if (!pkey_dilithium_init(dst))
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

static void pkey_dilithium_cleanup(EVP_PKEY_CTX *ctx)
{
    DILITHIUM_PKEY_CTX *rctx = ctx->data;
    if (rctx) {
        if (rctx->public_key) {
            OPENSSL_free(rctx->public_key);
        }
        OPENSSL_free(rctx);
    }
}

static int pkey_dilithium_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    DILITHIUM_PKEY_CTX *rctx = ctx->data;

    switch (type) {
        case EVP_PKEY_CTRL_DILITHIUM_KEYGEN_MODE:
            if (p1 < 1 || p1 > 4) {
                Dilithiumerr(DILITHIUM_F_PKEY_DILITHIUM_CTRL, DILITHIUM_R_BAD_MODE_VALUE);
                return -2;
            }
            rctx->mode = p1;
            return 1;
        default:
            return -2;
    }
}

static int pkey_dilithium_ctrl_str(EVP_PKEY_CTX *ctx,
                             const char *type, const char *value)
{
    if (value == NULL) {
        Dilithiumerr(DILITHIUM_F_PKEY_DILITHIUM_CTRL_STR, DILITHIUM_R_VALUE_MISSING);
        return 0;
    }
    if (strcmp(type, "dilithium_mode") == 0) {
        int mode;

        if (strcmp(value, "1") == 0) {
            mode = 1;
        } else if (strcmp(value, "2") == 0) {
            mode = 2;
        } else if (strcmp(value, "3") == 0) {
            mode = 3;
        } else if (strcmp(value, "4") == 0) {
            mode = 4;
        } else {
            Dilithiumerr(DILITHIUM_F_PKEY_DILITHIUM_CTRL_STR, DILITHIUM_R_BAD_MODE_VALUE);
            return -2;
        }
        return EVP_PKEY_CTX_set_dilithium_mode(ctx, mode);
    }

    return -2;
}

static int pkey_dilithium_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    Dilithium *dilithium = NULL;
    DILITHIUM_PKEY_CTX *rctx = ctx->data;
    int ret = 1;

    dilithium = dilithium_new();
    if (dilithium == NULL)
        return 0;
    if (!ossl_assert(EVP_PKEY_assign_Dilithium(pkey, dilithium))) {
        dilithium_free(dilithium);
        return 0;
    }

    return ret ? dilithium_generate_key_ex(dilithium, rctx->mode) : 0;
}

const EVP_PKEY_METHOD dilithium_pkey_meth = {
    EVP_PKEY_DILITHIUM,
    EVP_PKEY_FLAG_AUTOARGLEN,
    pkey_dilithium_init,
    pkey_dilithium_copy,
    pkey_dilithium_cleanup,

    0, 0,

    0,
    pkey_dilithium_keygen,

    0,
    0,

    0,
    0,

    0,
    0,

    0, 0, 0, 0,

    0,
    0,

    0,
    0,

    0, 0,

    pkey_dilithium_ctrl,
    pkey_dilithium_ctrl_str
};
