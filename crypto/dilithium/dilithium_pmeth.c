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
    /* message digest */
    const EVP_MD *md;
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
    dctx->md = sctx->md;

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
        case EVP_PKEY_CTRL_MD:
            if (EVP_MD_type((const EVP_MD *)p2) != NID_sha1 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha224 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha256 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha384 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha512 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha3_256 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha3_384 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha3_512) {
                    ECerr(EC_F_PKEY_EC_CTRL, EC_R_INVALID_DIGEST_TYPE);
                    return 0;
            }
            rctx->md = p2;
            return 1;
        case EVP_PKEY_CTRL_DIGESTINIT:
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

static int pkey_dilithium_sign(EVP_PKEY_CTX *ctx,
                 unsigned char *sig, size_t *siglen,
                 const unsigned char *dgst, size_t dgstlen) {
    int ret;
    Dilithium *dilithium = ctx->pkey->pkey.dilithium;
    const int sig_sz = Dilithium_sig_size(dilithium) - 64;
    unsigned int sltmp = 0;

    /* ensure cast to size_t is safe */
    if (!ossl_assert(sig_sz > 0))
        return 0;

    if (sig == NULL) {
        *siglen = (size_t)sig_sz;
        return 1;
    }

    if (*siglen < (size_t)sig_sz) {
        Dilithiumerr(DILITHIUM_F_PKEY_DILITHIUM_SIGN, DILITHIUM_R_BUFFER_TOO_SMALL);
        return 0;
    }

    ret = Dilithium_sign(dgst, (int)dgstlen, sig, &sltmp, dilithium);

    if (ret < 0)
        return ret;
    *siglen = (size_t)sltmp;
    return 1;
}

static int pkey_dilithium_verify(EVP_PKEY_CTX *ctx,
                   const unsigned char *sig, size_t siglen,
                   const unsigned char *dgst, size_t dgstlen) {
    int ret;
    Dilithium *dilithium = ctx->pkey->pkey.dilithium;

    ret = Dilithium_verify(dgst, (int)dgstlen, sig, (int)siglen, dilithium);

    return ret;
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
    pkey_dilithium_sign,

    0,
    pkey_dilithium_verify,

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
