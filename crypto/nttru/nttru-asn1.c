#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/asn1t.h>
#include "nttru-locl.h"
#include "nttru-params.h"

typedef struct nttru_privatekey_st {
    int32_t publickeybytes;
    int32_t secretkeybytes;
    ASN1_OCTET_STRING *private_key;
} NTTRUPrivateKey;

ASN1_SEQUENCE(NTTRUPrivateKey) = {
        ASN1_EMBED(NTTRUPrivateKey, publickeybytes, INT32),
        ASN1_EMBED(NTTRUPrivateKey, secretkeybytes, INT32),
        ASN1_SIMPLE(NTTRUPrivateKey, private_key, ASN1_OCTET_STRING),
} static_ASN1_SEQUENCE_END(NTTRUPrivateKey)

DECLARE_ASN1_FUNCTIONS_const(NTTRUPrivateKey)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(NTTRUPrivateKey, NTTRUPrivateKey)
IMPLEMENT_ASN1_FUNCTIONS_const(NTTRUPrivateKey)

typedef struct nttru_publickey_st {
    int32_t publickeybytes;
    int32_t secretkeybytes;
    ASN1_OCTET_STRING *public_key;
} NTTRUPublicKey;

ASN1_SEQUENCE(NTTRUPublicKey) = {
        ASN1_EMBED(NTTRUPrivateKey, publickeybytes, INT32),
        ASN1_EMBED(NTTRUPrivateKey, secretkeybytes, INT32),
        ASN1_SIMPLE(NTTRUPublicKey, public_key, ASN1_OCTET_STRING),
} static_ASN1_SEQUENCE_END(NTTRUPublicKey)

DECLARE_ASN1_FUNCTIONS_const(NTTRUPublicKey)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(NTTRUPublicKey, NTTRUPublicKey)
IMPLEMENT_ASN1_FUNCTIONS_const(NTTRUPublicKey)

NTTRU *NTTRUPublicKey_dup(NTTRU *nttru)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(NTTRUPublicKey), nttru);
}

NTTRU *NTTRUPrivateKey_dup(NTTRU *nttru)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(NTTRUPrivateKey), nttru);
}

int i2d_NttruPrivateKey(NTTRU *a, unsigned char **out)
{
    int ret = 0, ok = 0;
    unsigned char *priv= NULL;
    size_t privlen = 0;

    NTTRUPrivateKey *priv_key = NULL;

    if (a == NULL) {
        NTTRUerr(NTTRU_F_I2D_NTTRUPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    if ((priv_key = NTTRUPrivateKey_new()) == NULL) {
        NTTRUerr(NTTRU_F_I2D_NTTRUPRIVATEKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    priv_key->publickeybytes = NTTRU_PUBLICKEYBYTES;
    priv_key->secretkeybytes = NTTRU_SECRETKEYBYTES;

    privlen = a->private_key_size;

    if (privlen == 0) {
        NTTRUerr(NTTRU_F_I2D_NTTRUPRIVATEKEY, ERR_R_NTTRU_LIB);
        goto err;
    }

    if (nttru_copy_priv(a, &priv) == 0) {
        NTTRUerr(NTTRU_F_I2D_NTTRUPRIVATEKEY, ERR_R_NTTRU_LIB);
        goto err;
    }
    ASN1_STRING_set0(priv_key->private_key, priv, privlen);
    priv = NULL;

    if ((ret = i2d_NTTRUPrivateKey(priv_key, out)) == 0) {
        NTTRUerr(NTTRU_F_I2D_NTTRUPRIVATEKEY, ERR_R_NTTRU_LIB);
        goto err;
    }
    ok = 1;
 err:
    OPENSSL_clear_free(priv, privlen);
    NTTRUPrivateKey_free(priv_key);
    return (ok ? ret : 0);
}

NTTRU *d2i_NttruPrivateKey(NTTRU **a, const unsigned char **in, long len)
{
    NTTRU *ret = NULL;
    NTTRUPrivateKey *priv_key = NULL;
    const unsigned char *p = *in;

    if ((priv_key = d2i_NTTRUPrivateKey(NULL, &p, len)) == NULL) {
        NTTRUerr(NTTRU_F_D2I_NTTRUPRIVATEKEY, ERR_R_NTTRU_LIB);
        return NULL;
    }

    if (a == NULL || *a == NULL) {
        if ((ret = nttru_new()) == NULL) {
            NTTRUerr(NTTRU_F_D2I_NTTRUPRIVATEKEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else
        ret = *a;

    if (priv_key->private_key) {
        ASN1_OCTET_STRING *pkey = priv_key->private_key;
        ret->private_key_size = ASN1_STRING_length(pkey);

        if (ret->private_key) {
            OPENSSL_free(ret->private_key);
        }
        ret->private_key = OPENSSL_zalloc(ret->private_key_size);
        if (ret->private_key == NULL) {
            NTTRUerr(NTTRU_F_D2I_NTTRUPRIVATEKEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memmove(ret->private_key, ASN1_STRING_get0_data(pkey),
                ret->private_key_size);

        ret->public_key_size = priv_key->publickeybytes;
        if (ret->public_key) {
            OPENSSL_free(ret->public_key);
        }
        ret->public_key = OPENSSL_zalloc(ret->public_key_size);
        if (ret->public_key == NULL) {
            NTTRUerr(NTTRU_F_D2I_NTTRUPRIVATEKEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memmove(ret->public_key, ret->private_key, ret->public_key_size);
    } else {
        NTTRUerr(NTTRU_F_D2I_NTTRUPRIVATEKEY, NTTRU_R_MISSING_PRIVATE_KEY);
        goto err;
    }

    if (a)
        *a = ret;
    NTTRUPrivateKey_free(priv_key);
    *in = p;
    return ret;

 err:
    if (a == NULL || *a != ret)
        nttru_free(ret);
    NTTRUPrivateKey_free(priv_key);
    return NULL;
}

int i2d_NttruPublicKey(NTTRU *a, unsigned char **out)
{
    int ret = 0, ok = 0;
    unsigned char *pub= NULL;
    size_t publen = 0;

    NTTRUPublicKey *pub_key = NULL;

    if (a == NULL) {
        NTTRUerr(NTTRU_F_I2D_NTTRUPUBLICKEY, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    if ((pub_key = NTTRUPublicKey_new()) == NULL) {
        NTTRUerr(NTTRU_F_I2D_NTTRUPUBLICKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    publen = a->public_key_size;

    pub_key->publickeybytes = NTTRU_PUBLICKEYBYTES;
    pub_key->secretkeybytes = NTTRU_SECRETKEYBYTES;

    if (publen == 0) {
        NTTRUerr(NTTRU_F_I2D_NTTRUPUBLICKEY, ERR_R_NTTRU_LIB);
        goto err;
    }

    if (nttru_copy_pub(a, &pub) == 0) {
        NTTRUerr(NTTRU_F_I2D_NTTRUPUBLICKEY, ERR_R_NTTRU_LIB);
        goto err;
    }
    ASN1_STRING_set0(pub_key->public_key, pub, publen);
    pub = NULL;

    if ((ret = i2d_NTTRUPublicKey(pub_key, out)) == 0) {
        NTTRUerr(NTTRU_F_I2D_NTTRUPUBLICKEY, ERR_R_NTTRU_LIB);
        goto err;
    }
    ok = 1;
 err:
    OPENSSL_clear_free(pub, publen);
    NTTRUPublicKey_free(pub_key);
    return (ok ? ret : 0);
}

NTTRU *d2i_NttruPublicKey(NTTRU **a, const unsigned char **in, long len)
{
    NTTRU *ret = NULL;
    NTTRUPublicKey *pub_key = NULL;
    const unsigned char *p = *in;

    if ((pub_key = d2i_NTTRUPublicKey(NULL, &p, len)) == NULL) {
        NTTRUerr(NTTRU_F_D2I_NTTRUPUBLICKEY, ERR_R_NTTRU_LIB);
        return NULL;
    }

    if (a == NULL || *a == NULL) {
        if ((ret = nttru_new()) == NULL) {
            NTTRUerr(NTTRU_F_D2I_NTTRUPUBLICKEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else
        ret = *a;

    if (pub_key->public_key) {
        ASN1_OCTET_STRING *pkey = pub_key->public_key;
        ret->public_key_size = ASN1_STRING_length(pkey);

        if (ret->public_key) {
            OPENSSL_free(ret->public_key);
        }
        ret->public_key = OPENSSL_zalloc(ret->public_key_size);
        if (ret->public_key == NULL) {
            NTTRUerr(NTTRU_F_D2I_NTTRUPUBLICKEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memmove(ret->public_key, ASN1_STRING_get0_data(pkey),
                ret->public_key_size);
    } else {
        NTTRUerr(NTTRU_F_D2I_NTTRUPUBLICKEY, NTTRU_R_MISSING_PUBLIC_KEY);
        goto err;
    }

    if (a)
        *a = ret;
    NTTRUPublicKey_free(pub_key);
    *in = p;
    return ret;

 err:
    if (a == NULL || *a != ret)
        nttru_free(ret);
    NTTRUPublicKey_free(pub_key);
    return NULL;
}
