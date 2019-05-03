#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/asn1t.h>
#include "dilithium_locl.h"

typedef struct dilithium_privatekey_st {
    int32_t mode;
    int32_t crypto_publickeybytes;
    int32_t crypto_secretkeybytes;
    ASN1_OCTET_STRING *private_key;
    ASN1_OCTET_STRING *public_key;
} DILITHIUMPrivateKey;

ASN1_SEQUENCE(DILITHIUMPrivateKey) = {
        ASN1_EMBED(DILITHIUMPrivateKey, mode, INT32),
        ASN1_EMBED(DILITHIUMPrivateKey, crypto_publickeybytes, INT32),
        ASN1_EMBED(DILITHIUMPrivateKey, crypto_secretkeybytes, INT32),
        ASN1_SIMPLE(DILITHIUMPrivateKey, private_key, ASN1_OCTET_STRING),
        ASN1_SIMPLE(DILITHIUMPrivateKey, public_key, ASN1_OCTET_STRING),
} static_ASN1_SEQUENCE_END(DILITHIUMPrivateKey)

DECLARE_ASN1_FUNCTIONS_const(DILITHIUMPrivateKey)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(DILITHIUMPrivateKey, DILITHIUMPrivateKey)
IMPLEMENT_ASN1_FUNCTIONS_const(DILITHIUMPrivateKey)

typedef struct dilithium_publickey_st {
    int32_t mode;
    ASN1_OCTET_STRING *public_key;
} DILITHIUMPublicKey;

ASN1_SEQUENCE(DILITHIUMPublicKey) = {
        ASN1_EMBED(DILITHIUMPublicKey, mode, INT32),
        ASN1_SIMPLE(DILITHIUMPublicKey, public_key, ASN1_OCTET_STRING),
} static_ASN1_SEQUENCE_END(DILITHIUMPublicKey)

DECLARE_ASN1_FUNCTIONS_const(DILITHIUMPublicKey)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(DILITHIUMPublicKey, DILITHIUMPublicKey)
IMPLEMENT_ASN1_FUNCTIONS_const(DILITHIUMPublicKey)

Dilithium *DilithiumPublicKey_dup(Dilithium *dilithium)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(DILITHIUMPublicKey), dilithium);
}

Dilithium *DilithiumPrivateKey_dup(Dilithium *dilithium)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(DILITHIUMPrivateKey), dilithium);
}

int i2d_DilithiumPrivateKey(Dilithium *a, unsigned char **out)
{
    int ret = 0, ok = 0;
    unsigned char *priv = NULL, *pub = NULL;
    size_t privlen = 0, publen = 0;

    DILITHIUMPrivateKey *priv_key = NULL;

    if (a == NULL) {
        Dilithiumerr(DILITHIUM_F_I2D_DILITHIUMPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    if ((priv_key = DILITHIUMPrivateKey_new()) == NULL) {
        Dilithiumerr(DILITHIUM_F_I2D_DILITHIUMPRIVATEKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    priv_key->mode = a->mode;
    priv_key->crypto_publickeybytes = a->public_key_size;
    priv_key->crypto_secretkeybytes = a->private_key_size;

    privlen = a->private_key_size;

    if (privlen == 0) {
        Dilithiumerr(DILITHIUM_F_I2D_DILITHIUMPRIVATEKEY, ERR_R_DILITHIUM_LIB);
        goto err;
    }

    if (dilithium_copy_priv(a, &priv) == 0) {
        Dilithiumerr(DILITHIUM_F_I2D_DILITHIUMPRIVATEKEY, ERR_R_DILITHIUM_LIB);
        goto err;
    }
    ASN1_STRING_set0(priv_key->private_key, priv, privlen);
    priv = NULL;

    publen = a->public_key_size;

    if (dilithium_copy_pub(a, &pub) == 0) {
        Dilithiumerr(DILITHIUM_F_I2D_DILITHIUMPRIVATEKEY, ERR_R_DILITHIUM_LIB);
        goto err;
    }
    ASN1_STRING_set0(priv_key->public_key, pub, publen);
    pub = NULL;

    if ((ret = i2d_DILITHIUMPrivateKey(priv_key, out)) == 0) {
        Dilithiumerr(DILITHIUM_F_I2D_DILITHIUMPRIVATEKEY, ERR_R_DILITHIUM_LIB);
        goto err;
    }
    ok = 1;
 err:
    OPENSSL_clear_free(priv, privlen);
    DILITHIUMPrivateKey_free(priv_key);
    return (ok ? ret : 0);
}

Dilithium *d2i_DilithiumPrivateKey(Dilithium **a, const unsigned char **in, long len)
{
    Dilithium *ret = NULL;
    DILITHIUMPrivateKey *priv_key = NULL;
    const unsigned char *p = *in;

    if ((priv_key = d2i_DILITHIUMPrivateKey(NULL, &p, len)) == NULL) {
        Dilithiumerr(DILITHIUM_F_D2I_DILITHIUMPRIVATEKEY, ERR_R_DILITHIUM_LIB);
        return NULL;
    }

    if (a == NULL || *a == NULL) {
        if ((ret = dilithium_new()) == NULL) {
            Dilithiumerr(DILITHIUM_F_D2I_DILITHIUMPRIVATEKEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else
        ret = *a;

    ret->mode = priv_key->mode;
    ret->public_key_size  = priv_key->crypto_publickeybytes;
    ret->private_key_size = priv_key->crypto_secretkeybytes;

    if (priv_key->private_key) {
        ASN1_OCTET_STRING *pkey = priv_key->private_key;
        ret->private_key_size = ASN1_STRING_length(pkey);

        if (ret->private_key) {
            OPENSSL_free(ret->private_key);
        }
        ret->private_key = OPENSSL_zalloc(ret->private_key_size);
        if (ret->private_key == NULL) {
            Dilithiumerr(DILITHIUM_F_D2I_DILITHIUMPRIVATEKEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memmove(ret->private_key, ASN1_STRING_get0_data(pkey),
                ret->private_key_size);
    } else {
        Dilithiumerr(DILITHIUM_F_D2I_DILITHIUMPRIVATEKEY, DILITHIUM_R_MISSING_PRIVATE_KEY);
        goto err;
    }

    if (priv_key->public_key) {
        ASN1_OCTET_STRING *pkey = priv_key->public_key;
        ret->public_key_size = ASN1_STRING_length(pkey);

        if (ret->public_key) {
            OPENSSL_free(ret->public_key);
        }
        ret->public_key = OPENSSL_zalloc(ret->public_key_size);
        if (ret->public_key == NULL) {
            Dilithiumerr(DILITHIUM_F_D2I_DILITHIUMPRIVATEKEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memmove(ret->public_key, ASN1_STRING_get0_data(pkey),
                ret->public_key_size);
    } else {
        Dilithiumerr(DILITHIUM_F_D2I_DILITHIUMPRIVATEKEY, DILITHIUM_R_MISSING_PUBLIC_KEY);
        goto err;
    }

    if (a)
        *a = ret;
    DILITHIUMPrivateKey_free(priv_key);
    *in = p;
    return ret;

 err:
    if (a == NULL || *a != ret)
        dilithium_free(ret);
    DILITHIUMPrivateKey_free(priv_key);
    return NULL;
}

int i2d_DilithiumPublicKey(Dilithium *a, unsigned char **out)
{
    int ret = 0, ok = 0;
    unsigned char *pub= NULL;
    size_t publen = 0;

    DILITHIUMPublicKey *pub_key = NULL;

    if (a == NULL) {
        Dilithiumerr(DILITHIUM_F_I2D_DILITHIUMPUBLICKEY, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    if ((pub_key = DILITHIUMPublicKey_new()) == NULL) {
        Dilithiumerr(DILITHIUM_F_I2D_DILITHIUMPUBLICKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    pub_key->mode = a->mode;

    publen = a->public_key_size;

    if (publen == 0) {
        Dilithiumerr(DILITHIUM_F_I2D_DILITHIUMPUBLICKEY, ERR_R_DILITHIUM_LIB);
        goto err;
    }

    if (dilithium_copy_pub(a, &pub) == 0) {
        Dilithiumerr(DILITHIUM_F_I2D_DILITHIUMPUBLICKEY, ERR_R_DILITHIUM_LIB);
        goto err;
    }
    ASN1_STRING_set0(pub_key->public_key, pub, publen);
    pub = NULL;

    if ((ret = i2d_DILITHIUMPublicKey(pub_key, out)) == 0) {
        Dilithiumerr(DILITHIUM_F_I2D_DILITHIUMPUBLICKEY, ERR_R_DILITHIUM_LIB);
        goto err;
    }
    ok = 1;
 err:
    OPENSSL_clear_free(pub, publen);
    DILITHIUMPublicKey_free(pub_key);
    return (ok ? ret : 0);
}

Dilithium *d2i_DilithiumPublicKey(Dilithium **a, const unsigned char **in, long len)
{
    Dilithium *ret = NULL;
    DILITHIUMPublicKey *pub_key = NULL;
    const unsigned char *p = *in;

    if ((pub_key = d2i_DILITHIUMPublicKey(NULL, &p, len)) == NULL) {
        Dilithiumerr(DILITHIUM_F_D2I_DILITHIUMPUBLICKEY, ERR_R_DILITHIUM_LIB);
        return NULL;
    }

    if (a == NULL || *a == NULL) {
        if ((ret = dilithium_new()) == NULL) {
            Dilithiumerr(DILITHIUM_F_D2I_DILITHIUMPUBLICKEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else
        ret = *a;

    ret->mode = pub_key->mode;

    if (pub_key->public_key) {
        ASN1_OCTET_STRING *pkey = pub_key->public_key;
        ret->public_key_size = ASN1_STRING_length(pkey);

        if (ret->public_key) {
            OPENSSL_free(ret->public_key);
        }
        ret->public_key = OPENSSL_zalloc(ret->public_key_size);
        if (ret->public_key == NULL) {
            Dilithiumerr(DILITHIUM_F_D2I_DILITHIUMPUBLICKEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memmove(ret->public_key, ASN1_STRING_get0_data(pkey),
                ret->public_key_size);
    } else {
        Dilithiumerr(DILITHIUM_F_D2I_DILITHIUMPUBLICKEY, DILITHIUM_R_MISSING_PUBLIC_KEY);
        goto err;
    }

    if (a)
        *a = ret;
    DILITHIUMPublicKey_free(pub_key);
    *in = p;
    return ret;

 err:
    if (a == NULL || *a != ret)
        dilithium_free(ret);
    DILITHIUMPublicKey_free(pub_key);
    return NULL;
}
