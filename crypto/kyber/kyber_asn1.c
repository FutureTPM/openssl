#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/asn1t.h>
#include "kyber_locl.h"

typedef struct kyber_privatekey_st {
    int32_t mode;
    ASN1_OCTET_STRING *private_key;
} KYBERPrivateKey;

ASN1_SEQUENCE(KYBERPrivateKey) = {
        ASN1_EMBED(KYBERPrivateKey, mode, INT32),
        ASN1_SIMPLE(KYBERPrivateKey, private_key, ASN1_OCTET_STRING),
} static_ASN1_SEQUENCE_END(KYBERPrivateKey)

DECLARE_ASN1_FUNCTIONS_const(KYBERPrivateKey)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(KYBERPrivateKey, KYBERPrivateKey)
IMPLEMENT_ASN1_FUNCTIONS_const(KYBERPrivateKey)

typedef struct kyber_publickey_st {
    int32_t mode;
    ASN1_OCTET_STRING *public_key;
} KYBERPublicKey;

ASN1_SEQUENCE(KYBERPublicKey) = {
        ASN1_EMBED(KYBERPublicKey, mode, INT32),
        ASN1_SIMPLE(KYBERPublicKey, public_key, ASN1_OCTET_STRING),
} static_ASN1_SEQUENCE_END(KYBERPublicKey)

DECLARE_ASN1_FUNCTIONS_const(KYBERPublicKey)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(KYBERPublicKey, KYBERPublicKey)
IMPLEMENT_ASN1_FUNCTIONS_const(KYBERPublicKey)

Kyber *KyberPublicKey_dup(Kyber *kyber)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(KYBERPublicKey), kyber);
}

Kyber *KyberPrivateKey_dup(Kyber *kyber)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(KYBERPrivateKey), kyber);
}

int i2d_KyberPrivateKey(Kyber *a, unsigned char **out)
{
    int ret = 0, ok = 0;
    unsigned char *priv= NULL;
    size_t privlen = 0;

    KYBERPrivateKey *priv_key = NULL;

    if (a == NULL) {
        Kybererr(KYBER_F_I2D_KYBERPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    if ((priv_key = KYBERPrivateKey_new()) == NULL) {
        Kybererr(KYBER_F_I2D_KYBERPRIVATEKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    priv_key->mode = a->mode;

    privlen = a->private_key_size;

    if (privlen == 0) {
        Kybererr(KYBER_F_I2D_KYBERPRIVATEKEY, ERR_R_KYBER_LIB);
        goto err;
    }

    if (kyber_copy_priv(a, &priv) == 0) {
        Kybererr(KYBER_F_I2D_KYBERPRIVATEKEY, ERR_R_KYBER_LIB);
        goto err;
    }
    ASN1_STRING_set0(priv_key->private_key, priv, privlen);
    priv = NULL;

    if ((ret = i2d_KYBERPrivateKey(priv_key, out)) == 0) {
        Kybererr(KYBER_F_I2D_KYBERPRIVATEKEY, ERR_R_KYBER_LIB);
        goto err;
    }
    ok = 1;
 err:
    OPENSSL_clear_free(priv, privlen);
    KYBERPrivateKey_free(priv_key);
    return (ok ? ret : 0);
}

Kyber *d2i_KyberPrivateKey(Kyber **a, const unsigned char **in, long len)
{
    Kyber *ret = NULL;
    KYBERPrivateKey *priv_key = NULL;
    const unsigned char *p = *in;

    if ((priv_key = d2i_KYBERPrivateKey(NULL, &p, len)) == NULL) {
        Kybererr(KYBER_F_D2I_KYBERPRIVATEKEY, ERR_R_KYBER_LIB);
        return NULL;
    }

    if (a == NULL || *a == NULL) {
        if ((ret = kyber_new()) == NULL) {
            Kybererr(KYBER_F_D2I_KYBERPRIVATEKEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else
        ret = *a;

    ret->mode = priv_key->mode;

    KyberParams params = generate_kyber_params(ret->mode);

    if (priv_key->private_key) {
        ASN1_OCTET_STRING *pkey = priv_key->private_key;
        ret->private_key_size = ASN1_STRING_length(pkey);

        if (ret->private_key) {
            OPENSSL_free(ret->private_key);
        }
        ret->private_key = OPENSSL_zalloc(ret->private_key_size);
        if (ret->private_key == NULL) {
            Kybererr(KYBER_F_D2I_KYBERPRIVATEKEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memmove(ret->private_key, ASN1_STRING_get0_data(pkey),
                ret->private_key_size);

        ret->public_key_size = params.publickeybytes;
        if (ret->public_key) {
            OPENSSL_free(ret->public_key);
        }
        ret->public_key = OPENSSL_zalloc(ret->public_key_size);
        if (ret->public_key == NULL) {
            Kybererr(KYBER_F_D2I_KYBERPRIVATEKEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memmove(ret->public_key, ret->private_key + params.indcpa_secretkeybytes,
                ret->public_key_size);
    } else {
        Kybererr(KYBER_F_D2I_KYBERPRIVATEKEY, KYBER_R_MISSING_PRIVATE_KEY);
        goto err;
    }

    if (a)
        *a = ret;
    KYBERPrivateKey_free(priv_key);
    *in = p;
    return ret;

 err:
    if (a == NULL || *a != ret)
        kyber_free(ret);
    KYBERPrivateKey_free(priv_key);
    return NULL;
}

int i2d_KyberPublicKey(Kyber *a, unsigned char **out)
{
    int ret = 0, ok = 0;
    unsigned char *pub= NULL;
    size_t publen = 0;

    KYBERPublicKey *pub_key = NULL;

    if (a == NULL) {
        Kybererr(KYBER_F_I2D_KYBERPUBLICKEY, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    if ((pub_key = KYBERPublicKey_new()) == NULL) {
        Kybererr(KYBER_F_I2D_KYBERPUBLICKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    pub_key->mode = a->mode;

    publen = a->public_key_size;

    if (publen == 0) {
        Kybererr(KYBER_F_I2D_KYBERPUBLICKEY, ERR_R_KYBER_LIB);
        goto err;
    }

    if (kyber_copy_pub(a, &pub) == 0) {
        Kybererr(KYBER_F_I2D_KYBERPUBLICKEY, ERR_R_KYBER_LIB);
        goto err;
    }
    ASN1_STRING_set0(pub_key->public_key, pub, publen);
    pub = NULL;

    if ((ret = i2d_KYBERPublicKey(pub_key, out)) == 0) {
        Kybererr(KYBER_F_I2D_KYBERPUBLICKEY, ERR_R_KYBER_LIB);
        goto err;
    }
    ok = 1;
 err:
    OPENSSL_clear_free(pub, publen);
    KYBERPublicKey_free(pub_key);
    return (ok ? ret : 0);
}

Kyber *d2i_KyberPublicKey(Kyber **a, const unsigned char **in, long len)
{
    Kyber *ret = NULL;
    KYBERPublicKey *pub_key = NULL;
    const unsigned char *p = *in;

    if ((pub_key = d2i_KYBERPublicKey(NULL, &p, len)) == NULL) {
        Kybererr(KYBER_F_D2I_KYBERPUBLICKEY, ERR_R_KYBER_LIB);
        return NULL;
    }

    if (a == NULL || *a == NULL) {
        if ((ret = kyber_new()) == NULL) {
            Kybererr(KYBER_F_D2I_KYBERPUBLICKEY, ERR_R_MALLOC_FAILURE);
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
            Kybererr(KYBER_F_D2I_KYBERPUBLICKEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memmove(ret->public_key, ASN1_STRING_get0_data(pkey),
                ret->public_key_size);
    } else {
        Kybererr(KYBER_F_D2I_KYBERPUBLICKEY, KYBER_R_MISSING_PUBLIC_KEY);
        goto err;
    }

    if (a)
        *a = ret;
    KYBERPublicKey_free(pub_key);
    *in = p;
    return ret;

 err:
    if (a == NULL || *a != ret)
        kyber_free(ret);
    KYBERPublicKey_free(pub_key);
    return NULL;
}
