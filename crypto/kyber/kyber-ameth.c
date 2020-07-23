#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include "internal/asn1_int.h"
#include "internal/evp_int.h"
#include "kyber-locl.h"

static int kyber_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)
{
    unsigned char *penc = NULL;
    int penclen;

    penclen = i2d_KyberPublicKey(pkey->pkey.kyber, &penc);
    if (penclen <= 0)
        return 0;
    if (X509_PUBKEY_set0_param(pk, OBJ_nid2obj(EVP_PKEY_KYBER),
                               V_ASN1_NULL, NULL, penc, penclen))
        return 1;

    OPENSSL_free(penc);
    return 0;
}

static int kyber_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
    const unsigned char *p;
    int pklen;
    X509_ALGOR *alg;
    Kyber *kyber = NULL;

    if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, &alg, pubkey))
        return 0;
    if ((kyber = d2i_KyberPublicKey(NULL, &p, pklen)) == NULL) {
        Kybererr(KYBER_F_KYBER_PUB_DECODE, ERR_R_KYBER_LIB);
        return 0;
    }
    if (!EVP_PKEY_assign_Kyber(pkey, kyber)) {
        kyber_free(kyber);
        return 0;
    }
    return 1;
}

static int kyber_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    if (b->pkey.kyber->mode != a->pkey.kyber->mode
        || b->pkey.kyber->public_key_size != a->pkey.kyber->public_key_size
        || memcmp(b->pkey.kyber->public_key, a->pkey.kyber->public_key,
            a->pkey.kyber->public_key_size) != 0)
        return 0;
    return 1;
}

static int kyber_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
    unsigned char *rk = NULL;
    int rklen;

    if (!pkey->pkey.kyber || !pkey->pkey.kyber->private_key) {
        Kybererr(KYBER_F_KYBER_PRIV_ENCODE, KYBER_R_VALUE_MISSING);
        return 0;
    }

    rklen = i2d_KyberPrivateKey(pkey->pkey.kyber, &rk);
    if (rklen == 0) {
        OPENSSL_free(rk);
        Kybererr(KYBER_F_KYBER_PRIV_ENCODE, ERR_R_KYBER_LIB);
        return 0;
    }

    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_kyber), 0,
                         V_ASN1_NULL, NULL, rk, rklen)) {
        Kybererr(KYBER_F_KYBER_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(rk);
        return 0;
    }

    return 1;
}

static int kyber_priv_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8)
{
    const unsigned char *p;
    Kyber *kyber;
    int pklen;
    const X509_ALGOR *alg;
    int ptype;

    if (!PKCS8_pkey_get0(NULL, &p, &pklen, &alg, p8))
        return 0;
    X509_ALGOR_get0(NULL, &ptype, NULL, alg);

    if (ptype != V_ASN1_NULL)
        return 0;

    kyber = d2i_KyberPrivateKey(NULL, &p, pklen);
    if (kyber == NULL) {
        Kybererr(KYBER_F_KYBER_PRIV_DECODE, ERR_R_KYBER_LIB);
        return 0;
    }
    EVP_PKEY_assign_Kyber(pkey, kyber);
    return 1;
}

static void int_kyber_free(EVP_PKEY *pkey)
{
    kyber_free(pkey->pkey.kyber);
}

static int pkey_kyber_print(BIO *bp, const EVP_PKEY *pkey, int off, int priv)
{
    const Kyber *x = pkey->pkey.kyber;
    int ret = 0;

    if (!BIO_indent(bp, off, 128))
        goto err;

    if (BIO_printf(bp, "%s ", "Kyber") <= 0)
        goto err;

    if (BIO_printf(bp, "%s %hhd ", "Mode", x->mode) <= 0)
        goto err;

    if (priv && x->private_key) {
        if (BIO_printf(bp, "Private-Key (%u bytes): [", x->private_key_size) <= 0)
            goto err;

        for (size_t i = 0; i < x->private_key_size; i++) {
            if (BIO_printf(bp, "%02x", x->private_key[i]) <= 0)
                goto err;
        }

        if (BIO_printf(bp, "]\n") <= 0)
            goto err;
    } else {
        if (BIO_printf(bp, "Public-Key (%u bytes): [", x->public_key_size) <= 0)
            goto err;

        for (size_t i = 0; i < x->public_key_size; i++) {
            if (BIO_printf(bp, "%02x", x->public_key[i]) <= 0)
                goto err;
        }

        if (BIO_printf(bp, "]\n") <= 0)
            goto err;
    }

    ret = 1;

 err:
    return ret;
}

static int kyber_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *ctx)
{
    return pkey_kyber_print(bp, pkey, indent, 0);
}

static int kyber_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                          ASN1_PCTX *ctx)
{
    return pkey_kyber_print(bp, pkey, indent, 1);
}

static int kyber_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    X509_ALGOR *alg = NULL;

    switch (op) {

    case ASN1_PKEY_CTRL_PKCS7_ENCRYPT:
        if (arg1 == 0)
            PKCS7_RECIP_INFO_get0_alg(arg2, &alg);
        break;
    case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
        *(int *)arg2 = NID_sha3_256;
        return 1;
    case ASN1_PKEY_CTRL_SET1_TLS_KYBER_PK: {
        Kyber *kyber = EVP_PKEY_get0_Kyber(pkey);
        kyber->public_key = (unsigned char *) arg2;
        kyber->public_key_size = (int) arg1;
        break;
                                           }

    case ASN1_PKEY_CTRL_GET1_TLS_KYBER_PK: {
        Kyber *kyber = EVP_PKEY_get0_Kyber(pkey);
        *(unsigned char **)arg2 = kyber->public_key;
        return kyber->public_key_size;
                                           }

    default:
        return -2;

    }

    if (alg)
        X509_ALGOR_set0(alg, OBJ_nid2obj(NID_kyber), V_ASN1_NULL, 0);

    return 1;

}

static int old_kyber_priv_decode(EVP_PKEY *pkey,
                               const unsigned char **pder, int derlen)
{
    Kyber *kyber;

    if ((kyber = d2i_KyberPrivateKey(NULL, pder, derlen)) == NULL) {
        Kybererr(KYBER_F_OLD_KYBER_PRIV_DECODE, ERR_R_KYBER_LIB);
        return 0;
    }
    EVP_PKEY_assign_Kyber(pkey, kyber);
    return 1;
}

static int old_kyber_priv_encode(const EVP_PKEY *pkey, unsigned char **pder)
{
    return i2d_KyberPrivateKey(pkey->pkey.kyber, pder);
}

static int kyber_pkey_check(const EVP_PKEY *pkey)
{
    return kyber_check_key_ex(pkey->pkey.kyber);
}

static int kyber_size(const EVP_PKEY *pkey)
{
    switch (pkey->pkey.kyber->mode) {
        case 2:
            return 800 + 32;
        case 3:
            return 1184 + 32;
        case 4:
            return 1568 + 32;
    }
    return 0;
}

static int kyber_bits(const EVP_PKEY *pkey)
{
    return kyber_size(pkey) * 8;
}

const EVP_PKEY_ASN1_METHOD kyber_asn1_meth = {
     EVP_PKEY_KYBER,
     EVP_PKEY_KYBER,
     0,

     "KYBER",
     "OpenSSL Kyber method",

     kyber_pub_decode,
     kyber_pub_encode,
     kyber_pub_cmp,
     kyber_pub_print,

     kyber_priv_decode,
     kyber_priv_encode,
     kyber_priv_print,

     kyber_size,
     kyber_bits,
     0,

     0, 0, 0, 0, 0, 0, 0,
     int_kyber_free,
     kyber_pkey_ctrl,
     old_kyber_priv_decode,
     old_kyber_priv_encode,
     0, 0, 0,
     kyber_pkey_check
};
