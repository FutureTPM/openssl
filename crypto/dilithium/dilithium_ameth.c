#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include "internal/asn1_int.h"
#include "internal/evp_int.h"
#include "dilithium_locl.h"

static int dilithium_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)
{
    unsigned char *penc = NULL;
    int penclen;

    penclen = i2d_DilithiumPublicKey(pkey->pkey.dilithium, &penc);
    if (penclen <= 0)
        return 0;
    if (X509_PUBKEY_set0_param(pk, OBJ_nid2obj(EVP_PKEY_DILITHIUM),
                               V_ASN1_NULL, NULL, penc, penclen))
        return 1;

    OPENSSL_free(penc);
    return 0;
}

static int dilithium_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
    const unsigned char *p;
    int pklen;
    X509_ALGOR *alg;
    Dilithium *dilithium = NULL;

    if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, &alg, pubkey))
        return 0;
    if ((dilithium = d2i_DilithiumPublicKey(NULL, &p, pklen)) == NULL) {
        Dilithiumerr(DILITHIUM_F_DILITHIUM_PUB_DECODE, ERR_R_DILITHIUM_LIB);
        return 0;
    }
    if (!EVP_PKEY_assign_Dilithium(pkey, dilithium)) {
        dilithium_free(dilithium);
        return 0;
    }
    return 1;
}

static int dilithium_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    if (b->pkey.dilithium->mode != a->pkey.dilithium->mode
        || b->pkey.dilithium->public_key_size != a->pkey.dilithium->public_key_size
        || memcmp(b->pkey.dilithium->public_key, a->pkey.dilithium->public_key,
            a->pkey.dilithium->public_key_size) != 0)
        return 0;
    return 1;
}

static int dilithium_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
    unsigned char *rk = NULL;
    int rklen;

    if (!pkey->pkey.dilithium || !pkey->pkey.dilithium->private_key) {
        Dilithiumerr(DILITHIUM_F_DILITHIUM_PRIV_ENCODE, DILITHIUM_R_VALUE_MISSING);
        return 0;
    }

    rklen = i2d_DilithiumPrivateKey(pkey->pkey.dilithium, &rk);
    if (rklen == 0) {
        OPENSSL_free(rk);
        Dilithiumerr(DILITHIUM_F_DILITHIUM_PRIV_ENCODE, ERR_R_DILITHIUM_LIB);
        return 0;
    }

    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_dilithium), 0,
                         V_ASN1_NULL, NULL, rk, rklen)) {
        Dilithiumerr(DILITHIUM_F_DILITHIUM_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(rk);
        return 0;
    }

    return 1;
}

static int dilithium_priv_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8)
{
    const unsigned char *p;
    Dilithium *dilithium;
    int pklen;
    const X509_ALGOR *alg;
    int ptype;

    if (!PKCS8_pkey_get0(NULL, &p, &pklen, &alg, p8))
        return 0;
    X509_ALGOR_get0(NULL, &ptype, NULL, alg);

    if (ptype != V_ASN1_NULL)
        return 0;

    dilithium = d2i_DilithiumPrivateKey(NULL, &p, pklen);
    if (dilithium == NULL) {
        Dilithiumerr(DILITHIUM_F_DILITHIUM_PRIV_DECODE, ERR_R_DILITHIUM_LIB);
        return 0;
    }
    EVP_PKEY_assign_Dilithium(pkey, dilithium);
    return 1;
}

static void int_dilithium_free(EVP_PKEY *pkey)
{
    dilithium_free(pkey->pkey.dilithium);
}

static int pkey_dilithium_print(BIO *bp, const EVP_PKEY *pkey, int off, int priv)
{
    const Dilithium *x = pkey->pkey.dilithium;
    int ret = 0;

    if (!BIO_indent(bp, off, 128))
        goto err;

    if (BIO_printf(bp, "%s ", "Dilithium") <= 0)
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

static int dilithium_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *ctx)
{
    return pkey_dilithium_print(bp, pkey, indent, 0);
}

static int dilithium_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                          ASN1_PCTX *ctx)
{
    return pkey_dilithium_print(bp, pkey, indent, 1);
}

static int dilithium_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
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
    case ASN1_PKEY_CTRL_SET1_TLS_DILITHIUM_PK: {
        Dilithium *dilithium = EVP_PKEY_get0_Dilithium(pkey);
        dilithium->public_key = (unsigned char *) arg2;
        dilithium->public_key_size = (int) arg1;
        break;
                                           }

    case ASN1_PKEY_CTRL_GET1_TLS_DILITHIUM_PK: {
        Dilithium *dilithium = EVP_PKEY_get0_Dilithium(pkey);
        *(unsigned char **)arg2 = dilithium->public_key;
        return dilithium->public_key_size;
                                           }

    default:
        return -2;

    }

    if (alg)
        X509_ALGOR_set0(alg, OBJ_nid2obj(NID_dilithium), V_ASN1_NULL, 0);

    return 1;

}

static int old_dilithium_priv_decode(EVP_PKEY *pkey,
                               const unsigned char **pder, int derlen)
{
    Dilithium *dilithium;

    if ((dilithium = d2i_DilithiumPrivateKey(NULL, pder, derlen)) == NULL) {
        Dilithiumerr(DILITHIUM_F_OLD_DILITHIUM_PRIV_DECODE, ERR_R_DILITHIUM_LIB);
        return 0;
    }
    EVP_PKEY_assign_Dilithium(pkey, dilithium);
    return 1;
}

static int old_dilithium_priv_encode(const EVP_PKEY *pkey, unsigned char **pder)
{
    return i2d_DilithiumPrivateKey(pkey->pkey.dilithium, pder);
}

static int dilithium_pkey_check(const EVP_PKEY *pkey)
{
    return dilithium_check_key_ex(pkey->pkey.dilithium);
}

static int dilithium_size(const EVP_PKEY *pkey)
{
    return Dilithium_size(pkey->pkey.dilithium);
}

static int dilithium_bits(const EVP_PKEY *pkey)
{
    return Dilithium_size(pkey->pkey.dilithium) * 8;
}

const EVP_PKEY_ASN1_METHOD dilithium_asn1_meth = {
     EVP_PKEY_DILITHIUM,
     EVP_PKEY_DILITHIUM,
     0,

     "DILITHIUM",
     "OpenSSL Dilithium method",

     dilithium_pub_decode,
     dilithium_pub_encode,
     dilithium_pub_cmp,
     dilithium_pub_print,

     dilithium_priv_decode,
     dilithium_priv_encode,
     dilithium_priv_print,

     dilithium_size,
     dilithium_bits,
     0,

     0, 0, 0, 0, 0, 0, 0,
     int_dilithium_free,
     dilithium_pkey_ctrl,
     old_dilithium_priv_decode,
     old_dilithium_priv_encode,
     0, 0, 0,
     dilithium_pkey_check
};

