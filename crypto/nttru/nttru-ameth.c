#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include "internal/asn1_int.h"
#include "internal/evp_int.h"
#include "nttru-locl.h"
#include "nttru-params.h"

static int nttru_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)
{
    unsigned char *penc = NULL;
    int penclen;

    penclen = i2d_NttruPublicKey(pkey->pkey.nttru, &penc);
    if (penclen <= 0)
        return 0;
    if (X509_PUBKEY_set0_param(pk, OBJ_nid2obj(EVP_PKEY_NTTRU),
                               V_ASN1_NULL, NULL, penc, penclen))
        return 1;

    OPENSSL_free(penc);
    return 0;
}

static int nttru_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
    const unsigned char *p;
    int pklen;
    X509_ALGOR *alg;
    NTTRU *nttru = NULL;

    if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, &alg, pubkey))
        return 0;
    if ((nttru = d2i_NttruPublicKey(NULL, &p, pklen)) == NULL) {
        NTTRUerr(NTTRU_F_NTTRU_PUB_DECODE, ERR_R_NTTRU_LIB);
        return 0;
    }
    if (!EVP_PKEY_assign_NTTRU(pkey, nttru)) {
        nttru_free(nttru);
        return 0;
    }
    return 1;
}

static int nttru_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    if (b->pkey.nttru->mode != a->pkey.nttru->mode
        || b->pkey.nttru->public_key_size != a->pkey.nttru->public_key_size
        || memcmp(b->pkey.nttru->public_key, a->pkey.nttru->public_key,
            a->pkey.nttru->public_key_size) != 0)
        return 0;
    return 1;
}

static int nttru_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
    unsigned char *rk = NULL;
    int rklen;

    if (!pkey->pkey.nttru || !pkey->pkey.nttru->private_key) {
        NTTRUerr(NTTRU_F_NTTRU_PRIV_ENCODE, NTTRU_R_VALUE_MISSING);
        return 0;
    }

    rklen = i2d_NttruPrivateKey(pkey->pkey.nttru, &rk);
    if (rklen == 0) {
        OPENSSL_free(rk);
        NTTRUerr(NTTRU_F_NTTRU_PRIV_ENCODE, ERR_R_NTTRU_LIB);
        return 0;
    }

    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_NTTRU), 0,
                         V_ASN1_NULL, NULL, rk, rklen)) {
        NTTRUerr(NTTRU_F_NTTRU_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(rk);
        return 0;
    }

    return 1;
}

static int nttru_priv_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8)
{
    const unsigned char *p;
    NTTRU *nttru;
    int pklen;
    const X509_ALGOR *alg;
    int ptype;

    if (!PKCS8_pkey_get0(NULL, &p, &pklen, &alg, p8))
        return 0;
    X509_ALGOR_get0(NULL, &ptype, NULL, alg);

    if (ptype != V_ASN1_NULL)
        return 0;

    nttru = d2i_NttruPrivateKey(NULL, &p, pklen);
    if (nttru == NULL) {
        NTTRUerr(NTTRU_F_NTTRU_PRIV_DECODE, ERR_R_NTTRU_LIB);
        return 0;
    }
    EVP_PKEY_assign_NTTRU(pkey, nttru);
    return 1;
}

static void int_nttru_free(EVP_PKEY *pkey)
{
    nttru_free(pkey->pkey.nttru);
}

static int pkey_nttru_print(BIO *bp, const EVP_PKEY *pkey, int off, int priv)
{
    const NTTRU *x = pkey->pkey.nttru;
    int ret = 0;

    if (!BIO_indent(bp, off, 128))
        goto err;

    if (BIO_printf(bp, "%s ", "NTTRU") <= 0)
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

static int nttru_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *ctx)
{
    return pkey_nttru_print(bp, pkey, indent, 0);
}

static int nttru_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                          ASN1_PCTX *ctx)
{
    return pkey_nttru_print(bp, pkey, indent, 1);
}

static int nttru_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
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
    case ASN1_PKEY_CTRL_SET1_TLS_NTTRU_PK: {
        NTTRU *nttru = EVP_PKEY_get0_NTTRU(pkey);
        nttru->public_key = (unsigned char *) arg2;
        nttru->public_key_size = (int) arg1;
        break;
                                           }

    case ASN1_PKEY_CTRL_GET1_TLS_NTTRU_PK: {
        NTTRU *nttru = EVP_PKEY_get0_NTTRU(pkey);
        *(unsigned char **)arg2 = nttru->public_key;
        return nttru->public_key_size;
                                           }

    default:
        return -2;

    }

    if (alg)
        X509_ALGOR_set0(alg, OBJ_nid2obj(NID_NTTRU), V_ASN1_NULL, 0);

    return 1;

}

static int old_nttru_priv_decode(EVP_PKEY *pkey,
                               const unsigned char **pder, int derlen)
{
    NTTRU *nttru;

    if ((nttru = d2i_NttruPrivateKey(NULL, pder, derlen)) == NULL) {
        NTTRUerr(NTTRU_F_OLD_NTTRU_PRIV_DECODE, ERR_R_NTTRU_LIB);
        return 0;
    }
    EVP_PKEY_assign_NTTRU(pkey, nttru);
    return 1;
}

static int old_nttru_priv_encode(const EVP_PKEY *pkey, unsigned char **pder)
{
    return i2d_NttruPrivateKey(pkey->pkey.nttru, pder);
}

static int nttru_pkey_check(const EVP_PKEY *pkey)
{
    return nttru_check_key_ex(pkey->pkey.nttru);
}

static int nttru_size(const EVP_PKEY *pkey)
{
  return NTTRU_PUBLICKEYBYTES;
}

static int nttru_bits(const EVP_PKEY *pkey)
{
    return nttru_size(pkey) * 8;
}

const EVP_PKEY_ASN1_METHOD nttru_asn1_meth = {
     EVP_PKEY_NTTRU,
     EVP_PKEY_NTTRU,
     0,

     "NTTRU",
     "OpenSSL NTTRU method",

     nttru_pub_decode,
     nttru_pub_encode,
     nttru_pub_cmp,
     nttru_pub_print,

     nttru_priv_decode,
     nttru_priv_encode,
     nttru_priv_print,

     nttru_size,
     nttru_bits,
     0,

     0, 0, 0, 0, 0, 0, 0,
     int_nttru_free,
     nttru_pkey_ctrl,
     old_nttru_priv_decode,
     old_nttru_priv_encode,
     0, 0, 0,
     nttru_pkey_check
};
