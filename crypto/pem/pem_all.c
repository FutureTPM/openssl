/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/kyber.h>
#include <openssl/nttru.h>
#include <openssl/dilithium.h>

#ifndef OPENSSL_NO_RSA
static RSA *pkey_get_rsa(EVP_PKEY *key, RSA **rsa);
#endif
#ifndef OPENSSL_NO_DSA
static DSA *pkey_get_dsa(EVP_PKEY *key, DSA **dsa);
#endif

#ifndef OPENSSL_NO_EC
static EC_KEY *pkey_get_eckey(EVP_PKEY *key, EC_KEY **eckey);
#endif

#ifndef OPENSSL_NO_KYBER
static Kyber *pkey_get_kyber(EVP_PKEY *key, Kyber **kyber);
#endif

#ifndef OPENSSL_NO_DILITHIUM
static Dilithium *pkey_get_dilithium(EVP_PKEY *key, Dilithium **dilithium);
#endif

#ifndef OPENSSL_NO_NTTRU
static NTTRU *pkey_get_NTTRU(EVP_PKEY *key, NTTRU **nttru);
#endif

IMPLEMENT_PEM_rw(X509_REQ, X509_REQ, PEM_STRING_X509_REQ, X509_REQ)

IMPLEMENT_PEM_write(X509_REQ_NEW, X509_REQ, PEM_STRING_X509_REQ_OLD, X509_REQ)
IMPLEMENT_PEM_rw(X509_CRL, X509_CRL, PEM_STRING_X509_CRL, X509_CRL)
IMPLEMENT_PEM_rw(PKCS7, PKCS7, PEM_STRING_PKCS7, PKCS7)

IMPLEMENT_PEM_rw(NETSCAPE_CERT_SEQUENCE, NETSCAPE_CERT_SEQUENCE,
                 PEM_STRING_X509, NETSCAPE_CERT_SEQUENCE)
#ifndef OPENSSL_NO_RSA
/*
 * We treat RSA or DSA private keys as a special case. For private keys we
 * read in an EVP_PKEY structure with PEM_read_bio_PrivateKey() and extract
 * the relevant private key: this means can handle "traditional" and PKCS#8
 * formats transparently.
 */
static RSA *pkey_get_rsa(EVP_PKEY *key, RSA **rsa)
{
    RSA *rtmp;
    if (!key)
        return NULL;
    rtmp = EVP_PKEY_get1_RSA(key);
    EVP_PKEY_free(key);
    if (!rtmp)
        return NULL;
    if (rsa) {
        RSA_free(*rsa);
        *rsa = rtmp;
    }
    return rtmp;
}

RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **rsa, pem_password_cb *cb,
                                void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
    return pkey_get_rsa(pktmp, rsa);
}

# ifndef OPENSSL_NO_STDIO

RSA *PEM_read_RSAPrivateKey(FILE *fp, RSA **rsa, pem_password_cb *cb, void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
    return pkey_get_rsa(pktmp, rsa);
}

# endif

IMPLEMENT_PEM_write_cb_const(RSAPrivateKey, RSA, PEM_STRING_RSA,
                             RSAPrivateKey)


IMPLEMENT_PEM_rw_const(RSAPublicKey, RSA, PEM_STRING_RSA_PUBLIC,
                       RSAPublicKey) IMPLEMENT_PEM_rw(RSA_PUBKEY, RSA,
                                                      PEM_STRING_PUBLIC,
                                                      RSA_PUBKEY)
#endif
#ifndef OPENSSL_NO_DSA
static DSA *pkey_get_dsa(EVP_PKEY *key, DSA **dsa)
{
    DSA *dtmp;
    if (!key)
        return NULL;
    dtmp = EVP_PKEY_get1_DSA(key);
    EVP_PKEY_free(key);
    if (!dtmp)
        return NULL;
    if (dsa) {
        DSA_free(*dsa);
        *dsa = dtmp;
    }
    return dtmp;
}

DSA *PEM_read_bio_DSAPrivateKey(BIO *bp, DSA **dsa, pem_password_cb *cb,
                                void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
    return pkey_get_dsa(pktmp, dsa); /* will free pktmp */
}

IMPLEMENT_PEM_write_cb_const(DSAPrivateKey, DSA, PEM_STRING_DSA,
                             DSAPrivateKey)
    IMPLEMENT_PEM_rw(DSA_PUBKEY, DSA, PEM_STRING_PUBLIC, DSA_PUBKEY)
# ifndef OPENSSL_NO_STDIO
DSA *PEM_read_DSAPrivateKey(FILE *fp, DSA **dsa, pem_password_cb *cb, void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
    return pkey_get_dsa(pktmp, dsa); /* will free pktmp */
}

# endif

IMPLEMENT_PEM_rw_const(DSAparams, DSA, PEM_STRING_DSAPARAMS, DSAparams)
#endif
#ifndef OPENSSL_NO_EC
static EC_KEY *pkey_get_eckey(EVP_PKEY *key, EC_KEY **eckey)
{
    EC_KEY *dtmp;
    if (!key)
        return NULL;
    dtmp = EVP_PKEY_get1_EC_KEY(key);
    EVP_PKEY_free(key);
    if (!dtmp)
        return NULL;
    if (eckey) {
        EC_KEY_free(*eckey);
        *eckey = dtmp;
    }
    return dtmp;
}

EC_KEY *PEM_read_bio_ECPrivateKey(BIO *bp, EC_KEY **key, pem_password_cb *cb,
                                  void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
    return pkey_get_eckey(pktmp, key); /* will free pktmp */
}

IMPLEMENT_PEM_rw_const(ECPKParameters, EC_GROUP, PEM_STRING_ECPARAMETERS,
                       ECPKParameters)


IMPLEMENT_PEM_write_cb(ECPrivateKey, EC_KEY, PEM_STRING_ECPRIVATEKEY,
                       ECPrivateKey)
IMPLEMENT_PEM_rw(EC_PUBKEY, EC_KEY, PEM_STRING_PUBLIC, EC_PUBKEY)
# ifndef OPENSSL_NO_STDIO
EC_KEY *PEM_read_ECPrivateKey(FILE *fp, EC_KEY **eckey, pem_password_cb *cb,
                              void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
    return pkey_get_eckey(pktmp, eckey); /* will free pktmp */
}

# endif

#endif

#ifndef OPENSSL_NO_DH

IMPLEMENT_PEM_write_const(DHparams, DH, PEM_STRING_DHPARAMS, DHparams)
    IMPLEMENT_PEM_write_const(DHxparams, DH, PEM_STRING_DHXPARAMS, DHxparams)
#endif
IMPLEMENT_PEM_rw(PUBKEY, EVP_PKEY, PEM_STRING_PUBLIC, PUBKEY)

#ifndef OPENSSL_NO_KYBER
static Kyber *pkey_get_kyber(EVP_PKEY *key, Kyber **kyber)
{
    Kyber *dtmp;
    if (!key)
        return NULL;
    dtmp = EVP_PKEY_get1_Kyber(key);
    EVP_PKEY_free(key);
    if (!dtmp)
        return NULL;
    if (kyber) {
        kyber_free(*kyber);
        *kyber = dtmp;
    }
    return dtmp;
}

Kyber *PEM_read_bio_KyberPrivateKey(BIO *bp, Kyber **key, pem_password_cb *cb,
                                  void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
    return pkey_get_kyber(pktmp, key); /* will free pktmp */
}

IMPLEMENT_PEM_write_cb(KyberPrivateKey, Kyber, PEM_STRING_KYBER_PRIVATEKEY,
                       KyberPrivateKey)
IMPLEMENT_PEM_rw_const(KyberPublicKey, Kyber, PEM_STRING_KYBER_PUBLICKEY,
                       KyberPublicKey)
IMPLEMENT_PEM_rw(KYBER_PUBKEY, Kyber, PEM_STRING_PUBLIC, KYBER_PUBKEY)
# ifndef OPENSSL_NO_STDIO
Kyber *PEM_read_KyberPrivateKey(FILE *fp, Kyber **kyber, pem_password_cb *cb,
                              void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
    return pkey_get_kyber(pktmp, kyber); /* will free pktmp */
}

# endif

#endif


#ifndef OPENSSL_NO_DILITHIUM
static Dilithium *pkey_get_dilithium(EVP_PKEY *key, Dilithium **dilithium)
{
    Dilithium *dtmp;
    if (!key)
        return NULL;
    dtmp = EVP_PKEY_get1_Dilithium(key);
    EVP_PKEY_free(key);
    if (!dtmp)
        return NULL;
    if (dilithium) {
        dilithium_free(*dilithium);
        *dilithium = dtmp;
    }
    return dtmp;
}

Dilithium *PEM_read_bio_DilithiumPrivateKey(BIO *bp, Dilithium **key, pem_password_cb *cb,
                                  void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
    return pkey_get_dilithium(pktmp, key); /* will free pktmp */
}

IMPLEMENT_PEM_write_cb(DilithiumPrivateKey, Dilithium, PEM_STRING_DILITHIUM_PRIVATEKEY,
                       DilithiumPrivateKey)
IMPLEMENT_PEM_rw_const(DilithiumPublicKey, Dilithium, PEM_STRING_DILITHIUM_PUBLICKEY,
                       DilithiumPublicKey)
IMPLEMENT_PEM_rw(DILITHIUM_PUBKEY, Dilithium, PEM_STRING_PUBLIC, DILITHIUM_PUBKEY)
# ifndef OPENSSL_NO_STDIO
Dilithium *PEM_read_DilithiumPrivateKey(FILE *fp, Dilithium **dilithium, pem_password_cb *cb,
                              void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
    return pkey_get_dilithium(pktmp, dilithium); /* will free pktmp */
}

# endif

#endif


#ifndef OPENSSL_NO_NTTRU
static NTTRU *pkey_get_NTTRU(EVP_PKEY *key, NTTRU **nttru)
{
    NTTRU *dtmp;
    if (!key)
        return NULL;
    dtmp = EVP_PKEY_get1_NTTRU(key);
    EVP_PKEY_free(key);
    if (!dtmp)
        return NULL;
    if (nttru) {
        nttru_free(*nttru);
        *nttru = dtmp;
    }
    return dtmp;
}

NTTRU *PEM_read_bio_NttruPrivateKey(BIO *bp, NTTRU **key, pem_password_cb *cb,
                                  void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
    return pkey_get_NTTRU(pktmp, key); /* will free pktmp */
}

IMPLEMENT_PEM_write_cb(NttruPrivateKey, NTTRU, PEM_STRING_NTTRU_PRIVATEKEY,
                       NttruPrivateKey)
IMPLEMENT_PEM_rw_const(NttruPublicKey, NTTRU, PEM_STRING_NTTRU_PUBLICKEY,
                       NttruPublicKey)
IMPLEMENT_PEM_rw(NTTRU_PUBKEY, NTTRU, PEM_STRING_PUBLIC, NTTRU_PUBKEY)

# ifndef OPENSSL_NO_STDIO
NTTRU *PEM_read_NttruPrivateKey(FILE *fp, NTTRU **nttru, pem_password_cb *cb,
                              void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
    return pkey_get_NTTRU(pktmp, nttru); /* will free pktmp */
}
# endif
#endif
