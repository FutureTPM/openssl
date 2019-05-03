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
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/kyber.h>
#include <openssl/dilithium.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>

int i2d_PublicKey(EVP_PKEY *a, unsigned char **pp)
{
    switch (EVP_PKEY_id(a)) {
#ifndef OPENSSL_NO_RSA
    case EVP_PKEY_RSA:
        return i2d_RSAPublicKey(EVP_PKEY_get0_RSA(a), pp);
#endif
#ifndef OPENSSL_NO_DSA
    case EVP_PKEY_DSA:
        return i2d_DSAPublicKey(EVP_PKEY_get0_DSA(a), pp);
#endif
#ifndef OPENSSL_NO_KYBER
    case EVP_PKEY_KYBER:
        return i2d_KyberPublicKey(EVP_PKEY_get0_Kyber(a), pp);
#endif
#ifndef OPENSSL_NO_DILITHIUM
    case EVP_PKEY_DILITHIUM:
        return i2d_DilithiumPublicKey(EVP_PKEY_get0_Dilithium(a), pp);
#endif
#ifndef OPENSSL_NO_EC
    case EVP_PKEY_EC:
        return i2o_ECPublicKey(EVP_PKEY_get0_EC_KEY(a), pp);
#endif
    default:
        ASN1err(ASN1_F_I2D_PUBLICKEY, ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
        return -1;
    }
}
