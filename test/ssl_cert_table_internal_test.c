/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal tests for the x509 and x509v3 modules */

#include <stdio.h>
#include <string.h>

#include "internal/nelem.h"
#include "testutil.h"
#include <openssl/ssl.h>

#ifdef __VMS
#pragma names save
#pragma names as_is, shortened
#endif

#include "../ssl/ssl_cert_table.h"
#include "../ssl/ssl_locl.h"

#ifdef __VMS
#pragma names restore
#endif

#define test_cert_table(nid, amask, idx)                                       \
  do_test_cert_table(nid, amask, idx, #idx)

static int do_test_cert_table(int nid, uint32_t amask, size_t idx,
                              const char *idxname) {
  const SSL_CERT_LOOKUP *clu = &ssl_cert_info[idx];

  if (clu->nid == nid && clu->amask == amask)
    return 1;

  TEST_error("Invalid table entry for certificate type %s, index %zu", idxname,
             idx);
  if (clu->nid != nid)
    TEST_note("Expected %s, got %s\n", OBJ_nid2sn(nid), OBJ_nid2sn(clu->nid));
  if (clu->amask != amask)
    TEST_note("Expected auth mask 0x%x, got 0x%x\n", amask, clu->amask);
  return 0;
}

/* Sanity check of ssl_cert_table */

static int test_ssl_cert_table(void) {
  TEST_size_t_eq(OSSL_NELEM(ssl_cert_info), SSL_PKEY_NUM);
  if (!test_cert_table(EVP_PKEY_RSA, SSL_aRSA, SSL_PKEY_RSA))
    return 0;
  if (!test_cert_table(EVP_PKEY_DSA, SSL_aDSS, SSL_PKEY_DSA_SIGN))
    return 0;
  if (!test_cert_table(EVP_PKEY_EC, SSL_aECDSA, SSL_PKEY_ECC))
    return 0;
  if (!test_cert_table(NID_id_GostR3410_2001, SSL_aGOST01, SSL_PKEY_GOST01))
    return 0;
  if (!test_cert_table(NID_id_GostR3410_2012_256, SSL_aGOST12,
                       SSL_PKEY_GOST12_256))
    return 0;
  if (!test_cert_table(NID_id_GostR3410_2012_512, SSL_aGOST12,
                       SSL_PKEY_GOST12_512))
    return 0;
  if (!test_cert_table(EVP_PKEY_ED25519, SSL_aECDSA, SSL_PKEY_ED25519))
    return 0;
  if (!test_cert_table(EVP_PKEY_ED448, SSL_aECDSA, SSL_PKEY_ED448))
    return 0;

  return 1;
}

int setup_tests(void) {
  ADD_TEST(test_ssl_cert_table);
  return 1;
}
