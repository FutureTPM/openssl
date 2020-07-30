#include <stdio.h>
#include <string.h>

#include "internal/nelem.h"

#include <openssl/crypto.h>
#include <openssl/err.h>

#include "testutil.h"

#ifdef OPENSSL_NO_NTTRU
int setup_tests(void) {
  /* No tests */
  return 1;
}
#else
#include <openssl/nttru.h>

static int test_nttru_encrypt_decrypt() {
  int ret = 0;
  NTTRU *key = nttru_new();
  unsigned char ptext[256];
  unsigned char ctext[8192];
  static unsigned char ptext_ex[] = "Hello world!\n";
  int plen;
  int clen = 1248 + 32; // ciphertext size
  int num;

  plen = sizeof(ptext_ex) - 1;

  ret = nttru_generate_key_ex(key);
  if (ret == 0) {
    TEST_info("Failed generating key\n");
    return ret;
  }

  num = nttru_public_encrypt(plen, ptext_ex, ctext, key);
  if (!TEST_int_eq(num, clen)) {
    TEST_info("Encrypt size error\n");
    goto err;
  }
  num = nttru_private_decrypt(num, ctext + 32, ptext, key);
  if (!TEST_mem_eq(ptext, num, ctext, 32)) {
    TEST_info("Decrypt error\n");
    goto err;
  }
  ret = 1;
err:
  nttru_free(key);
  return ret;
}

static int test_nttru_key_generation(int mode) {
  NTTRU *key = nttru_new();
  if (key == NULL) {
    TEST_info("Failed creating NTTRU object\n");
    return 0;
  }

  int ret = nttru_generate_key_ex(key);
  if (ret == 0) {
    TEST_info("Failed generating key\n");
    return ret;
  }

  ret = nttru_check_key(key);

  nttru_free(key);
  return ret;
}

int setup_tests(void) {
  ADD_ALL_TESTS(test_nttru_key_generation, 1);
  ADD_ALL_TESTS(test_nttru_encrypt_decrypt, 1);
  return 1;
}
#endif
