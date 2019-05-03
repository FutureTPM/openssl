#include <stdio.h>
#include <string.h>

#include "internal/nelem.h"

#include <openssl/crypto.h>
#include <openssl/err.h>

#include "testutil.h"

#ifdef OPENSSL_NO_KYBER
int setup_tests(void)
{
    /* No tests */
    return 1;
}
#else
# include <openssl/kyber.h>

static int test_kyber_encrypt_decrypt(int mode)
{
    int ret = 0;
    Kyber *key = kyber_new();
    unsigned char ptext[256];
    unsigned char ctext[8192];
    static unsigned char ptext_ex[] = "Hello world!\n";
    int plen;
    int clen = 0;
    int num;

    plen = sizeof(ptext_ex) - 1;
    clen = ((mode + 2) * 352 + 96) + 32;

    ret = kyber_generate_key_ex(key, (mode + 2) & 0xff);
    if (ret == 0) {
        TEST_info("Failed generating key\n");
        return ret;
    }

    num = kyber_public_encrypt(plen, ptext_ex, ctext, key);
    if (!TEST_int_eq(num, clen))
        goto err;

    num = kyber_private_decrypt(num, ctext + 32, ptext, key);
    if (!TEST_mem_eq(ptext, num, ctext, 32))
        goto err;

    ret = 1;
err:
    kyber_free(key);
    return ret;
}

static int test_kyber_key_generation(int mode)
{
    Kyber *key = kyber_new();
    if (key == NULL) {
        TEST_info("Failed creating Kyber object\n");
        return 0;
    }

    int ret = kyber_generate_key_ex(key, (mode + 2) & 0xff);
    if (ret == 0) {
        TEST_info("Failed generating key\n");
        return ret;
    }

    ret = kyber_check_key(key);

    kyber_free(key);
    return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_kyber_key_generation, 3);
    ADD_ALL_TESTS(test_kyber_encrypt_decrypt, 3);
    return 1;
}
#endif
