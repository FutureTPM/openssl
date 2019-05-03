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
# include <openssl/dilithium.h>

static int test_dilithium_sign_verify(int mode)
{
    int ret = 0;
    Dilithium *key = dilithium_new();
    static unsigned char ctext[8192];
    static unsigned char ptext_ex[] = "Hello world!\n";
    int plen;
    unsigned int clen = 0;

    plen = sizeof(ptext_ex) - 1;

    ret = dilithium_generate_key_ex(key, (mode + 1) & 0xff);
    if (ret == 0) {
        TEST_info("Failed generating key\n");
        return ret;
    }

    TEST_info("Sign\n");
    ret = Dilithium_sign(ptext_ex, plen, ctext, &clen, key);
    if (ret == 0) {
        TEST_info("Failed signature generation\n");
        goto err;
    }

    TEST_info("Verify\n");
    ret = Dilithium_verify(ptext_ex, plen, ctext, clen, key);
    if (ret == 0) {
        TEST_info("Failed signature verification\n");
        goto err;
    }

    TEST_info("Done\n");
    ret = 1;
err:
    dilithium_free(key);
    return ret;
}

static int test_dilithium_key_generation(int mode)
{
    Dilithium *key = dilithium_new();
    if (key == NULL) {
        TEST_info("Failed creating Dilithium object\n");
        return 0;
    }

    int ret = dilithium_generate_key_ex(key, (mode + 1) & 0xff);
    if (ret == 0) {
        TEST_info("Failed generating key\n");
        return ret;
    }

    ret = dilithium_check_key(key);

    dilithium_free(key);
    return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_dilithium_key_generation, 4);
    ADD_ALL_TESTS(test_dilithium_sign_verify, 4);
    return 1;
}
#endif
