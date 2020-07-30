#include "internal/cryptlib.h"
#include "nttru-locl.h"
#include "internal/constant_time_locl.h"
#include "nttru-params.h"
#include "openssl/evp.h"

static int nttru_ossl_public_encrypt(int flen, const unsigned char *from,
                                  unsigned char *to, NTTRU *nttru);
static int nttru_ossl_private_decrypt(int flen, const unsigned char *from,
                                   unsigned char *to, NTTRU *nttru);
static int nttru_ossl_init(NTTRU *nttru);
static int nttru_ossl_finish(NTTRU *nttru);
static NTTRU_METHOD nttru_ossl_meth = {
    "OpenSSL NTTRU",
    nttru_ossl_public_encrypt,
    nttru_ossl_private_decrypt,

    nttru_ossl_init,
    nttru_ossl_finish,
    0,       /* flags */
    NULL,
    NULL,                       /* nttru_keygen */
};

static const NTTRU_METHOD *default_nttru_meth = &nttru_ossl_meth;

void nttru_set_default_method(const NTTRU_METHOD *meth)
{
    default_nttru_meth = meth;
}

const NTTRU_METHOD *nttru_get_default_method(void)
{
    return default_nttru_meth;
}

const NTTRU_METHOD *nttru_OpenSSL(void)
{
    return &nttru_ossl_meth;
}

const NTTRU_METHOD *nttru_null_method(void)
{
    return NULL;
}

static int nttru_ossl_public_encrypt(int flen, const uint8_t *from,
                                  uint8_t *to, NTTRU *nttru)
{
    uint8_t ss[32];
    uint8_t *ct = NULL;

    // @1: ct is allocated inside nttru_encapsulate; don't forget to free it
    int ret = nttru_encapsulate(nttru, ss, &ct);
    if (ret < 0 || ct == NULL)
        return ret;

    // Copy cipher text and shared secret to out
    if (to != NULL) {
        memmove(to, ss, 32);
        memmove(to + 32, ct, ret);
    }
    OPENSSL_free(ct); // free @1

    return 32 + ret;
}

static int nttru_ossl_private_decrypt(int flen, const unsigned char *from,
                                   unsigned char *to, NTTRU *nttru)
{
    int r = -1;

    if (!nttru_decapsulate(nttru, to, from))
        return r;

    return 32;
}

static int nttru_ossl_init(NTTRU *nttru)
{
    nttru->flags |= NTTRU_FLAG_CACHE_PUBLIC | NTTRU_FLAG_CACHE_PRIVATE;
    return 1;
}

static int nttru_ossl_finish(NTTRU *nttru)
{
    return 1;
}
