#include "internal/cryptlib.h"
#include "kyber_locl.h"
#include "internal/constant_time_locl.h"
#include "kyber_params.h"
#include "openssl/evp.h"

static int kyber_ossl_public_encrypt(int flen, const unsigned char *from,
                                  unsigned char *to, Kyber *kyber);
static int kyber_ossl_private_decrypt(int flen, const unsigned char *from,
                                   unsigned char *to, Kyber *kyber);
static int kyber_ossl_init(Kyber *kyber);
static int kyber_ossl_finish(Kyber *kyber);
static KYBER_METHOD kyber_ossl_meth = {
    "OpenSSL Kyber",
    kyber_ossl_public_encrypt,
    kyber_ossl_private_decrypt,

    kyber_ossl_init,
    kyber_ossl_finish,
    0,       /* flags */
    NULL,
    NULL,                       /* kyber_keygen */
};

static const KYBER_METHOD *default_kyber_meth = &kyber_ossl_meth;

void kyber_set_default_method(const KYBER_METHOD *meth)
{
    default_kyber_meth = meth;
}

const KYBER_METHOD *kyber_get_default_method(void)
{
    return default_kyber_meth;
}

const KYBER_METHOD *kyber_OpenSSL(void)
{
    return &kyber_ossl_meth;
}

const KYBER_METHOD *kyber_null_method(void)
{
    return NULL;
}

static int kyber_ossl_public_encrypt(int flen, const uint8_t *from,
                                  uint8_t *to, Kyber *kyber)
{
    uint8_t ss[32];
    uint8_t *ct = NULL;

    // @1: ct is allocated inside kyber_encapsulate; don't forget to free it
    int ret = kyber_encapsulate(kyber, ss, &ct);
    if (ret < 0 || ct == NULL)
        return ret;

    // Copy cipher text and shared secret to out
    memmove(to, ss, 32);
    memmove(to + 32, ct, ret);
    OPENSSL_free(ct); // free @1

    return 32 + ret;
}

static int kyber_ossl_private_decrypt(int flen, const unsigned char *from,
                                   unsigned char *to, Kyber *kyber)
{
    int r = -1;

    if (!kyber_decapsulate(kyber, to, from))
        return r;

    return 32;
}

static int kyber_ossl_init(Kyber *kyber)
{
    kyber->flags |= KYBER_FLAG_CACHE_PUBLIC | KYBER_FLAG_CACHE_PRIVATE;
    return 1;
}

static int kyber_ossl_finish(Kyber *kyber)
{
    return 1;
}

