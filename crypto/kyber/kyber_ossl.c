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
    int r = -1;
    uint8_t *ct = NULL;
    int len, tmplen;

    // @1: ct is allocated inside kyber_encapsulate; don't forget to free it
    r = kyber_encapsulate(kyber, ss, &ct);
    if (r == -1 || ct == NULL)
        return r;

    memmove(to, ct, r);
    OPENSSL_free(ct); // free @1

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, ss, NULL);
    EVP_EncryptUpdate(ctx, to + r, &len, from, flen);
    EVP_EncryptFinal_ex(ctx, to + r + len, &tmplen);
    EVP_CIPHER_CTX_free(ctx);

    r += tmplen + len;

    return r;
}

static int kyber_ossl_private_decrypt(int flen, const unsigned char *from,
                                   unsigned char *to, Kyber *kyber)
{
    uint8_t ss[32];
    int r = -1;
    int len, tmplen;
    KyberParams params = generate_kyber_params(kyber->mode);

    if (kyber_decapsulate(kyber, ss, from) != 1)
        return r;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, ss, NULL);
    EVP_DecryptUpdate(ctx, to, &len, from + params.ciphertextbytes,
            flen - params.ciphertextbytes);
    EVP_DecryptFinal_ex(ctx, to + len, &tmplen);
    EVP_CIPHER_CTX_free(ctx);

    r = len + tmplen;

    return r;
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

