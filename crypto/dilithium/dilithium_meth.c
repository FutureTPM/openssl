#include <string.h>
#include "dilithium_locl.h"
#include <openssl/err.h>

DILITHIUM_METHOD *dilithium_meth_new(const char *name, int flags)
{
    DILITHIUM_METHOD *meth = OPENSSL_zalloc(sizeof(*meth));

    if (meth != NULL) {
        meth->flags = flags;

        meth->name = OPENSSL_strdup(name);
        if (meth->name != NULL)
            return meth;

        OPENSSL_free(meth);
    }

    Dilithiumerr(DILITHIUM_F_DILITHIUM_METH_NEW, ERR_R_MALLOC_FAILURE);
    return NULL;
}

void dilithium_meth_free(DILITHIUM_METHOD *meth)
{
    if (meth != NULL) {
        OPENSSL_free(meth->name);
        OPENSSL_free(meth);
    }
}

DILITHIUM_METHOD *dilithium_meth_dup(const DILITHIUM_METHOD *meth)
{
    DILITHIUM_METHOD *ret = OPENSSL_malloc(sizeof(*ret));

    if (ret != NULL) {
        memcpy(ret, meth, sizeof(*meth));

        ret->name = OPENSSL_strdup(meth->name);
        if (ret->name != NULL)
            return ret;

        OPENSSL_free(ret);
    }

    Dilithiumerr(DILITHIUM_F_DILITHIUM_METH_DUP, ERR_R_MALLOC_FAILURE);
    return NULL;
}

const char *dilithium_meth_get0_name(const DILITHIUM_METHOD *meth)
{
    return meth->name;
}

int dilithium_meth_set1_name(DILITHIUM_METHOD *meth, const char *name)
{
    char *tmpname = OPENSSL_strdup(name);

    if (tmpname == NULL) {
        Dilithiumerr(DILITHIUM_F_DILITHIUM_METH_SET1_NAME, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    OPENSSL_free(meth->name);
    meth->name = tmpname;

    return 1;
}

int dilithium_meth_get_flags(const DILITHIUM_METHOD *meth)
{
    return meth->flags;
}

int dilithium_meth_set_flags(DILITHIUM_METHOD *meth, int flags)
{
    meth->flags = flags;
    return 1;
}

void *dilithium_meth_get0_app_data(const DILITHIUM_METHOD *meth)
{
    return meth->app_data;
}

int dilithium_meth_set0_app_data(DILITHIUM_METHOD *meth, void *app_data)
{
    meth->app_data = app_data;
    return 1;
}

    /* called at new */
int (*dilithium_meth_get_init(const DILITHIUM_METHOD *meth)) (Dilithium *dilithium)
{
    return meth->init;
}

int dilithium_meth_set_init(DILITHIUM_METHOD *meth, int (*init) (Dilithium *dilithium))
{
    meth->init = init;
    return 1;
}

    /* called at free */
int (*dilithium_meth_get_finish(const DILITHIUM_METHOD *meth)) (Dilithium *dilithium)
{
    return meth->finish;
}

int dilithium_meth_set_finish(DILITHIUM_METHOD *meth, int (*finish) (Dilithium *dilithium))
{
    meth->finish = finish;
    return 1;
}

int (*dilithium_meth_get_keygen(const DILITHIUM_METHOD *meth))
    (Dilithium *dilithium, int mode)
{
    return meth->dilithium_keygen;
}

int dilithium_meth_set_keygen(DILITHIUM_METHOD *meth,
                        int (*keygen) (Dilithium *dilithium, int mode))
{
    meth->dilithium_keygen = keygen;
    return 1;
}

int (*dilithium_meth_get_sign(const DILITHIUM_METHOD *meth))
    (const unsigned char *m, unsigned int m_length,
     unsigned char *sigret, unsigned int *siglen,
     const Dilithium *dilithium)
{
    return meth->dilithium_sign;
}

int dilithium_meth_set_sign(DILITHIUM_METHOD *meth,
                      int (*sign) (const unsigned char *m, unsigned int m_length,
                                   unsigned char *sigret, unsigned int *siglen,
                                   const Dilithium *dilithium))
{
    meth->dilithium_sign = sign;
    return 1;
}

int (*dilithium_meth_get_verify(const DILITHIUM_METHOD *meth))
    (const unsigned char *m, unsigned int m_length,
     const unsigned char *sigbuf, unsigned int siglen,
     const Dilithium *dilithium)
{
    return meth->dilithium_verify;
}

int dilithium_meth_set_verify(DILITHIUM_METHOD *meth,
                        int (*verify) (const unsigned char *m, unsigned int m_length,
                                       const unsigned char *sigbuf, unsigned int siglen,
                                       const Dilithium *dilithium))
{
    meth->dilithium_verify = verify;
    return 1;
}
