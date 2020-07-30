#include <string.h>
#include "nttru-locl.h"
#include <openssl/err.h>

NTTRU_METHOD *nttru_meth_new(const char *name, int flags)
{
    NTTRU_METHOD *meth = OPENSSL_zalloc(sizeof(*meth));

    if (meth != NULL) {
        meth->flags = flags;

        meth->name = OPENSSL_strdup(name);
        if (meth->name != NULL)
            return meth;

        OPENSSL_free(meth);
    }

    NTTRUerr(NTTRU_F_NTTRU_METH_NEW, ERR_R_MALLOC_FAILURE);
    return NULL;
}

void nttru_meth_free(NTTRU_METHOD *meth)
{
    if (meth != NULL) {
        OPENSSL_free(meth->name);
        OPENSSL_free(meth);
    }
}

NTTRU_METHOD *nttru_meth_dup(const NTTRU_METHOD *meth)
{
    NTTRU_METHOD *ret = OPENSSL_malloc(sizeof(*ret));

    if (ret != NULL) {
        memcpy(ret, meth, sizeof(*meth));

        ret->name = OPENSSL_strdup(meth->name);
        if (ret->name != NULL)
            return ret;

        OPENSSL_free(ret);
    }

    NTTRUerr(NTTRU_F_NTTRU_METH_DUP, ERR_R_MALLOC_FAILURE);
    return NULL;
}

const char *nttru_meth_get0_name(const NTTRU_METHOD *meth)
{
    return meth->name;
}

int nttru_meth_set1_name(NTTRU_METHOD *meth, const char *name)
{
    char *tmpname = OPENSSL_strdup(name);

    if (tmpname == NULL) {
        NTTRUerr(NTTRU_F_NTTRU_METH_SET1_NAME, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    OPENSSL_free(meth->name);
    meth->name = tmpname;

    return 1;
}

int nttru_meth_get_flags(const NTTRU_METHOD *meth)
{
    return meth->flags;
}

int nttru_meth_set_flags(NTTRU_METHOD *meth, int flags)
{
    meth->flags = flags;
    return 1;
}

void *nttru_meth_get0_app_data(const NTTRU_METHOD *meth)
{
    return meth->app_data;
}

int nttru_meth_set0_app_data(NTTRU_METHOD *meth, void *app_data)
{
    meth->app_data = app_data;
    return 1;
}

int (*nttru_meth_get_pub_enc(const NTTRU_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, NTTRU *nttru)
{
    return meth->nttru_pub_enc;
}

int nttru_meth_set_pub_enc(NTTRU_METHOD *meth,
                         int (*pub_enc) (int flen, const unsigned char *from,
                                         unsigned char *to, NTTRU *nttru))
{
    meth->nttru_pub_enc = pub_enc;
    return 1;
}

int (*nttru_meth_get_priv_dec(const NTTRU_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, NTTRU *nttru)
{
    return meth->nttru_priv_dec;
}

int nttru_meth_set_priv_dec(NTTRU_METHOD *meth,
                          int (*priv_dec) (int flen, const unsigned char *from,
                                           unsigned char *to, NTTRU *nttru))
{
    meth->nttru_priv_dec = priv_dec;
    return 1;
}


    /* called at new */
int (*nttru_meth_get_init(const NTTRU_METHOD *meth)) (NTTRU *nttru)
{
    return meth->init;
}

int nttru_meth_set_init(NTTRU_METHOD *meth, int (*init) (NTTRU *nttru))
{
    meth->init = init;
    return 1;
}

    /* called at free */
int (*nttru_meth_get_finish(const NTTRU_METHOD *meth)) (NTTRU *nttru)
{
    return meth->finish;
}

int nttru_meth_set_finish(NTTRU_METHOD *meth, int (*finish) (NTTRU *nttru))
{
    meth->finish = finish;
    return 1;
}

int (*nttru_meth_get_keygen(const NTTRU_METHOD *meth))
    (NTTRU *nttru)
{
    return meth->nttru_keygen;
}

int nttru_meth_set_keygen(NTTRU_METHOD *meth,
                        int (*keygen) (NTTRU *nttru))
{
    meth->nttru_keygen = keygen;
    return 1;
}

