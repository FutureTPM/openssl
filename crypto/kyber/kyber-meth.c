#include <string.h>
#include "kyber-locl.h"
#include <openssl/err.h>

KYBER_METHOD *kyber_meth_new(const char *name, int flags)
{
    KYBER_METHOD *meth = OPENSSL_zalloc(sizeof(*meth));

    if (meth != NULL) {
        meth->flags = flags;

        meth->name = OPENSSL_strdup(name);
        if (meth->name != NULL)
            return meth;

        OPENSSL_free(meth);
    }

    Kybererr(KYBER_F_KYBER_METH_NEW, ERR_R_MALLOC_FAILURE);
    return NULL;
}

void kyber_meth_free(KYBER_METHOD *meth)
{
    if (meth != NULL) {
        OPENSSL_free(meth->name);
        OPENSSL_free(meth);
    }
}

KYBER_METHOD *kyber_meth_dup(const KYBER_METHOD *meth)
{
    KYBER_METHOD *ret = OPENSSL_malloc(sizeof(*ret));

    if (ret != NULL) {
        memcpy(ret, meth, sizeof(*meth));

        ret->name = OPENSSL_strdup(meth->name);
        if (ret->name != NULL)
            return ret;

        OPENSSL_free(ret);
    }

    Kybererr(KYBER_F_KYBER_METH_DUP, ERR_R_MALLOC_FAILURE);
    return NULL;
}

const char *kyber_meth_get0_name(const KYBER_METHOD *meth)
{
    return meth->name;
}

int kyber_meth_set1_name(KYBER_METHOD *meth, const char *name)
{
    char *tmpname = OPENSSL_strdup(name);

    if (tmpname == NULL) {
        Kybererr(KYBER_F_KYBER_METH_SET1_NAME, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    OPENSSL_free(meth->name);
    meth->name = tmpname;

    return 1;
}

int kyber_meth_get_flags(const KYBER_METHOD *meth)
{
    return meth->flags;
}

int kyber_meth_set_flags(KYBER_METHOD *meth, int flags)
{
    meth->flags = flags;
    return 1;
}

void *kyber_meth_get0_app_data(const KYBER_METHOD *meth)
{
    return meth->app_data;
}

int kyber_meth_set0_app_data(KYBER_METHOD *meth, void *app_data)
{
    meth->app_data = app_data;
    return 1;
}

int (*kyber_meth_get_pub_enc(const KYBER_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, Kyber *kyber)
{
    return meth->kyber_pub_enc;
}

int kyber_meth_set_pub_enc(KYBER_METHOD *meth,
                         int (*pub_enc) (int flen, const unsigned char *from,
                                         unsigned char *to, Kyber *kyber))
{
    meth->kyber_pub_enc = pub_enc;
    return 1;
}

int (*kyber_meth_get_priv_dec(const KYBER_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, Kyber *kyber)
{
    return meth->kyber_priv_dec;
}

int kyber_meth_set_priv_dec(KYBER_METHOD *meth,
                          int (*priv_dec) (int flen, const unsigned char *from,
                                           unsigned char *to, Kyber *kyber))
{
    meth->kyber_priv_dec = priv_dec;
    return 1;
}


    /* called at new */
int (*kyber_meth_get_init(const KYBER_METHOD *meth)) (Kyber *kyber)
{
    return meth->init;
}

int kyber_meth_set_init(KYBER_METHOD *meth, int (*init) (Kyber *kyber))
{
    meth->init = init;
    return 1;
}

    /* called at free */
int (*kyber_meth_get_finish(const KYBER_METHOD *meth)) (Kyber *kyber)
{
    return meth->finish;
}

int kyber_meth_set_finish(KYBER_METHOD *meth, int (*finish) (Kyber *kyber))
{
    meth->finish = finish;
    return 1;
}

int (*kyber_meth_get_keygen(const KYBER_METHOD *meth))
    (Kyber *kyber, int mode)
{
    return meth->kyber_keygen;
}

int kyber_meth_set_keygen(KYBER_METHOD *meth,
                        int (*keygen) (Kyber *kyber, int mode))
{
    meth->kyber_keygen = keygen;
    return 1;
}

