#include <stdio.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"
#include <openssl/engine.h>
#include <openssl/evp.h>
#include "internal/evp_int.h"
#include "kyber-locl.h"

Kyber *kyber_new(void)
{
    return kyber_new_method(NULL);
}

const KYBER_METHOD *kyber_get_method(const Kyber *kyber)
{
    return kyber->meth;
}

int kyber_set_method(Kyber *kyber, const KYBER_METHOD *meth)
{
    /*
     * NB: The caller is specifically setting a method, so it's not up to us
     * to deal with which ENGINE it comes from.
     */
    const KYBER_METHOD *mtmp;
    mtmp = kyber->meth;
    if (mtmp->finish)
        mtmp->finish(kyber);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(kyber->engine);
    kyber->engine = NULL;
#endif
    kyber->meth = meth;
    if (meth->init)
        meth->init(kyber);
    return 1;
}

Kyber *kyber_new_method(ENGINE *engine)
{
    Kyber *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        Kybererr(KYBER_F_KYBER_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->references = 1;
    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        Kybererr(KYBER_F_KYBER_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(ret);
        return NULL;
    }

    ret->meth = kyber_get_default_method();
#ifndef OPENSSL_NO_ENGINE
    ret->flags = ret->meth->flags;
    if (engine) {
        if (!ENGINE_init(engine)) {
            Kybererr(KYBER_F_KYBER_NEW_METHOD, ERR_R_ENGINE_LIB);
            goto err;
        }
        ret->engine = engine;
    } else {
        ret->engine = ENGINE_get_default_Kyber();
    }
    if (ret->engine) {
        ret->meth = ENGINE_get_Kyber(ret->engine);
        if (ret->meth == NULL) {
            Kybererr(KYBER_F_KYBER_NEW_METHOD, ERR_R_ENGINE_LIB);
            goto err;
        }
    }
#endif

    ret->flags = ret->meth->flags;
    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_KYBER, ret, &ret->ex_data)) {
        goto err;
    }

    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
        Kybererr(KYBER_F_KYBER_NEW_METHOD, ERR_R_INIT_FAIL);
        goto err;
    }

    return ret;

 err:
    kyber_free(ret);
    return NULL;
}

void kyber_free(Kyber *r)
{
    int i;

    if (r == NULL)
        return;

    CRYPTO_DOWN_REF(&r->references, &i, r->lock);
    REF_PRINT_COUNT("Kyber", r);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    if (r->meth != NULL && r->meth->finish != NULL)
        r->meth->finish(r);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(r->engine);
#endif

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_KYBER, r, &r->ex_data);

    CRYPTO_THREAD_lock_free(r->lock);

    OPENSSL_free(r->public_key);
    OPENSSL_free(r->private_key);

    OPENSSL_free(r);
}

int kyber_up_ref(Kyber *r)
{
    int i;

    if (CRYPTO_UP_REF(&r->references, &i, r->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("Kyber", r);
    REF_ASSERT_ISNT(i < 2);
    return i > 1 ? 1 : 0;
}

int kyber_set_ex_data(Kyber *r, int idx, void *arg)
{
    return CRYPTO_set_ex_data(&r->ex_data, idx, arg);
}

void *kyber_get_ex_data(const Kyber *r, int idx)
{
    return CRYPTO_get_ex_data(&r->ex_data, idx);
}

int kyber_set0_crt_params(Kyber *r, int mode)
{
    if (r == NULL || (mode != 2 && mode != 3 && mode != 4))
        return 0;

    r->mode = mode;

    return 1;
}

void kyber_get0_crt_params(const Kyber *r,
                         const int **mode)
{
    if (mode != NULL)
        *mode = &r->mode;
}

const int *kyber_get0_mode(const Kyber *r)
{
    return &r->mode;
}

void kyber_clear_flags(Kyber *r, int flags)
{
    r->flags &= ~flags;
}

int kyber_test_flags(const Kyber *r, int flags)
{
    return r->flags & flags;
}

void kyber_set_flags(Kyber *r, int flags)
{
    r->flags |= flags;
}

ENGINE *kyber_get0_engine(const Kyber *r)
{
    return r->engine;
}

int kyber_set0_key(Kyber *r, uint8_t *public_key,
        const int public_key_size)
{
    if (r->public_key == NULL && public_key == NULL)
        return 0;

    r->public_key_size = public_key_size;
    if (public_key != NULL) {
        r->public_key = public_key;
    }

    return 1;
}

void kyber_get0_key(const Kyber *r,
                  const uint8_t **public_key, int *public_key_size)
{
    if (public_key != NULL)
        *public_key = r->public_key;
    if (public_key_size != NULL)
        *public_key_size = r->public_key_size;
}

int kyber_pkey_ctx_ctrl(EVP_PKEY_CTX *ctx, int optype, int cmd, int p1, void *p2)
{
    /* If key type not Kyber return error */
    if (ctx != NULL && ctx->pmeth != NULL
        && ctx->pmeth->pkey_id != EVP_PKEY_KYBER)
        return -1;
     return EVP_PKEY_CTX_ctrl(ctx, -1, optype, cmd, p1, p2);
}

size_t kyber_copy_priv(const Kyber *key, unsigned char **pbuf)
{
    unsigned char *buf;

    if (key->private_key_size <= 0)
        return 0;
    if ((buf = OPENSSL_malloc(key->private_key_size)) == NULL) {
        Kybererr(KYBER_F_KYBER_KEY_COPYPRIV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memmove(buf, key->private_key, key->private_key_size);
    *pbuf = buf;
    return key->private_key_size;
}

size_t kyber_copy_pub(const Kyber *key, unsigned char **pbuf)
{
    unsigned char *buf;

    if (key->public_key_size <= 0)
        return 0;
    if ((buf = OPENSSL_malloc(key->public_key_size)) == NULL) {
        Kybererr(KYBER_F_KYBER_KEY_COPYPRIV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memmove(buf, key->public_key, key->public_key_size);
    *pbuf = buf;
    return key->public_key_size;
}
