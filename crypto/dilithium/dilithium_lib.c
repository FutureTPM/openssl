#include <stdio.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"
#include <openssl/engine.h>
#include <openssl/evp.h>
#include "internal/evp_int.h"
#include "dilithium_locl.h"

Dilithium *dilithium_new(void)
{
    return dilithium_new_method(NULL);
}

const DILITHIUM_METHOD *dilithium_get_method(const Dilithium *dilithium)
{
    return dilithium->meth;
}

int dilithium_set_method(Dilithium *dilithium, const DILITHIUM_METHOD *meth)
{
    /*
     * NB: The caller is specifically setting a method, so it's not up to us
     * to deal with which ENGINE it comes from.
     */
    const DILITHIUM_METHOD *mtmp;
    mtmp = dilithium->meth;
    if (mtmp->finish)
        mtmp->finish(dilithium);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(dilithium->engine);
    dilithium->engine = NULL;
#endif
    dilithium->meth = meth;
    if (meth->init)
        meth->init(dilithium);
    return 1;
}

Dilithium *dilithium_new_method(ENGINE *engine)
{
    Dilithium *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        Dilithiumerr(DILITHIUM_F_DILITHIUM_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->references = 1;
    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        Dilithiumerr(DILITHIUM_F_DILITHIUM_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(ret);
        return NULL;
    }

    ret->meth = dilithium_get_default_method();
#ifndef OPENSSL_NO_ENGINE
    ret->flags = ret->meth->flags;
    if (engine) {
        if (!ENGINE_init(engine)) {
            Dilithiumerr(DILITHIUM_F_DILITHIUM_NEW_METHOD, ERR_R_ENGINE_LIB);
            goto err;
        }
        ret->engine = engine;
    } else {
        ret->engine = ENGINE_get_default_Dilithium();
    }
    if (ret->engine) {
        ret->meth = ENGINE_get_Dilithium(ret->engine);
        if (ret->meth == NULL) {
            Dilithiumerr(DILITHIUM_F_DILITHIUM_NEW_METHOD, ERR_R_ENGINE_LIB);
            goto err;
        }
    }
#endif

    ret->flags = ret->meth->flags;
    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_DILITHIUM, ret, &ret->ex_data)) {
        goto err;
    }

    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
        Dilithiumerr(DILITHIUM_F_DILITHIUM_NEW_METHOD, ERR_R_INIT_FAIL);
        goto err;
    }

    return ret;

 err:
    dilithium_free(ret);
    return NULL;
}

void dilithium_free(Dilithium *r)
{
    int i;

    if (r == NULL)
        return;

    CRYPTO_DOWN_REF(&r->references, &i, r->lock);
    REF_PRINT_COUNT("Dilithium", r);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    if (r->meth != NULL && r->meth->finish != NULL)
        r->meth->finish(r);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(r->engine);
#endif

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DILITHIUM, r, &r->ex_data);

    CRYPTO_THREAD_lock_free(r->lock);

    OPENSSL_free(r->public_key);
    OPENSSL_free(r->private_key);

    OPENSSL_free(r);
}

int dilithium_up_ref(Dilithium *r)
{
    int i;

    if (CRYPTO_UP_REF(&r->references, &i, r->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("Dilithium", r);
    REF_ASSERT_ISNT(i < 2);
    return i > 1 ? 1 : 0;
}

int dilithium_set_ex_data(Dilithium *r, int idx, void *arg)
{
    return CRYPTO_set_ex_data(&r->ex_data, idx, arg);
}

void *dilithium_get_ex_data(const Dilithium *r, int idx)
{
    return CRYPTO_get_ex_data(&r->ex_data, idx);
}

int dilithium_set0_crt_params(Dilithium *r, int mode)
{
    if (r == NULL || (mode != 1 && mode != 2 && mode != 3 && mode != 4))
        return 0;

    r->mode = mode;

    return 1;
}

void dilithium_get0_crt_params(const Dilithium *r, const int **mode)
{
    if (mode != NULL)
        *mode = &r->mode;
}

const int *dilithium_get0_mode(const Dilithium *r)
{
    return &r->mode;
}

void dilithium_clear_flags(Dilithium *r, int flags)
{
    r->flags &= ~flags;
}

int dilithium_test_flags(const Dilithium *r, int flags)
{
    return r->flags & flags;
}

void dilithium_set_flags(Dilithium *r, int flags)
{
    r->flags |= flags;
}

ENGINE *dilithium_get0_engine(const Dilithium *r)
{
    return r->engine;
}

int dilithium_set0_key(Dilithium *r, uint8_t *public_key,
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

void dilithium_get0_key(const Dilithium *r,
                  const uint8_t **public_key, int *public_key_size)
{
    if (public_key != NULL)
        *public_key = r->public_key;
    if (public_key_size != NULL)
        *public_key_size = r->public_key_size;
}

int dilithium_pkey_ctx_ctrl(EVP_PKEY_CTX *ctx, int optype, int cmd, int p1, void *p2)
{
    /* If key type not Dilithium return error */
    if (ctx != NULL && ctx->pmeth != NULL
        && ctx->pmeth->pkey_id != EVP_PKEY_DILITHIUM)
        return -1;
     return EVP_PKEY_CTX_ctrl(ctx, -1, optype, cmd, p1, p2);
}

size_t dilithium_copy_priv(const Dilithium *key, unsigned char **pbuf)
{
    unsigned char *buf;

    if (key->private_key_size <= 0)
        return 0;
    if ((buf = OPENSSL_malloc(key->private_key_size)) == NULL) {
        Dilithiumerr(DILITHIUM_F_DILITHIUM_KEY_COPYPRIV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memmove(buf, key->private_key, key->private_key_size);
    *pbuf = buf;
    return key->private_key_size;
}

size_t dilithium_copy_pub(const Dilithium *key, unsigned char **pbuf)
{
    unsigned char *buf;

    if (key->public_key_size <= 0)
        return 0;
    if ((buf = OPENSSL_malloc(key->public_key_size)) == NULL) {
        Dilithiumerr(DILITHIUM_F_DILITHIUM_KEY_COPYPRIV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memmove(buf, key->public_key, key->public_key_size);
    *pbuf = buf;
    return key->public_key_size;
}

int Dilithium_security_bits(const Dilithium *dilithium)
{
    switch (dilithium->mode) {
        case 1:
            return 68;
        case 2:
            return 103;
        case 3:
            return 138;
        case 4:
            return 176;
        default:
            return 0;
    }
}
