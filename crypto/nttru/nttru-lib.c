#include <stdio.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"
#include <openssl/engine.h>
#include <openssl/evp.h>
#include "internal/evp_int.h"
#include "nttru-locl.h"
#include "nttru-ntt.h"

NTTRU *nttru_new(void)
{
    return nttru_new_method(NULL);
}

const NTTRU_METHOD *nttru_get_method(const NTTRU *nttru)
{
    return nttru->meth;
}

int nttru_set_method(NTTRU *nttru, const NTTRU_METHOD *meth)
{
    /*
     * NB: The caller is specifically setting a method, so it's not up to us
     * to deal with which ENGINE it comes from.
     */
    const NTTRU_METHOD *mtmp;
    mtmp = nttru->meth;
    if (mtmp->finish)
        mtmp->finish(nttru);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(nttru->engine);
    nttru->engine = NULL;
#endif
    nttru->meth = meth;
    if (meth->init)
        meth->init(nttru);
    return 1;
}

NTTRU *nttru_new_method(ENGINE *engine)
{
    NTTRU *ret = OPENSSL_zalloc(sizeof(*ret));

    nttru_init_ntt();

    if (ret == NULL) {
        NTTRUerr(NTTRU_F_NTTRU_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->references = 1;
    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        NTTRUerr(NTTRU_F_NTTRU_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(ret);
        return NULL;
    }

    ret->meth = nttru_get_default_method();
#ifndef OPENSSL_NO_ENGINE
    ret->flags = ret->meth->flags;
    if (engine) {
        if (!ENGINE_init(engine)) {
            NTTRUerr(NTTRU_F_NTTRU_NEW_METHOD, ERR_R_ENGINE_LIB);
            goto err;
        }
        ret->engine = engine;
    } else {
        ret->engine = ENGINE_get_default_NTTRU();
    }
    if (ret->engine) {
        ret->meth = ENGINE_get_NTTRU(ret->engine);
        if (ret->meth == NULL) {
            NTTRUerr(NTTRU_F_NTTRU_NEW_METHOD, ERR_R_ENGINE_LIB);
            goto err;
        }
    }
#endif

    ret->flags = ret->meth->flags;
    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_NTTRU, ret, &ret->ex_data)) {
        goto err;
    }

    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
        NTTRUerr(NTTRU_F_NTTRU_NEW_METHOD, ERR_R_INIT_FAIL);
        goto err;
    }

    return ret;

 err:
    nttru_free(ret);
    return NULL;
}

void nttru_free(NTTRU *r)
{
    int i;

    if (r == NULL)
        return;

    CRYPTO_DOWN_REF(&r->references, &i, r->lock);
    REF_PRINT_COUNT("NTTRU", r);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    if (r->meth != NULL && r->meth->finish != NULL)
        r->meth->finish(r);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(r->engine);
#endif

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_NTTRU, r, &r->ex_data);

    CRYPTO_THREAD_lock_free(r->lock);
    OPENSSL_free(r->public_key);
    OPENSSL_free(r->private_key);
    OPENSSL_free(r);
}

int nttru_up_ref(NTTRU *r)
{
    int i;

    if (CRYPTO_UP_REF(&r->references, &i, r->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("NTTRU", r);
    REF_ASSERT_ISNT(i < 2);
    return i > 1 ? 1 : 0;
}

int nttru_set_ex_data(NTTRU *r, int idx, void *arg)
{
    return CRYPTO_set_ex_data(&r->ex_data, idx, arg);
}

void *nttru_get_ex_data(const NTTRU *r, int idx)
{
    return CRYPTO_get_ex_data(&r->ex_data, idx);
}

/* int nttru_set0_crt_params(NTTRU *r, int mode) */
/* { */
/*     if (r == NULL || (mode != 2 && mode != 3 && mode != 4)) */
/*         return 0; */

/*     r->mode = mode; */

/*     return 1; */
/* } */

/* void nttru_get0_crt_params(const NTTRU *r, */
/*                          const int **mode) */
/* { */
/*     if (mode != NULL) */
/*         *mode = &r->mode; */
/* } */

const int *nttru_get0_mode(const NTTRU *r)
{
    return &r->mode;
}

void nttru_clear_flags(NTTRU *r, int flags)
{
    r->flags &= ~flags;
}

int nttru_test_flags(const NTTRU *r, int flags)
{
    return r->flags & flags;
}

void nttru_set_flags(NTTRU *r, int flags)
{
    r->flags |= flags;
}

ENGINE *nttru_get0_engine(const NTTRU *r)
{
    return r->engine;
}

int nttru_set0_key(NTTRU *r, uint8_t *public_key,
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

void nttru_get0_key(const NTTRU *r,
                  const uint8_t **public_key, int *public_key_size)
{
    if (public_key != NULL)
        *public_key = r->public_key;
    if (public_key_size != NULL)
        *public_key_size = r->public_key_size;
}

void nttru_get0_privkey(const NTTRU *r, const uint8_t **priv_key,
                    int *priv_key_size) {
  if (priv_key != NULL)
    *priv_key = r->private_key;
  if (priv_key_size != NULL)
    *priv_key_size = r->private_key_size;
}

int nttru_pkey_ctx_ctrl(EVP_PKEY_CTX *ctx, int optype, int cmd, int p1, void *p2)
{
    /* If key type not NTTRU return error */
    if (ctx != NULL && ctx->pmeth != NULL
        && ctx->pmeth->pkey_id != EVP_PKEY_NTTRU)
        return -1;
     return EVP_PKEY_CTX_ctrl(ctx, -1, optype, cmd, p1, p2);
}

size_t nttru_copy_priv(const NTTRU *key, unsigned char **pbuf)
{
    unsigned char *buf;

    if (key->private_key_size <= 0)
        return 0;
    if ((buf = OPENSSL_malloc(key->private_key_size)) == NULL) {
        NTTRUerr(NTTRU_F_NTTRU_KEY_COPYPRIV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memmove(buf, key->private_key, key->private_key_size);
    *pbuf = buf;
    return key->private_key_size;
}

size_t nttru_copy_pub(const NTTRU *key, unsigned char **pbuf)
{
    unsigned char *buf;

    if (key->public_key_size <= 0)
        return 0;
    if ((buf = OPENSSL_malloc(key->public_key_size)) == NULL) {
        NTTRUerr(NTTRU_F_NTTRU_KEY_COPYPRIV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memmove(buf, key->public_key, key->public_key_size);
    *pbuf = buf;
    return key->public_key_size;
}
