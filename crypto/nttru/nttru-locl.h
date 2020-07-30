#include <openssl/nttru.h>
#include "internal/refcount.h"

struct nttru_st {
    const NTTRU_METHOD *meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
    int mode;
    uint8_t *public_key;
    int public_key_size;
    uint8_t *private_key;
    int private_key_size;
    /* be careful using this if the NTTRU structure is shared */
    CRYPTO_EX_DATA ex_data;
    CRYPTO_REF_COUNT references;
    int flags;
    CRYPTO_RWLOCK *lock;
};

struct nttru_meth_st {
    char *name;
    int (*nttru_pub_enc) (int flen, const unsigned char *from,
                        unsigned char *to, NTTRU *nttru);
    int (*nttru_priv_dec) (int flen, const unsigned char *from,
                         unsigned char *to, NTTRU *nttru);
    /* called at new */
    int (*init) (NTTRU *nttru);
    /* called at free */
    int (*finish) (NTTRU *nttru);
    /* NTTRU_METHOD_FLAG_* things */
    int flags;
    /* may be needed! */
    char *app_data;
    /*
     * If this callback is NULL, the builtin software NTTRU key-gen will be
     * used. This is for behavioural compatibility whilst the code gets
     * rewired, but one day it would be nice to assume there are no such
     * things as "builtin software" implementations.
     */
    int (*nttru_keygen) (NTTRU *nttru);
};

int nttru_encapsulate(const NTTRU *nttru, uint8_t *ss, uint8_t **ct);
int nttru_decapsulate(const NTTRU *nttru, uint8_t *ss, const uint8_t *ct);
size_t nttru_copy_priv(const NTTRU *key, unsigned char **pbuf);
size_t nttru_copy_pub(const NTTRU *key, unsigned char **pbuf);
int NTTRU_size(const NTTRU *r);
