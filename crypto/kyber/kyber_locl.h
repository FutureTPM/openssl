#include <openssl/kyber.h>
#include "internal/refcount.h"

struct kyber_st {
    const KYBER_METHOD *meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
    int mode;
    uint8_t *public_key;
    int public_key_size;
    uint8_t *private_key;
    int private_key_size;
    /* be careful using this if the Kyber structure is shared */
    CRYPTO_EX_DATA ex_data;
    CRYPTO_REF_COUNT references;
    int flags;
    CRYPTO_RWLOCK *lock;
};

struct kyber_meth_st {
    char *name;
    int (*kyber_pub_enc) (int flen, const unsigned char *from,
                        unsigned char *to, Kyber *kyber);
    int (*kyber_priv_dec) (int flen, const unsigned char *from,
                         unsigned char *to, Kyber *kyber);
    /* called at new */
    int (*init) (Kyber *kyber);
    /* called at free */
    int (*finish) (Kyber *kyber);
    /* KYBER_METHOD_FLAG_* things */
    int flags;
    /* may be needed! */
    char *app_data;
    /*
     * If this callback is NULL, the builtin software Kyber key-gen will be
     * used. This is for behavioural compatibility whilst the code gets
     * rewired, but one day it would be nice to assume there are no such
     * things as "builtin software" implementations.
     */
    int (*kyber_keygen) (Kyber *kyber, int mode);
};

typedef struct {
    uint64_t k;
    uint64_t eta;
    uint64_t publickeybytes;
    uint64_t secretkeybytes;
    uint64_t polyveccompressedbytes;
    uint64_t indcpa_secretkeybytes;
    uint64_t indcpa_publickeybytes;
    uint64_t ciphertextbytes;
} KyberParams;

KyberParams generate_kyber_params(const int kyber_k);
int kyber_encapsulate(const Kyber *kyber, uint8_t *ss, uint8_t **ct);
int kyber_decapsulate(const Kyber *kyber, uint8_t *ss, const uint8_t *ct);
size_t kyber_copy_priv(const Kyber *key, unsigned char **pbuf);
size_t kyber_copy_pub(const Kyber *key, unsigned char **pbuf);
int Kyber_size(const Kyber *r);
