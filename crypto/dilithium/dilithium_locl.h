#include <openssl/dilithium.h>
#include "internal/refcount.h"

struct dilithium_st {
    const DILITHIUM_METHOD *meth;
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

struct dilithium_meth_st {
    char *name;
    /* called at new */
    int (*init) (Dilithium *dilithium);
    /* called at free */
    int (*finish) (Dilithium *dilithium);
    /* KYBER_METHOD_FLAG_* things */
    int flags;
    /* may be needed! */
    char *app_data;

    int (*dilithium_sign) (const unsigned char *m, unsigned int m_length,
                     unsigned char *sigret, unsigned int *siglen,
                     const Dilithium *dilithium);
    int (*dilithium_verify) (const unsigned char *m, unsigned int m_length,
                     const unsigned char *sigbuf, unsigned int siglen,
                     const Dilithium *dilithium);
    /*
     * If this callback is NULL, the builtin software Kyber key-gen will be
     * used. This is for behavioural compatibility whilst the code gets
     * rewired, but one day it would be nice to assume there are no such
     * things as "builtin software" implementations.
     */
    int (*dilithium_keygen) (Dilithium *dilithium, int mode);
};

typedef struct {
    uint64_t k;
    uint64_t l;
    uint64_t eta;
    uint64_t setabits;
    uint64_t beta;
    uint64_t omega;
    uint64_t polt0_size_packed;
    uint64_t polt1_size_packed;
    uint64_t poleta_size_packed;
    uint64_t polz_size_packed;
    uint64_t crypto_publickeybytes;
    uint64_t crypto_secretkeybytes;
    uint64_t crypto_bytes;
    uint64_t pol_size_packed;
    uint64_t polw1_size_packed;
    uint64_t polveck_size_packed;
    uint64_t polvecl_size_packed;
} DilithiumParams;

DilithiumParams generate_dilithium_params(const int mode);
size_t dilithium_copy_priv(const Dilithium *key, unsigned char **pbuf);
size_t dilithium_copy_pub(const Dilithium *key, unsigned char **pbuf);
int Dilithium_size(const Dilithium *r);
int Dilithium_sig_size(const Dilithium *r);
int Dilithium_verify(const unsigned char *m, unsigned int m_len,
             const unsigned char *sigbuf, unsigned int siglen, const Dilithium *dilithium);
int Dilithium_sign(const unsigned char *m, unsigned int m_len,
             unsigned char *sigret, unsigned int *siglen, const Dilithium *dilithium);
int int_dilithium_sign(const unsigned char *m, unsigned int m_len,
             unsigned char *sigret, unsigned int *siglen, const Dilithium *dilithium);
int int_dilithium_verify(const unsigned char *m, unsigned int m_len,
             const unsigned char *sigbuf, unsigned int siglen, const Dilithium *dilithium);
