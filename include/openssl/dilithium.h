#ifndef HEADER_DILITHIUM_H
# define HEADER_DILITHIUM_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_DILITHIUM
# include <openssl/asn1.h>
# include <openssl/bio.h>
# include <openssl/crypto.h>
# include <openssl/ossl_typ.h>
# include <openssl/dilithiumerr.h>
# ifdef  __cplusplus
extern "C" {
# endif

# define DILITHIUM_FLAG_CACHE_PUBLIC           0x0002
# define DILITHIUM_FLAG_CACHE_PRIVATE          0x0004

# define EVP_PKEY_CTRL_DILITHIUM_KEYGEN_MODE   (EVP_PKEY_ALG_CTRL + 1)

# define Dilithium_set_app_data(s,arg)         Dilithium_set_ex_data(s,0,arg)
# define Dilithium_get_app_data(s)             Dilithium_get_ex_data(s,0)

# define EVP_PKEY_CTX_set_dilithium_mode(ctx, mode) \
        dilithium_pkey_ctx_ctrl(ctx, -1, EVP_PKEY_CTRL_DILITHIUM_KEYGEN_MODE, mode, NULL)

Dilithium *dilithium_new(void);
Dilithium *dilithium_new_method(ENGINE *engine);

int dilithium_set0_key(Dilithium *r, uint8_t *public_key,
        const int public_key_size);
int dilithium_set0_crt_params(Dilithium *r, int mode);
void dilithium_get0_key(const Dilithium *r,
                  const uint8_t **public_key, int *public_key_size);
void dilithium_get0_crt_params(const Dilithium *r, const int **mode);

void dilithium_clear_flags(Dilithium *r, int flags);
int dilithium_test_flags(const Dilithium *r, int flags);
void dilithium_set_flags(Dilithium *r, int flags);
ENGINE *dilithium_get0_engine(const Dilithium *r);

/* New version */
int dilithium_generate_key_ex(Dilithium *dilithium, int mode);

int dilithium_check_key(const Dilithium *);
int dilithium_check_key_ex(const Dilithium *);
        /* next 4 return -1 on error */
int Dilithium_sign(const unsigned char *m, unsigned int m_len,
             unsigned char *sigret, unsigned int *siglen, const Dilithium *dilithium);
int Dilithium_verify(const unsigned char *m, unsigned int m_len,
               const unsigned char *sigbuf, unsigned int siglen, const Dilithium *dilithium);
void dilithium_free(Dilithium *r);
/* "up" the Dilithium object's reference count */
int dilithium_up_ref(Dilithium *r);

int dilithium_flags(const Dilithium *r);

void dilithium_set_default_method(const DILITHIUM_METHOD *meth);
const DILITHIUM_METHOD *dilithium_get_default_method(void);
const DILITHIUM_METHOD *dilithium_null_method(void);
const DILITHIUM_METHOD *dilithium_get_method(const Dilithium *dilithium);
int dilithium_set_method(Dilithium *dilithium, const DILITHIUM_METHOD *meth);
const DILITHIUM_METHOD *Dilithium_OpenSSL(void);

int dilithium_pkey_ctx_ctrl(EVP_PKEY_CTX *ctx, int optype, int cmd, int p1, void *p2);

int i2d_DilithiumPrivateKey(Dilithium *a, unsigned char **out);
Dilithium *d2i_DilithiumPrivateKey(Dilithium **a, const unsigned char **in, long len);
int i2d_DilithiumPublicKey(Dilithium *a, unsigned char **out);
Dilithium *d2i_DilithiumPublicKey(Dilithium **a, const unsigned char **in, long len);

# ifndef OPENSSL_NO_STDIO
int dilithium_print_fp(FILE *fp, const Dilithium *r, int offset);
# endif

int dilithium_print(BIO *bp, const Dilithium *r, int offset);

#define Dilithium_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DILITHIUM, l, p, newf, dupf, freef)
int dilithium_set_ex_data(Dilithium *r, int idx, void *arg);
void *dilithium_get_ex_data(const Dilithium *r, int idx);

Dilithium *DilithiumPublicKey_dup(Dilithium *dilithium);
Dilithium *DilithiumPrivateKey_dup(Dilithium *dilithium);

DILITHIUM_METHOD *dilithium_meth_new(const char *name, int flags);
void dilithium_meth_free(DILITHIUM_METHOD *meth);
DILITHIUM_METHOD *dilithium_meth_dup(const DILITHIUM_METHOD *meth);
const char *dilithium_meth_get0_name(const DILITHIUM_METHOD *meth);
int dilithium_meth_set1_name(DILITHIUM_METHOD *meth, const char *name);
int dilithium_meth_get_flags(const DILITHIUM_METHOD *meth);
int dilithium_meth_set_flags(DILITHIUM_METHOD *meth, int flags);
void *dilithium_meth_get0_app_data(const DILITHIUM_METHOD *meth);
int dilithium_meth_set0_app_data(DILITHIUM_METHOD *meth, void *app_data);
int (*dilithium_meth_get_init(const DILITHIUM_METHOD *meth)) (Dilithium *dilithium);
int dilithium_meth_set_init(DILITHIUM_METHOD *dilithium, int (*init) (Dilithium *dilithium));
int (*dilithium_meth_get_finish(const DILITHIUM_METHOD *meth)) (Dilithium *dilithium);
int dilithium_meth_set_finish(DILITHIUM_METHOD *dilithium, int (*finish) (Dilithium *dilithium));
int (*dilithium_meth_get_keygen(const DILITHIUM_METHOD *meth))
    (Dilithium *dilithium, int mode);
int dilithium_meth_set_keygen(DILITHIUM_METHOD *dilithium,
                        int (*keygen) (Dilithium *dilithium, int mode));

#  ifdef  __cplusplus
}
#  endif
# endif
#endif
