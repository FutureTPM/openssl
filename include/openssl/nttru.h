#ifndef HEADER_NTTRU_H
# define HEADER_NTTRU_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_NTTRU
# include <openssl/asn1.h>
# include <openssl/bio.h>
# include <openssl/crypto.h>
# include <openssl/ossl_typ.h>
# include <openssl/nttruerr.h>
# ifdef  __cplusplus
extern "C" {
# endif

# define NTTRU_FLAG_CACHE_PUBLIC           0x0002
# define NTTRU_FLAG_CACHE_PRIVATE          0x0004

# define EVP_PKEY_CTRL_NTTRU_KEYGEN_MODE   (EVP_PKEY_ALG_CTRL + 1)

# define NTTRU_set_app_data(s,arg)         nttru_set_ex_data(s,0,arg)
# define NTTRU_get_app_data(s)             nttru_get_ex_data(s,0)

/* # define EVP_PKEY_CTX_set_nttru_mode(ctx) \ */
/*         nttru_pkey_ctx_ctrl(ctx, -1, EVP_PKEY_CTRL_NTTRU_KEYGEN_MODE, mode, NULL) */



NTTRU *nttru_new(void);
NTTRU *nttru_new_method(ENGINE *engine);

int nttru_set0_key(NTTRU *r, uint8_t *public_key,
        const int public_key_size);
/* int nttru_set0_crt_params(NTTRU *r, int mode); */
void nttru_get0_key(const NTTRU *r,
                  const uint8_t **public_key, int *public_key_size);
void nttru_get0_privkey(const NTTRU *r,
                        const uint8_t **priv_key, int *priv_key_size);
/* void nttru_get0_crt_params(const NTTRU *r, const int **mode); */

void nttru_clear_flags(NTTRU *r, int flags);
int nttru_test_flags(const NTTRU *r, int flags);
void nttru_set_flags(NTTRU *r, int flags);
ENGINE *nttru_get0_engine(const NTTRU *r);

/* New version */
int nttru_generate_key_ex(NTTRU *nttru);

int nttru_check_key(const NTTRU *);
int nttru_check_key_ex(const NTTRU *);
        /* next 4 return -1 on error */
int nttru_public_encrypt(int flen, const unsigned char *from,
                       unsigned char *to, NTTRU *nttru);
int nttru_private_decrypt(int flen, const unsigned char *from,
                        unsigned char *to, NTTRU *nttru);
void nttru_free(NTTRU *r);
/* "up" the NTTRU object's reference count */
int nttru_up_ref(NTTRU *r);

int nttru_flags(const NTTRU *r);

void nttru_set_default_method(const NTTRU_METHOD *meth);
const NTTRU_METHOD *nttru_get_default_method(void);
const NTTRU_METHOD *nttru_null_method(void);
const NTTRU_METHOD *nttru_get_method(const NTTRU *nttru);
int nttru_set_method(NTTRU *nttru, const NTTRU_METHOD *meth);
const NTTRU_METHOD *nttru_OpenSSL(void);

int nttru_pkey_ctx_ctrl(EVP_PKEY_CTX *ctx, int optype, int cmd, int p1, void *p2);

int i2d_NttruPrivateKey(NTTRU *a, unsigned char **out);
NTTRU *d2i_NttruPrivateKey(NTTRU **a, const unsigned char **in, long len);
int i2d_NttruPublicKey(NTTRU *a, unsigned char **out);
NTTRU *d2i_NttruPublicKey(NTTRU **a, const unsigned char **in, long len);

# ifndef OPENSSL_NO_STDIO
int nttru_print_fp(FILE *fp, const NTTRU *r, int offset);
# endif

int nttru_print(BIO *bp, const NTTRU *r, int offset);

#define NTTRU_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_NTTRU, l, p, newf, dupf, freef)
int nttru_set_ex_data(NTTRU *r, int idx, void *arg);
void *nttru_get_ex_data(const NTTRU *r, int idx);

NTTRU *NTTRUPublicKey_dup(NTTRU *nttru);
NTTRU *NTTRUPrivateKey_dup(NTTRU *nttru);

NTTRU_METHOD *nttru_meth_new(const char *name, int flags);
void nttru_meth_free(NTTRU_METHOD *meth);
NTTRU_METHOD *nttru_meth_dup(const NTTRU_METHOD *meth);
const char *nttru_meth_get0_name(const NTTRU_METHOD *meth);
int nttru_meth_set1_name(NTTRU_METHOD *meth, const char *name);
int nttru_meth_get_flags(const NTTRU_METHOD *meth);
int nttru_meth_set_flags(NTTRU_METHOD *meth, int flags);
void *nttru_meth_get0_app_data(const NTTRU_METHOD *meth);
int nttru_meth_set0_app_data(NTTRU_METHOD *meth, void *app_data);
int (*nttru_meth_get_pub_enc(const NTTRU_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, NTTRU *nttru);
int nttru_meth_set_pub_enc(NTTRU_METHOD *nttru,
                         int (*pub_enc) (int flen, const unsigned char *from,
                                         unsigned char *to, NTTRU *nttru));
int (*nttru_meth_get_priv_dec(const NTTRU_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, NTTRU *nttru);
int nttru_meth_set_priv_dec(NTTRU_METHOD *nttru,
                          int (*priv_dec) (int flen, const unsigned char *from,
                                           unsigned char *to, NTTRU *nttru));
int (*nttru_meth_get_init(const NTTRU_METHOD *meth)) (NTTRU *nttru);
int nttru_meth_set_init(NTTRU_METHOD *nttru, int (*init) (NTTRU *nttru));
int (*nttru_meth_get_finish(const NTTRU_METHOD *meth)) (NTTRU *nttru);
int nttru_meth_set_finish(NTTRU_METHOD *nttru, int (*finish) (NTTRU *nttru));
int (*nttru_meth_get_keygen(const NTTRU_METHOD *meth))
    (NTTRU *nttru);
int nttru_meth_set_keygen(NTTRU_METHOD *nttru,
                        int (*keygen) (NTTRU *nttru));

#  ifdef  __cplusplus
}
#  endif
# endif
#endif
