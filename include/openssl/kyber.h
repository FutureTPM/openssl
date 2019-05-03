#ifndef HEADER_KYBER_H
# define HEADER_KYBER_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_KYBER
# include <openssl/asn1.h>
# include <openssl/bio.h>
# include <openssl/crypto.h>
# include <openssl/ossl_typ.h>
# include <openssl/kybererr.h>
# ifdef  __cplusplus
extern "C" {
# endif

# define KYBER_FLAG_CACHE_PUBLIC           0x0002
# define KYBER_FLAG_CACHE_PRIVATE          0x0004

# define EVP_PKEY_CTRL_KYBER_KEYGEN_MODE   (EVP_PKEY_ALG_CTRL + 1)

# define Kyber_set_app_data(s,arg)         Kyber_set_ex_data(s,0,arg)
# define Kyber_get_app_data(s)             Kyber_get_ex_data(s,0)

# define EVP_PKEY_CTX_set_kyber_mode(ctx, mode) \
        kyber_pkey_ctx_ctrl(ctx, -1, EVP_PKEY_CTRL_KYBER_KEYGEN_MODE, mode, NULL)

Kyber *kyber_new(void);
Kyber *kyber_new_method(ENGINE *engine);

int kyber_set0_key(Kyber *r, uint8_t *public_key,
        const int public_key_size);
int kyber_set0_crt_params(Kyber *r, int mode);
void kyber_get0_key(const Kyber *r,
                  const uint8_t **public_key, int *public_key_size);
void kyber_get0_crt_params(const Kyber *r, const int **mode);

void kyber_clear_flags(Kyber *r, int flags);
int kyber_test_flags(const Kyber *r, int flags);
void kyber_set_flags(Kyber *r, int flags);
ENGINE *kyber_get0_engine(const Kyber *r);

/* New version */
int kyber_generate_key_ex(Kyber *kyber, int mode);

int kyber_check_key(const Kyber *);
int kyber_check_key_ex(const Kyber *);
        /* next 4 return -1 on error */
int kyber_public_encrypt(int flen, const unsigned char *from,
                       unsigned char *to, Kyber *kyber);
int kyber_private_decrypt(int flen, const unsigned char *from,
                        unsigned char *to, Kyber *kyber);
void kyber_free(Kyber *r);
/* "up" the Kyber object's reference count */
int kyber_up_ref(Kyber *r);

int kyber_flags(const Kyber *r);

void kyber_set_default_method(const KYBER_METHOD *meth);
const KYBER_METHOD *kyber_get_default_method(void);
const KYBER_METHOD *kyber_null_method(void);
const KYBER_METHOD *kyber_get_method(const Kyber *kyber);
int kyber_set_method(Kyber *kyber, const KYBER_METHOD *meth);
const KYBER_METHOD *kyber_OpenSSL(void);

int kyber_pkey_ctx_ctrl(EVP_PKEY_CTX *ctx, int optype, int cmd, int p1, void *p2);

int i2d_KyberPrivateKey(Kyber *a, unsigned char **out);
Kyber *d2i_KyberPrivateKey(Kyber **a, const unsigned char **in, long len);
int i2d_KyberPublicKey(Kyber *a, unsigned char **out);
Kyber *d2i_KyberPublicKey(Kyber **a, const unsigned char **in, long len);

# ifndef OPENSSL_NO_STDIO
int kyber_print_fp(FILE *fp, const Kyber *r, int offset);
# endif

int kyber_print(BIO *bp, const Kyber *r, int offset);

#define Kyber_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_KYBER, l, p, newf, dupf, freef)
int kyber_set_ex_data(Kyber *r, int idx, void *arg);
void *kyber_get_ex_data(const Kyber *r, int idx);

Kyber *KyberPublicKey_dup(Kyber *kyber);
Kyber *KyberPrivateKey_dup(Kyber *kyber);

KYBER_METHOD *kyber_meth_new(const char *name, int flags);
void kyber_meth_free(KYBER_METHOD *meth);
KYBER_METHOD *kyber_meth_dup(const KYBER_METHOD *meth);
const char *kyber_meth_get0_name(const KYBER_METHOD *meth);
int kyber_meth_set1_name(KYBER_METHOD *meth, const char *name);
int kyber_meth_get_flags(const KYBER_METHOD *meth);
int kyber_meth_set_flags(KYBER_METHOD *meth, int flags);
void *kyber_meth_get0_app_data(const KYBER_METHOD *meth);
int kyber_meth_set0_app_data(KYBER_METHOD *meth, void *app_data);
int (*kyber_meth_get_pub_enc(const KYBER_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, Kyber *kyber);
int kyber_meth_set_pub_enc(KYBER_METHOD *kyber,
                         int (*pub_enc) (int flen, const unsigned char *from,
                                         unsigned char *to, Kyber *kyber));
int (*kyber_meth_get_priv_dec(const KYBER_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, Kyber *kyber);
int kyber_meth_set_priv_dec(KYBER_METHOD *kyber,
                          int (*priv_dec) (int flen, const unsigned char *from,
                                           unsigned char *to, Kyber *kyber));
int (*kyber_meth_get_init(const KYBER_METHOD *meth)) (Kyber *kyber);
int kyber_meth_set_init(KYBER_METHOD *kyber, int (*init) (Kyber *kyber));
int (*kyber_meth_get_finish(const KYBER_METHOD *meth)) (Kyber *kyber);
int kyber_meth_set_finish(KYBER_METHOD *kyber, int (*finish) (Kyber *kyber));
int (*kyber_meth_get_keygen(const KYBER_METHOD *meth))
    (Kyber *kyber, int mode);
int kyber_meth_set_keygen(KYBER_METHOD *kyber,
                        int (*keygen) (Kyber *kyber, int mode));

#  ifdef  __cplusplus
}
#  endif
# endif
#endif
