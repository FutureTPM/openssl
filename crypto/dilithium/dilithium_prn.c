#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/dilithium.h>
#include <openssl/evp.h>

#ifndef OPENSSL_NO_STDIO
int dilithium_print_fp(FILE *fp, const Dilithium *x, int off)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        Dilithiumerr(DILITHIUM_F_DILITHIUM_PRINT_FP, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = dilithium_print(b, x, off);
    BIO_free(b);
    return ret;
}
#endif

int dilithium_print(BIO *bp, const Dilithium *x, int off)
{
    EVP_PKEY *pk;
    int ret;
    pk = EVP_PKEY_new();
    if (pk == NULL || !EVP_PKEY_set1_Dilithium(pk, (Dilithium *)x))
        return 0;
    ret = EVP_PKEY_print_private(bp, pk, off, NULL);
    EVP_PKEY_free(pk);
    return ret;
}
