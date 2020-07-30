#include <stdio.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include <openssl/rand.h>
#include "nttru-locl.h"

int nttru_public_encrypt(int flen, const unsigned char *from,
                        unsigned char *to, NTTRU *nttru)
{
    return nttru->meth->nttru_pub_enc(flen, from, to, nttru);
}

int nttru_private_decrypt(int flen, const unsigned char *from,
                        unsigned char *to, NTTRU *nttru)
{
    return nttru->meth->nttru_priv_dec(flen, from, to, nttru);
}

int nttru_flags(const NTTRU *r)
{
    return r == NULL ? 0 : r->meth->flags;
}

int NTTRU_size(const NTTRU *r)
{
    return r->public_key_size;
}

