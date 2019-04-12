#include <stdio.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include <openssl/rand.h>
#include "kyber_locl.h"

int kyber_public_encrypt(int flen, const unsigned char *from,
                        unsigned char *to, Kyber *kyber)
{
    return kyber->meth->kyber_pub_enc(flen, from, to, kyber);
}

int kyber_private_decrypt(int flen, const unsigned char *from,
                        unsigned char *to, Kyber *kyber)
{
    return kyber->meth->kyber_priv_dec(flen, from, to, kyber);
}

int kyber_flags(const Kyber *r)
{
    return r == NULL ? 0 : r->meth->flags;
}

