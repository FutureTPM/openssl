#include <stdio.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include <openssl/rand.h>
#include "dilithium_locl.h"

int dilithium_flags(const Dilithium *r)
{
    return r == NULL ? 0 : r->meth->flags;
}

int Dilithium_size(const Dilithium *r)
{
    return r->public_key_size;
}

/*
 * Add to 64 bytes to the signature size to account for the largest digest size.
 * This should have been specified by the PKEY_METHODS.
 */
int Dilithium_sig_size(const Dilithium *r)
{
    switch (r->mode) {
        case 1:
            return 1387 + 64;
        case 2:
            return 2044 + 64;
        case 3:
            return 2701 + 64;
        case 4:
            return 3366 + 64;
        default:
            return 0;
    };
}
