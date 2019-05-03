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

int Dilithium_sig_size(const Dilithium *r)
{
    switch (r->mode) {
        case 1:
            return 1387;
        case 2:
            return 2044;
        case 3:
            return 2701;
        case 4:
            return 3366;
        default:
            return 0;
    };
}
