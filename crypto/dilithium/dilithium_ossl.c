#include "internal/cryptlib.h"
#include "dilithium_locl.h"
#include "internal/constant_time_locl.h"

static int dilithium_ossl_init(Dilithium *dilithium);
static int dilithium_ossl_finish(Dilithium *dilithium);
static DILITHIUM_METHOD dilithium_ossl_meth = {
    "OpenSSL Dilithium",
    dilithium_ossl_init,
    dilithium_ossl_finish,
    0,       /* flags */
    NULL,
    int_dilithium_sign,
    int_dilithium_verify,
    NULL,
};

static const DILITHIUM_METHOD *default_Dilithium_meth = &dilithium_ossl_meth;

void dilithium_set_default_method(const DILITHIUM_METHOD *meth)
{
    default_Dilithium_meth = meth;
}

const DILITHIUM_METHOD *dilithium_get_default_method(void)
{
    return default_Dilithium_meth;
}

const DILITHIUM_METHOD *Dilithium_OpenSSL(void)
{
    return &dilithium_ossl_meth;
}

const DILITHIUM_METHOD *dilithium_null_method(void)
{
    return NULL;
}

static int dilithium_ossl_init(Dilithium *dilithium)
{
    dilithium->flags |= DILITHIUM_FLAG_CACHE_PUBLIC | DILITHIUM_FLAG_CACHE_PRIVATE;
    return 1;
}

static int dilithium_ossl_finish(Dilithium *dilithium)
{
    return 1;
}
