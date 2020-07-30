#include <openssl/err.h>
#include "nttru-locl.h"

int nttru_check_key(const NTTRU *key)
{
    return nttru_check_key_ex(key);
}

int nttru_check_key_ex(const NTTRU *key)
{
    int ret = 1;

    if (key->private_key == NULL ||
            key->public_key == NULL) {
        NTTRUerr(NTTRU_F_NTTRU_CHECK_KEY_EX, NTTRU_R_VALUE_MISSING);
        return 0;
    }

    if (key->public_key_size != 1248 || key->private_key_size != 2496) {
      ret = 0;
      NTTRUerr(NTTRU_F_NTTRU_CHECK_KEY_EX, NTTRU_R_WRONG_KEY_SIZE);
    }
    return ret;
}
