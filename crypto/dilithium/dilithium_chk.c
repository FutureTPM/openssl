#include <openssl/err.h>
#include "dilithium_locl.h"

int dilithium_check_key(const Dilithium *key)
{
    return dilithium_check_key_ex(key);
}

int dilithium_check_key_ex(const Dilithium *key)
{
    int ret = 1;

    if (key->private_key == NULL || key->public_key == NULL) {
        Dilithiumerr(DILITHIUM_F_DILITHIUM_CHECK_KEY_EX, DILITHIUM_R_VALUE_MISSING);
        return 0;
    }

    switch(key->mode) {
        case 1:
            if (key->public_key_size != 896 || key->private_key_size != 2096) {
                ret = 0;
                Dilithiumerr(DILITHIUM_F_DILITHIUM_CHECK_KEY_EX, DILITHIUM_R_WRONG_KEY_SIZE);
            }
            break;
        case 2:
            if (key->public_key_size != 1184 || key->private_key_size != 2800) {
                ret = 0;
                Dilithiumerr(DILITHIUM_F_DILITHIUM_CHECK_KEY_EX, DILITHIUM_R_WRONG_KEY_SIZE);
            }
            break;
        case 3:
            if (key->public_key_size != 1472 || key->private_key_size != 3504) {
                ret = 0;
                Dilithiumerr(DILITHIUM_F_DILITHIUM_CHECK_KEY_EX, DILITHIUM_R_WRONG_KEY_SIZE);
            }
            break;
        case 4:
            if (key->public_key_size != 1760 || key->private_key_size != 3856) {
                ret = 0;
                Dilithiumerr(DILITHIUM_F_DILITHIUM_CHECK_KEY_EX, DILITHIUM_R_WRONG_KEY_SIZE);
            }
            break;
        default:
            ret = 0;
            Dilithiumerr(DILITHIUM_F_DILITHIUM_CHECK_KEY_EX, DILITHIUM_R_WRONG_KEY_SIZE);
    }

    return ret;
}
