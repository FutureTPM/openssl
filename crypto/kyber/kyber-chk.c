#include <openssl/err.h>
#include "kyber-locl.h"

int kyber_check_key(const Kyber *key)
{
    return kyber_check_key_ex(key);
}

int kyber_check_key_ex(const Kyber *key)
{
    int ret = 1;

    if (key->private_key == NULL ||
            key->public_key == NULL) {
        Kybererr(KYBER_F_KYBER_CHECK_KEY_EX, KYBER_R_VALUE_MISSING);
        return 0;
    }

    switch(key->mode) {
        case 2:
            if (key->public_key_size != 800|| key->private_key_size != 1632) {
                ret = 0;
                Kybererr(KYBER_F_KYBER_CHECK_KEY_EX, KYBER_R_WRONG_KEY_SIZE);
            }
            break;
        case 3:
            if (key->public_key_size != 1184 || key->private_key_size != 2400) {
                ret = 0;
                Kybererr(KYBER_F_KYBER_CHECK_KEY_EX, KYBER_R_WRONG_KEY_SIZE);
            }
            break;
        case 4:
            if (key->public_key_size != 1568 || key->private_key_size != 3168) {
                ret = 0;
                Kybererr(KYBER_F_KYBER_CHECK_KEY_EX, KYBER_R_WRONG_KEY_SIZE);
            }
            break;
        default:
            ret = 0;
            Kybererr(KYBER_F_KYBER_CHECK_KEY_EX, KYBER_R_WRONG_KEY_SIZE);
    }

    return ret;
}
