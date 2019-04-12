#include <openssl/err.h>
#include <openssl/kybererr.h>

#ifndef OPENSSL_NO_ERR

static const ERR_STRING_DATA KYBER_str_functs[] = {
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_PKEY_KYBER_CTRL, 0), "pkey_kyber_ctrl"},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_PKEY_KYBER_CTRL_STR, 0), "pkey_kyber_ctrl_str"},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_KYBER_BUILTIN_KEYGEN, 0), "kyber_builtin_keygen"},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_KYBER_CHECK_KEY, 0), "KYBER_check_key"},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_KYBER_CHECK_KEY_EX, 0), "KYBER_check_key_ex"},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_KYBER_ITEM_VERIFY, 0), "kyber_item_verify"},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_KYBER_METH_DUP, 0), "kyber_meth_dup"},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_KYBER_METH_NEW, 0), "kyber_meth_new"},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_KYBER_METH_SET1_NAME, 0), "KYBER_meth_set1_name"},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_KYBER_NEW_METHOD, 0), "KYBER_new_method"},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_KYBER_NULL, 0), ""},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_KYBER_NULL_PRIVATE_DECRYPT, 0), ""},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_KYBER_NULL_PRIVATE_ENCRYPT, 0), ""},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_KYBER_NULL_PUBLIC_DECRYPT, 0), ""},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_KYBER_NULL_PUBLIC_ENCRYPT, 0), ""},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_KYBER_PARAM_DECODE, 0), "kyber_param_decode"},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_KYBER_PRINT, 0), "KYBER_print"},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_KYBER_PRINT_FP, 0), "KYBER_print_fp"},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_KYBER_PRIV_DECODE, 0), "kyber_priv_decode"},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_KYBER_PRIV_ENCODE, 0), "kyber_priv_encode"},
    {ERR_PACK(ERR_LIB_KYBER, KYBER_F_KYBER_PUB_DECODE, 0), "kyber_pub_decode"},
    {0, NULL}
};

static const ERR_STRING_DATA KYBER_str_reasons[] = {
    {ERR_PACK(ERR_LIB_KYBER, 0, KYBER_R_ALGORITHM_MISMATCH), "algorithm mismatch"},
    {ERR_PACK(ERR_LIB_KYBER, 0, KYBER_R_BAD_FIXED_HEADER_DECRYPT),
    "bad fixed header decrypt"},
    {ERR_PACK(ERR_LIB_KYBER, 0, KYBER_R_WRONG_KEY_SIZE), "wrong key size"},
    {ERR_PACK(ERR_LIB_KYBER, 0, KYBER_R_BLOCK_TYPE_IS_NOT_01),
    "block type is not 01"},
    {ERR_PACK(ERR_LIB_KYBER, 0, KYBER_R_BLOCK_TYPE_IS_NOT_02),
    "block type is not 02"},
    {ERR_PACK(ERR_LIB_KYBER, 0, KYBER_R_DATA_TOO_LARGE), "data too large"},
    {ERR_PACK(ERR_LIB_KYBER, 0, KYBER_R_DATA_TOO_LARGE_FOR_KEY_SIZE),
    "data too large for key size"},
    {ERR_PACK(ERR_LIB_KYBER, 0, KYBER_R_DATA_TOO_SMALL), "data too small"},
    {ERR_PACK(ERR_LIB_KYBER, 0, KYBER_R_DATA_TOO_SMALL_FOR_KEY_SIZE),
    "data too small for key size"},
    {ERR_PACK(ERR_LIB_KYBER, 0, KYBER_R_FIRST_OCTET_INVALID),
    "first octet invalid"},
    {ERR_PACK(ERR_LIB_KYBER, 0, KYBER_R_INVALID_HEADER), "invalid header"},
    {ERR_PACK(ERR_LIB_KYBER, 0, KYBER_R_INVALID_LABEL), "invalid label"},
    {ERR_PACK(ERR_LIB_KYBER, 0, KYBER_R_NULL_BEFORE_BLOCK_MISSING),
    "null before block missing"},
    {ERR_PACK(ERR_LIB_KYBER, 0, KYBER_R_UNKNOWN_ALGORITHM_TYPE),
    "unknown algorithm type"},
    {ERR_PACK(ERR_LIB_KYBER, 0, KYBER_R_UNSUPPORTED_ENCRYPTION_TYPE),
    "unsupported encryption type"},
    {ERR_PACK(ERR_LIB_KYBER, 0, KYBER_R_UNSUPPORTED_LABEL_SOURCE),
    "unsupported label source"},
    {ERR_PACK(ERR_LIB_KYBER, 0, KYBER_R_VALUE_MISSING), "value missing"},
    {0, NULL}
};

#endif

int ERR_load_KYBER_strings(void)
{
#ifndef OPENSSL_NO_ERR
    if (ERR_func_error_string(KYBER_str_functs[0].error) == NULL) {
        ERR_load_strings_const(KYBER_str_functs);
        ERR_load_strings_const(KYBER_str_reasons);
    }
#endif
    return 1;
}
