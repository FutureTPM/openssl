/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_NTTRUERR_H
# define HEADER_NTTRUERR_H

# ifdef  __cplusplus
extern "C"
# endif
int ERR_load_NTTRU_strings(void);

/*
 * NTTRU function codes.
 */
# define NTTRU_F_INT_NTTRU_VERIFY                             145
# define NTTRU_F_OLD_NTTRU_PRIV_DECODE                        147
# define NTTRU_F_PKEY_NTTRU_CTRL                              143
# define NTTRU_F_PKEY_NTTRU_CTRL_STR                          144
# define NTTRU_F_NTTRU_BUILTIN_KEYGEN                         129
# define NTTRU_F_NTTRU_CHECK_KEY                              123
# define NTTRU_F_NTTRU_CHECK_KEY_EX                           160
# define NTTRU_F_NTTRU_ITEM_VERIFY                            148
# define NTTRU_F_NTTRU_METH_DUP                               161
# define NTTRU_F_NTTRU_METH_NEW                               162
# define NTTRU_F_NTTRU_METH_SET1_NAME                         163
# define NTTRU_F_NTTRU_MULTIP_INFO_NEW                        166
# define NTTRU_F_NTTRU_NEW_METHOD                             106
# define NTTRU_F_NTTRU_NULL                                   124
# define NTTRU_F_NTTRU_NULL_PRIVATE_DECRYPT                   132
# define NTTRU_F_NTTRU_NULL_PRIVATE_ENCRYPT                   133
# define NTTRU_F_NTTRU_NULL_PUBLIC_DECRYPT                    134
# define NTTRU_F_NTTRU_NULL_PUBLIC_ENCRYPT                    135
# define NTTRU_F_NTTRU_PARAM_DECODE                           164
# define NTTRU_F_NTTRU_PRINT                                  115
# define NTTRU_F_NTTRU_PRINT_FP                               116
# define NTTRU_F_NTTRU_PRIV_DECODE                            150
# define NTTRU_F_NTTRU_KEY_COPYPRIV                           194
# define NTTRU_F_NTTRU_PRIV_ENCODE                            138
# define NTTRU_F_NTTRU_PUB_DECODE                             139
# define NTTRU_F_I2D_NTTRUPRIVATEKEY                          192
# define NTTRU_F_D2I_NTTRUPRIVATEKEY                          193
# define NTTRU_F_I2D_NTTRUPUBLICKEY                           195
# define NTTRU_F_D2I_NTTRUPUBLICKEY                           196

/*
 * NTTRU reason codes.
 */
# define NTTRU_R_ALGORITHM_MISMATCH                         100
# define NTTRU_R_WRONG_KEY_SIZE                             101
# define NTTRU_R_BAD_FIXED_HEADER_DECRYPT                   102
# define NTTRU_R_BAD_MODE_VALUE                             103
# define NTTRU_R_BLOCK_TYPE_IS_NOT_01                       106
# define NTTRU_R_BLOCK_TYPE_IS_NOT_02                       107
# define NTTRU_R_DATA_TOO_LARGE                             109
# define NTTRU_R_DATA_TOO_LARGE_FOR_KEY_SIZE                110
# define NTTRU_R_DATA_TOO_SMALL                             111
# define NTTRU_R_DATA_TOO_SMALL_FOR_KEY_SIZE                122
# define NTTRU_R_FIRST_OCTET_INVALID                        133
# define NTTRU_R_INVALID_HEADER                             137
# define NTTRU_R_INVALID_LABEL                              160
# define NTTRU_R_INVALID_TRAILER                            139
# define NTTRU_R_KEY_SIZE_TOO_SMALL                         120
# define NTTRU_R_LAST_OCTET_INVALID                         134
# define NTTRU_R_NULL_BEFORE_BLOCK_MISSING                  113
# define NTTRU_R_SLEN_CHECK_FAILED                          136
# define NTTRU_R_SLEN_RECOVERY_FAILED                       135
# define NTTRU_R_UNKNOWN_ALGORITHM_TYPE                     117
# define NTTRU_R_UNSUPPORTED_ENCRYPTION_TYPE                162
# define NTTRU_R_UNSUPPORTED_LABEL_SOURCE                   163
# define NTTRU_R_VALUE_MISSING                              147
# define NTTRU_R_MISSING_PRIVATE_KEY                        148
# define NTTRU_R_MISSING_PUBLIC_KEY                         149

#endif