/*
 * Copyright 2001-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "eng_int.h"

static ENGINE_TABLE *dilithium_table = NULL;
static const int dummy_nid = 1;

void ENGINE_unregister_Dilithium(ENGINE *e)
{
    engine_table_unregister(&dilithium_table, e);
}

static void engine_unregister_all_Dilithium(void)
{
    engine_table_cleanup(&dilithium_table);
}

int ENGINE_register_Dilithium(ENGINE *e)
{
    if (e->dilithium_meth)
        return engine_table_register(&dilithium_table,
                                     engine_unregister_all_Dilithium, e, &dummy_nid,
                                     1, 0);
    return 1;
}

void ENGINE_register_all_Dilithium(void)
{
    ENGINE *e;

    for (e = ENGINE_get_first(); e; e = ENGINE_get_next(e))
        ENGINE_register_Dilithium(e);
}

int ENGINE_set_default_Dilithium(ENGINE *e)
{
    if (e->dilithium_meth)
        return engine_table_register(&dilithium_table,
                                     engine_unregister_all_Dilithium, e, &dummy_nid,
                                     1, 1);
    return 1;
}

/*
 * Exposed API function to get a functional reference from the implementation
 * table (ie. try to get a functional reference from the tabled structural
 * references).
 */

ENGINE *ENGINE_get_default_Dilithium(void)
{
    return engine_table_select(&dilithium_table, dummy_nid);
}

/* Obtains an Dilithium implementation from an ENGINE functional reference */
const DILITHIUM_METHOD *ENGINE_get_Dilithium(const ENGINE *e)
{
    return e->dilithium_meth;
}

/* Sets an Dilithium implementation in an ENGINE structure */
int ENGINE_set_Dilithium(ENGINE *e, const DILITHIUM_METHOD *dilithium_meth)
{
    e->dilithium_meth = dilithium_meth;

    return 1;
}
