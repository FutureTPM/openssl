/*
 * Copyright 2001-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "eng_int.h"

static ENGINE_TABLE *nttru_table = NULL;
static const int dummy_nid = 1;

void ENGINE_unregister_NTTRU(ENGINE *e)
{
    engine_table_unregister(&nttru_table, e);
}

static void engine_unregister_all_NTTRU(void)
{
    engine_table_cleanup(&nttru_table);
}

int ENGINE_register_NTTRU(ENGINE *e)
{
    if (e->nttru_meth)
        return engine_table_register(&nttru_table,
                                     engine_unregister_all_NTTRU, e, &dummy_nid,
                                     1, 0);
    return 1;
}

void ENGINE_register_all_NTTRU(void)
{
    ENGINE *e;

    for (e = ENGINE_get_first(); e; e = ENGINE_get_next(e))
        ENGINE_register_NTTRU(e);
}

int ENGINE_set_default_NTTRU(ENGINE *e)
{
    if (e->nttru_meth)
        return engine_table_register(&nttru_table,
                                     engine_unregister_all_NTTRU, e, &dummy_nid,
                                     1, 1);
    return 1;
}

/*
 * Exposed API function to get a functional reference from the implementation
 * table (ie. try to get a functional reference from the tabled structural
 * references).
 */
ENGINE *ENGINE_get_default_NTTRU(void)
{
    return engine_table_select(&nttru_table, dummy_nid);
}

/* Obtains an NTTRU implementation from an ENGINE functional reference */
const NTTRU_METHOD *ENGINE_get_NTTRU(const ENGINE *e)
{
    return e->nttru_meth;
}

/* Sets an NTTRU implementation in an ENGINE structure */
int ENGINE_set_NTTRU(ENGINE *e, const NTTRU_METHOD *nttru_meth)
{
    e->nttru_meth = nttru_meth;
    return 1;
}
