/*
 * Copyright 2001-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "eng_int.h"

static ENGINE_TABLE *kyber_table = NULL;
static const int dummy_nid = 1;

void ENGINE_unregister_Kyber(ENGINE *e)
{
    engine_table_unregister(&kyber_table, e);
}

static void engine_unregister_all_Kyber(void)
{
    engine_table_cleanup(&kyber_table);
}

int ENGINE_register_Kyber(ENGINE *e)
{
    if (e->kyber_meth)
        return engine_table_register(&kyber_table,
                                     engine_unregister_all_Kyber, e, &dummy_nid,
                                     1, 0);
    return 1;
}

void ENGINE_register_all_Kyber(void)
{
    ENGINE *e;

    for (e = ENGINE_get_first(); e; e = ENGINE_get_next(e))
        ENGINE_register_Kyber(e);
}

int ENGINE_set_default_Kyber(ENGINE *e)
{
    if (e->kyber_meth)
        return engine_table_register(&kyber_table,
                                     engine_unregister_all_Kyber, e, &dummy_nid,
                                     1, 1);
    return 1;
}

/*
 * Exposed API function to get a functional reference from the implementation
 * table (ie. try to get a functional reference from the tabled structural
 * references).
 */
ENGINE *ENGINE_get_default_Kyber(void)
{
    return engine_table_select(&kyber_table, dummy_nid);
}

/* Obtains an Kyber implementation from an ENGINE functional reference */
const KYBER_METHOD *ENGINE_get_Kyber(const ENGINE *e)
{
    return e->kyber_meth;
}

/* Sets an Kyber implementation in an ENGINE structure */
int ENGINE_set_Kyber(ENGINE *e, const KYBER_METHOD *kyber_meth)
{
    e->kyber_meth = kyber_meth;
    return 1;
}
