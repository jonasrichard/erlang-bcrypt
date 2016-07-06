/*
 * Copyright (c) 2011-2012 Hunter Morris <hunter.morris@smarkets.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "erl_nif.h"
#include "erl_blf.h"
#include "bcrypt_nif.h"

static ERL_NIF_TERM inner_hashpw(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM encode(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM
bcrypt_encode_salt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary csalt, bin;
    unsigned long log_rounds;

    if (!enif_inspect_binary(env, argv[0], &csalt) || 16 != csalt.size) {
        return enif_make_badarg(env);
    }

    if (!enif_get_ulong(env, argv[1], &log_rounds)) {
        enif_release_binary(&csalt);
        return enif_make_badarg(env);
    }

    if (!enif_alloc_binary(64, &bin)) {
        enif_release_binary(&csalt);
        return enif_make_badarg(env);
    }

    encode_salt((char *)bin.data, (u_int8_t*)csalt.data, csalt.size, log_rounds);
    enif_release_binary(&csalt);

    return enif_make_tuple2(
            env,
            enif_make_atom(env, "ok"),
            enif_make_string(env, (char *)bin.data, ERL_NIF_LATIN1));
}

static ERL_NIF_TERM
bcrypt_hashpw(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary        pass, salt;
    ErlNifResourceType  *res_type;
    ERL_NIF_TERM        result;

    if (!enif_inspect_iolist_as_binary(
                env,
                enif_make_copy(env, argv[0]),
                &pass)) {
        enif_release_binary(&pass);
        return enif_make_badarg(env);
    }

    if (!enif_inspect_iolist_as_binary(
                env,
                enif_make_copy(env, argv[1]),
                &salt)) {
        enif_release_binary(&pass);
        enif_release_binary(&salt);
        return enif_make_badarg(env);
    }

    /* Allocate bcrypt context as a resource */
    res_type = (ErlNifResourceType *)enif_priv_data(env);

    bcrypt_param    *bp;
    bp = enif_alloc_resource(res_type, sizeof(bcrypt_param));

    /* Copy password to bcrypt state */
    size_t password_sz = 1024;
    if (password_sz > pass.size)
        password_sz = pass.size;

    (void) memcpy(bp->key, pass.data, password_sz);

    /* Copy salt to bcrypt state */
    size_t salt_sz = 1024;
    if (salt_sz > salt.size)
        salt_sz = salt.size;

    (void) memcpy(bp->salt, salt.data, salt_sz);

    enif_release_binary(&pass);
    enif_release_binary(&salt);

    /* Init bcrypt state */
    if (bcrypt_init(bp)) {
        enif_release_resource(bp);

        return -1;
    }

    /* Schedule inner_hashpw nif */
    ERL_NIF_TERM newargv[1];
    newargv[0] = enif_make_resource(env, bp);

    enif_release_resource(bp);

    return enif_schedule_nif(env, "inner_hashpw", 0, inner_hashpw, 1, newargv);
}

static ERL_NIF_TERM
inner_hashpw(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifResourceType  *res_type = (ErlNifResourceType *)enif_priv_data(env);
    bcrypt_param        *bp;

    /* Process the parameters */
    if (argc != 1 || !enif_get_resource(env, argv[0], res_type, &bp)) {
        return enif_make_badarg(env);
    }

    bcrypt_compute(bp);

    if (bp->steps < bp->rounds) {
        return enif_schedule_nif(env, "inner_hashpw", 0, inner_hashpw, 1, argv);
    } else {
        return enif_schedule_nif(env, "encode", 0, encode, 1, argv);
    }
}

static ERL_NIF_TERM
encode(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifResourceType  *res_type = (ErlNifResourceType *)enif_priv_data(env);
    bcrypt_param        *bp;
    char                encrypted[1024];

    /* Process the parameters */
    if (argc != 1 || !enif_get_resource(env, argv[0], res_type, &bp)) {
        return enif_make_badarg(env);
    }

    if (bcrypt_encode(bp, encrypted)) {
        return enif_make_tuple2(
            env,
            enif_make_atom(env, "error"),
            enif_make_string(env, "bcrypt failed", ERL_NIF_LATIN1));
    }

    return enif_make_tuple2(
        env,
        enif_make_atom(env, "ok"),
        enif_make_string(env, encrypted, ERL_NIF_LATIN1));
}

/* We need to create resource type for bcrypt state in order that
 * later we can allocate, release and use that opaque pointer */
static int
nifload(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{
    *priv_data = enif_open_resource_type(env,
                                         NULL,
                                         "bcrypt_state",
                                         NULL,
                                         ERL_NIF_RT_CREATE|ERL_NIF_RT_TAKEOVER,
                                         NULL);
    return 0;
}

static int
nifupgrade(ErlNifEnv* env, void** priv_data, void** old_priv_data, ERL_NIF_TERM load_info)
{
    *priv_data = enif_open_resource_type(env,
                                         NULL,
                                         "bcrypt_state",
                                         NULL,
                                         ERL_NIF_RT_TAKEOVER,
                                         NULL);
    return 0;
}

static ErlNifFunc bcrypt_nif_funcs[] =
{
    {"encode_salt", 2, bcrypt_encode_salt},
    {"hashpw", 2, bcrypt_hashpw}
};

ERL_NIF_INIT(bcrypt_nif, bcrypt_nif_funcs, nifload, NULL, nifupgrade, NULL)
