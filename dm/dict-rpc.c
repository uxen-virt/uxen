/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#include "dict.h"
#include "dict-rpc.h"
#include "queue.h"

static critical_section dict_rpc_lock;
static int rpc_cb_exit = 0;

static int
set_status(dict d, const char *status, const char *command,
           const char *id)
{
    int ret;

    if (status) {
        ret = dict_put_string(d, "status", status);
        if (ret) {
            warnx("%s: dict_put_string(status,%s)", __FUNCTION__, status);
            return -1;
        }
    }

    if (command) {
        ret = dict_put_string(d, "command", command);
        if (ret) {
            warnx("%s: dict_put_string(command,%s)", __FUNCTION__, command);
            return -1;
        }
    }

    if (id) {
        ret = dict_put_string(d, "id", id);
        if (ret) {
            warnx("%s: dict_put_string(id,%s)", __FUNCTION__, id);
            return -1;
        }
    }

    return 0;
}

static int
write_msg(dict d, char **buf, size_t *len,
          const char *status, const char *command, const char *id)
{
    int ret;

    ret = set_status(d, status, command, id);
    if (ret) {
        warnx("%s: set_status(%s)", __FUNCTION__, status);
        goto out;
    }

    ret = dict_write_buf(d, buf, len);
    if (ret) {
        warnx("%s: dict_write_buf", __FUNCTION__);
        goto out;
    }

  out:
    return ret;
}

int
dict_rpc_vmsg(dict_rpc_send_fn send_fn, void *send_opaque,
              const char *status, const char *command, const char *id,
              const char *args, va_list ap)
{
    char *buf = NULL;
    size_t len;
    const char *key, *val;
    uint64_t val_n;
    int64_t val_i;
    dict val_d;
    va_list val_ap;
    dict d;
    int ret;

    d = dict_new();
    if (!d) {
        warnx("%s: dict_new", __FUNCTION__);
        return -1;
    }

    while (args && *args) {
        switch (*args) {
        case 'a':
            va_copy(val_ap, va_arg(ap, void *));
            while ((key = va_arg(val_ap, const char *))) {
                val = va_arg(val_ap, const char *);
                if (!val)
                    break;

                ret = dict_put_string(d, key, val);
                if (ret) {
                    warnx("%s: dict_put_string(%s,%s)", __FUNCTION__, key, val);
                    goto out;
                }
            }
            va_end(val_ap);
            break;

        case 'd':
            val_d = va_arg(ap, dict);
            if (!val_d)
                break;
            ret = dict_merge(val_d, d);
            if (ret) {
                warnx("%s: dict_merge()", __FUNCTION__);
                goto out;
            }
            break;

        case 'f':
            key = va_arg(ap, const char *);
            if (!key) {
                warnx("%s: args 'f': key missing", __FUNCTION__);
                ret = -1;
                goto out;
            }
            val = va_arg(ap, const char *);
            if (!val) {
                warnx("%s: args 'f': fmt missing", __FUNCTION__);
                ret = -1;
                goto out;
            }
            va_copy(val_ap, va_arg(ap, void *));
            ret = dict_put_vstringf(d, key, val, val_ap);
            va_end(val_ap);
            if (ret) {
                warnx("%s: args 'f': dict_put_vstringf(%s,%s,...)",
                      __FUNCTION__, key, val);
                goto out;
            }
            break;

        case 'i':
            key = va_arg(ap, const char *);
            if (!key) {
                warnx("%s: args 'i': key missing", __FUNCTION__);
                ret = -1;
                goto out;
            }
            val_i = va_arg(ap, int64_t);
            /* can't check for invalid value */

            ret = dict_put_integer(d, key, val_i);
            if (ret) {
                warnx("%s: args 's': dict_put_string(%s,%"PRId64")",
                      __FUNCTION__, key, val_i);
                goto out;
            }
            break;

        case 's':
            key = va_arg(ap, const char *);
            if (!key) {
                warnx("%s: args 's': key missing", __FUNCTION__);
                ret = -1;
                goto out;
            }
            val = va_arg(ap, const char *);
            if (!val) {
                warnx("%s: args 's': val missing", __FUNCTION__);
                ret = -1;
                goto out;
            }

            ret = dict_put_string(d, key, val);
            if (ret) {
                warnx("%s: args 's': dict_put_string(%s,%s)", __FUNCTION__,
                      key, val);
                goto out;
            }
            break;

        case 'x':
            key = va_arg(ap, const char *);
            if (!key) {
                warnx("%s: args 'x': key missing", __FUNCTION__);
                ret = -1;
                goto out;
            }
            val_n = va_arg(ap, uint64_t);
            /* can't check for invalid value */

            ret = dict_put_stringf(d, key, "0x%"PRIx64, val_n);
            if (ret) {
                warnx("%s: args 'x': dict_put_string(%s,0x%"PRIx64")",
                      __FUNCTION__, key, val_n);
                goto out;
            }
            break;
        }

        args++;
    }

    ret = write_msg(d, &buf, &len, status, command, id);
    if (ret) {
        warnx("%s: write_msg", __FUNCTION__);
        goto out;
    }

    ret = send_fn(send_opaque, buf, len);
    buf = NULL;                 /* buf freed in send_fn */

  out:
    if (buf)
        free(buf);
    dict_free(d);
    return ret;
}

int
dict_rpc_msg(dict_rpc_send_fn send_fn, void *send_opaque,
             const char *status, const char *command, const char *id,
             const char *args, ...)
{
    va_list ap;
    int ret;

    va_start(ap, args);
    ret = dict_rpc_vmsg(send_fn, send_opaque, status, command, id, args, ap);
    va_end(ap);

    if (ret) {
        warnx("%s: dict_rpc_vmsg", __FUNCTION__);
        goto out;
    }

  out:
    return ret;
}

int
dict_rpc_verror(dict_rpc_send_fn send_fn, void *send_opaque,
                const char *command, const char *id,
                int _errno, const char *fmt, va_list ap)
{
    int ret;

    ret = dict_rpc_msg(send_fn, send_opaque, "error", command, id,
                       "fi", "error", fmt, ap, "errno", (int64_t)_errno);
    if (ret) {
        warnx("%s: dict_rpc_msg", __FUNCTION__);
        goto out;
    }

  out:
    return ret;
}

int
dict_rpc_error(dict_rpc_send_fn send_fn, void *send_opaque,
               const char *command, const char *id,
               int _errno, const char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = dict_rpc_verror(send_fn, send_opaque, command, id,
                          _errno, fmt, ap);
    va_end(ap);

    if (ret) {
        warnx("%s: dict_rpc_verror", __FUNCTION__);
        goto out;
    }

  out:
    return ret;
}

int
dict_rpc_vok(dict_rpc_send_fn send_fn, void *send_opaque,
             const char *command, const char *id,
             const char *fmt, va_list ap)
{
    int ret;

    if (!fmt)
        ret = dict_rpc_msg(send_fn, send_opaque, "ok", command, id, NULL);
    else
        ret = dict_rpc_msg(send_fn, send_opaque, "ok", command, id,
                           "f", "info", fmt, ap);
    if (ret) {
        warnx("%s: dict_rpc_msg", __FUNCTION__);
        goto out;
    }

  out:
    return ret;
}

int
dict_rpc_ok(dict_rpc_send_fn send_fn, void *send_opaque,
            const char *command, const char *id,
            const char *fmt, ...)
{
    va_list ap;
    int ret;

    if (fmt)
        va_start(ap, fmt);

    ret = dict_rpc_vok(send_fn, send_opaque, command, id, fmt, fmt ? ap : NULL);

    if (fmt)
        va_end(ap);

    if (ret) {
        warnx("%s: dict_rpc_vok", __FUNCTION__);
        goto out;
    }

  out:
    return ret;
}

int
dict_rpc_status(dict_rpc_send_fn send_fn, void *send_opaque,
                const char *args, ...)
{
    va_list ap;
    int ret;

    va_start(ap, args);
    ret = dict_rpc_vmsg(send_fn, send_opaque, "status", NULL, NULL, args, ap);
    va_end(ap);

    if (ret) {
        warnx("%s: dict_rpc_vmsg", __FUNCTION__);
        goto out;
    }

  out:
    return ret;
}

struct request_id {
    LIST_ENTRY(request_id) entry;
    char id[24];          /* sizeof(MAX_INT64) + NUL = 21 */
    void (*callback)(void *, dict);
    void *callback_opaque;
};

static LIST_HEAD(, request_id) request_ids =
    LIST_HEAD_INITIALIZER(&request_ids);

const char *
gen_request_id(void (*callback)(void *, dict), void *callback_opaque)
{
    static uint64_t next_id = 0;
    struct request_id *ri;
    const char *id = NULL;
    int ret;

    ri = calloc(1, sizeof(struct request_id));
    if (!ri) {
        warn("%s: calloc", __FUNCTION__);
        return NULL;
    }

    critical_section_enter(&dict_rpc_lock);
    if (rpc_cb_exit) {
        warn("%s: no more rpc cb accepted", __FUNCTION__);
        goto out;
    }

    ret = snprintf(&ri->id[0], sizeof(ri->id), "%"PRId64, next_id);
    if (ret < 0) {
        warn("%s: snprintf", __FUNCTION__);
        goto out;
    }

    ri->callback = callback;
    ri->callback_opaque = callback_opaque;

    LIST_INSERT_HEAD(&request_ids, ri, entry);

    next_id++;

    id = &ri->id[0];
  out:
    if (!id && ri)
        free(ri);
    critical_section_leave(&dict_rpc_lock);
    return id;
}

struct request_id *
find_request(const char *id)
{
    struct request_id *ri;

    critical_section_enter(&dict_rpc_lock);
    LIST_FOREACH(ri, &request_ids, entry)
        if (!strcmp(ri->id, id))
            break;

    if (!ri) {
        critical_section_leave(&dict_rpc_lock);
        return NULL;
    }

    LIST_REMOVE(ri, entry);
    critical_section_leave(&dict_rpc_lock);

    return ri;
}

int
dict_rpc_request(dict_rpc_send_fn send_fn, void *send_opaque,
                 const char *command, void (*callback)(void *, dict),
                 void *callback_opaque, const char *args, ...)
{
    va_list ap;
    const char *id;
    int ret;

    id = gen_request_id(callback, callback_opaque);
    if (!id) {
      warnx("%s: gen_request_id", __FUNCTION__);
      return -1;
    }

    va_start(ap, args);
    ret = dict_rpc_vmsg(send_fn, send_opaque, NULL, command, id, args, ap);
    va_end(ap);

    if (ret) {
        warnx("%s: dict_rpc_request", __FUNCTION__);
        goto out;
    }

  out:
    return ret;
}

static int
comp_command(const void *c1, const void *c2)
{
    struct dict_rpc_command *co1 = (struct dict_rpc_command *)c1;
    struct dict_rpc_command *co2 = (struct dict_rpc_command *)c2;
    return strcmp(co1->command, co2->command);
}

static int
validate_arguments(struct dict_rpc_command *c, dict obj,
                   char *errbuf, size_t errbuf_size)
{
    struct dict_rpc_arg_desc *ad;

    for (ad = c->args; ad && ad->name && ad->name[0]; ad++) {
        dict v = dict_get(obj, ad->name);
        if (!v) {
            switch (ad->type) {
            case DICT_RPC_ARG_TYPE_STRING:
                if (ad->defval.string)
                    dict_put_string(obj, ad->name, ad->defval.string);
                break;
            case DICT_RPC_ARG_TYPE_INTEGER:
                if (ad->defval.integer)
                    dict_put_number(obj, ad->name, ad->defval.integer);
                break;
            case DICT_RPC_ARG_TYPE_ARRAY:
                break;
            case DICT_RPC_ARG_TYPE_BOOLEAN:
                if (ad->defval.boolean)
                    dict_put_string(obj, ad->name, ad->defval.boolean);
                break;
            default:
                break;
            }
            v = dict_get(obj, ad->name);
            if (!v && ad->optional) {
                snprintf(errbuf, errbuf_size, "argument \"%s\" is required",
                         ad->name);
                return EINVAL;
            }
        }
        switch (ad->type) {
        case DICT_RPC_ARG_TYPE_STRING:
            if (dict_typeof(v) != DICT_TYPE_STRING)
                goto mismatch;
            break;
        case DICT_RPC_ARG_TYPE_INTEGER:
            if (dict_typeof(v) != DICT_TYPE_NUMBER)
                goto mismatch;
            break;
        case DICT_RPC_ARG_TYPE_ARRAY:
            if (dict_typeof(v) != DICT_TYPE_ARRAY)
                goto mismatch;
            break;
        case DICT_RPC_ARG_TYPE_BOOLEAN:
            if (dict_typeof(v) == DICT_TYPE_STRING) {
                int b;
                b = dict_string_as_bool(YAJL_GET_STRING(v), -1);
                if (b == -1)
                    goto mismatch;
                dict_put_boolean(obj, ad->name, b);
                v = dict_get(obj, ad->name);
            }
            if (dict_typeof(v) != DICT_TYPE_TRUE &&
                dict_typeof(v) != DICT_TYPE_FALSE)
                goto mismatch;
            break;
        default:
        mismatch:
            snprintf(errbuf, errbuf_size, "argument \"%s\" is wrong type",
                     ad->name);
            return EINVAL;
        }
    }

    return 0;
}

int
dict_rpc_process_input(dict_rpc_send_fn send_fn, void *send_opaque, dict d,
                       struct dict_rpc_command *commands, size_t n_commands,
                       void *fn_opaque)
{
    char errbuf[1024];
    struct dict_rpc_command *c, c_key;
    const char *command = NULL, *id = NULL, *status;
    int ret;

    /* fetch (optional) id */
    id = dict_get_string(d, "id");

    status = dict_get_string(d, "status");
    if (status) {
        struct request_id *ri;

        if (!id) {
            warnx("%s: unexpected status '%s' without id", __FUNCTION__,
                  status);
            ret = -1;
            goto out;
        }

        ri = find_request(id);
        if (!ri) {
            warnx("%s: can't find request for status '%s' for id '%s'",
                  __FUNCTION__, status, id);
            ret = -1;
            goto out;
        }

        if (ri->callback)
            ri->callback(ri->callback_opaque, d);
        else
            dict_free(d);

        free(ri);

        return 0;
    }

    command = dict_get_string(d, "command");
    if (!command) {
        dict_rpc_error(send_fn, send_opaque, command, id, EINVAL,
                       "%s", "malformed input: \"command\" missing");
        ret = -1;
        goto out;
    }

    c_key.command = command;
    c = bsearch(&c_key, commands, n_commands, sizeof(*c), comp_command);
    if (!c) {
        dict_rpc_error(send_fn, send_opaque, command, id, EINVAL,
                       "malformed input: unknown command \"%s\"",
                       c_key.command);
        ret = -1;
        goto out;
    }

    ret = validate_arguments(c, d, errbuf, sizeof(errbuf));
    if (ret) {
        dict_rpc_error(send_fn, send_opaque, command, id, ret,
                       "malformed input: command \"%s\" "
                       "argument validation failed: %s",
                       c_key.command, errbuf);
        goto out;
    }

    ret = c->fn(fn_opaque, id, c->command, d, c->opaque);
    if (ret) {
        dict_rpc_error(send_fn, send_opaque, command, id, ret,
                       "processing error: command \"%s\" failed",
                       command);
        goto out;
    }

  out:
    dict_free(d);
    return ret;
}

int
dict_rpc_process_input_buffer(dict_rpc_send_fn send_fn, void *send_opaque,
                              const char *input,
                              struct dict_rpc_command *commands,
                              size_t n_commands, void *fn_opaque)
{
    dict d;
    char errbuf[1024];

    d = dict_new_from_buffer(input, errbuf, sizeof(errbuf));
    if (d == NULL) {
        dict_rpc_error(send_fn, send_opaque, NULL, NULL, EINVAL, "%s", errbuf);
        return -1;
    }

    return dict_rpc_process_input(send_fn, send_opaque, d,
                                  commands, n_commands, fn_opaque);
}

void dict_rpc_init(void)
{
    static uint32_t init = 0;

    if (cmpxchg(&init, 0, 1) != 0)
        return;

    critical_section_init(&dict_rpc_lock);
}

void dict_rpc_cb_exit(void)
{
    struct request_id *ri;

    critical_section_enter(&dict_rpc_lock);
    if (rpc_cb_exit)
        goto out;
    rpc_cb_exit = 1;
    critical_section_leave(&dict_rpc_lock);

    debug_printf("%s: no more rpc commands\n", __FUNCTION__);


    for (;;) {
        void (*callback)(void *, dict);
        void *callback_opaque;

        critical_section_enter(&dict_rpc_lock);
        if (LIST_EMPTY(&request_ids))
            break;
        ri = LIST_FIRST(&request_ids);
        callback = ri->callback;
        callback_opaque = ri->callback_opaque;
        ri->callback = NULL;
        ri->callback_opaque = NULL;
        LIST_REMOVE(ri, entry);
        critical_section_leave(&dict_rpc_lock);

        if (callback) {
            dict d;
            d = dict_new();
            dict_put_boolean(d, "dict_rpc_exit", true);
            dict_put_string(d, "status", "error");
            callback(callback_opaque, d);
        }
    }

out:
    critical_section_leave(&dict_rpc_lock);
}
