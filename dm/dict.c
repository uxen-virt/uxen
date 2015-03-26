/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <stdint.h>
#include <stdio.h>

#include "dict.h"
#include "yajl.h"

static int dict_write(dict, yajl_gen);

static int
dict_write_array(dict d, yajl_gen yg)
{
    dict val;
    int i;
    int ret;

    if (!YAJL_IS_ARRAY(d)) {
        warnx("%s: not an array", __FUNCTION__);
        return -1;
    }

    yajl_gen_array_open(yg);

    ARRAY_FOREACH(val, d, i) {
        ret = dict_write(val, yg);
        if (ret) {
            warnx("%s: dict_write failed", __FUNCTION__);
            return -1;
        }
    }

    yajl_gen_array_close(yg);

    return 0;
}

static int
dict_write_map(dict d, yajl_gen yg)
{
    const char *key;
    dict val;
    int i;
    int ret;

    if (!YAJL_IS_OBJECT(d)) {
        warnx("%s: not a map", __FUNCTION__);
        return -1;
    }

    yajl_gen_map_open(yg);

    DICT_FOREACH(key, val, d, i) {
        yajl_gen_cstring(yg, key);
        ret = dict_write(val, yg);
        if (ret) {
            warnx("%s: dict_write failed", __FUNCTION__);
            return -1;
        }
    }

    yajl_gen_map_close(yg);

    return 0;
}

static int
dict_write(dict v, yajl_gen yg)
{
    int ret = -1;

    if (YAJL_IS_STRING(v))
        ret = yajl_gen_cstring(yg, YAJL_GET_STRING(v));
    else if (YAJL_IS_NUMBER(v)) {
        const char *s = YAJL_GET_NUMBER(v);
        ret = yajl_gen_number(yg, s, strlen(s));
    } else if (YAJL_IS_OBJECT(v))
        return dict_write_map(v, yg);
    else if (YAJL_IS_ARRAY(v))
        return dict_write_array(v, yg);
    else if (YAJL_IS_TRUE(v))
        ret = yajl_gen_bool(yg, 1);
    else if (YAJL_IS_FALSE(v))
        ret = yajl_gen_bool(yg, 0);
    else if (YAJL_IS_NULL(v))
        ret = yajl_gen_null(yg);
    else
        warnx("%s: unexpected type", __FUNCTION__);

    return ret ? -1 : 0;
}

int
dict_write_buf(dict d, char **buf, size_t *len)
{
    yajl_gen yg;
    const unsigned char *ybuf;
    int ret;

    *buf = NULL;
    *len = 0;

    yg = yajl_gen_alloc(NULL);
    if (!yg) {
        warnx("%s: yajl_gen_alloc", __FUNCTION__);
        return -1;
    }

    ret = !yajl_gen_config(yg, yajl_gen_beautify, 0);
    if (ret) {
        warnx("%s: yajl_gen_config", __FUNCTION__);
        ret = -1;
        goto out;
    }

    ret = dict_write_map(d, yg);
    if (ret) {
        warnx("%s: dict_write_map", __FUNCTION__);
        goto out;
    }

    ret = yajl_gen_get_buf(yg, &ybuf, len);
    if (ret) {
        warnx("%s: yajl_gen_get_buf: %d", __FUNCTION__, ret);
        ret = -1;
        goto out;
    }

    *buf = malloc(*len);
    if (*buf == NULL) {
        warn("%s: malloc", __FUNCTION__);
        ret = -1;
    }

    memcpy(*buf, ybuf, *len);

  out:
    yajl_gen_free(yg);

    return ret;
}

static int dict_copy(dict, dict *);

static int
dict_copy_array(dict d, dict *c)
{
    dict val;
    int i;
    int ret;

    if (!YAJL_IS_ARRAY(d)) {
        warnx("%s: not an array", __FUNCTION__);
        *c = NULL;
        return -1;
    }

    *c = yajl_tree_new_array();
    if (!*c) {
        warnx("%s: yajl_tree_new_array", __FUNCTION__);
        return -1;
    }

    ARRAY_FOREACH(val, d, i) {
        dict cval = NULL;
        ret = dict_copy(val, &cval);
        if (ret) {
            warnx("%s: dict_copy failed", __FUNCTION__);
            dict_free(*c);
            c = NULL;
            return -1;
        }
        _dict_array_put(*c, cval);
    }

    return 0;
}

static int
dict_copy_map(dict d, dict *c)
{
    const char *key;
    dict val;
    int alloc = 0;
    int i;
    int ret;

    if (!YAJL_IS_OBJECT(d)) {
        warnx("%s: not a map", __FUNCTION__);
        *c = NULL;
        return -1;
    }

    if (!*c) {
        alloc = 1;
        *c = dict_new();
        if (!*c) {
            warnx("%s: dict_new", __FUNCTION__);
            return -1;
        }
    }

    if (!YAJL_GET_OBJECT(d)->keys)
        return 0;

    DICT_FOREACH(key, val, d, i) {
        dict cval = NULL;
        ret = dict_copy(val, &cval);
        if (ret) {
            warnx("%s: dict_copy failed", __FUNCTION__);
            if (alloc)
                dict_free(*c);
            c = NULL;
            return -1;
        }
        _dict_put(*c, key, cval);
    }

    return 0;
}

static int
dict_copy(dict v, dict *c)
{

    if (YAJL_IS_STRING(v)) {
        const char *s;
        s = YAJL_GET_STRING(v);
        *c = yajl_tree_new_string((const unsigned char *)s, strlen(s));
    } else if (YAJL_IS_NUMBER(v)) {
        const char *s;
        s = YAJL_GET_NUMBER(v);
        *c = yajl_tree_new_number((const unsigned char *)s, strlen(s));
    } else if (YAJL_IS_OBJECT(v))
        dict_copy_map(v, c);
    else if (YAJL_IS_ARRAY(v))
        dict_copy_array(v, c);
    else if (YAJL_IS_TRUE(v))
        *c = yajl_tree_new_boolean(1);
    else if (YAJL_IS_FALSE(v))
        *c = yajl_tree_new_boolean(0);
    else if (YAJL_IS_NULL(v))
        *c = yajl_tree_new_null();
    else
        warnx("%s: unexpected type", __FUNCTION__);

    return *c ? 0 : -1;
}

int
dict_merge(dict d, dict c)
{

    if (!YAJL_IS_OBJECT(d)) {
        warnx("%s: source not a map", __FUNCTION__);
        return -1;
    }

    if (!YAJL_IS_OBJECT(c)) {
        warnx("%s: dest not a map", __FUNCTION__);
        return -1;
    }

    return dict_copy_map(d, &c);
}
