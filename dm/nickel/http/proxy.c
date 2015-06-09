/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/rbtree.h>
#include <dm/timer.h>
#include <buff.h>
#include <log.h>
#include <nickel.h>
#include "proxy.h"

static LIST_HEAD(, proxy_t) proxy_list = LIST_HEAD_INITIALIZER(&proxy_list);

struct proxy_t * proxy_find(const char *name, uint16_t port)
{
    struct proxy_t *proxy = NULL;

    LIST_FOREACH (proxy, &proxy_list, entry) {
       if (!strcasecmp(name, proxy->name) && port == proxy->port)
           break;
    }

    return proxy;
}

struct proxy_t *
proxy_save(const char *name, uint16_t port, int ct, const char *realm)
{
    struct proxy_t *proxy = NULL;

    proxy = proxy_find(name, port);
    if (!proxy) {
        proxy = calloc(1, sizeof(*proxy));
        if (!proxy) {
            warnx("%s: malloc", __FUNCTION__);
            goto out;
        }
        proxy->name = strdup(name);
        proxy->port = port;
        RLIST_INIT(&proxy->w_list, w_list);
        LIST_INSERT_HEAD(&proxy_list, proxy, entry);
    }

    proxy->ct = ct;
    if (!proxy->realm && realm && *realm)
        proxy->realm = ni_priv_strdup(realm);

out:
    return proxy;
}

void proxy_update(struct proxy_t *proxy, int ct, const char *realm)
{
    proxy->ct = ct;
    if (!proxy->realm && realm)
        proxy->realm = ni_priv_strdup(realm);
}

void proxy_reset(struct proxy_t *proxy)
{
    if (!proxy)
        return;

    free(proxy->a);
    proxy->a = NULL;
    free(proxy->canon_name);
    proxy->canon_name = NULL;
    proxy->resolved = 0;
    proxy->ct = 0;
    if (proxy->realm) {
        ni_priv_free(proxy->realm);
        proxy->realm = NULL;
    }
    proxy_cache_reset();
}

int proxy_number_waiting(struct proxy_t *proxy)
{
    int ret = 0;
    struct clt_ctx *cx;

    if (RLIST_EMPTY(&proxy->w_list, w_list))
        goto out;

    RLIST_FOREACH(cx, &proxy->w_list, w_list)
        ret++;
out:
    return ret;
}

/* cache */
#define MAX_NUMBER_CACHE_ENTRIES    128
#define CACHE_PURGE_TIMEOUT_MS  (30*1000)
struct proxy_cache_t {
    LIST_ENTRY(proxy_cache_t) entry;
    char *url;
    struct proxy_t *proxy;
    struct rb_node cache_rbnode;
};
static LIST_HEAD(, proxy_cache_t) cache_list = LIST_HEAD_INITIALIZER(&cache_list);
struct proxy_t proxy_direct;
static rb_tree_t cache_rbtree;
static int number_cache_entries = 0;
Timer *cache_timer = NULL;

static int cache_compare_key(void *ctx, const void *b, const void *key)
{
    const struct proxy_cache_t * const pc = b;
    const char * const k = key;

    return strcmp(pc->url, k);
}

static int cache_compare_nodes(void *ctx, const void *parent, const void *node)
{
    const struct proxy_cache_t * const np = node;

    return cache_compare_key(ctx, parent, np->url);
}

static const rb_tree_ops_t cache_rbtree_ops = {
    .rbto_compare_nodes = cache_compare_nodes,
    .rbto_compare_key = cache_compare_key,
    .rbto_node_offset = offsetof(struct proxy_cache_t, cache_rbnode),
    .rbto_context = NULL
};

static void cache_timer_cb(void *unused)
{
    proxy_cache_reset();
}

static void cache_init(struct nickel *ni)
{
    proxy_cache_reset();
    if (!cache_timer)
        cache_timer = ni_new_vm_timer(ni, CACHE_PURGE_TIMEOUT_MS, cache_timer_cb, NULL);
}

void proxy_cache_add(struct nickel *ni, const char *schema, const char *domain, int port, struct proxy_t *proxy)
{
    struct proxy_cache_t *pc = NULL;
    char *url;

    if (!cache_timer || number_cache_entries >= MAX_NUMBER_CACHE_ENTRIES)
        cache_init(ni);
    pc = calloc(1, sizeof(*pc));
    if (!pc)
        goto mem_err;

    if (asprintf(&url, "%s%s%s:%hu", schema ? schema : "",
                schema ? "://" : "", domain, ntohs((uint16_t) port)) < 0)
        goto mem_err;
    buff_strtolower(url);
    pc->url = url;
    pc->proxy = proxy ? proxy : &proxy_direct;

    if (rb_tree_insert_node(&cache_rbtree, pc) != pc)
        goto cleanup;

    LIST_INSERT_HEAD(&cache_list, pc, entry);
    number_cache_entries ++;
    PRXL4("adding %s", url);
    return;

mem_err:
    warnx("%s: malloc", __FUNCTION__);
cleanup:
    if (pc)
        free(pc->url);
    free(pc);
}

struct proxy_t *
proxy_cache_find(const char *schema, const char *domain, int port)
{
    struct proxy_cache_t *pc = NULL;
    char *url = NULL;

    if (!cache_timer)
        goto out;
    if (asprintf(&url, "%s%s%s:%hu", schema ? schema : "",
                schema ? "://" : "", domain, ntohs((uint16_t) port)) < 0) {

        warnx("%s: malloc (asprintf)", __FUNCTION__);
        goto out;
    }
    buff_strtolower(url);
    pc = rb_tree_find_node(&cache_rbtree, url);
out:
    if (url) {
        NETLOG5("%s: url %s %"PRIxPTR, __FUNCTION__, url,
                (uintptr_t) (pc ? pc->proxy : NULL));
    }
    free(url);
    return pc ? pc->proxy : NULL;
}

void proxy_cache_reset(void)
{
    struct proxy_cache_t *pc, *pc_next;

    if (cache_timer) {
        free_timer(cache_timer);
        cache_timer = NULL;
    }

    if (!LIST_EMPTY(&cache_list))
        NETLOG4("%s: CACHE RESET", __FUNCTION__);

    LIST_FOREACH_SAFE(pc, &cache_list, entry, pc_next) {
        LIST_REMOVE(pc, entry);
        free(pc->url);
        free(pc);
    }

    rb_tree_init(&cache_rbtree, &cache_rbtree_ops);
    number_cache_entries = 0;
}
