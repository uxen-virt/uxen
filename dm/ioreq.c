/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <stdint.h>

#include "dm.h"
#include "introspection.h"
#include "ioh.h"
#include "ioport.h"
#include "ioreq.h"
#include "mapcache.h"
#include "memory.h"
#include "monitor.h"
#include "timer.h"
#include "uxen.h"
#include "vm.h"

#include "rbtree.h"

#include <xenctrl.h>
#undef _IOREQ_H_
#include <xen/hvm/ioreq.h>

#define LONG_IOREQ_MS 100

struct ioreq_state *default_ioreq_state = NULL;

int ioreq_dump = 0;
uint64_t ioreq_count = 0;

static void handle_ioreq(void *opaque);

struct ioreqstat_key {
    unsigned int isk_addr;
    unsigned int isk_size;
};

struct ioreqstat_node {
    struct rb_node is_rbnode;
    struct ioreqstat_key is_key;
#define is_addr is_key.isk_addr
#define is_size is_key.isk_size
    int is_triggered;
    LIST_ENTRY(ioreqstat_node) is_list;
};

static int
ioreqstat_compare_key(void *ctx, const void *b, const void *key)
{
    const struct ioreqstat_node * const pnp = b;
    const struct ioreqstat_key * const fhp = key;

    if (pnp->is_addr != fhp->isk_addr)
	return pnp->is_addr - fhp->isk_addr;
    return pnp->is_size - fhp->isk_size;
}

static int
ioreqstat_compare_nodes(void *ctx, const void *parent, const void *node)
{
    const struct ioreqstat_node * const np = node;

    return ioreqstat_compare_key(ctx, parent, &np->is_key);
}

static LIST_HEAD(, ioreqstat_node) ioreqstat_list =
    LIST_HEAD_INITIALIZER(&ioreqstat_list);
static rb_tree_t ioreqstat_rbtree;
static const rb_tree_ops_t ioreqstat_rbtree_ops = {
    .rbto_compare_nodes = ioreqstat_compare_nodes,
    .rbto_compare_key = ioreqstat_compare_key,
    .rbto_node_offset = offsetof(struct ioreqstat_node, is_rbnode),
    .rbto_context = NULL
};

void
ioreqstat_clear(void)
{
    struct ioreqstat_node *isp;

    LIST_FOREACH(isp, &ioreqstat_list, is_list)
	isp->is_triggered = 0;
    ioreq_count = 0;
}

void
ioreqstat_update(ioreq_t *req)
{
    struct ioreqstat_key iskey;
    struct ioreqstat_node *isp;
    struct ioreqstat_node *next;

    if (ioreq_dump && (req->addr < 0x170 || req->addr > 0x177))
	debug_printf("ioreq: "
                     "%x, ptr: %x, port: %"PRIx64", "
                     "data: %"PRIx64", count: %u, size: %u\n",
                     req->state, req->data_is_ptr, req->addr,
                     req->data, req->count, req->size);

    iskey.isk_addr = req->addr;
    iskey.isk_size = req->size;

    if (iskey.isk_addr >= 0xa0000 && iskey.isk_addr < 0xc0000) /* vga */
	iskey.isk_addr = 0xa0000;

    isp = rb_tree_find_node(&ioreqstat_rbtree, &iskey);
    if (isp == NULL) {
	isp = calloc(1, sizeof(*isp));
        if (!isp)
            return;
	isp->is_key = iskey;
	rb_tree_insert_node(&ioreqstat_rbtree, isp);
        LIST_INSERT_HEAD(&ioreqstat_list, isp, is_list);
    }
    isp->is_triggered++;
    while ((next = LIST_NEXT(isp, is_list)) &&
           isp->is_triggered > next->is_triggered) {
        LIST_REMOVE(isp, is_list);
        LIST_INSERT_AFTER(next, isp, is_list);
    }
}

#ifdef MONITOR
void
ic_ioreq(Monitor *mon)
{
    ioreq_t *req;
    int i;
    struct ioreqstat_node *isp;
    int is_triggered_tot = 0;

    LIST_FOREACH(isp, &ioreqstat_list, is_list) {
	if (isp->is_triggered)
	    monitor_printf(mon, "addr %8x size %2x triggered %8d\n",
                           isp->is_addr, isp->is_size, isp->is_triggered);
	is_triggered_tot += isp->is_triggered;
    }
    monitor_printf(mon, "triggered total: %d\n", is_triggered_tot);

    for (i = 0; i < vm_vcpus; i++) {
        req = &default_ioreq_state->io_page->vcpu_ioreq[i];
        monitor_printf(mon, "  req state: %x, ptr: %x, addr: %"PRIx64", "
                       "data: %"PRIx64", count: %u, size: %u\n",
                       req->state, req->data_is_ptr, req->addr,
                       req->data, req->count, req->size);
        monitor_printf(mon, "  IO totally occurred on this vcpu: %u %"PRId64
                       "\n", req->count, ioreq_count);
    }
}
#endif  /* MONITOR */


void
ioreq_init(void)
{

    default_ioreq_state = ioreq_new_server();
    if (default_ioreq_state == NULL)
        errx(1, "ioreq_new_server failed");

    rb_tree_init(&ioreqstat_rbtree, &ioreqstat_rbtree_ops);
}

struct ioreq_state *
ioreq_new_server(void)
{
    int i, ret;
    struct ioreq_state *state;
    xen_pfn_t pfn;

    state = calloc(1, sizeof(*state));
    if (state == NULL)
	err(1, "calloc");

    ret = xc_hvm_register_ioreq_server(xc_handle, vm_id, &state->serverid);
    if (ret)
	err(1, "xc_hvm_register_ioreq_server failed");
    dprintf("registered ioreq server %d\n", state->serverid);

    pfn = xc_hvm_iopage(xc_handle, vm_id, state->serverid, XC_HVM_IOPAGE);
    dprintf("server %d shared io page at pfn %"PRIx64"\n", state->serverid,
	    pfn);
    
    state->io_page = xc_map_foreign_range(xc_handle, vm_id, XC_PAGE_SIZE,
					  PROT_READ|PROT_WRITE, pfn);
    if (state->io_page == NULL)
        err(1, "server %d map shared IO page failed", state->serverid);

    state->events = calloc(vm_vcpus, sizeof(*state->events));
    if (state->events == NULL)
	err(1, "calloc");

    for (i = 0; i < vm_vcpus; i++) {
	state->events[i].state = state;
        uxen_notification_event_init(&state->events[i].signal);
        uxen_user_notification_event_init(&state->events[i].completed);

        dprintf("vcpu%d ioreq eport %d\n", i,
                state->io_page->vcpu_ioreq[i].vp_eport);
        ret = uxen_setup_event_channel(
            i, state->io_page->vcpu_ioreq[i].vp_eport,
            &state->events[i].signal, &state->events[i].completed);
	if (ret)
            errx(1, "uxen_setup_event_channel ioreq");
    }

    return state;
}

void
ioreq_wait_server_events(struct ioreq_state *is)
{
    int i;

    for (i = 0; i < vm_vcpus; i++)
        uxen_notification_add_wait_object(&is->events[i].signal, handle_ioreq,
                                          &is->events[i]);
}

static ioreq_t *
get_ioreq(struct ioreq_state *is, unsigned int vcpu)
{
    ioreq_t *req = &is->io_page->vcpu_ioreq[vcpu];

    if (req->state != STATE_IOREQ_READY) {
        error_printf("I/O request not ready: "
                     "%x, ptr: %x, port: %"PRIx64", "
                     "data: %"PRIx64", count: %u, size: %u\n",
                     req->state, req->data_is_ptr, req->addr,
                     req->data, req->count, req->size);
        return NULL;
    }

    xen_rmb(); /* see IOREQ_READY /then/ read contents of ioreq */

    req->state = STATE_IOREQ_INPROCESS;
    return req;
}

static uint32_t do_inp(uint32_t addr, int size)
{

    int width = ioport_width(size, "inp: bad size: %lx %lx\n", addr, size);
    return ioport_read(width, addr);
}

static void do_outp(uint32_t addr, int size, uint32_t val)
{

    int width = ioport_width(size, "outp: bad size: %lx %lx\n", addr, size);
    return ioport_write(width, addr, val);
}

static inline void read_physical(uint64_t addr, unsigned long size, void *val)
{
    vm_memory_rw(addr, val, size, 0);
}

static inline void write_physical(uint64_t addr, unsigned long size, void *val)
{
    vm_memory_rw(addr, val, size, 1);
}

static void ioreq_pio(ioreq_t *req)
{
    int i, sign;

    sign = req->df ? -1 : 1;

    assert(req->size <= 4);

    if (req->dir == IOREQ_READ) {
        if (!req->data_is_ptr)
            req->data = do_inp(req->addr, req->size);
        else {
            uint32_t tmp;

            for (i = 0; i < req->count; i++) {
                tmp = do_inp(req->addr, req->size);
                write_physical(req->data + (sign * i * req->size),
                               req->size, &tmp);
            }
        }
    } else if (req->dir == IOREQ_WRITE) {
        if (!req->data_is_ptr)
            do_outp(req->addr, req->size, req->data);
        else {
            for (i = 0; i < req->count; i++) {
                uint32_t tmp = 0;

                read_physical(req->data + (sign * i * req->size),
                              req->size, &tmp);
                do_outp(req->addr, req->size, tmp);
            }
        }
    }
}

static void ioreq_timeoffset(ioreq_t *req)
{
}

static void ioreq_move(ioreq_t *req)
{
    int i, sign;

    sign = req->df ? -1 : 1;

    if (!req->data_is_ptr) {
        if (req->dir == IOREQ_READ) {
            for (i = 0; i < req->count; i++) {
                read_physical(req->addr + (sign * i * req->size),
                              req->size, &req->data);
            }
        } else if (req->dir == IOREQ_WRITE) {
            for (i = 0; i < req->count; i++) {
                write_physical(req->addr + (sign * i * req->size),
                               req->size, &req->data);
            }
        }
    } else {
        uint64_t tmp, src, dest;

        if (req->dir == IOREQ_READ) {
            src = req->addr;
            dest = req->data;
        } else if (req->dir == IOREQ_WRITE) {
            src = req->data;
            dest = req->addr;
        }
        for (i = 0; i < req->count; i++) {
            read_physical(src + (sign * i * req->size), req->size, &tmp);
            write_physical(dest + (sign * i * req->size), req->size, &tmp);
        }
    }
}

static void ioreq_config_space(ioreq_t *req)
{
    uint64_t addr = req->addr;
    uint64_t cf8 = req->addr & (~0x3);

    req->addr = 0xcfc + (addr & 0x3);
    do_outp(0xcf8, 4, cf8); 
    ioreq_pio(req);
    req->addr = addr;
}

static void __handle_ioreq(ioreq_t *req)
{
    if (!req->data_is_ptr && (req->dir == IOREQ_WRITE) &&
        (req->size < sizeof(uint64_t)))
        req->data &= (1ULL << (8 * req->size)) - 1;

    ioreqstat_update(req);

    switch (req->type) {
    case IOREQ_TYPE_PIO:
        ioreq_pio(req);
        break;
    case IOREQ_TYPE_COPY:
        ioreq_move(req);
        break;
#ifndef __UXEN__
    case IOREQ_TYPE_TIMEOFFSET:
        ioreq_timeoffset(req);
        break;
    case IOREQ_TYPE_INVALIDATE:
        mapcache_invalidate();
        break;
#endif  /* __UXEN__ */
    case IOREQ_TYPE_PCI_CONFIG:
        ioreq_config_space(req);
        break;
    case IOREQ_TYPE_INTROSPECTION:
        send_introspection_event(req);
        break;
    default:
        warnx("Invalid ioreq type 0x%x", req->type);
        vm_set_run_mode(DESTROY_VM);
        break;
    }
}

/* running time without periods spent in sleep state */
static uint64_t
unbiased_time_ms(void)
{
#if 0
    extern WINAPI BOOL QueryUnbiasedInterruptTime(PULONGLONG);
    ULONGLONG t = 0;
    QueryUnbiasedInterruptTime(&t);
    return t / 10000;
#else
    return os_get_clock() / SCALE_MS;
#endif
}

static void
handle_ioreq(void *opaque)
{
    struct ioreq_event *ev = opaque;
    struct ioreq_state *is = ev->state;
    unsigned int vcpu = ev - &is->events[0];
    ioreq_t *req = get_ioreq(is, vcpu);
    uint64_t t0, t1;

    if (req) {
        t0 = unbiased_time_ms();

        __handle_ioreq(req);

        if (req->state != STATE_IOREQ_INPROCESS) {
            warnx("Badness in I/O request ... not in service?!: "
                  "%x, ptr: %x, port: %"PRIx64", "
                  "data: %"PRIx64", count: %u, size: %u",
                  req->state, req->data_is_ptr, req->addr,
                  req->data, req->count, req->size);
            vm_set_run_mode(DESTROY_VM);
            return;
        }

        xen_wmb(); /* Update ioreq contents /then/ update state. */

        req->state = STATE_IORESP_READY;
        uxen_user_notification_event_set(&ev->completed);
	ioreq_count++;

        t1 = unbiased_time_ms();
        if (t1 - t0 >= LONG_IOREQ_MS)
            debug_printf("long I/O request: %dms, dir=%d, "
                         "ptr: %x, port: %"PRIx64", "
                         "data: %"PRIx64", count: %u, size: %u\n",
                         (int)(t1-t0),
                         req->dir, req->data_is_ptr, req->addr,
                         req->data, req->count, req->size);
    }
}

#ifdef MONITOR
void
mc_toggle_ioreq(Monitor *mon, dict args)
{

    ioreq_dump = 1 - ioreq_dump;
}
#endif  /* MONITOR */
