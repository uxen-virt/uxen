/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "kdx.h"

#define pos_of(x) ((x) & 0xffffffffULL)
#define ovfl_of(x) ((x) & ~0xffffffffULL)
#define wrap_of(x) (ovfl_of(x) + 0x100000000ULL)

def_usym_sizeof (domain, 0x1000);
def_usym        (domain, domain_id,         0x0000);
def_usym_addr   (domain, vm_info_shared,         0x0090);
def_usym_addr   (domain, next_in_list,      0x00a0);

ULONG64 EXT_CLASS::get_domain_by_id(uint16_t id)
{
    ULONG64 usym_addr(domain);

    usym_addr(domain) = GetExpression("poi(uxen!domain_list)");

    while (0 != usym_addr(domain)) {

        usym_fetch_struct(domain, break);

        if (usym_read_u16(domain, domain_id) == id)
            return usym_addr(domain);

        usym_addr(domain) = usym_read_addr(domain, next_in_list);
    }

    return ~(ULONG64)0;
}


char *
EXT_CLASS::uxen_logging_read(
    struct uxen_logging_buffer *logbuf,
    uint64_t *reader,
    uint32_t *incomplete,
    uint64_t *log_size)
{
    char *buf = NULL;
    uint64_t cons, prod;
    uint32_t a1, a2;

    if (incomplete)
        *incomplete = 0;

  again:
    prod = logbuf->ulb_producer;
    if (*reader == prod)
        return NULL;

    cons = logbuf->ulb_consumer;
    if (cons > *reader && !(wrap_of(cons) == ovfl_of(*reader) &&
                            pos_of(*reader) <= pos_of(cons))) {
        if (incomplete)
            *incomplete = 1;
        *reader = cons;
    }

    a1 = pos_of(prod) > pos_of(*reader) ? pos_of(prod) - pos_of(*reader) :
         (uint32_t)strnlen(&logbuf->ulb_buffer[pos_of(*reader)],
                           logbuf->ulb_size - pos_of(*reader));
    a2 = pos_of(prod) < pos_of(*reader) ? pos_of(prod) : 0;

    *log_size = a1 + a2 + 1;
    buf = (char *)calloc(1, (size_t)*log_size);
    if (!buf) {
        Out("%s: calloc(,%d) failed", __FUNCTION__, a1 + a2 + 1);
        return NULL;
    }

    memcpy(buf, &logbuf->ulb_buffer[pos_of(*reader)], a1);
    buf[a1] = 0;
    if (a2) {
        memcpy(&buf[a1], &logbuf->ulb_buffer[0], a2);
        buf[a1 + a2] = 0;
    }

    cons = logbuf->ulb_consumer;
    if (cons > *reader && !(wrap_of(cons) == ovfl_of(*reader) &&
                            pos_of(*reader) <= pos_of(cons))) {
        unsigned int trim = 0;
        if (ovfl_of(cons) != ovfl_of(*reader)) {
            trim += a1;
            *reader = wrap_of(*reader);
            if (ovfl_of(cons) != ovfl_of(*reader)) {
                *reader = cons;
                free(buf);
                if (incomplete)
                    *incomplete = 1;
                goto again;
            }
        }
        trim += pos_of(cons - *reader);
        if (trim >= a1 + a2) {
            /* sanity check: this shouldn't/can't happen */
            *reader = cons;
            free(buf);
            if (incomplete)
                *incomplete = 1;
            goto again;
        }
        memmove(buf, &buf[trim], a1 + a2 + 1 - trim);
        if (incomplete)
            *incomplete = 1;
    }

    *reader = prod;

    return buf;
}

EXT_COMMAND(
    dumplog,
    "dumps uxen.sys log",
    "{;e,d=0;domid;a domid or pointer to struct domain}"
    "")
{
    char *buf, *curr, tmp;
    uint64_t pos, log_size, chunk_size;
    uint32_t incomplete;
    struct uxen_logging_buffer *logbuf;

    ULONG64 usym_addr(domain) = GetUnnamedArgU64(0);

    ExtRemoteTyped ulbd_r;

    if (!usym_addr(domain)) {
        ulbd_r = ExtRemoteTyped("uxen!uxen_logging_buffer_desc");
    } else {

        if (usym_addr(domain) < 65536)
            usym_addr(domain) = get_domain_by_id((uint16_t) usym_addr(domain));

        if (usym_addr(domain) == ~(ULONG64)0 )  {
            Out("Domain not found\n");
            return;
        }

        usym_fetch_struct(domain, { Out("unable to read domain struct\n"); return; } );

        ULONG64 vmi = usym_read_addr(domain, vm_info_shared);

        ulbd_r = ExtRemoteTyped("((uxen!vm_info *) @$extin)->vmi_logging_desc", vmi);
    }

    ULONG64 ulbd_addr = ulbd_r.GetPointerTo().GetPtr();

    ULONG ret_size;
    ULONG ulb_size = ulbd_r.Field("size").GetUlong();
    ULONG64 ulb_addr = ulbd_r.Field("buffer").GetPtr();
    ExtRemoteData ulb_r(ulb_addr, ulb_size);

    RequireKernelMode();

    Dml("<exec cmd=\"dt uxen!uxen_logging_buffer_desc 0x%p\">"
        "uxen_logging_buffer_desc</exec> @ 0x%p\n",
        ulbd_addr, ulbd_addr);
    Dml("<exec cmd=\"dt uxen!uxen_logging_buffer 0x%p\">"
        "uxen_logging_buffer</exec> @ 0x%p (size=0x%x)\n\n",
        ulb_addr, ulb_addr, ulb_size);
    
    logbuf = (uxen_logging_buffer *)malloc(ulb_size);
    ret_size = ulb_r.ReadBuffer(logbuf, ulb_size, false);

    if (ret_size == ulb_size) {
        pos = 0;
        buf = uxen_logging_read(logbuf, &pos, &incomplete, &log_size);

        if (incomplete) {
            Out("*** log is incomplete ***\n");
        }

        Out("========================= log start =========================\n");

        curr = buf;
        while (curr < (buf + log_size)) {
            chunk_size = min((15 << 10), (buf + log_size - curr));
            tmp = curr[chunk_size - 1];
            curr[chunk_size - 1] = 0;
            Out("%s", curr);
            curr[chunk_size - 1] = tmp;
            curr += chunk_size;
        }
        Out("\n========================== log end ==========================\n");

    } else {

        Out("!!! Failed to read whole log buffer (read:0x%x, actual size:0x%x)\n", 
            ret_size, ulb_size);
    }

    Out("\n");
}
