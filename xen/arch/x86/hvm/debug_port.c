/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/xmalloc.h>
#include <xen/hvm/debug_port.h>
#include <asm/hvm/support.h>

static void
uxen_debug_flush(struct debug_port_state *s, domid_t domid)
{

    if (s->buf_ptr > DEBUG_PORT_BUFSZ)
        s->buf_ptr = DEBUG_PORT_BUFSZ;

    s->buf[s->buf_ptr] = '\0';

    printk(XENLOG_G_INFO "vm%d debug: %s\n", domid, (char *)s->buf);
}

static inline void
uxen_debug_char(struct debug_port_state *s, domid_t domid, unsigned char c)
{

    if (s->last_was_eom && (c == DEBUG_PORT_EOM_CHAR))
        return;

    s->last_was_eom = 0;

    if (s->buf_ptr >= DEBUG_PORT_BUFSZ) {
        uxen_debug_flush(s, domid);
        s->buf_ptr = 0;
    }

    if (c == DEBUG_PORT_EOM_CHAR) {
        uxen_debug_flush(s, domid);
        s->last_was_eom = 1;
        s->buf_ptr = 0;
    } else
        s->buf[s->buf_ptr++] = c;
}



static int
debug_write(int dir, uint32_t port, uint32_t size, uint32_t *val)
{
    struct domain *d = current->domain;
    struct debug_port_state *s = d->debug_port;
    uint32_t v = *val;

    (void)port;

    if (!s)
        return X86EMUL_UNHANDLEABLE;

    if (dir == IOREQ_READ)
        return X86EMUL_UNHANDLEABLE;

    while (size) {
        uxen_debug_char(s, d->domain_id, v & 0xff);
        v >>= 8;
        size--;
    }
    return X86EMUL_OKAY;
}

void
hvm_init_debug_port(struct domain *d)
{

    d->debug_port = &d->extra_1->debug_port;

    memset(d->debug_port, 0, sizeof(struct debug_port_state));

    register_portio_handler(d, 0x54, 4, debug_write);

    return;
}
