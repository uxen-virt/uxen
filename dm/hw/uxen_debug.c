/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/qemu/hw/isa.h>

#define BUFSZ	256
#define EOM_CHAR	0xa

typedef struct _UXenDebugState
{
    ISADevice dev;
    MemoryRegion io;
    unsigned char buf[BUFSZ+1];
    size_t buf_ptr;
    int last_was_eom;
} UXenDebugState;


static void
uxen_debug_flush(UXenDebugState *s)
{
    if (s->buf_ptr > BUFSZ)
        s->buf_ptr = BUFSZ;
    s->buf[s->buf_ptr] = '\0';

    debug_printf("debug: %s\n", s->buf);
}


static inline void
uxen_debug_char(UXenDebugState *s, unsigned char c)
{
    if (s->last_was_eom && (c == EOM_CHAR))
        return;

    s->last_was_eom = 0;

    if (s->buf_ptr >= BUFSZ) {
        uxen_debug_flush(s);
        s->buf_ptr = 0;
    }

    if (c == EOM_CHAR) {
        uxen_debug_flush(s);
        s->last_was_eom = 1;
        s->buf_ptr = 0;
    } else
        s->buf[s->buf_ptr++] = c;
}




static void
uxen_debug_write(void *opaque, target_phys_addr_t addr, uint64_t value,
                 unsigned size)
{
    UXenDebugState *s = opaque;

//    debug_printf("%s: %08"PRIx64" %08"PRIx64" %d\n", addr, value, size);

    while (size) {
        uxen_debug_char(s, value & 0xff);
        value >>= 8;
        size--;
    }
}



static const MemoryRegionOps uxen_debug_io_ops = {
    .write = &uxen_debug_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};


static int uxen_debug_initfn(ISADevice *dev)
{
    UXenDebugState *s = DO_UPCAST(UXenDebugState, dev, dev);

    s->buf_ptr = 0;
    s->last_was_eom = 0;

    debug_printf("%s: registering\n", __FUNCTION__);

    memory_region_init_io(&s->io, &uxen_debug_io_ops, s, "uxen_debug", 4);
    isa_register_ioport(dev, &s->io, 0x54);

    return 0;
}


static ISADeviceInfo uxen_debug_info = {
    .qdev.name     = "uxen_debug",
    .qdev.size     = sizeof(UXenDebugState),
    .init          = uxen_debug_initfn,
};


static void uxen_debug_register(void)
{
    isa_qdev_register(&uxen_debug_info);
}

device_init(uxen_debug_register);
