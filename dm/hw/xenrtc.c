/*
 * Copyright 2012-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/qemu/hw/isa.h>

#include <time.h>

// #define DEBUG_CMOS

#ifdef DEBUG_CMOS
# define CMOS_DPRINTF(format, ...)      debug_printf(format, ## __VA_ARGS__)
#else
# define CMOS_DPRINTF(format, ...)      do { } while (0)
#endif

struct RTCState {
    ISADevice dev;
    uint8_t cmos_data[128];
    uint8_t cmos_index;
};

static inline int rtc_to_bcd(RTCState *s, int a)
{
    return ((a / 10) << 4) | (a % 10);
}

static void cmos_ioport_write(void *opaque, uint32_t addr, uint32_t data)
{
    RTCState *s = opaque;

    if ((addr & 1) == 0) {
        s->cmos_index = data & 0x7f;
    } else {
        CMOS_DPRINTF("cmos: write index=0x%02x val=0x%02x\n",
                     s->cmos_index, data);
        s->cmos_data[s->cmos_index] = data;
    }
}

static uint32_t cmos_ioport_read(void *opaque, uint32_t addr)
{
    RTCState *s = opaque;
    int ret;
    if ((addr & 1) == 0) {
        return 0xff;
    } else {
        ret = s->cmos_data[s->cmos_index];
        CMOS_DPRINTF("cmos: read index=0x%02x val=0x%02x\n",
                     s->cmos_index, ret);
        return ret;
    }
}

void uxen_rtc_set_memory(ISADevice *dev, int addr, int val)
{
    RTCState *s = DO_UPCAST(RTCState, dev, dev);
    if (addr >= 0 && addr <= 127)
        s->cmos_data[addr] = val;
}

/* PC cmos mappings */
#define REG_IBM_CENTURY_BYTE        0x32
#define REG_IBM_PS2_CENTURY_BYTE    0x37

static void rtc_set_date_from_host(ISADevice *dev)
{
    RTCState *s = DO_UPCAST(RTCState, dev, dev);
    time_t ti;
    struct tm *tm;
    int val;

    /* set the CMOS date */
    time(&ti);
    tm = gmtime(&ti);		/* XXX localtime and update from guest? */

    val = rtc_to_bcd(s, (tm->tm_year / 100) + 19);
    uxen_rtc_set_memory(dev, REG_IBM_CENTURY_BYTE, val);
    uxen_rtc_set_memory(dev, REG_IBM_PS2_CENTURY_BYTE, val);
}

static const VMStateDescription vmstate_rtc = {
    .name = "xenrtc",
    .version_id = 2,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .fields      = (VMStateField []) {
        VMSTATE_BUFFER(cmos_data, RTCState),
        VMSTATE_UINT8(cmos_index, RTCState),
        VMSTATE_END_OF_LIST()
    }
};

static const MemoryRegionPortio cmos_portio[] = {
    {0, 2, 1, .read = cmos_ioport_read, .write = cmos_ioport_write },
    PORTIO_END_OF_LIST(),
};

static int rtc_initfn(ISADevice *dev)
{
    RTCState *s = DO_UPCAST(RTCState, dev, dev);
    int base = 0x70;

    rtc_set_date_from_host(dev);

    isa_register_portio_list(dev, base, cmos_portio, s, "rtc");

    return 0;
}

static ISADeviceInfo xenrtc_info = {
    .qdev.name     = "xenrtc",
    .qdev.size     = sizeof(RTCState),
    // .qdev.no_user  = 1,
    .qdev.vmsd     = &vmstate_rtc,
    .init          = rtc_initfn,
};

static void xenrtc_register(void)
{
    isa_qdev_register(&xenrtc_info);
}
device_init(xenrtc_register)
