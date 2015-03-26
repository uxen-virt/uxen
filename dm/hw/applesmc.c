/*
 *  Apple SMC controller
 *
 *  Copyright (c) 2007 Alexander Graf
 *
 *  Authors: Alexander Graf <agraf@suse.de>
 *           Susanne Graf <suse@csgraf.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 * *****************************************************************
 *
 * In all Intel-based Apple hardware there is an SMC chip to control the
 * backlight, fans and several other generic device parameters. It also
 * contains the magic keys used to dongle Mac OS X to the device.
 *
 * This driver was mostly created by looking at the Linux AppleSMC driver
 * implementation and does not support IRQ.
 *
 */
/*
 * uXen changes:
 *
 * Copyright 2014-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <dm/qemu_glue.h>
#include <dm/dev.h>
#include <dm/qemu/hw/isa.h>
#include <dm/firmware.h>

//#define DEBUG_SMC

#define APPLESMC_DEFAULT_IOBASE        0x300
/* data port used by Apple SMC */
#define APPLESMC_DATA_PORT             0x0
/* command/status port used by Apple SMC */
#define APPLESMC_CMD_PORT              0x4
#define APPLESMC_NR_PORTS              32
#define APPLESMC_MAX_DATA_LENGTH       32

#define APPLESMC_READ_CMD              0x10
#define APPLESMC_WRITE_CMD             0x11
#define APPLESMC_GET_KEY_BY_INDEX_CMD  0x12
#define APPLESMC_GET_KEY_TYPE_CMD      0x13
#define APPLESMC_RESET_CMD             0xff

#ifdef DEBUG_SMC
#define smc_debug(...) debug_printf("AppleSMC: " __VA_ARGS__)
#else
#define smc_debug(...) do { } while(0)
#endif

struct AppleSMCStatus {
    ISADevice dev;
    uint32_t iobase;
    uint8_t cmd;
    uint8_t status;
    uint8_t key[4];
    uint8_t read_pos;
    uint8_t data_len;
    uint8_t data_pos;
    uint8_t data[255];
    uint8_t charactic[4];
};

static void applesmc_io_cmd_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    struct AppleSMCStatus *s = opaque;

    smc_debug("CMD Write B: %#x = %#x\n", addr, val);
    switch(val) {
        case APPLESMC_READ_CMD:
            s->status = 0x0c;
            break;
        case APPLESMC_RESET_CMD:
            s->status = 0x0;
            break;
    }
    s->cmd = val;
    s->read_pos = 0;
    s->data_pos = 0;
}

static void applesmc_fill_data(struct AppleSMCStatus *s)
{
    void *data;
    size_t len;

    data = smc_key_lookup((const char *)s->key, &len);
    if (!data) {
        smc_debug("Key not matched \"%c%c%c%c\"\n",
                  s->key[0], s->key[1], s->key[2], s->key[3]);
        return;
    }

    smc_debug("Key matched \"%c%c%c%c\", len=%d\n",
              s->key[0], s->key[1], s->key[2], s->key[3], len);
    memcpy(s->data, data, len);
}

static void applesmc_io_data_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    struct AppleSMCStatus *s = opaque;

    smc_debug("DATA Write B: %#x = %#x\n", addr, val);
    switch(s->cmd) {
        case APPLESMC_READ_CMD:
            if(s->read_pos < 4) {
                s->key[s->read_pos] = val;
                s->status = 0x04;
            } else if(s->read_pos == 4) {
                s->data_len = val;
                s->status = 0x05;
                s->data_pos = 0;
                smc_debug("Key = \"%c%c%c%c\" Len = %d\n", s->key[0],
                          s->key[1], s->key[2], s->key[3], val);
                applesmc_fill_data(s);
            }
            s->read_pos++;
            break;
    }
}

static uint32_t applesmc_io_data_readb(void *opaque, uint32_t addr1)
{
    struct AppleSMCStatus *s = opaque;
    uint8_t retval = 0;

    switch(s->cmd) {
        case APPLESMC_READ_CMD:
            if(s->data_pos < s->data_len) {
                retval = s->data[s->data_pos];
                smc_debug("READ_DATA[%d] = %#hhx\n", s->data_pos,
                          retval);
                s->data_pos++;
                if(s->data_pos == s->data_len) {
                    s->status = 0x00;
                    smc_debug("EOF\n");
                } else
                    s->status = 0x05;
            }
    }
    smc_debug("DATA Read b: %#x = %#x\n", addr1, retval);

    return retval;
}

static uint32_t applesmc_io_cmd_readb(void *opaque, uint32_t addr1)
{
    struct AppleSMCStatus *s = opaque;

    smc_debug("CMD Read B: %#x = %#x\n", addr1, s->status);
    return s->status;
}

static void qdev_applesmc_isa_reset(DeviceState *dev)
{
}

static int applesmc_isa_init(ISADevice *dev)
{
    struct AppleSMCStatus *s = DO_UPCAST(struct AppleSMCStatus, dev, dev);

    register_ioport_read(s->iobase + APPLESMC_DATA_PORT, 4, 1,
                         applesmc_io_data_readb, s);
    register_ioport_read(s->iobase + APPLESMC_CMD_PORT, 4, 1,
                         applesmc_io_cmd_readb, s);
    register_ioport_write(s->iobase + APPLESMC_DATA_PORT, 4, 1,
                          applesmc_io_data_writeb, s);
    register_ioport_write(s->iobase + APPLESMC_CMD_PORT, 4, 1,
                          applesmc_io_cmd_writeb, s);

    qdev_applesmc_isa_reset(&dev->qdev);

    return 0;
}

static ISADeviceInfo applesmc_isa_info = {
    .qdev.name  = "isa-applesmc",
    .qdev.size  = sizeof(struct AppleSMCStatus),
    .qdev.reset = qdev_applesmc_isa_reset,
    .init       = applesmc_isa_init,
    .qdev.props = (Property[]) {
        DEFINE_PROP_HEX32("iobase", struct AppleSMCStatus, iobase,
                          APPLESMC_DEFAULT_IOBASE),
        DEFINE_PROP_END_OF_LIST(),
    },
};

static void applesmc_register_devices(void)
{
    isa_qdev_register(&applesmc_isa_info);
}

device_init(applesmc_register_devices)
