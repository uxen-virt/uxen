/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

/* This device is not multithreaded safe. */

#include "../config.h"

#include <dm/qemu_glue.h>
#include <dm/qemu/hw/isa.h>
#include <dm/dmpdev.h>
#include "dmpdev-prot.h"

#include <unistd.h>

bool dmpdev_enabled = true;
char *dmpdev_dump_location = NULL;
uint8_t dmpdev_max_dumps = 8;
uint64_t dmpdev_max_dump_size = 0;
bool dmpdev_overwrite = true;
uint8_t dmpdev_max_log_events = 8;
bool dmpdev_query = false;
uint16_t dmpdev_max_logged_modules = 256;
uint64_t dmpdev_PsLoadedModulesList;
uint64_t dmpdev_PsActiveProcessHead;

#define dmpdev_log(fmt, ...)                                    \
    do {                                                        \
        if (dmpdev_max_log_events) {                            \
            debug_printf("dmpdev: " fmt, ## __VA_ARGS__);       \
            dmpdev_max_log_events--;                            \
            if (!dmpdev_max_log_events)                         \
                debug_printf("dmpdev: log limit reached\n");    \
        }                                                       \
    } while (0)

typedef struct DMPDEVCtrlDesc {
    uint8_t ctrl_code;
    uint32_t data_size;
} DMPDEVCtrlDesc;

static const DMPDEVCtrlDesc ctrl_desc[] = {
    {.ctrl_code = DMPDEV_CTRL_UNINTIALIZED, .data_size = 0},
    {.ctrl_code = DMPDEV_CTRL_VERSION,      .data_size = sizeof(DMPDEV_VERSION)},
    {.ctrl_code = DMPDEV_CTRL_FAILURE,      .data_size = sizeof(DMPDRV_FAILURE_INFO)},
    {.ctrl_code = DMPDEV_CTRL_CRASH_INFO,   .data_size = sizeof(DMPDEV_CRASH_INFO)},
    {.ctrl_code = DMPDEV_CTRL_MODULE_INFO,  .data_size = sizeof(DMPDEV_MODULES_INFO)},
    {.ctrl_code = DMPDEV_CTRL_DUMP_DATA,    .data_size = sizeof(DMPDEV_DUMP_DATA)},
    {.ctrl_code = DMPDEV_CTRL_GLOBALS_INFO, .data_size = sizeof(DMPDEV_GLOBALS_INFO)},
};

typedef struct DMPDEVState {
    bool active;

    uint8_t ctrl_code;
    uint32_t bytes_to_collect;
    uint32_t bytes_collected;
    union {
        DMPDEV_VERSION ver;
        DMPDRV_FAILURE_INFO failure_info;
        DMPDEV_CRASH_INFO crash_info;
        DMPDEV_MODULES_INFO modules_info;
        DMPDEV_DUMP_DATA dump_data;
        DMPDEV_GLOBALS_INFO globals_info;
        uint8_t raw[1];
    } ctrl;

    FILE *dump_file;
    char *dump_name;
    uint64_t dump_size;
} DMPDEVState;

typedef struct ISADMPDEVState {
    ISADevice dev;
    DMPDEVState state;
} ISADMPDEVState;

static bool is_str_printable(uint8_t *str)
{
    while (*str)
        if (!isprint(*str++))
            return false;
    return true;
}

static void dmpdev_cmd_write_command(void *opaque, uint32_t addr, uint32_t val)
{
    DMPDEVState *s = opaque;

    if (!s->active)
        return;

    if (DMPDEV_CTRL_UNINTIALIZED != s->ctrl_code) {
        /* this should not happen: request already in progress */
        dmpdev_log("out of order cmd: current-%d, new-%d\n", s->ctrl_code, val);
        s->ctrl_code = DMPDEV_CTRL_UNINTIALIZED;
        s->bytes_to_collect = 0;
        s->bytes_collected = 0;
        return;
    }

    if (DMPDEV_CTRL_UNINTIALIZED == val || val >= DMPDEV_CTRL_MAX) {
        /* this should not happen: invalid control code */
        dmpdev_log("invalid cmd: %d\n", val);
        return;
    }

    if (val != ctrl_desc[val].ctrl_code) {
        /* this should not happen: protocol defs corruption */
        dmpdev_log("proto corruption: current-%d != desc-%d\n",
                   val, ctrl_desc[val].ctrl_code);
        return;
    }

    s->ctrl_code        = val;
    s->bytes_to_collect = ctrl_desc[val].data_size;
    s->bytes_collected  = 0;
}

static void process_cmd(DMPDEVState *s)
{
    switch (s->ctrl_code) {
    case DMPDEV_CTRL_VERSION:
        if (DMPDEV_PROTOCOL_VERSION == s->ctrl.ver.version)
            dmpdev_log("guest connected\n");
        else {
            dmpdev_log("unknown protocol version requested by guest-%d\n",
                       s->ctrl.ver.version);
            s->active = false;
        }
        break;
    case DMPDEV_CTRL_FAILURE:
        dmpdev_log("guest dmpdrv failure: type-%d, code-%d\n",
                   s->ctrl.failure_info.type, s->ctrl.failure_info.code);
        break;
    case DMPDEV_CTRL_CRASH_INFO:
        dmpdev_log("guest crashed: 0x%X(0x%"PRIx64
                   ", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",
                   s->ctrl.crash_info.code,
                   s->ctrl.crash_info.param1, s->ctrl.crash_info.param2,
                   s->ctrl.crash_info.param3, s->ctrl.crash_info.param4);
        if (dmpdev_dump_location &&
            dmpdev_query &&
            !dmpdev_query_dump_allowed())
        {
            /* don't allow dump creation if RPC query result was negative */
            free(dmpdev_dump_location);
            dmpdev_dump_location = NULL;
        }
        break;
    case DMPDEV_CTRL_MODULE_INFO:
    {
        uint8_t *modules, *modules_base;
        void *mapped;
        uint64_t len, remain;
        uint64_t addr;
        uint32_t i, number_of_modules;

        if (!dmpdev_max_logged_modules)
            break;

        if (!s->ctrl.modules_info.phys_addr ||
            !s->ctrl.modules_info.size ||
            !s->ctrl.modules_info.entry_size ||
            s->ctrl.modules_info.flags & ~DMPDEV_MIF_VALID_MASK ||
            s->ctrl.modules_info.entry_size < sizeof (DMPDEV_MODULE_ENTRY_32) ||
            s->ctrl.modules_info.size >
                dmpdev_max_logged_modules * s->ctrl.modules_info.entry_size ||
            s->ctrl.modules_info.entry_size > 512 ||
            s->ctrl.modules_info.size % s->ctrl.modules_info.entry_size)
        {
            debug_printf("dmpdev: invalid module list descriptor: "
                         "addr:0x%"PRIx64", size:0x%x, entry_size:0x%x, flags:0x%x\n",
                         s->ctrl.modules_info.phys_addr,
                         s->ctrl.modules_info.size,
                         s->ctrl.modules_info.entry_size,
                         s->ctrl.modules_info.flags);
            break;
        }

        modules_base = malloc(s->ctrl.modules_info.size);
        if (!modules_base) {
            dmpdev_log("couldn't allocate 0x%x bytes for modules table\n",
                       s->ctrl.modules_info.size);
            break;
        }
        memset(modules_base, 0, s->ctrl.modules_info.size);

        /* for now guest modules buffer has to be allocated as contiguous pages */
        modules = modules_base;
        addr = s->ctrl.modules_info.phys_addr;
        remain = s->ctrl.modules_info.size;
        while (remain > 0) {
            len = remain;
            mapped = vm_memory_map(addr, &len, 0, 0);
            if (mapped) {
                memcpy(modules, mapped, len);
                vm_memory_unmap(addr, len, 0, 0, mapped, len);
                modules += len;
                addr += len;
                remain -= len;
            } else {
                dmpdev_log("failed to map modules buffer-0x%"PRIx64"(0x%"PRIx64")\n",
                           addr, len);
                free(modules);
                return;
            }
        }

        /* dump guest modules table */
        modules = modules_base;
        number_of_modules = s->ctrl.modules_info.size /
                            s->ctrl.modules_info.entry_size;
        for (i = 0; i < number_of_modules; i++) {
            modules[s->ctrl.modules_info.entry_size - 1] = 0;

            if (s->ctrl.modules_info.flags & DMPDEV_MIF_X64) {
                DMPDEV_MODULE_ENTRY_64 *entry = (DMPDEV_MODULE_ENTRY_64 *)modules;
                if ((size_t)entry->name_offset + 
                            offsetof(DMPDEV_MODULE_ENTRY_64, full_name) >= 
                    s->ctrl.modules_info.entry_size)
                    break;
                if (is_str_printable(entry->full_name + entry->name_offset))
                    debug_printf("dmpdev: km_mod: 0x%"PRIx64"-0x%"PRIx64" %s\n",
                                 entry->base_addr,
                                 entry->base_addr + entry->size,
                                 entry->full_name + entry->name_offset);
            } else {
                DMPDEV_MODULE_ENTRY_32 *entry = (DMPDEV_MODULE_ENTRY_32 *)modules;
                if ((size_t)entry->name_offset + 
                            offsetof(DMPDEV_MODULE_ENTRY_32, full_name) >= 
                    s->ctrl.modules_info.entry_size)
                    break;
                if (is_str_printable(entry->full_name + entry->name_offset))
                    debug_printf("dmpdev: km_mod: 0x%"PRIx32"-0x%"PRIx32" %s\n",
                                 entry->base_addr,
                                 entry->base_addr + entry->size,
                                 entry->full_name + entry->name_offset);
            }

            if (!--dmpdev_max_logged_modules) {
                if (i + 1 < number_of_modules)
                    dmpdev_log("logged modules limit reached\n");
                break;
            }
            modules += s->ctrl.modules_info.entry_size;
        }

        free(modules_base);
        break;
    }
    case DMPDEV_CTRL_DUMP_DATA:
    {
        uint64_t addr;
        uint64_t len;
        uint64_t remain;
        uint8_t *dmp_buf;
        uint8_t i;
        bool dump_save_failure = false;

        if (!dmpdev_dump_location)
            break;

        if (!s->dump_file) {
            if (asprintf(&s->dump_name, "%s.dmp", dmpdev_dump_location) == -1) {
                dmpdev_log("failed to allocate dump path\n");
                s->active = false;
                break;
            }
            if (dmpdev_overwrite)
                unlink(s->dump_name);
            else {
                for (i = 1;
                    -1 != access(s->dump_name, F_OK) && i < dmpdev_max_dumps;
                    i++)
                {
                    free(s->dump_name);
                    if (asprintf(&s->dump_name, "%s-%d.dmp",
                                 dmpdev_dump_location, i) == -1)
                    {
                        dmpdev_log("failed to allocate dump file name\n");
                        s->active = false;
                        dump_save_failure = true;
                        break;
                    }
                }

                if (dump_save_failure)
                    break;
                    
                if (i == dmpdev_max_dumps) {
                    dmpdev_log("max number of dumps exceeded\n");
                    s->active = false;
                    break;
                }
            }

            s->dump_file = fopen(s->dump_name, "wb");
            if (!s->dump_file) {
                dmpdev_log("failed to create dump file \"%s\": %d\n",
                           s->dump_name, errno);
                s->active = false;
                break;
            }
        }

        remain = s->ctrl.dump_data.size;
        addr = s->ctrl.dump_data.phys_addr;
        if (remain > 0) {
            while (addr < s->ctrl.dump_data.phys_addr + s->ctrl.dump_data.size) {
                len = remain;
                dmp_buf = vm_memory_map(addr, &len, 0, 0);
                if (dmp_buf) {
                    if (s->dump_size + len > dmpdev_max_dump_size) {
                        vm_memory_unmap(addr, len, 0, 0, dmp_buf, len);
                        dmpdev_log(
                            "dump file \"%s\" exceeded max allowed size - deleted\n",
                            s->dump_name);
                        dump_save_failure = true;
                        break;
                    }
                    if (fwrite(dmp_buf, 1, len, s->dump_file) == len) {
                        vm_memory_unmap(addr, len, 0, 0, dmp_buf, len);
                        addr += len;
                        remain -= len;
                        s->dump_size += len;
                    } else {
                        vm_memory_unmap(addr, len, 0, 0, dmp_buf, len);
                        dmpdev_log("failed to save dump buffer to \"%s\": %d\n",
                                   s->dump_name, errno);
                        dump_save_failure = true;
                        break;
                    }
                } else {
                    dmpdev_log("failed to map dump buffer-0x%"PRIx64
                               "(0x%"PRIx64")\n",
                               addr, len);
                    dump_save_failure = true;
                    break;
                }
            }
        }

        if (1 == s->ctrl.dump_data.flags || dump_save_failure) {
            fclose(s->dump_file);
            s->dump_file = NULL;
            if (!dump_save_failure)
                dmpdev_log("vm (domid %d) dump saved to \"%s\","
                           " size:0x%"PRIx64"\n",
                           domid, s->dump_name, s->dump_size);
            s->active = false;
            dmpdev_notify_dump_complete(!dump_save_failure);
            free(s->dump_name);
            s->dump_name = NULL;
        }
        break;
    }
    case DMPDEV_CTRL_GLOBALS_INFO:
        if (dmpdev_PsActiveProcessHead || dmpdev_PsLoadedModulesList) {
            dmpdev_log("Refusing duplicate DMPDEV_CTRL_GLOBALS_INFO (from clone?)\n");
            break;
        }
        dmpdev_PsActiveProcessHead = s->ctrl.globals_info.PsActiveProcessHead;
        dmpdev_PsLoadedModulesList = s->ctrl.globals_info.PsLoadedModulesList;
        dmpdev_log("dmpdev_PsLoadedModulesList at 0x%"PRIx64
                   " dmpdev_PsActiveProcessHead at 0x%"PRIx64"\n",
                   dmpdev_PsLoadedModulesList, dmpdev_PsActiveProcessHead);
        break;
    default:
        dmpdev_log("cmd-%d not implemented yet\n", s->ctrl_code);
    }
}

static void dmpdev_data_write_command(void *opaque, uint32_t addr, uint32_t val)
{
    DMPDEVState *s = opaque;

    if (!s->active) return;

    if (DMPDEV_CTRL_UNINTIALIZED == s->ctrl_code) {
        /* this should not happen: unexpected data */
        dmpdev_log("unexpected data\n");
        return;
    }

    s->ctrl.raw[s->bytes_collected++] = (uint8_t)val;

    if (s->bytes_collected >= s->bytes_to_collect) {
        process_cmd(s);
        s->ctrl_code        = DMPDEV_CTRL_UNINTIALIZED;
        s->bytes_to_collect = 0;
        s->bytes_collected  = 0;
    }
}

static void dmpdev_data_write_commandl(void *opaque, uint32_t addr, uint32_t val)
{
    DMPDEVState *s = opaque;

    if (!s->active) return;

    if (DMPDEV_CTRL_UNINTIALIZED == s->ctrl_code) {
        /* this should not happen: unexpected data */
        dmpdev_log("unexpected data\n");
        return;
    }

    *((uint32_t *)&s->ctrl.raw[s->bytes_collected]) = val;
    s->bytes_collected += sizeof(val);

    if (s->bytes_collected >= s->bytes_to_collect) {
        process_cmd(s);
        s->ctrl_code        = DMPDEV_CTRL_UNINTIALIZED;
        s->bytes_to_collect = 0;
        s->bytes_collected  = 0;
    }
}

static const MemoryRegionPortio dmpdev_cmd_portio[] = {
    {0, 1, 1, .read = NULL, .write = dmpdev_cmd_write_command},
    PORTIO_END_OF_LIST()
};

static const MemoryRegionPortio dmpdev_data_portio[] = {
    {0, 1, 1, .read = NULL, .write = dmpdev_data_write_command},
    {0, 1, 4, .read = NULL, .write = dmpdev_data_write_commandl},
    PORTIO_END_OF_LIST()
};

static int dmpdev_initfn(ISADevice *dev)
{
    ISADMPDEVState *isa_s = DO_UPCAST(ISADMPDEVState, dev, dev);
    DMPDEVState *s = &isa_s->state;

    /* usually full dumps are smaller than amount of RAM */
    /* but we add 50MB (arbitrary value) just in case */
    if (0 == dmpdev_max_dump_size)
        dmpdev_max_dump_size = (vm_mem_mb + 50) << 20;

    s->ctrl_code        = DMPDEV_CTRL_UNINTIALIZED;
    s->bytes_to_collect = 0;
    s->bytes_collected  = 0;
    s->dump_file        = NULL;
    s->dump_name        = NULL;
    s->dump_size        = 0;

    isa_register_portio_list(dev, DMPDEV_CONTROL_PORT, dmpdev_cmd_portio, s,
                             "dmpdev-cmd");
    isa_register_portio_list(dev, DMPDEV_DATA_PORT, dmpdev_data_portio, s,
                             "dmpdev-data");

    s->active = true;

    return 0;
}

static ISADeviceInfo dmpdev_info = {
    .qdev.name     = "dmpdev",
    .qdev.size     = sizeof(ISADMPDEVState),
    .init          = dmpdev_initfn,
};

static void dmpdev_register(void)
{
    isa_qdev_register(&dmpdev_info);
}
device_init(dmpdev_register)
