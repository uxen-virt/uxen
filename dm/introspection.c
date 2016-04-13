/*
 * Copyright 2013-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include "control.h"
#include "dict.h"
#include "dict-rpc.h"
#include "dm.h"
#include "dm/introspection.h"

#include "xen/hvm/ioreq.h"

#include "BrEvent.h"
#include <xen/introspection-features.h>

#define MAX_STRING_SIZE 256
static dict get_addr_info(uint64_t address)
{
    dict ret = dict_new();

#if defined(_WIN32)
    char basename[MAX_STRING_SIZE];
    char fullname[MAX_STRING_SIZE];
    uint64_t module_offset;

    introspection_get_module_name(address, &module_offset, basename, fullname,
        MAX_STRING_SIZE);
    dict_put_integer(ret, "address-low", (int)(address&0xffffffff));
    dict_put_integer(ret, "address-hi", (int)(address>>32));
    dict_put_integer(ret, "module-offset", module_offset);
    dict_put_string(ret, "basename", basename);
    dict_put_string(ret, "fullname", fullname);
#endif  /* _WIN32 */

    return ret;
}

static void send_event(int type, uint64_t rip, uint64_t target)
{
    dict args = dict_new();

    dict_put_integer(args, "event-type", type);
    _dict_put(args, "rip-info", get_addr_info(rip));
    _dict_put(args, "target-info", get_addr_info(target));

    warnx("sending introspection-event type 0x%x rip 0x%"PRIx64
          " target 0x%"PRIx64, type, rip, target);

    control_send_command("introspection-event", args, NULL, NULL);
}

#ifdef _WIN32
static void send_event_pshid(int pid, unsigned char *imagename)
{
    int type = BRO_EVENT_TYPE_INTRO_HIDDEN_PROCESS_DETECTED;
    dict args = dict_new();
    dict details = dict_new();

    dict_put_integer(args, "event-type", type);

    dict_put_integer(details, "address-low", pid);
    dict_put_integer(details, "address-hi", 0);
    dict_put_integer(details, "module-offset", -1);
    dict_put_string(details, "basename", (const char*)imagename);
    dict_put_string(details, "fullname", "");

    _dict_put(args, "rip-info", details);
    _dict_put(args, "target-info", get_addr_info(-1ULL));

    warnx("sending introspection-event type 0x%x pid %d image %s", type, pid,
          imagename);

    control_send_command("introspection-event", args, NULL, NULL);
}
#endif

void lava_check_mbr_vbr_write(int64_t sector_num)
{

    /* MBR is at offset 0. We make the boot partition to be the first one,
       at sector offset 2048. Win7 VBR is 9 sectors long */
#define MAX_BOOT_SECTOR_OFFSET (2048 + 9)
    if (sector_num < MAX_BOOT_SECTOR_OFFSET && 
        strstr(lava_options, "mbrvbr_write"))
        send_event(BRO_EVENT_TYPE_INTRO_BOOT_SECTOR_WRITE, -1ULL, -1ULL);
}

void send_introspection_event(ioreq_t *req)
{
    int type;
#ifdef _WIN32
    int pid;
    unsigned char imagename[16] = "";
#endif

    /* We use "size" field as event type */
    switch (req->size) {
    case XEN_DOMCTL_INTROSPECTION_FEATURE_CR0WPCLEAR:
        type = BRO_EVENT_TYPE_INTRO_WP_CR0_CLEAR;
        break;

    case XEN_DOMCTL_INTROSPECTION_FEATURE_CR4VMXESET:
        type = BRO_EVENT_TYPE_INTRO_VMXE_CR4_SET;
        break;

    case XEN_DOMCTL_INTROSPECTION_FEATURE_SMEP:
        type = BRO_EVENT_TYPE_INTRO_SMEP_VIOLATION;
        break;

    case XEN_DOMCTL_INTROSPECTION_FEATURE_CR4SMEPCLEAR:
        type = BRO_EVENT_TYPE_INTRO_SMEP_CR4_CLEAR;
        break;

    case XEN_DOMCTL_INTROSPECTION_FEATURE_IMMUTABLE_MEMORY:
        type = BRO_EVENT_TYPE_INTRO_IMMUTABLE_MEMORY_VIOLATION;
        introspection_dump_kernel_modules();
        break;

    case XEN_DOMCTL_INTROSPECTION_FEATURE_DR_BACKDOOR:
        type = BRO_EVENT_TYPE_INTRO_DEBUG_ROOTKIT;
        break;

#ifdef _WIN32
    case XEN_DOMCTL_INTROSPECTION_FEATURE_HIDDEN_PROCESS:
        pid = introspection_run_hidden_process_detector(req->data, req->addr,
            imagename);
        if (pid)
            send_event_pshid(pid, imagename);
        return;
#endif

    default:
        warnx("unknown introspection ioreq type %d", req->size);
        return;
    }

    send_event(type, req->addr, req->data);
}
