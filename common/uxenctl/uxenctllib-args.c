/*
 *  uxenctllib-args.c
 *  uxen
 *
 * Copyright 2013-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "uxenctllib.h"

#include <uxen_ioctl.h>

#include <xen/xen.h>
#include <xen/version.h>

enum uxen_param_type {
    OPT_STR,
    OPT_INT,
    OPT_UINT,
    OPT_SIZE,
    OPT_BOOL,
    OPT_INVBOOL,
    OPT_CUSTOM,
    OPT_LAST
};

static struct uxen_param {
    enum uxen_param_type type;
    char name[32];
    uint64_t mask;
    size_t offset;
    size_t mask_offset;
    size_t size;
    int (*parse)(struct uxen_init_desc *, struct uxen_param *, const char *);
} params[];

#define SIMPLE_OPTION(t, n, f, m, mb) {                          \
        .type = t,                                               \
            .offset = offsetof(struct uxen_init_desc, f),        \
            .mask_offset = offsetof(struct uxen_init_desc, m),   \
            .mask = mb,                                          \
            .size = sizeof(((struct uxen_init_desc *)NULL)->f),  \
            .name = n                                            \
            }

#define BOOLEAN_OPTION(n, o)                                            \
    SIMPLE_OPTION(OPT_BOOL, n, o, UXEN_INIT_ ## o ## _MASK, UXEN_INIT_ ## o)
#define INT_OPTION(n, o)                                                \
    SIMPLE_OPTION(OPT_INT, n, o, UXEN_INIT_ ## o ## _MASK, UXEN_INIT_ ## o)
#define INVBOOLEAN_OPTION(n, o)                                         \
    SIMPLE_OPTION(OPT_INVBOOL, n, o, UXEN_INIT_ ## o ## _MASK, UXEN_INIT_ ## o)
#define UINT_OPTION(n, o)                                               \
    SIMPLE_OPTION(OPT_UINT, n, o, UXEN_INIT_ ## o ## _MASK, UXEN_INIT_ ## o)
#define SIZE_OPTION(n, o)                                               \
    SIMPLE_OPTION(OPT_SIZE, n, o, UXEN_INIT_ ## o ## _MASK, UXEN_INIT_ ## o)
#define STRING_OPTION(n, o)                                             \
    SIMPLE_OPTION(OPT_STR, n, o, UXEN_INIT_ ## o ## _MASK, UXEN_INIT_ ## o)
#define LAST_OPTION { .type = OPT_LAST }

static struct uxen_param params[] = {
    BOOLEAN_OPTION("bootscrub", opt_bootscrub),
    STRING_OPTION("console", opt_console),
    BOOLEAN_OPTION("console_timestamps", opt_console_timestamps),
    UINT_OPTION("cpuid_mask_ecx", opt_cpuid_mask_ecx),
    UINT_OPTION("cpuid_mask_edx", opt_cpuid_mask_edx),
    UINT_OPTION("cpuid_mask_ext_ecx", opt_cpuid_mask_ext_ecx),
    UINT_OPTION("cpuid_mask_ext_edx", opt_cpuid_mask_ext_edx),
    UINT_OPTION("cpuid_mask_xsave_eax", opt_cpuid_mask_xsave_eax),
    BOOLEAN_OPTION("cpuinfo", opt_cpu_info),
    STRING_OPTION("com1", opt_com1),
    STRING_OPTION("com2", opt_com2),
    UINT_OPTION("debug_stack_lines", debug_stack_lines),
    STRING_OPTION("gdb", opt_gdb),
    BOOLEAN_OPTION("hap_1gb", opt_hap_1gb),
    BOOLEAN_OPTION("hap_2mb", opt_hap_2mb),
    UINT_OPTION("hiddenmem", use_hidden_mem),
    UINT_OPTION("hvm_debug", opt_hvm_debug_level),
    BOOLEAN_OPTION("ler", opt_ler),
    UINT_OPTION("ple_gap", ple_gap),
    UINT_OPTION("ple_window", ple_window),
    INVBOOLEAN_OPTION("pv_vmx", disable_pv_vmx),
    BOOLEAN_OPTION("sync_console", opt_sync_console),
    UINT_OPTION("xfeatures", opt_xfeatures),
    BOOLEAN_OPTION("xsave", use_xsave),
    STRING_OPTION("debug", opt_debug),
    BOOLEAN_OPTION("hvmonoff", opt_hvmonoff),
    UINT_OPTION("crash_on", opt_crash_on),
    UINT_OPTION("v4v_thread_priority", opt_v4v_thread_priority),
    UINT_OPTION("spec_ctrl", opt_spec_ctrl),
    BOOLEAN_OPTION("whp", opt_whp),
    LAST_OPTION
};


static void
set_mask_bit(struct uxen_init_desc *uid, struct uxen_param *param)
{
    unsigned char *ptr = (unsigned char *)uid;

    ptr += param->mask_offset;
    *(uint64_t *)ptr |= param->mask;
}

static int
assign_integer_param(struct uxen_init_desc *uid, struct uxen_param *param,
                     uint64_t val)
{
    unsigned char *ptr = (unsigned char *)uid;

    set_mask_bit(uid, param);

    ptr += param->offset;

    switch (param->size) {
    case sizeof(uint8_t):
        *(uint8_t *)ptr = val;
        break;

    case sizeof(uint16_t):
        *(uint16_t *)ptr = val;
        break;

    case sizeof(uint32_t):
        *(uint32_t *)ptr = val;
        break;

    case sizeof(uint64_t):
        *(uint64_t *)ptr = val;
        break;

    default:
        return -1;
    }

    return 0;
}


static int
assign_string_param(struct uxen_init_desc *uid, struct uxen_param *param,
                    const char *val)
{
    char *ptr = (char *) uid;

    set_mask_bit(uid, param);

    ptr += param->offset;

    strncpy(ptr, val, param->size);

    ptr[param->size - 1] = '\0';

    return 0;
}

static uint64_t
parse_size_and_unit(const char *s, const char **ps)
{
    uint64_t ret;
    char *s1;

    ret = strtoull(s, &s1, 0);

    switch (*s1) {
    case 'G':
    case 'g':
        ret <<= 10;

    case 'M':
    case 'm':
        ret <<= 10;

    case 'K':
    case 'k':
        ret <<= 10;

    case 'B':
    case 'b':
        s1++;
        break;

    default:
        ret <<= 10; /* default to kB */
        break;
    }

    if (ps != NULL)
        *ps = s1;

    return ret;
}

static int
parse_bool(const char *s)
{

    if (!strcmp("no", s) ||
        !strcmp("off", s) ||
        !strcmp("false", s) ||
        !strcmp("disable", s) ||
        !strcmp("0", s))
        return 0;

    if (!strcmp("yes", s) ||
        !strcmp("on", s) ||
        !strcmp("true", s) ||
        !strcmp("enable", s) ||
        !strcmp("1", s))
        return 1;

    return -1;
}

int
uxen_parse_init_arg(struct uxen_init_desc *uid, const char *arg)
{
    char opt[100], *optval, *optkey, *q;
    const char *p = arg;
    struct uxen_param *param;
    int bool_assert;

    if (p == NULL)
        return -1;

    while (*p == ' ')
        p++;

    if (*p == '\0')
        return -1;

    /* Grab the next whitespace-delimited option. */
    q = optkey = opt;

    while ((*p != ' ') && (*p != '\0')) {
        if ((q - opt) < (sizeof(opt) - 1)) /* avoid overflow */
            *q++ = *p;

        p++;
    }

    *q = '\0';

    /* Search for value part of a key=value option. */
    optval = strchr(opt, '=');

    if (optval != NULL)
        *optval++ = '\0'; /* nul-terminate the option value */
    else
        optval = q;       /* default option value is empty string */

    /* Boolean parameters can be inverted with 'no-' prefix. */
    bool_assert = !!strncmp("no-", optkey, 3);

    if (!bool_assert)
        optkey += 3;

    for (param = params; param->type != OPT_LAST; param++) {
        if (strncmp(param->name, optkey, sizeof(param->name)))
            continue;

        switch (param->type) {
        case OPT_STR:
            return assign_string_param(uid, param, optval);

        case OPT_INT:
        case OPT_UINT:
            return assign_integer_param(uid, param, strtoll(optval, NULL, 0));

        case OPT_BOOL:
        case OPT_INVBOOL:
            if (!parse_bool(optval))
                bool_assert = !bool_assert;

            return assign_integer_param(
                uid, param, (param->type == OPT_BOOL) == bool_assert);

        case OPT_SIZE:
            return assign_integer_param(uid, param,
                                        parse_size_and_unit(optval, NULL));

        case OPT_CUSTOM:
            return param->parse(uid, param, optval);

        default:
            return -1;
        }
    }

    return -1;
}
