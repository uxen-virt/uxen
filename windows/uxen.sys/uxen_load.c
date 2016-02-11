/*
 *  uxen_load.c
 *  uxen
 *
 * Copyright 2011-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

#include "uxen.h"

#include <ntddk.h>
#include <stdio.h>
#include <xen/errno.h>
#include <xen/types.h>

#include <uxen_ioctl.h>

#define NO_XEN_ELF_NOTE
#include <libelf/libelf.h>

#define UXEN_DEFINE_SYMBOLS_CODE
#include <uxen/uxen_link.h>
#ifdef __x86_64__
UXEN_GET_SYMS(uxen_get_symbols, _)
#else  /* __x86_64__ */
UXEN_GET_SYMS(uxen_get_symbols, )
#endif  /* __x86_64__ */
UXEN_CLEAR_SYMS(uxen_clear_symbols)

#if !defined(__UXEN_EMBEDDED__)
static void
elf_log_cb(struct elf_binary *elf, void *called_data, int iserr,
           const char *fmt, va_list ap)
{

    uxen_vprintk(NULL, fmt, ap);
}

int
uxen_load(struct uxen_load_desc *uld)
{
    int ret;
    uint8_t *image;
    struct elf_binary elf;
    const char *missing_symbol;

    if (uxen_hv) {
        fail_msg("already loaded");
	return EINVAL;
    }

    get_xen_guest_handle(image, uld->uld_uvaddr);
    if (image == NULL) {
        fail_msg("no address");
	return EINVAL;
    }

    ret = elf_init(&elf, (const char *)image, uld->uld_size);
    if (ret != 0) {
        fail_msg("elf_init failed: %d", ret);
	ret = EINVAL;
	goto error;
    }

    elf_set_log(&elf, elf_log_cb, NULL, 1);
    elf_parse_binary(&elf);

    uxen_size = (size_t)(elf.pend - elf.pstart);
    uxen_hv = kernel_malloc(uxen_size);
    if (uxen_hv == NULL) {
        fail_msg("malloc %u bytes failed", uxen_size);
	ret = ENOMEM;
	goto error;
    }

    elf.dest = (char *)uxen_hv;
    elf_load_binary(&elf);

    ret = elf_reloc(&elf);
    if (ret != 0) {
        fail_msg("elf_reloc failed: %d", ret);
	ret = EINVAL;
	goto error;
    }

    ret = uxen_get_symbols(&elf, uxen_hv, &missing_symbol);
    if (ret != 0) {
        fail_msg("uxen get symbol %s failed: %d", missing_symbol, ret);
	ret = EINVAL;
	goto error;
    }

#if 0
    ret = uxen_fixup_os_code(&elf, uxen_hv, "windows");
    if (ret != 0) {
        fail_msg("fixup os code failed: %d", ret);
	ret = EINVAL;
	goto error;
    }
#endif

    dprintk("uxen_load done\n");
    ret = 0;
error:
    if (ret && uxen_hv) {
	kernel_free(uxen_hv, uxen_size);
	uxen_hv = NULL;
    }
    return ret;
}
#else
int
uxen_load_symbols(void)
{
    int ret;
    const char *missing_symbol;

    ret = uxen_get_symbols(NULL, NULL, &missing_symbol);
    if (ret != 0) {
        fail_msg("uxen get symbol %s failed: %d", missing_symbol, ret);
	ret = EINVAL;
	goto error;
    }

 error:
    return ret;
}
#endif

int
uxen_unload(void)
{

    uxen_complete_shutdown();

    uxen_op_init_free_allocs();

#if !defined(__UXEN_EMBEDDED__)
    if (uxen_hv) {
	kernel_free(uxen_hv, uxen_size);
	uxen_hv = NULL;
    }
#else
    uxen_clear_symbols();
#endif

    return 0;
}
