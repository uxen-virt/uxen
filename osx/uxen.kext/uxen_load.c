/*
 *  uxen_load.c
 *  uxen
 *
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 * 
 */

#include "uxen.h"

#include <sys/errno.h>
#include <libkern/libkern.h>
#include <mach/vm_map.h>

#define NO_XEN_ELF_NOTE
#include <libelf/libelf.h>

#define UXEN_DEFINE_SYMBOLS_CODE
#include <uxen/uxen_link.h>
UXEN_GET_SYMS(uxen_get_symbols, _)
UXEN_CLEAR_SYMS(uxen_clear_symbols)

extern kmod_info_t KMOD_INFO_NAME;

#if !defined(__UXEN_EMBEDDED__)
static void
set_hv_addr(void *addr)
{
    kmod_info_t *ki = &KMOD_INFO_NAME;
    char b[32];

    snprintf(b, sizeof(b), ",hv@%p", addr);
    strlcat(ki->version, b, KMOD_MAX_NAME);
}

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
    dprintk("uxen_hv = %p\n", uxen_hv);
    /* Set max prot */
    ret = vm_protect(xnu_kernel_map(), (uint64_t)uxen_hv, uxen_size,
                     1, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (ret) {
        fail_msg("vm_protect(,,,1,) returned %d", ret);
        goto error;
    }
    /* Set prot */
    ret = vm_protect(xnu_kernel_map(), (uint64_t)uxen_hv, uxen_size,
                     0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (ret) {
        fail_msg("vm_protect(,,,0,) returned %d", ret);
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

    set_hv_addr(uxen_hv);

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

    uxen_clear_symbols();

#if !defined(__UXEN_EMBEDDED__)
    if (uxen_hv) {
        kernel_free(uxen_hv, uxen_size);
        uxen_hv = NULL;
    }
#endif

    dprintk("uxen_unload done\n");

    return 0;
}


