/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "uxen.h"
#include <libkern/libkern.h>

static int xnu_symbols_loaded = 0;
int xnu_symbols_present = 0;

struct xnu_symbol {
    const char *name;
    uint64_t addr;
};

static char *string_table = NULL;
static struct xnu_symbol *symbols = NULL;
static uint32_t str_tbl_sz, sym_tbl_sz;
static uint32_t symbol_count = 0;

int
uxen_load_xnu_symbols(struct uxen_syms_desc *usd)
{
    struct uxen_xnu_sym *syms;
    void *desc;
    uint32_t i;
    int rc;

    if (xnu_symbols_loaded) {
        fail_msg("already loaded");
        return EINVAL;
    }

    if (usd->usd_size < usd->usd_symnum * sizeof(struct uxen_xnu_sym)) {
        fail_msg("invalid array");
        return EINVAL;
    }

    desc = kernel_malloc(usd->usd_size);
    if (desc == NULL) {
	fail_msg("out of memory");
        return ENOMEM;
    }

    rc = copyin((user_addr_t)usd->usd_xnu_syms, desc, usd->usd_size);
    if (rc) {
        fail_msg("wrong user addr");
        kernel_free(desc, usd->usd_size);
        return EFAULT;
    }
    syms = desc;

    sym_tbl_sz = usd->usd_symnum * sizeof (struct xnu_symbol);
    symbols = kernel_malloc(sym_tbl_sz);
    if (symbols == NULL) {
        fail_msg("symbols alloc, out of memory");
        kernel_free(desc, usd->usd_size);
	return ENOMEM;
    }

    str_tbl_sz = usd->usd_size - usd->usd_symnum * sizeof (struct uxen_xnu_sym);
    string_table = kernel_malloc(str_tbl_sz);
    if (string_table == NULL) {
        fail_msg("strtbl alloc, out of memory");
        kernel_free(desc, usd->usd_size);
        kernel_free(symbols, sym_tbl_sz);
        return ENOMEM;
    }

    memcpy(string_table,
           (char *)desc + usd->usd_symnum * sizeof(struct uxen_xnu_sym),
           str_tbl_sz);

    for (i = 0, syms = desc; i < usd->usd_symnum; i++, syms++) {
        /* This function essentially ask us to trust the issuer of ioctl,
         * so security is pointless but, for the paranoid,
         * we should check that syms->name is sane and that the address
         * is a kernel address (belonging to Mach?). */
        symbols[i].addr = syms->addr;
        symbols[i].name = string_table + syms->name;
    }
    symbol_count = i;

    kernel_free(desc, usd->usd_size);
    xnu_symbols_loaded = 1;
    dprintk("%d XNU symbols loaded.\n", i);

    return 0;
}

static void
unload_xnu_symbols(void)
{

    kernel_free(symbols, sym_tbl_sz);
    kernel_free(string_table, str_tbl_sz);

    xnu_symbols_loaded = 0;
}

static void *
find_xnu_symbol(const char *name)
{
    int i;

    for (i = 0; i < symbol_count; i++)
        if (!strcmp(name, symbols[i].name))
            return (void *)symbols[i].addr;

    dprintk("symbol \"%s\" not found\n", name);

    return NULL;
}


static processor_t dummy_thread_bind(processor_t p)
{
    return (processor_t)0;
}

static processor_t dummy_cpu_to_processor(int cpu)
{
    return (processor_t)0;
}


vm_page_grab_t xnu_vm_page_grab;
vm_page_wait_t xnu_vm_page_wait;
vm_page_release_t xnu_vm_page_release;
vm_page_free_list_t xnu_vm_page_free_list;
pmap_enter_t xnu_pmap_enter;
pmap_remove_t xnu_pmap_remove;
vm_map_wire_t xnu_vm_map_wire;
vm_map_unwire_t xnu_vm_map_unwire;
vm_map_deallocate_t xnu_vm_map_deallocate;
get_task_map_reference_t xnu_get_task_map_reference;
get_map_pmap_t xnu_get_map_pmap;
_enable_preemption_t xnu_enable_preemption;
_disable_preemption_t xnu_disable_preemption;
thread_bind_t xnu_thread_bind = dummy_thread_bind;
cpu_to_processor_t xnu_cpu_to_processor = dummy_cpu_to_processor;
current_processor_t xnu_current_processor;
mp_cpus_call_t xnu_mp_cpus_call;
timer_call_enter_t xnu_timer_call_enter;
timer_call_setup_t xnu_timer_call_setup;
timer_call_cancel_t xnu_timer_call_cancel;
ast_pending_t xnu_ast_pending;
thread_block_reason_t xnu_thread_block_reason;
clock_gettimeofday_t xnu_clock_gettimeofday;

static vm_map_t *kernel_map;
static unsigned *pmap_memory_region_count;
static void *pmap_memory_regions;
static uint64_t *physmap_base;
static uint64_t *physmap_max;
static cpu_data_t **cpu_data_ptr;

int
init_xnu_symbols(void)
{
    uint64_t slide;
    int i;

    if (!xnu_symbols_loaded) {
        fail_msg("no symbols loaded");
        return -1;
    }

    slide = (uintptr_t)(void *)printf - (uintptr_t)find_xnu_symbol("_printf");

    dprintk("Kernel slide = %llx\n", slide);

    for (i = 0; i < symbol_count; i++)
        symbols[i].addr += slide;

    xnu_vm_page_grab = find_xnu_symbol("_vm_page_grab");
    xnu_vm_page_wait = find_xnu_symbol("_vm_page_wait");
    xnu_vm_page_release = find_xnu_symbol("_vm_page_release");
    xnu_vm_page_free_list = find_xnu_symbol("_vm_page_free_list");
    xnu_pmap_enter = find_xnu_symbol("_pmap_enter");
    xnu_pmap_remove = find_xnu_symbol("_pmap_remove");
    xnu_vm_map_wire = find_xnu_symbol("_vm_map_wire");
    xnu_vm_map_unwire = find_xnu_symbol("_vm_map_unwire");
    xnu_vm_map_deallocate = find_xnu_symbol("_vm_map_deallocate");
    xnu_get_task_map_reference = find_xnu_symbol("_get_task_map_reference");
    xnu_get_map_pmap = find_xnu_symbol("_get_map_pmap");
    xnu_enable_preemption = find_xnu_symbol("__enable_preemption");
    xnu_disable_preemption = find_xnu_symbol("__disable_preemption");
    xnu_thread_bind = find_xnu_symbol("_thread_bind");
    xnu_cpu_to_processor = find_xnu_symbol("_cpu_to_processor");
    xnu_current_processor = find_xnu_symbol("_current_processor");
    xnu_mp_cpus_call = find_xnu_symbol("_mp_cpus_call");
    xnu_timer_call_enter = find_xnu_symbol("_timer_call_enter");
    xnu_timer_call_setup = find_xnu_symbol("_timer_call_setup");
    xnu_timer_call_cancel = find_xnu_symbol("_timer_call_cancel");
    xnu_ast_pending = find_xnu_symbol("_ast_pending");
    xnu_thread_block_reason = find_xnu_symbol("_thread_block_reason");
    xnu_clock_gettimeofday = find_xnu_symbol("_clock_gettimeofday");
    kernel_map = find_xnu_symbol("_kernel_map");
    pmap_memory_regions = find_xnu_symbol("_pmap_memory_regions");
    pmap_memory_region_count = find_xnu_symbol("_pmap_memory_region_count");
    cpu_data_ptr = find_xnu_symbol("_cpu_data_ptr");
    physmap_base = find_xnu_symbol("_physmap_base");
    physmap_max = find_xnu_symbol("_physmap_max");
#ifdef __XNU_BUG_VM_PAGE_WIRE_COUNT_WORKAROUND__
    xnu_vm_page_locks = find_xnu_symbol("_vm_page_locks");
    xnu_vm_page_wire_count = find_xnu_symbol("_vm_page_wire_count");
#endif

    xnu_symbols_present = 1;

    unload_xnu_symbols();

    return 0;
}

vm_map_t
xnu_kernel_map(void)
{
    return *kernel_map;
}

unsigned
xnu_pmap_memory_region_count(void)
{
    return *pmap_memory_region_count;
}

void *
xnu_pmap_memory_regions(void)
{
    return pmap_memory_regions;
}

uint64_t
xnu_physmap_base(void)
{
    return *physmap_base;
}

uint64_t
xnu_physmap_max(void)
{
    return *physmap_max;
}

cpu_data_t **
xnu_cpu_data_ptr(void)
{
    return cpu_data_ptr;
}
