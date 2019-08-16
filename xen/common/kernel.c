/******************************************************************************
 * kernel.c
 * 
 * Copyright (c) 2002-2005 K A Fraser
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/version.h>
#include <xen/sched.h>
#include <xen/paging.h>
#include <xen/nmi.h>
#include <xen/guest_access.h>
#include <asm/current.h>
#include <public/nmi.h>
#include <public/version.h>
#ifdef CONFIG_X86
#include <asm/shared.h>
#include <asm/setup.h>
#endif

#ifndef COMPAT

int tainted;

/**
 *      print_tainted - return a string to represent the kernel taint state.
 *
 *  'S' - SMP with CPUs not designed for SMP.
 *  'M' - Machine had a machine check experience.
 *  'B' - System has hit bad_page.
 *
 *      The string is overwritten by the next call to print_taint().
 */
char *print_tainted(char *str)
{
    if ( tainted )
    {
        snprintf(str, TAINT_STRING_MAX_LEN, "Tainted: %c%c%c%c",
                 tainted & TAINT_UNSAFE_SMP ? 'S' : ' ',
                 tainted & TAINT_MACHINE_CHECK ? 'M' : ' ',
                 tainted & TAINT_BAD_PAGE ? 'B' : ' ',
                 tainted & TAINT_SYNC_CONSOLE ? 'C' : ' ');
    }
    else
    {
        snprintf(str, TAINT_STRING_MAX_LEN, "Not tainted");
    }

    return str;
}

void add_taint(unsigned flag)
{
    tainted |= flag;
}

extern initcall_t __initcall_start, __presmp_initcall_end, __initcall_end;

void __init do_presmp_initcalls(void)
{
    initcall_t *call;
    for ( call = &__initcall_start; call < &__presmp_initcall_end; call++ )
        BUG_ON((*call)());
}

void __init do_initcalls(void)
{
    initcall_t *call;
    for ( call = &__presmp_initcall_end; call < &__initcall_end; call++ )
        BUG_ON((*call)());
}

# define DO(fn) long do_##fn

#endif

/*
 * Simple hypercalls.
 */

DO(xen_version)(int cmd, XEN_GUEST_HANDLE(void) arg)
{
    switch ( cmd )
    {
    case XENVER_version:
    {
        return (xen_major_version() << 16) | xen_minor_version();
    }

    case XENVER_extraversion:
    {
        xen_extraversion_t extraversion = { };
        safe_strcpy(extraversion, xen_extra_version());
        if ( copy_to_guest(arg, extraversion, ARRAY_SIZE(extraversion)) )
            return -EFAULT;
        return 0;
    }

    case XENVER_compile_info:
    {
        struct xen_compile_info info = { };
        safe_strcpy(info.compiler,       xen_compiler());
        safe_strcpy(info.compile_by,     xen_compile_by());
        safe_strcpy(info.compile_domain, xen_compile_domain());
        safe_strcpy(info.compile_date,   xen_compile_date());
        if ( copy_to_guest(arg, &info, 1) )
            return -EFAULT;
        return 0;
    }

    case XENVER_capabilities:
    {
        xen_capabilities_info_t info = { };

        arch_get_xen_caps(&info);

        if ( copy_to_guest(arg, info, ARRAY_SIZE(info)) )
            return -EFAULT;
        return 0;
    }
    
    case XENVER_platform_parameters:
    {
        xen_platform_parameters_t params = {
            .virt_start = HYPERVISOR_VIRT_START
        };
        if ( copy_to_guest(arg, &params, 1) )
            return -EFAULT;
        return 0;
        
    }
    
    case XENVER_changeset:
    {
        xen_changeset_info_t chgset = { };
        safe_strcpy(chgset, xen_changeset());
        if ( copy_to_guest(arg, chgset, ARRAY_SIZE(chgset)) )
            return -EFAULT;
        return 0;
    }

    case XENVER_get_features:
    {
        xen_feature_info_t fi;
        struct domain *d = current->domain;

        if ( copy_from_guest(&fi, arg, 1) )
            return -EFAULT;

        switch ( fi.submap_idx )
        {
        case 0:
            fi.submap = 0;
            if ( VM_ASSIST(d, VMASST_TYPE_pae_extended_cr3) )
                fi.submap |= (1U << XENFEAT_pae_pgdir_above_4gb);
            if ( paging_mode_translate(current->domain) )
                fi.submap |= 
                    (1U << XENFEAT_writable_page_tables) |
                    (1U << XENFEAT_auto_translated_physmap);
            if ( supervisor_mode_kernel )
                fi.submap |= 1U << XENFEAT_supervisor_mode_kernel;
            if ( current->domain == dom0 )
                fi.submap |= 1U << XENFEAT_dom0;
#ifdef CONFIG_X86
            if ( !is_hvm_vcpu(current) )
                fi.submap |= (1U << XENFEAT_mmu_pt_update_preserve_ad) |
                             (1U << XENFEAT_highmem_assist) |
                             (1U << XENFEAT_gnttab_map_avail_bits);
            else
                fi.submap |= (1U << XENFEAT_hvm_safe_pvclock) |
                             (1U << XENFEAT_hvm_callback_vector) |
                             (1U << XENFEAT_hvm_pirqs);
#endif
            break;
        default:
            return -EINVAL;
        }

        if ( copy_to_guest(arg, &fi, 1) )
            return -EFAULT;
        return 0;
    }

    case XENVER_pagesize:
    {
        return (!guest_handle_is_null(arg) ? -EINVAL : PAGE_SIZE);
    }

    case XENVER_guest_handle:
    {
        xen_domain_handle_t handle;

        if (restricted_hvm_hypercalls(current->domain))
            return -ENOSYS;

        atomic_read_domain_handle(&current->domain->handle_atomic,
                                  (uint128_t *)handle);

        if ( copy_to_guest(arg, handle, ARRAY_SIZE(handle)) )
            return -EFAULT;
        return 0;
    }

    case XENVER_opt_debug:
    {
        if (!IS_HOST(current->domain))
            return -ENOSYS;

        if ( copy_to_guest(arg, opt_debug, ARRAY_SIZE(opt_debug)) )
            return -EFAULT;
        return 0;
    }
    }

    return -ENOSYS;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
