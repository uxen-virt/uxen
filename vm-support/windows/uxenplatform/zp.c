/*
 * Copyright 2015-2018, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <ntifs.h>

#include <wdm.h>
#include <aux_klib.h>

#include "uxenvmlib.h"

#include "zp.h"

#include <xen/xen.h>
#define __XEN_TOOLS__
#include <xen/xen.h>
#include <xen/memory.h>

#define IN_RANGE(c, s, e) ((s) <= (c) && (c) < (e))
#define BUILD_BUG_ON(condition) ((void)sizeof(struct { int:-!!(condition); }))

#define MEMTAG_ZP_AUX (ULONG)'pzxu'

enum {
    zp_single = 0,
    zp_multiple
};

struct fn_sig {
    uint8_t *sig;
    unsigned int sig_size;
    unsigned int entry;
    unsigned int ret;
    uintptr_t zero_thread_info;
    uint8_t nr_gpfns_mode;
    uint8_t gva_mode;
    uint8_t prologue_mode;
    uint8_t zero_thread_mode;
};

#define DEF_NT_SIG(n, e, r, zt_info, nr_gpfns_mode, gva_mode, prologue_mode, zt_mode) \
    { sig_nt_##n, sizeof(sig_nt_##n), e, (unsigned int)sizeof(sig_nt_##n) - r, \
            zt_info, nr_gpfns_mode, gva_mode, prologue_mode, zt_mode }
#define DEF_NT_SIG_END { NULL, }

struct os_info {
    struct fn_sig *nt_sig;
    uint32_t min_build_num;
};

#ifdef _AMD64_

static uint8_t sig_nt_KeZeroSinglePage_win7[] = {
    0x33, 0xc0, 0xba, 0x40, 0x00, 0x00, 0x00, 0x66,
    0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x89, 0x01, 0x48, 0x89, 0x41, 0x08, 0x48,
    0x89, 0x41, 0x10, 0x48, 0x83, 0xc1, 0x40, 0x48,
    0x89, 0x41, 0xd8, 0x48, 0x89, 0x41, 0xe0, 0xff,
    0xca, 0x48, 0x89, 0x41, 0xe8, 0x48, 0x89, 0x41,
    0xf0, 0x48, 0x89, 0x41, 0xf8, 0x75, 0xd9, 0xc2
};
static uint8_t sig_nt_KeZeroPages_win7[] = {
    0x33, 0xc0, 0x48, 0xc1, 0xea, 0x07, 0x66, 0x66,
    0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x0f, 0xc3, 0x01, 0x48, 0x0f, 0xc3, 0x41,
    0x08, 0x48, 0x0f, 0xc3, 0x41, 0x10, 0x48, 0x0f,
    0xc3, 0x41, 0x18, 0x48, 0x0f, 0xc3, 0x41, 0x20,
    0x48, 0x0f, 0xc3, 0x41, 0x28, 0x48, 0x0f, 0xc3,
    0x41, 0x30, 0x48, 0x0f, 0xc3, 0x41, 0x38, 0x48,
    0x81, 0xc1, 0x80, 0x00, 0x00, 0x00, 0x48, 0x0f,
    0xc3, 0x41, 0xc0, 0x48, 0x0f, 0xc3, 0x41, 0xc8,
    0x48, 0x0f, 0xc3, 0x41, 0xd0, 0x48, 0x0f, 0xc3,
    0x41, 0xd8, 0x48, 0x0f, 0xc3, 0x41, 0xe0, 0x48,
    0x0f, 0xc3, 0x41, 0xe8, 0x48, 0x0f, 0xc3, 0x41,
    0xf0, 0x48, 0x0f, 0xc3, 0x41, 0xf8, 0x48, 0xff,
    0xca, 0x75, 0xa5, 0xf0, 0x80, 0x0c, 0x24, 0x00,
    0xc3
};

static uint8_t sig_nt_KeZeroSinglePage_win10[] = {
    0x33, 0xc0, 0xba, 0x40, 0x00, 0x00, 0x00, 0x66,
    0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x89, 0x01, 0x48, 0x89, 0x41, 0x08, 0x48,
    0x89, 0x41, 0x10, 0x48, 0x83, 0xc1, 0x40, 0x48,
    0x89, 0x41, 0xd8, 0x48, 0x89, 0x41, 0xe0, 0xff,
    0xca, 0x48, 0x89, 0x41, 0xe8, 0x48, 0x89, 0x41,
    0xf0, 0x48, 0x89, 0x41, 0xf8, 0x75, 0xd9, 0xc3
};
static uint8_t sig_nt_KeZeroPages_win10[] = {
    0x33, 0xc0, 0x48, 0xc1, 0xea, 0x07, 0x66, 0x66,
    0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x0f, 0xc3, 0x01, 0x48, 0x0f, 0xc3, 0x41,
    0x08, 0x48, 0x0f, 0xc3, 0x41, 0x10, 0x48, 0x0f,
    0xc3, 0x41, 0x18, 0x48, 0x0f, 0xc3, 0x41, 0x20,
    0x48, 0x0f, 0xc3, 0x41, 0x28, 0x48, 0x0f, 0xc3,
    0x41, 0x30, 0x48, 0x0f, 0xc3, 0x41, 0x38, 0x48,
    0x81, 0xc1, 0x80, 0x00, 0x00, 0x00, 0x48, 0x0f,
    0xc3, 0x41, 0xc0, 0x48, 0x0f, 0xc3, 0x41, 0xc8,
    0x48, 0x0f, 0xc3, 0x41, 0xd0, 0x48, 0x0f, 0xc3,
    0x41, 0xd8, 0x48, 0x0f, 0xc3, 0x41, 0xe0, 0x48,
    0x0f, 0xc3, 0x41, 0xe8, 0x48, 0x0f, 0xc3, 0x41,
    0xf0, 0x48, 0x0f, 0xc3, 0x41, 0xf8, 0x48, 0xff,
    0xca, 0x75, 0xa5, 0x0f, 0xae, 0xf8, 0xc3
};

static struct fn_sig nt_sig_win7[] = {
    DEF_NT_SIG(KeZeroSinglePage_win7, 16, 1, 0,
               XEN_MEMORY_SET_ZERO_PAGE_NR_GPFN_MODE_single,
               XEN_MEMORY_SET_ZERO_PAGE_GVA_MODE_single,
               XEN_MEMORY_SET_ZERO_PAGE_PROLOGUE_none,
               XEN_MEMORY_SET_ZERO_PAGE_ZERO_THREAD_MODE_none),
    DEF_NT_SIG(KeZeroPages_win7, 16, 1, 8,
               XEN_MEMORY_SET_ZERO_PAGE_NR_GPFN_MODE_edx_shift_5,
               XEN_MEMORY_SET_ZERO_PAGE_GVA_MODE_ecx,
               XEN_MEMORY_SET_ZERO_PAGE_PROLOGUE_none,
               XEN_MEMORY_SET_ZERO_PAGE_ZERO_THREAD_MODE_gs_pcr_188),
    DEF_NT_SIG_END
};

static struct fn_sig nt_sig_win10[] = {
    DEF_NT_SIG(KeZeroSinglePage_win10, 16, 1, 0,
               XEN_MEMORY_SET_ZERO_PAGE_NR_GPFN_MODE_single,
               XEN_MEMORY_SET_ZERO_PAGE_GVA_MODE_single,
               XEN_MEMORY_SET_ZERO_PAGE_PROLOGUE_none,
               XEN_MEMORY_SET_ZERO_PAGE_ZERO_THREAD_MODE_none),
    DEF_NT_SIG(KeZeroPages_win10, 16, 1, 0x28,
               XEN_MEMORY_SET_ZERO_PAGE_NR_GPFN_MODE_edx_shift_5,
               XEN_MEMORY_SET_ZERO_PAGE_GVA_MODE_ecx,
               XEN_MEMORY_SET_ZERO_PAGE_PROLOGUE_none,
               XEN_MEMORY_SET_ZERO_PAGE_ZERO_THREAD_MODE_cr3),
    DEF_NT_SIG_END
};

static struct os_info oses[] = {
    /* this needs to be sorted by min_build_num */
    { nt_sig_win7, 7601 },
    { nt_sig_win10, 10240 },
};

#else  /* _AMD64_ */

static uint8_t sig_nt_KiXMMIZeroPagesNoSave_win7_32b[] = {
    0x0f, 0x57, 0xc0, 0xc1, 0xea, 0x06, 0x0f, 0x2b,
    0x01, 0x0f, 0x2b, 0x41, 0x10, 0x0f, 0x2b, 0x41,
    0x20, 0x0f, 0x2b, 0x41, 0x30, 0x83, 0xc1, 0x40,
    0x4a, 0x75, 0xeb, 0x0f, 0xae, 0xf8, 0x87, 0x54,
    0x24, 0xfc, 0xc3
};

static uint8_t sig_nt_KiZeroPages_win7_32b[] = {
    0x57, 0x33, 0xc0, 0x8b, 0xf9, 0x8b, 0xca, 0xc1,
    0xe9, 0x02, 0xf3, 0xab, 0x5f, 0xc3
};

static struct fn_sig nt_sig_win7[] = {
    DEF_NT_SIG(KiXMMIZeroPagesNoSave_win7_32b, 6, 1, 8,
               XEN_MEMORY_SET_ZERO_PAGE_NR_GPFN_MODE_edx_shift_6,
               XEN_MEMORY_SET_ZERO_PAGE_GVA_MODE_ecx,
               XEN_MEMORY_SET_ZERO_PAGE_PROLOGUE_clear_edx,
               XEN_MEMORY_SET_ZERO_PAGE_ZERO_THREAD_MODE_fs_pcr_124),
    DEF_NT_SIG(KiZeroPages_win7_32b, 10, 2, 8,
               XEN_MEMORY_SET_ZERO_PAGE_NR_GPFN_MODE_ecx_shift_10,
               XEN_MEMORY_SET_ZERO_PAGE_GVA_MODE_edi,
               XEN_MEMORY_SET_ZERO_PAGE_PROLOGUE_none,
               XEN_MEMORY_SET_ZERO_PAGE_ZERO_THREAD_MODE_fs_pcr_124),
    DEF_NT_SIG_END
};

static struct os_info oses[] = {
    /* this needs to be sorted by min_build_num */
    { nt_sig_win7, 7601 },
};

#endif  /* _AMD64_ */

struct module_range {
    uint8_t *base;
    unsigned int size;
};

static void
get_module_range(char *module, uintptr_t addr, struct module_range *range)
{
    NTSTATUS status;
    AUX_MODULE_EXTENDED_INFO *modules = NULL;
    ULONG modules_size, i;

    range->base = NULL;
    range->size = 0;

    status = AuxKlibInitialize();
    if (!NT_SUCCESS(status))
        goto out;

    status = AuxKlibQueryModuleInformation(&modules_size,
                                           sizeof(*modules),
                                           NULL);
    if (!NT_SUCCESS(status) || modules_size == 0)
        goto out;

    modules = (AUX_MODULE_EXTENDED_INFO *)ExAllocatePoolWithTag(
        NonPagedPool,
        modules_size,
        MEMTAG_ZP_AUX);
    if (!modules)
        goto out;

    RtlZeroMemory(modules, modules_size);
    status = AuxKlibQueryModuleInformation(&modules_size,
                                           sizeof(*modules),
                                           modules);
    if (!NT_SUCCESS(status))
        goto out;

    for (i = 0; i < (modules_size / sizeof(*modules)); i++)
        if (!_strnicmp(
                (char *)&modules[i].FullPathName[modules[i].FileNameOffset],
                module, TRUE) &&
            IN_RANGE(addr,
                     (uintptr_t)modules[i].BasicInfo.ImageBase,
                     (uintptr_t)modules[i].BasicInfo.ImageBase +
                     (uintptr_t)modules[i].ImageSize)) {
            range->base = (uint8_t *)modules[i].BasicInfo.ImageBase;
            range->size = modules[i].ImageSize;
            break;
        }

  out:
    if (modules)
        ExFreePool(modules);
}

static void
find_fn(struct module_range *nt, struct xen_memory_set_zero_page_desc *zp,
        struct fn_sig *fn)
{
    NTSTATUS status;
    uint8_t t[256], o;
    unsigned int i, s = fn->sig_size;
    uint8_t *sig = fn->sig;
    uint8_t *base = NULL;
    unsigned int size = 0;

    IMAGE_DOS_HEADER *dos_h = (IMAGE_DOS_HEADER *)nt->base;
    IMAGE_NT_HEADERS *nt_h;
    IMAGE_SECTION_HEADER *sec_h;
    int sec;

    if (dos_h->e_magic != IMAGE_DOS_SIGNATURE) {
        uxen_err("zp-%s: IMAGE_DOS_SIGNATURE not found", __FUNCTION__);
        return;
    }

    nt_h = (IMAGE_NT_HEADERS *)(nt->base + dos_h->e_lfanew);
    if (nt_h->Signature != IMAGE_NT_SIGNATURE) {
        uxen_err("zp-%s: IMAGE_NT_SIGNATURE not found", __FUNCTION__);
        return;
    }

    sec_h = IMAGE_FIRST_SECTION(nt_h);
    uxen_debug("dos_h %p nt_h %p nr_sec %d sec_h %p boc %p",
               dos_h, nt_h, nt_h->FileHeader.NumberOfSections, sec_h,
               (void *)(nt_h->OptionalHeader.BaseOfCode));

    for (sec = 0; sec < nt_h->FileHeader.NumberOfSections; sec++) {
        uxen_debug("  sec %.*s va %p size %lx",
                   IMAGE_SIZEOF_SHORT_NAME, sec_h[sec].Name,
                   (void *)(nt->base + sec_h[sec].VirtualAddress),
                   sec_h[sec].Misc.VirtualSize);
        if (sec_h[sec].VirtualAddress == nt_h->OptionalHeader.BaseOfCode) {
            base = nt->base + sec_h[sec].VirtualAddress;
            size = sec_h[sec].Misc.VirtualSize;
            break;
        }
    }

    if (!base) {
        uxen_msg("zp-%s: no BaseOfCode code section found", __FUNCTION__);
        return;
    }

    ASSERT(s < 255);
    memset(t, 0, 256);
    for (i = 0; i < s; i++)
        t[sig[i]] = (uint8_t)(i + 1);

    i = s - 1;
    while (i < size) {
        o = t[base[i]];
        if (o == s) {
            i -= (o - 1);
            if (!memcmp(sig, &base[i], s)) {
                uxen_msg("zp-%s: found @ 0x%p (entry:0x%x ret:0x%x, type:%s)",
                         __FUNCTION__, (void *)&base[i], fn->entry, fn->ret,
                         (fn->nr_gpfns_mode ==
                          XEN_MEMORY_SET_ZERO_PAGE_NR_GPFN_MODE_single) ?
                         "single" : "multi");
                zp->entry = (uint64_t)&base[i] + fn->entry;
                zp->ret = (uint64_t)&base[i] + fn->ret;
                zp->nr_gpfns_mode = fn->nr_gpfns_mode;
                zp->gva_mode = fn->gva_mode;
                zp->prologue_mode = fn->prologue_mode;
                if (fn->zero_thread_mode ==
                    XEN_MEMORY_SET_ZERO_PAGE_ZERO_THREAD_MODE_gs_pcr_188 ||
                    fn->zero_thread_mode ==
                    XEN_MEMORY_SET_ZERO_PAGE_ZERO_THREAD_MODE_fs_pcr_124) {
                    status = PsLookupThreadByThreadId(
                        (HANDLE)fn->zero_thread_info,
                        (PETHREAD *)&zp->zero_thread_addr);
                    if (!NT_SUCCESS(status)) {
                        uxen_msg("zp-%s: unable to lookup zero thread id %I64d",
                                 __FUNCTION__, (uint64_t)fn->zero_thread_info);
                        zp->zero_thread_addr = 0;
                    } else {
                        uxen_msg("zp-%s: zero thread @ 0x%I64x", __FUNCTION__,
                                 zp->zero_thread_addr);
                        zp->zero_thread_mode = fn->zero_thread_mode;
                    }
                } else if (fn->zero_thread_mode ==
                           XEN_MEMORY_SET_ZERO_PAGE_ZERO_THREAD_MODE_cr3) {
                    if (PsGetCurrentProcess() == PsInitialSystemProcess)
                        zp->zero_thread_paging_base = __readcr3() & ~((uint64_t) 0xfff);
                    else
                        zp->zero_thread_paging_base =
                            (uint64_t)PsInitialSystemProcess +
                            fn->zero_thread_info;
                    uxen_msg("zp-%s: zero thread cr3 is 0x%I64x", __FUNCTION__,
                             zp->zero_thread_paging_base);
                    zp->zero_thread_mode = fn->zero_thread_mode;
                }
                return;
            }
            i += s;
        } else
            i += s - o;
    }
}

void
zp_init(void)
{
    struct module_range nt;
    struct xen_memory_set_zero_page_ctxt zp_arg;
    int rc, n, zp_arg_nr = 0;
    NTSTATUS status;
    RTL_OSVERSIONINFOW os_ver;
    struct os_info *os;

    get_module_range("ntoskrnl.exe", (uintptr_t)&KeWaitForSingleObject, &nt);
    if (!nt.base || nt.size == 0) {
        uxen_msg("zp: unable to find NT module");
        return;
    }

    RtlZeroMemory(&os_ver, sizeof(os_ver));
    os_ver.dwOSVersionInfoSize = sizeof(os_ver);
    status = RtlGetVersion(&os_ver);
    uxen_msg("zp: os-build: %d", os_ver.dwBuildNumber);

    os = NULL;
    for (n = ARRAYSIZE(oses) - 1; n >= 0; n--)
        if (os_ver.dwBuildNumber >= oses[n].min_build_num) {
            os = &oses[n];
            break;
        }
    if (!os) {
        uxen_msg("zp: unable to find present OS details");
        return;
    }

    BUILD_BUG_ON(
        XEN_MEMORY_SET_ZERO_PAGE_DESC_MAX < ARRAYSIZE(nt_sig_win7) - 1);
#ifdef _AMD64_
    BUILD_BUG_ON(
        XEN_MEMORY_SET_ZERO_PAGE_DESC_MAX < ARRAYSIZE(nt_sig_win10) - 1);
#endif /* _AMD64_ */

    RtlZeroMemory(&zp_arg, sizeof(zp_arg));

    n = 0;
    while (os->nt_sig[n].sig && zp_arg_nr < XEN_MEMORY_SET_ZERO_PAGE_DESC_MAX) {
        find_fn(&nt, &zp_arg.zp[zp_arg_nr], &os->nt_sig[n]);
        if (zp_arg.zp[zp_arg_nr].entry)
            zp_arg_nr++;
        n++;
    }
    if (!zp_arg_nr) {
        uxen_msg("zp: unable to find any page zeroing functions");
        return;
    }
    zp_arg.nr_desc = zp_arg_nr;

    rc = uxen_hypercall_memory_op(XENMEM_set_zero_page_ctxt, &zp_arg);
    if (rc)
        uxen_msg("zp: hypercall XENMEM_set_zero_page_ctxt failed: %d", rc);
}
