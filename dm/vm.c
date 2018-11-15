/*
 * Copyright 2012-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "aio.h"
#include "console.h"
#include "control.h"
#include "dm.h"
#include "dmreq.h"
#include "firmware.h"
#include "ioh.h"
#include "ioreq.h"
#include "mapcache.h"
#include "monitor.h"
#include "sockets.h"
#include "hw.h"
#include "uxen.h"
#include "vm.h"
#include "vm-save.h"
#include "shared-folders.h"
#include "clipboard.h"
#include "hw/uxen_platform.h"
#include "dm-features.h"

#if defined(CONFIG_NICKEL)
#include <dm/libnickel.h>
#endif

#ifdef CONFIG_DUMP_PERIODIC_STATS
#include <sys/time.h>
#include "timer.h"
#endif  /* CONFIG_DUMP_PERIODIC_STATS */

#include <xenctrl.h>
#include <xc_private.h>
#undef _IOREQ_H_
#include <xen/hvm/ioreq.h>
#include <xenguest.h>

#ifdef HAS_AUDIO
#include "hw/uxen_audio_ctrl.h"
#endif

#include <dm/whpx/whpx.h>

#include "vm-savefile-simple.h"

static struct xc_hvm_oem_info oem_info = { 0 };
static critical_section vm_run_mode_lock;
critical_section vm_pause_lock;
static ioh_event vm_run_mode_change;
static int vm_init_lk = 0;

uint64_t vm_restricted_x86_emul = 0;
uint64_t vm_viridian_crash_domain = 0;
uint64_t vm_vpt_align = 0;
uint64_t vm_vpt_coalesce_period = 0;

bool vm_run_patcher = true;
uint64_t seed_generation = 1;
uint64_t surf_copy_reduction = 1;

bool vm_quit_interrupt = false;

static void vm_run_mode_change_cb(void *opaque);

#ifdef CONFIG_DUMP_PERIODIC_STATS
static struct Timer *periodic_stats_timer = NULL;
static int periodic_stats_rep = 129;

static void dump_stats(void)
{
#ifdef CONFIG_DUMP_CPU_STAT
    float cpu, cpu_k, cpu_u;
#endif  /* CONFIG_DUMP_CPU_STAT */
#ifdef CONFIG_DUMP_BLOCK_STAT
    static uint64_t prevrds = 0, prevrdops = 0, prevwrs = 0, prevwrops = 0;
    uint64_t rds, rdops, wrs, wrops;
#endif  /* CONFIG_DUMP_BLOCK_STAT */
    uint64_t vm_now;
    xc_dominfo_t info = { };
    int ret;

    vm_now = get_clock_ms(vm_clock); 

#ifdef CONFIG_DUMP_MEMORY_STAT
    int bln_sz = 0, bln_min = 0, bln_max = 0;
    if (!whpx_enable)
        ret = xc_domain_getinfo(xc_handle, vm_id, 1, &info);
    else {
        ret = 1;
        info.domid = vm_id;
    }
    uxen_platform_get_balloon_size(&bln_sz, &bln_min, &bln_max);
#else  /* CONFIG_DUMP_MEMORY_STAT */
    ret = 1;
    info.domid = vm_id;
#endif  /* CONFIG_DUMP_MEMORY_STAT */

#ifdef CONFIG_DUMP_BLOCK_STAT
    blockstats_getabs(&rds, &rdops, &wrs, &wrops);
#endif  /* CONFIG_DUMP_BLOCK_STAT */

#ifdef CONFIG_DUMP_CPU_STAT
    cpu_usage(&cpu_u, &cpu_k, NULL, NULL);
    cpu = cpu_u + cpu_k;
#endif  /* CONFIG_DUMP_CPU_STAT */

    if (ret == 1 && info.domid == vm_id) {
	debug_printf("DMEM %08"PRIu64
#ifdef CONFIG_DUMP_MEMORY_STAT
                     " %lu %lu %lu %lu %lu %u %u %u"
#endif  /* CONFIG_DUMP_MEMORY_STAT */
#ifdef CONFIG_DUMP_BLOCK_STAT
                     " %"PRId64" %"PRId64" %"PRId64" %"PRId64
#endif  /* CONFIG_DUMP_BLOCK_STAT */
#ifdef CONFIG_DUMP_CPU_STAT
                     " [ %.2f: %.2f, %.2f]"
#endif  /* CONFIG_DUMP_CPU_STAT */
                     "\n", vm_now
#ifdef CONFIG_DUMP_MEMORY_STAT
                     ,
                     info.nr_pages,
                     info.nr_hidden_pages,
                     info.nr_pod_pages,
                     info.nr_zero_shared_pages,
                     info.nr_tmpl_shared_pages,
                     bln_sz, bln_min, bln_max
#endif  /* CONFIG_DUMP_MEMORY_STAT */
#ifdef CONFIG_DUMP_BLOCK_STAT
                     ,
                     rds - prevrds, rdops - prevrdops,
                     wrs - prevwrs, wrops - prevwrops
#endif  /* CONFIG_DUMP_BLOCK_STAT */
#ifdef CONFIG_DUMP_CPU_STAT
                     ,
                     100 * cpu, 100 * cpu_k, 100 * cpu_u
#endif  /* CONFIG_DUMP_CPU_STAT */
            );
    }
#ifdef CONFIG_DUMP_BLOCK_STAT
    prevrds = rds;
    prevrdops = rdops;
    prevwrs = wrs;
    prevwrops = wrops;
#endif  /* CONFIG_DUMP_BLOCK_STAT */
}
#ifdef CONFIG_DUMP_SWAP_STAT
extern void dump_swapstat(void);
#endif  /* CONFIG_DUMP_SWAP_STAT */

static void aperiodic_stats(void *opaque)
{
    uint64_t now = get_clock_ms(vm_clock);
    uint64_t interval;

    dump_stats();
#ifdef CONFIG_DUMP_SWAP_STAT
    dump_swapstat();
#endif  /* CONFIG_DUMP_SWAP_STAT */

    if (periodic_stats_rep > 0) {
	if (periodic_stats_rep-- > 60)
	    interval = 100;
	else
            interval = 1000;
    } else
        interval = 60000;

    mod_timer(periodic_stats_timer, now + interval);
}

#ifdef CONFIG_DUMP_MEMORY_STAT
static void dump_periodic_stats_reset(void)
{
    periodic_stats_rep = 129;
    aperiodic_stats(NULL);
}
#endif

static void dump_periodic_stats_init(void)
{
    uint64_t now = get_clock_ms(vm_clock);

    periodic_stats_timer = new_timer_ms(vm_clock, aperiodic_stats, NULL);
    mod_timer(periodic_stats_timer, now + 100);
}
#endif  /* CONFIG_DUMP_PERIODIC_STATS */

#define LOG_SIZE 16384
struct uxen_logging_buffer *vm_logging_buffer;
int vm_logging_buffer_size = LOG_SIZE - sizeof(struct uxen_logging_buffer);
static uxen_notification_event vm_logging_event = NULL;

void
vm_set_oem_id(const char *oem_id)
{
    memcpy(oem_info.oem_id, oem_id, 6);
    oem_info.flags |= XC_HVM_OEM_ID;
}

void
vm_set_oem_table_id(const char *oem_table_id)
{
    memcpy(oem_info.oem_table_id, oem_table_id, 8);
    oem_info.flags |= XC_HVM_OEM_TABLE_ID;
}

void
vm_set_oem_revision(uint32_t revision)
{
    oem_info.oem_revision = revision;
    oem_info.flags |= XC_HVM_OEM_REVISION;
}

void
vm_set_oem_creator_id(const char *creator_id)
{
    memcpy(oem_info.creator_id, creator_id, 4);
    oem_info.flags |= XC_HVM_CREATOR_ID;
}

void
vm_set_oem_creator_revision(uint32_t revision)
{
    oem_info.creator_revision = revision;
    oem_info.flags |= XC_HVM_CREATOR_REVISION;
}

void
vm_set_smbios_version_major(uint8_t major)
{
    oem_info.smbios_version_major = major;
    oem_info.flags |= XC_HVM_SMBIOS_MAJOR;
}

void
vm_set_smbios_version_minor(uint8_t minor)
{
    oem_info.smbios_version_minor = minor;
    oem_info.flags |= XC_HVM_SMBIOS_MINOR;
}

static struct xc_hvm_mod_entry *
mod_entries(struct fw_list_head *list, size_t *ent_count)
{
    struct xc_hvm_mod_entry *entries;
    size_t count = 0;
    struct firmware_info *fi;
    size_t i = 0;

    TAILQ_FOREACH(fi, list, link)
        count++;

    if (!count) {
        *ent_count = 0;
        return NULL;
    }

    entries = calloc(count, sizeof(*entries));

    TAILQ_FOREACH(fi, list, link) {
        entries[i].base = fi->data;
        entries[i].len = fi->len;
        entries[i].flags = 0;
        i++;
    }

    *ent_count = i;

    return entries;
}

void
vm_cleanup_modules(struct xc_hvm_module *modules, size_t count)
{
    int i;

    for (i = 0; i < count; i++) {
        free(modules[i].entries);
    }

    free(modules);
}

struct xc_hvm_module *
vm_get_modules(int *mod_count)
{
    struct xc_hvm_module *modules = NULL;
    int count = 0;

    modules = calloc(2, sizeof(*modules));
    if (!modules)
        return NULL;

    /* ACPI modules */
    modules[count].type = XC_HVM_MODULE_ACPI;
    modules[count].entries = mod_entries(&acpi_modules,
                                         &modules[count].nent);
    if (modules[count].entries)
        count++;

    /* SMBIOS modules */
    modules[count].type = XC_HVM_MODULE_SMBIOS;
    modules[count].entries = mod_entries(&smbios_modules,
                                         &modules[count].nent);
    if (modules[count].entries)
        count++;

    if (!count) {
        free(modules);
        return NULL;
    }

    *mod_count = count;

    return modules;
}

static int check_smep_cpu_support()
{
    char brand[13];
    unsigned int regs[4];
    unsigned int input[2] = {7, 0};

    xc_cpuid_brand_get(brand);
    if (!strstr(brand, "Intel")) {
        warnx("SMEP not supported on non-Intel CPU");
        return 0;
    }

    xc_cpuid(input, regs);
    /* See Intel SDM, volume 2, table 3-17 */
    if (regs[1] & (1<<7)) {
        warnx("SMEP forced in the guest");
        return 1;
    } else {
        warnx("SMEP not supported by CPU");
        return 0;
    }
}

static uint64_t compute_introspection_features()
{
    uint64_t features = 0;

    if (strstr(lava_options, "cr0wp"))
        features |= XEN_DOMCTL_INTROSPECTION_FEATURE_CR0WPCLEAR;

    if (strstr(lava_options, "cr4vmxe"))
        features |= XEN_DOMCTL_INTROSPECTION_FEATURE_CR4VMXESET;

    if (strstr(lava_options, "immutable_memory"))
        features |= XEN_DOMCTL_INTROSPECTION_FEATURE_IMMUTABLE_MEMORY;

    if (strstr(lava_options, "process_hiding"))
        features |= XEN_DOMCTL_INTROSPECTION_FEATURE_HIDDEN_PROCESS;

    if (strstr(lava_options, "debug_rootkit"))
        features |= XEN_DOMCTL_INTROSPECTION_FEATURE_DR_BACKDOOR;

    if (strstr(lava_options, "smep") && check_smep_cpu_support())
        features |= XEN_DOMCTL_INTROSPECTION_FEATURE_SMEP;

    debug_printf("compute_introspection_features: 0x%lx\n",
                 (long unsigned int)features);

    return features;
}

static void
handle_logging_event(void *opaque)
{
    char *buf;
    static uint64_t pos = 0;
    uint32_t incomplete;

    while (1) {
        buf = uxen_logging_read(vm_logging_buffer, &pos, &incomplete);
        if (!buf)
            break;
        if (incomplete)
            debug_printf("[vm logbuf overflow -- output incomplete]");
        debug_printf("%s", buf);
        free(buf);
    }
}

static bool template_load_failed = true;
static void
error_template_destroy(void)
{

    if (template_load_failed)
        uxen_destroy_vm(uxen_handle, vm_uuid); /* ignore errors */
}

void
vm_set_vpt_coalesce(int onoff)
{
    if (!whpx_enable)
        xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_VPT_COALESCE_NS,
            onoff ? vm_vpt_coalesce_period : 0);
}

void
vm_create(int restore_mode)
{
    int i;
    int ret;

    critical_section_init(&vm_run_mode_lock);
    critical_section_init(&vm_pause_lock);
    ioh_event_init(&vm_run_mode_change);
    ioh_add_wait_object(&vm_run_mode_change, vm_run_mode_change_cb, NULL, NULL);
    vm_init_lk = 1;

    for (i = 0; i < vm_vcpus; i++)
        vm_vcpu_avail[i / 8] |= 1 << (i % 8);

    if (v4v_idtoken_is_vm_uuid)
        memcpy(v4v_idtoken, vm_uuid, sizeof(v4v_idtoken));

    if (whpx_enable)
        return;

    ret = uxen_create_vm(uxen_handle, vm_uuid, v4v_idtoken,
                         XEN_DOMCTL_CDF_hvm_guest | XEN_DOMCTL_CDF_hap |
                         (restore_mode == VM_RESTORE_TEMPLATE ?
                          XEN_DOMCTL_CDF_template : 0) |
                         (vm_hidden_mem == 1 ? XEN_DOMCTL_CDF_hidden_mem : 0),
                         0, vm_vcpus, &vm_id);
    if (ret && errno == EEXIST && restore_mode == VM_RESTORE_TEMPLATE)
        errx(0, "template vm already setup");
    if (ret)
        err(1, "uxen_create_vm");
    debug_printf("created vm: domid %d\n", vm_id);
}

static void
uxen_vm_init(const char *loadvm, int restore_mode)
{
    uint64_t ram_size = vm_mem_mb << 20;
    struct hvm_info_table *hvm_info;
    uint8_t *hvm_info_page;
    int i;
    int ret;
    uint8_t sum;
    uint64_t rand_seed[2];
    union dm_features ftres;

    if (restore_mode == VM_RESTORE_TEMPLATE)
        atexit(error_template_destroy);

    uxen_notification_event_init(&vm_logging_event);
    ret = uxen_logging(uxen_handle, vm_logging_buffer_size, vm_logging_event,
                       &vm_logging_buffer);
    if (ret)
        err(1, "vm logging setup failed");

    uxen_notification_add_wait_object(&vm_logging_event, handle_logging_event,
                                      NULL, NULL);

    ret = xc_domain_setmaxmem(xc_handle, vm_id,
                              ((ram_size + (512 << 20)) >> 10) + 1024);
    /* 1024 = LIBXL_MAXMEM_CONSTANT */
    if (ret != 0)
	err(1, "xc_domain_setmaxmem");

    xc_domain_set_introspection_features(xc_handle, vm_id,
                                         compute_introspection_features());

    xc_domain_set_tsc_info(xc_handle, vm_id, vm_tsc_mode /* info->tsc_mode */,
			   0, 0, 0);

    xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_PAE_ENABLED, vm_pae);
    xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_VIRIDIAN, vm_viridian);
    xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_HPET_ENABLED, vm_hpet);
    xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_ZERO_PAGE,
                     vm_zero_page ?
                     (HVM_PARAM_ZERO_PAGE_enable_load |
                      (vm_zero_page_setup ?
                       HVM_PARAM_ZERO_PAGE_enable_setup : 0)) : 0);

    xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_RESTRICTED_X86_EMUL,
                     vm_restricted_x86_emul);
    xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_VIRIDIAN_CRASH_DOMAIN,
                     vm_viridian_crash_domain);

    xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_TIMER_MODE,
                     vm_timer_mode);
    xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_VPT_ALIGN, vm_vpt_align);
    xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_VPT_COALESCE_NS,
                     vm_vpt_coalesce_period);

    generate_random_bytes(rand_seed, sizeof(rand_seed));
    xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_RAND_SEED_LO,
                     rand_seed[0]);
    xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_RAND_SEED_HI,
                     rand_seed[1]);

    xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_LOG_RATELIMIT_GUEST_BURST,
                     log_ratelimit_guest_burst);
    xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_LOG_RATELIMIT_GUEST_MS,
                     log_ratelimit_guest_ms);

    ftres.blob = 0;
    ftres.bits.run_patcher = (vm_run_patcher) ? 1 : 0;
    ftres.bits.seed_generation = (!!seed_generation) ? 1 : 0;
    ftres.bits.surf_copy_reduction = (!!surf_copy_reduction) ? 1 : 0;
    xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_DM_FEATURES, ftres.blob);

    if (vm_hvm_params) {
        const char *k;
        yajl_val v;
        unsigned int i;

        YAJL_FOREACH_OBJECT_KEYS(k, v, vm_hvm_params, i) {
            unsigned long p;

            p = strtoul(k, NULL, 10);
            if (p == ULONG_MAX || (!p && errno == EINVAL)) {
                warnx("invalid hvm-params \"%s\"", k);
                continue;
            }
            if (p >= HVM_NR_PARAMS) {
                warnx("hvm-params \"%s\" too large", k);
                continue;
            }
            if (!YAJL_IS_INTEGER(v)) {
                warnx("hvm-params \"%s\" not integer", k);
                continue;
            }

            xc_set_hvm_param(xc_handle, vm_id, p, YAJL_GET_INTEGER(v));
        }
    }

    vm_time_offset = get_timeoffset();
    xc_domain_set_time_offset(xc_handle, vm_id, vm_time_offset);

#if defined(CONFIG_VBOXDRV)
    ret = sf_service_start();
    if (ret)
        err(1, "sf_service_start");
#endif

    if (!loadvm) {
        char *hvmloader_path = NULL;
        struct xc_hvm_module *modules;
        int mod_count = 0;

        ret = mapcache_init(vm_mem_mb);
        if (ret)
            err(1, "mapcache_init");

        asprintf(&hvmloader_path, "%s/hvmloader", dm_path);
        if (!hvmloader_path)
            err(1, "asprintf(hvmloader)");

        modules = vm_get_modules(&mod_count);

        if (xc_hvm_build(xc_handle, vm_id, ram_size >> 20, vm_vcpus,
                         NR_IOREQ_SERVERS, hvmloader_path, modules, mod_count,
                         &oem_info))
            errx(1, "xc_hvm_build failed");

        if (modules)
            vm_cleanup_modules(modules, mod_count);

        free(hvmloader_path);

        dmreq_init();

        hvm_info_page = xc_map_foreign_range(xc_handle, vm_id, XC_PAGE_SIZE,
                                             PROT_READ | PROT_WRITE,
                                             HVM_INFO_PFN);
        if (hvm_info_page == NULL)
            err(1, "xc_map_foreign_range(HVM_INFO_PFN)");

        hvm_info = (struct hvm_info_table *)(hvm_info_page + HVM_INFO_OFFSET);

        hvm_info->apic_mode = vm_apic;
        hvm_info->nr_vcpus = vm_vcpus;
        memcpy(hvm_info->vcpu_online, vm_vcpu_avail,
               sizeof(hvm_info->vcpu_online));

        for (i = 0, sum = 0; i < hvm_info->length; i++)
            sum += ((uint8_t *) hvm_info)[i];
        hvm_info->checksum -= sum;

        xc_munmap(xc_handle, vm_id, hvm_info_page, XC_PAGE_SIZE);
    } else {
	ret = vm_load(loadvm, restore_mode);
	if (ret)
	    err(1, "vm_load(%s, %s) failed", loadvm,
		restore_mode == VM_RESTORE_TEMPLATE ? "template" :
		(restore_mode == VM_RESTORE_CLONE ? "clone" : "load"));
        if (restore_mode == VM_RESTORE_TEMPLATE) {
            template_load_failed = false;
            control_send_status("template", "loaded", NULL);
            control_flush();
#ifdef CONFIG_DUMP_MEMORY_STAT
            dump_stats();
#endif  /* CONFIG_DUMP_MEMORY_STAT */
            errx(0, "template vm setup done");
        }
    }

    if (vm_quit_interrupt)
        errx(0, "%s quit interrupt", __FUNCTION__);

    ioreq_init();

    pc_init_xen();

    if (loadvm) {
        ret = vm_load_finish();
        if (ret)
            err(1, "vm_load_finish failed");
    }

    xc_cpuid_apply_policy(xc_handle, vm_id);

#if defined(CONFIG_VBOXDRV)
    ret = clip_service_start();
    if (ret)
        err(1, "clip_service_start");
#endif

#ifdef CONFIG_DUMP_PERIODIC_STATS
    dump_periodic_stats_init();
#endif  /* CONFIG_DUMP_PERIODIC_STAT */

    dev_machine_creation_done();
}

void
vm_init(const char *loadvm, int restore_mode)
{
    if (!whpx_enable)
        uxen_vm_init(loadvm, restore_mode);
    else {
        int ret = whpx_vm_init(loadvm, restore_mode);

        if (ret)
            err(1, "failed to init whpx vm: %d", ret);
#ifdef CONFIG_DUMP_PERIODIC_STATS
        dump_periodic_stats_init();
#endif  /* CONFIG_DUMP_PERIODIC_STAT */
    }
}

int vm_is_paused(void)
{
    if (!whpx_enable) {
        xc_dominfo_t info;
        int ret;

        ret = xc_domain_getinfo(xc_handle, vm_id, 1, &info);
        if (ret)
            return info.paused;
        return 0;
    } else
        return whpx_vm_is_paused();
}

int vm_pause(void)
{
    if (!whpx_enable)
        return xc_domain_pause(xc_handle, vm_id);
    else
        return whpx_vm_pause();
}

int vm_unpause(void)
{
    if (!whpx_enable)
        return xc_domain_unpause(xc_handle, vm_id);
    else
        return whpx_vm_unpause();
}

static uxen_notification_event exceptionEvent;

static uint32_t running_vcpus = 0;
static enum vm_run_mode run_mode = RUNNING_VM;
static enum vm_run_mode old_run_mode = SETUP_VM;

#if defined(_WIN32)
static DWORD WINAPI
vmrun_thread(PVOID dummy)
{
    int vcpu = (int)(uintptr_t)dummy;
#elif defined(__APPLE__)
static void *
vmrun_thread(void *dummy)
{
    int vcpu = (int)dummy;
#endif
    int ret;
    uint32_t r, nr, or;

    do {
        ret = uxen_run(vcpu);
    } while (ret < 0 && (errno == EAGAIN || errno == EINTR) &&
             (run_mode == RUNNING_VM || run_mode == PAUSE_VM ||
              run_mode == SUSPEND_VM));

    r = running_vcpus;
    do {
        or = r;
        nr = or - 1;
    } while ((r = cmpxchg(&running_vcpus, or, nr)) != or);

    vm_set_run_mode(DESTROY_VM);

    warnx("%s: vcpu %d exiting", __FUNCTION__, vcpu);
    return 0;
}

static void
vm_exit(void *opaque)
{
    static uint32_t destroy_done = 0;
    static uint32_t ending = 0;

    if (cmpxchg(&destroy_done, 0, 1) == 0) {
        if (!whpx_enable)
            uxen_destroy(vm_uuid);
        else
            whpx_destroy();
    }
    if (running_vcpus)
        return;

    if (cmpxchg(&ending, 0, 1) != 0)
        return;

#if defined(CONFIG_NICKEL)
        ni_suspend_flush();
#endif

    /* close vm save file if open */
    vm_save_finalize();

    /* flush logs before sending quit command acknowledgment */
    fflush(stderr);

    /* call control_command_exit as early as possible
     * to avoid deadlock on rpc sync commands */
    control_command_exit();

    /* interrupting quit, exit instantly */
    if (vm_quit_interrupt) {
        fflush(stderr);
        _exit(0);
    }

    /* Since we are going to exit here, make sure everything is flushed. */
    bdrv_flush_all(1);
    /* Call aio_flush() after flushing the backends, to not hang if backends
     * use never-to-be-serviced timers for IO rate limiting. */
    aio_flush();
#if defined(HAS_AUDIO)
    uxenaudio_exit();
#endif
#if defined(CONFIG_NICKEL)
    ni_exit();
#endif

#if defined(CONFIG_VBOXDRV)
    sf_service_stop();
    clip_service_stop();
#endif

    console_exit();
    control_exit();
    dmreq_exit();

#if defined(_WIN32)
    socket_cleanup();
#endif
    exit(0);
}

static void
vm_run_mode_change_cb(void *opaque)
{
    switch (run_mode) {
    case RUNNING_VM:
        if (old_run_mode == SUSPEND_VM)
            vm_resume();
        vm_time_update();
#ifdef CONFIG_DUMP_MEMORY_STAT
      dump_periodic_stats_reset();
#endif  /* CONFIG_DUMP_MEMORY_STAT */
        vm_clock_unpause();
#if defined(CONFIG_NICKEL)
        ni_vm_unpause();
#endif
#if defined(CONFIG_VBOXDRV)
        sf_vm_unpause();
#endif
        break;
    case POWEROFF_VM:
    case DESTROY_VM:
        break;
    case PAUSE_VM:
    case SUSPEND_VM:
        vm_clock_pause();
#if defined(CONFIG_NICKEL)
        ni_vm_pause();
#endif
#if defined(CONFIG_VBOXDRV)
        sf_vm_pause();
#endif
        break;
    case SETUP_VM:
        break;
    }

    if (run_mode == DESTROY_VM &&
        !vm_save_info.awaiting_suspend && !vm_save_info.save_requested)
        vm_exit(opaque);
    old_run_mode = run_mode;
}

static void
handle_exception_event(void *opaque)
{
    xc_dominfo_t info;
    int ret;

    ret = xc_domain_getinfo(xc_handle, vm_id, 1, &info);
    if (ret == 1 && info.domid == vm_id) {
        debug_printf("exception event:%s%s%s%s%s\n",
                     info.crashed ? " crashed" : "",
                     info.shutdown ? " shutdown" : "",
                     info.paused ? " paused" : "",
                     info.blocked ? " blocked" : "",
                     info.running ? " running" : "");
        if (info.shutdown)
            debug_printf("shutdown reason: %d\n", info.shutdown_reason);

        time_pause_adjust = info.pause_time;

        if (vm_save_info.awaiting_suspend && vm_process_suspend(&info))
            return;

        if ((info.shutdown && info.shutdown_reason != SHUTDOWN_suspend) ||
            info.crashed) {
            if (info.crashed && vmsavefile_on_crash) {
                debug_printf("%s: domain crash, generating savefile\n",
                             __FUNCTION__);
                vmsavefile_save_simple(xc_handle, vmsavefile_on_crash,
                                       vm_uuid, vm_id);
            }
            vm_set_run_mode(DESTROY_VM);
            return;
        }

        if (info.paused) {
            vm_set_run_mode(PAUSE_VM);
            return;
        }

        if (!info.shutdown && !info.shutting_down && !vm_save_info.awaiting_suspend)
            vm_set_run_mode(RUNNING_VM);
    }
}

void
vm_start_run(void)
{
    unsigned int vcpu;
    int ret;

    if (run_mode == DESTROY_VM) {
        vm_set_run_mode(DESTROY_VM);
        return;
    }

    ioreq_wait_server_events(default_ioreq_state);

    uxen_notification_event_init(&exceptionEvent);
    uxen_notification_add_wait_object(&exceptionEvent, handle_exception_event,
                                      NULL, NULL);

    ret = uxen_ioemu_event(UXEN_IOEMU_EVENT_EXCEPTION, &exceptionEvent);
    if (ret)
        errx(1, "uxen_ioemu_events");

    running_vcpus = vm_vcpus;

    for (vcpu = 0; vcpu < vm_vcpus; vcpu++) {
        uxen_thread thread;
        ret = create_thread(&thread, vmrun_thread, (void *)(uintptr_t)vcpu);
        if (ret) {
            Wwarn("create_thread vmrun");
            vm_set_run_mode(DESTROY_VM);
        }
    }
}

void
vm_set_run_mode(enum vm_run_mode r)
{
    if (!vm_init_lk) {
        if (r == DESTROY_VM)
            run_mode = r;
        return;
    }

    critical_section_enter(&vm_run_mode_lock);
    switch (run_mode) {
    case PAUSE_VM:
        if (r == SUSPEND_VM)
            break;
    case SETUP_VM:
    case SUSPEND_VM:
        if (r == RUNNING_VM)
            break;
    case POWEROFF_VM:
    case DESTROY_VM:
        if (r == DESTROY_VM)
            break;
        critical_section_leave(&vm_run_mode_lock);
        return;
    case RUNNING_VM:
        break;
    }

    run_mode = r;
    critical_section_leave(&vm_run_mode_lock);

    switch (r) {
    case RUNNING_VM:
        break;
    case PAUSE_VM:
        break;
    case SUSPEND_VM:
        break;
    case POWEROFF_VM:
        vm_poweroff();
        break;
    case DESTROY_VM:
        break;
    case SETUP_VM:
        break;
    }

    ioh_event_set(&vm_run_mode_change);
}

enum vm_run_mode
vm_get_run_mode(void)
{
    return run_mode;
}

void
vm_poweroff(void)
{
    int ret;

    if (!whpx_enable)
        ret = xc_domain_shutdown(xc_handle, vm_id, SHUTDOWN_poweroff);
    else
        ret = whpx_vm_shutdown(SHUTDOWN_poweroff);
    if (ret)
        warn("xc_domain_shutdown(poweroff, %d) failed ret = %d", vm_id, ret);
    else
        warnx("xc_domain_shutdown(poweroff, %d) succeeded", vm_id);
}

void
vm_shutdown_sync(void)
{

    /* XXX: this should run an event loop to wait for vmrunEndEvent
     * and then invoke vm_exit repeatedly */
    while (1) {
        vm_exit(NULL);
#if defined(_WIN32)
        Sleep(50);
#elif defined(__APPLE__)
        usleep(50000);
#endif
    }
}

void
vm_time_update(void)
{

    uxen_platform_time_update();

#ifdef _WIN32
    windows_time_update();
#endif
}

void
vm_inject_nmi()
{
    int ret;

    ret = xc_hvm_inject_trap(xc_handle, vm_id, 0, 2, -1, 0);
    if (ret)
        warn("vm_inject_nmi failed: vm = %d, ret = %d", vm_id, ret);
    else
        warnx("vm_inject_nmi succeeded: vm = %d", vm_id);
}

#ifdef MONITOR
void
mc_quit(Monitor *mon, const dict args)
{

    vm_quit_interrupt = dict_get_boolean_default(args, "interrupt", 0);
    if (run_mode != RUNNING_VM || dict_get_boolean_default(args, "force", 1))
        vm_set_run_mode(DESTROY_VM);
    else
        vm_set_run_mode(POWEROFF_VM);
}
#endif  /* MONITOR */

#ifdef MONITOR
void
mc_inject_trap(Monitor *mon, const dict args)
{
    int vcpu;
    uint32_t trap;
    uint32_t error_code;
    uint64_t cr2;
    int ret;

    vcpu = dict_get_integer(args, "vcpu");
    trap = dict_get_integer(args, "trap");
    error_code = dict_get_integer_default(args, "error_code", -1);
    cr2 = dict_get_integer_default(args, "cr2", 0);

    ret = xc_hvm_inject_trap(xc_handle, vm_id, vcpu, trap, error_code, cr2);
    if (ret)
        monitor_printf(mon, "xc_hvm_inject_trap failed: %d\n", ret);
}
#endif  /* MONITOR */

#ifdef MONITOR
void
mc_vm_pause(Monitor *mon, const dict args)
{
    int ret;

    critical_section_enter(&vm_pause_lock);
    ret = vm_pause();
    critical_section_leave(&vm_pause_lock);
    if (ret)
        monitor_printf(mon, "vm_pause failed: %d\n", ret);
}

void
mc_vm_unpause(Monitor *mon, const dict args)
{
    int ret;

    critical_section_enter(&vm_pause_lock);
    ret = vm_unpause();
    critical_section_leave(&vm_pause_lock);
    if (ret)
        monitor_printf(mon, "vm_unpause failed: %d\n", ret);
}

#ifdef HAS_AUDIO
void
mc_vm_audio_mute(Monitor *mon, const dict args)
{
    int mute = dict_get_integer(args, "mute");
    uxenaudio_mute(mute);
}
#endif /* HAS_AUDIO */

void
mc_vm_time_update(Monitor *mon, const dict args)
{

    vm_time_update();
}

void
mc_vm_throttle(Monitor *mon, const dict args)
{
    uint64_t period, rate;

    period = dict_get_integer(args, "period");
    rate = dict_get_integer(args, "rate");

    xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_THROTTLE_PERIOD, period);
    xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_THROTTLE_RATE, rate);
}

#endif  /* MONITOR */
