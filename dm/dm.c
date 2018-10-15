/*
 * Copyright 2012-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "aio.h"
#include "bh.h"
#include "block.h"
#include "char.h"
#include "conffile.h"
#include "console.h"
#include "control.h"
#include "dev.h"
#include "dict-rpc.h"
#include "dm.h"
#include "ioh.h"
#include "iomem.h"
#include "ioport.h"
#include "ioreq.h"
#include "monitor.h"
#include "mr.h"
#include "net.h"
#include "timer.h"
#include "os.h"
#include "sockets.h"
#include "version.h"
#include "vm.h"
#include "vm-save.h"
#include "uuidgen.h"
#include "uxen.h"
#include "uxenh264.h"
#include "hw/pv_vblank.h"

#if defined(CONFIG_NICKEL)
#include "libnickel.h"
#endif

#include <xenctrl.h>
#include <uuid/uuid.h>

#if defined(_WIN32)
#include <filecrypt.h>
#include "whpx/whpx.h"
#endif

char *dm_path = ".";

const char *boot_order = NULL;
#ifdef MONITOR
const char *monitor_device = NULL;
#endif  /* MONITOR */
const char *lava_options = "";

int vm_cloneid = -1;
uint32_t vm_id = 0;
char *vm_loadfile = NULL;
uint64_t vm_mem_mb = 0;
uint64_t balloon_min_mb = 0;
uint64_t balloon_max_mb = 0;
const char *vm_name = NULL;
long vm_time_offset = 0;
xen_domain_handle_t vm_uuid;
xen_domain_handle_t vm_template_uuid;
int vm_has_template_uuid = 0;
char *vm_template_file = NULL;
int vm_restore_mode = VM_RESTORE_NONE;
uint64_t vm_lazy_load = 0;
static int vm_start_paused = 0;
window_handle vm_window = NULL;
window_handle vm_window_parent = NULL;
uint64_t vm_vcpus = 1;
uint8_t vm_vcpu_avail[(HVM_MAX_VCPUS + 7) / 8] = {1, 0};
uint64_t vm_timer_mode = 0;
uint64_t vm_tsc_mode = 2;
uint64_t vm_vga_mb_mapped = 0;
uint64_t vm_pae = 1;
uint64_t vm_viridian = 1;
uint64_t vm_virt_mode_change = 0;
uint64_t vm_hpet = 1;
uint64_t vm_zero_page = 1;
uint64_t vm_zero_page_setup = 1;
uint64_t vm_apic = 1;
uint64_t vm_hidden_mem = 1;
uint64_t vm_ignore_storage_space_fix = 0;
uint64_t vm_use_v4v_net = 0;
uint64_t vm_use_v4v_disk = 0;
uint64_t vm_v4v_storage = 1;
uint64_t vm_v4v_disable_ahci_clones = 0;
uint64_t vm_vram_dirty_tracking = 0;
uint8_t v4v_idtoken[16] = { };
uint8_t v4v_idtoken_is_vm_uuid = 1;
const char *vmsavefile_on_crash = NULL;
const char *vmsavefile_on_restricted_pci = NULL;
const char *vmsavefile_on_kbd_reboot = NULL;
uint64_t guest_drivers_logmask = 0x2; /* Include LogRel, not Log */
uint64_t debugkey_level = 0;
uint64_t malloc_limit_bytes = 0;
uint64_t restore_framebuffer_pattern = 0xffffffff;
dict vm_audio = NULL;
dict vm_hvm_params = NULL;
int restore = 0;
int *disabled_keys = NULL;
size_t disabled_keys_len = 0;
uint64_t ps2_fallback = 1;
const char *app_dump_command = NULL;
uint64_t event_service_mouse_moves = 0;
char *save_file_prefix = "uxenvm-";
uint64_t disp_fps_counter = 0;
uint64_t disp_pv_vblank = PV_VBLANK_NATIVE;
#if defined(_WIN32)
const char *console_type = "win32";
#elif defined(__APPLE__)
const char *console_type = "osx";
#endif
static char *control_path = NULL;
uint64_t h264_offload = 0;
uint64_t hbmon_period = 0;
uint64_t hbmon_timeout_period = 2000;
uint64_t hbmon_verbose = 0;

const char *clipboard_formats_blacklist_host2vm = NULL;
const char *clipboard_formats_whitelist_host2vm = NULL;
const char *clipboard_formats_blacklist_vm2host = NULL;
const char *clipboard_formats_whitelist_vm2host = NULL;
uint64_t deferred_clipboard = 0;

xc_interface *xc_handle = NULL;
int xen_logdirty_enabled = 0;

FILE *logfile;
int loglevel = 0;
uint64_t hide_log_sensitive_data = 0;

uint64_t log_ratelimit_guest_burst = 0;
uint64_t log_ratelimit_guest_ms = 0;

uint64_t whpx_enable = 0;
uint64_t whpx_perf_stats = 0;
uint64_t whpx_reftsc = 1;

static void
usage(const char *progname)
{

    errx(1, "usage: %s [-h] [--config config-string] [-F|--file config-file]\n"
         "   [-C|--control control-pipe] [-n|--name name]\n"
         "   [-l|--load loadstate] [-t|--template] [-c|--clone]\n"
         "   [--window-parent hwnd]", progname);
}

enum {
    OPTION_INDEX_CONFIG,
    OPTION_INDEX_WINDOW_PARENT,
};

void
parse_options(int argc, char **argv)
{
    int ret;

    while (1) {
      int c, index = 0;
      static int long_index;
      static struct option long_options[] = {
          {"clone",        no_argument,       NULL,       'c'},
          {"config",       required_argument, &long_index, OPTION_INDEX_CONFIG},
          {"control",      required_argument, NULL,       'C'},
          {"file",         required_argument, NULL,       'F'},
          {"gui",          required_argument, NULL,       'G'},
          {"help",         no_argument,       NULL,       'h'},
          {"load",         required_argument, NULL,       'l'},
          {"name",         required_argument, NULL,       'n'},
          {"paused",       no_argument,       NULL,       'p'},
          {"template",     no_argument,       NULL,       't'},
          {"uuid",         required_argument, NULL,       'u'},
          {"window-parent", required_argument, &long_index,
           OPTION_INDEX_WINDOW_PARENT},
          {NULL,           0,                 NULL,        0}
      };
      char *s, *q;
      struct conffile *cf;

      long_index = 0;

      c = getopt_long(argc, argv, "hcC:F:G:l:n:tp", long_options, &index);
      if (c == -1)
	  break;

      switch (c) {
      case 0:
	  switch (long_index) {
	  case OPTION_INDEX_CONFIG:
	      s = strdup(optarg);
	      q = s;
	      while ((q = strchr(q, '\'')))
		  *q = '"';
	      cf = config_string(s);
	      config_parse(cf);
	      config_free_input(cf);
	      free(s);
	      break;
          case OPTION_INDEX_WINDOW_PARENT:
              vm_window_parent =
                  (window_handle)(uintptr_t)strtoull(optarg, NULL, 0);
              break;
	  }
	  break;
      case 'h':
	  usage(argv[0]);
	  /* NOTREACHED */
      case 'C':
	  control_path = strdup(optarg);
	  break;
      case 'F':
	  cf = config_load(optarg);
	  config_parse(cf);
	  config_free_input(cf);
	  break;
      case 'G':
	  console_type = optarg;
	  break;
      case 'c':
          vm_restore_mode = VM_RESTORE_CLONE;
	  break;
      case 'l':
	  vm_loadfile = optarg;
	  restore = 1;
	  if (vm_restore_mode == VM_RESTORE_NONE)
	      vm_restore_mode = VM_RESTORE_NORMAL;
	  break;
      case 'n':
	  vm_name = optarg;
	  break;
      case 'p':
	  vm_start_paused = 1;
	  break;
      case 't':
	  vm_restore_mode = VM_RESTORE_TEMPLATE;
	  break;
      case 'u':
          ret = uuid_parse(optarg + (optarg[0] == '{' ? 1 : 0), vm_uuid);
          if (ret)
              errx(1, "failed to parse command line option uuid '%s'", optarg);
          break;
      }
    }
}

int
main(int argc, char **argv)
{
    char *vm_window_str;
    char *dom_id_str;
    char *v4v_idtoken_str;
    int i;
    int ret;

    logfile = stderr; /* initial value */

#ifdef _WIN32
    debug_printf("dm pid: %ld\n", GetCurrentProcessId());
#elif __APPLE__
    debug_printf("dm pid: %d\n", getpid());
#endif

    log_version();

    chardev_init();
    dict_rpc_init();
    ioh_init();
    bh_init();
    timers_init(NULL);
    ioport_init();
    mmio_init();

    aio_init();

#ifdef _WIN32
    if (fc_init())
        warnx("filecrypt init FAILED");
    socket_init();
#ifdef CONFIG_VBOXDRV
    uxenclipboard_gdi_startup_with_atexit();
#endif /* CONFIG_VBOXDRV */
#endif

#ifdef __APPLE__
    set_nofides();
#endif

    bdrv_init();

    uuid_generate_truly_random(vm_uuid);

    init_memory_region();

    config_parse(config_default());

    parse_options(argc, argv);

    if (control_path) {
        control_open(control_path);
        free(control_path);
        control_path = NULL;
    }

    if (vm_restore_mode != VM_RESTORE_NONE && !vm_loadfile)
        errx(1, "no load file specified for template or clone");

    debug_printf("dm path:         %s\n", dm_path);
    debug_printf("cmd line:       ");
    for (i = 0; i < argc; i++)
        debug_printf(" %s", argv[i]);
    debug_printf("\n");
    debug_printf("boot order:      %s\n", boot_order);
#ifdef MONITOR
    debug_printf("monitor device:  %s\n", monitor_device);
#endif  /* MONITOR */
    debug_printf("vm mem mb:       %"PRId64"\n", vm_mem_mb);
    debug_printf("vm name:         %s\n", vm_name);
    debug_printf("vcpus:           %"PRId64"\n", vm_vcpus);

#ifdef MONITOR
    if (monitor_device) {
	CharDriverState *monitor_hd;
        monitor_hd = qemu_chr_open("monitor", monitor_device, NULL, NULL);
        if (!monitor_hd)
            errx(1, "could not open monitor device '%s'", monitor_device);
        monitor_init(monitor_hd, 1);
    } else
        monitor_init(NULL, 0);
#endif  /* MONITOR */

#ifdef _WIN32
    SetProcessShutdownParameters(process_shutdown_priority, 0);
#endif

    xc_handle = xc_interface_open(0, 0, 0, dm_path);
    if (xc_handle == NULL)
        errx(1, "xc_interface_open");

    if (uxen_setup((UXEN_HANDLE_T)xc_interface_handle(xc_handle)))
        err(1, "uxen_setup");

    uxen_log_version();

    if (whpx_enable)
        whpx_early_init();

    debug_printf("creating vm\n");
    vm_create(vm_restore_mode);
    if (vm_restore_mode == VM_RESTORE_TEMPLATE)
        goto vm_init;

    debug_printf("initializing device modules\n");
    module_call_init(MODULE_INIT_DEVICE);

    debug_printf("initializing serial devices\n");
    for(i = 0; i < MAX_SERIAL_PORTS; i++) {
	char label[32];
        if (!serial_devices[i])
	    continue;
	snprintf(label, sizeof(label), "serial%d", i);
	serial_hds[i] = qemu_chr_open(label, serial_devices[i], NULL, NULL);
	if (!serial_hds[i])
	    errx(1, "could not open serial device %i '%s'", i,
		 serial_devices[i]);
    }

    debug_printf("initializing console\n");
    if (console_init(console_type))
        errx(1, "Failed to initialize GUI '%s'", console_type);

vm_init:
    debug_printf("initializing vm\n");
    vm_init(vm_loadfile, vm_restore_mode);

#ifdef CONFIG_NET
    net_check_clients();
#endif

    {
        char uuid[37];

        debug_printf("vm id:           %d\n", vm_id);
        uuid_unparse_lower(vm_uuid, uuid);
        debug_printf("vm uuid:         %s\n", uuid);
    }

    console_start();

    qemu_chr_initial_reset();

#if defined(CONFIG_NICKEL)
    ni_start();
#endif

    if (!whpx_enable) {
        vm_start_run();

        if (!vm_start_paused)
            vm_unpause();
    } else
        whpx_vm_start();

    if (h264_offload)
        uxenh264_start();

    plog("ready");
    ret = asprintf(&vm_window_str, "0x%"PRIx64, (uint64_t)(uintptr_t)vm_window);
    if (ret <= 0)
        err(1, "asprintf vm_window failed");

    ret = asprintf(&dom_id_str, "%d", vm_id);
    if (ret <= 0)
        err(1, "asprintf dom_id_str failed");

    ret = asprintf(&v4v_idtoken_str, "%"PRIuuid, PRIuuid_arg(v4v_idtoken));
    if (ret <= 0)
        err(1, "asprintf v4v_idtoken_str failed");

    control_send_status("vm-runstate", "running", "hwnd", vm_window_str,
                        "v4v-idtoken", v4v_idtoken_str, "dom-id", dom_id_str,
                        NULL);
    free(vm_window_str);
    free(dom_id_str);
    free(v4v_idtoken_str);

    while (1) {
	int timeout;

        setvbuf(stderr, NULL, _IOFBF, 0x4000);
	while (!vm_save_info.save_requested) {
	    timeout = 10000; /* 10s */

	    bh_update_timeout(&timeout);

	    host_main_loop_wait(&timeout);

	    bh_poll();
	}
        setvbuf(stderr, NULL, _IONBF, 0);

	timeout = 1;
        host_main_loop_wait(&timeout); /* For the select() on events */

        /* complete any in-flight disk ops */
        bdrv_flush_all(0);
        aio_flush();
        vm_save_execute();

	vm_save_info.save_requested = 0;

        /* reset run mode to trigger mode changes suppressed during
         * save */
        vm_set_run_mode(vm_get_run_mode());
    }

    if (h264_offload)
        uxenh264_stop();

#if defined(CONFIG_NICKEL)
    ni_exit();
#endif
    console_exit();
    net_cleanup();

#if defined(_WIN32)
    socket_cleanup();
#endif

    return 0;
}

#ifdef MONITOR
void
ic_uuid(Monitor *mon)
{
    char uuid[37];

    uuid_unparse_lower(vm_uuid, uuid);
    monitor_printf(mon, "%s\n", uuid);
}
#endif  /* MONITOR */
