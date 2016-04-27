/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "char.h"
#include "clock.h"
#include "console.h"
#include "control.h"
#include "dict.h"
#include "dict-rpc.h"
#include "dm.h"
#include "hw/uxen_platform.h"
#include "hw/uxen_audio_ctrl.h"
#include "vm.h"
#include "vm-save.h"
#include "input.h"
#include "timer.h"
#include "block.h"
#include "guest-agent.h"

#if defined(CONFIG_NICKEL)
#include "libnickel.h"
#endif

#include <xenctrl.h>
#include <xc_private.h>

#define CONTROL_MAX_LINE_LEN 4096
#define CONTROL_INPUT_REALLOC_SIZE 512
#define DEFAULT_TIMEOUT_MS 0x7fffffff // ideally would be INFINITE

static struct io_handler_queue control_io_handlers;
static WaitObjects control_wait_objects;
static ioh_event control_ev;
static uxen_thread control_thread;

static int control_thread_exit = 0;

static struct control_desc {
    CharDriverState *chr;
    char *input;
    int input_len;
    int input_size;
    int discard;
} control = { NULL, };

static int
control_send(void *send_opaque, char *buf, size_t len)
{
    struct control_desc *cd = (struct control_desc *)send_opaque;
    char *tmp;

    tmp = realloc(buf, len + 1);
    if (!tmp) {
        free(buf);
        return -1;
    }
    buf = tmp;

    tmp[len] = '\n';

    qemu_chr_write(cd->chr, (const uint8_t *)buf, len + 1);

    free(buf);

    return 0;
}

static int
control_send_error(struct control_desc *cd, const char *command,
		   const char *id, int _errno, const char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = dict_rpc_verror(control_send, cd, command, id, _errno, fmt, ap);
    va_end(ap);
    if (ret) {
        warnx("%s: dict_rpc_verror", __FUNCTION__);
        goto out;
    }

  out:
    return ret;
}

int
control_send_ok(void *send_opaque, const char *command, const char *id,
		const char *fmt, ...)
{
    va_list ap;
    int ret;

    if (fmt)
        va_start(ap, fmt);

    ret = dict_rpc_ok(control_send, send_opaque, command, id, fmt, fmt ? ap : NULL);

    if (fmt)
        va_end(ap);

    if (ret) {
        warnx("%s: dict_rpc_ok", __FUNCTION__);
        goto out;
    }

  out:
    return ret;
}

int
control_send_status(const char *key, const char *val, ...)
{
    va_list ap;
    int ret;

    if (!control.chr) {
        warnx("%s: control chr unavailable", __FUNCTION__);
        errno = EINVAL;
        return -1;
    }

    va_start(ap, val);
    ret = dict_rpc_status(control_send, &control,
                          "sa", key, val, ap);
    va_end(ap);
    if (ret) {
        warnx("%s: dict_rpc_status", __FUNCTION__);
        goto out;
    }

  out:
    return ret;
}

#ifdef SAVE_CUCKOO_ENABLED
HANDLE control_dup_handle(HANDLE handle)
{
    if (!control.chr) {
        warnx("%s: control chr unavailable", __FUNCTION__);
        errno = EINVAL;
        return NULL;
    }
    return qemu_chr_dup_handle(control.chr, handle);
}
#endif

__attribute__ ((__format__ (printf, 6, 0)))
void control_err_vprintf(const char *function, int line,
                         const char *type,
                         int errval, const char *errdesc,
                         const char *fmt, va_list ap)
{
    char *msg;

    vasprintf(&msg, fmt, ap);

    if (errdesc)
        debug_printf("%s: %s (%08X)\n", msg, errdesc, errval);
    else if (errval)
        debug_printf("%s: (%08X)\n", msg, errval);
    else
        debug_printf("%s\n", msg);

    if (control.chr) {
        if (errval || errdesc)
            dict_rpc_status(control_send, &control,
                            "ssisis",
                            "uxendm", type,
                            "function", function,
                            "line", (uint64_t)line,
                            "message", msg,
                            "value", (uint64_t)errval,
                            "description", errdesc,
                            NULL);
        else
            dict_rpc_status(control_send, &control,
                            "ssis",
                            "uxendm", type,
                            "function", function,
                            "line", (uint64_t)line,
                            "message", msg,
                            NULL);
    }

    free(msg);
}

void control_flush(void)
{
    if (control.chr)
        qemu_chr_write_flush(control.chr);
}

void control_err_flush(void)
{
    control_flush();
    fflush(stderr);
}

int
control_send_command(const char *command, const dict args,
                     void (*callback)(void *, dict), void *callback_opaque)
{
    int ret;

    if (!control.chr) {
        warnx("%s: control chr unavailable", __FUNCTION__);
        return -1;
    }

    ret = dict_rpc_request(control_send, &control,
                           command, callback, callback_opaque, "d", args);
    if (ret) {
        warnx("%s: dict_rpc_request", __FUNCTION__);
        goto out;
    }

  out:
    return ret;
}

struct control_queue_entry {
    STAILQ_ENTRY(control_queue_entry) next;
    CharDriverState *chr;
    char *buf;
    size_t len;
};
STAILQ_HEAD(, control_queue_entry) control_queue_entries =
    STAILQ_HEAD_INITIALIZER(control_queue_entries);

static int
control_queue(void *send_opaque, char *buf, size_t len)
{
    struct control_desc *cd = (struct control_desc *)send_opaque;
    char *tmp;
    struct control_queue_entry *cqe;

    tmp = realloc(buf, len + 1);
    if (!tmp) {
        free(buf);
        return -1;
    }
    buf = tmp;

    buf[len] = '\n';

    cqe = malloc(sizeof(struct control_queue_entry));
    if (!cqe) {
        free(buf);
        return -1;
    }
    cqe->chr = cd->chr;
    cqe->buf = buf;
    cqe->len = len + 1;
    STAILQ_INSERT_TAIL(&control_queue_entries, cqe, next);

    return 0;
}

static void
control_send_queued(void)
{
    struct control_queue_entry *cqe;

    while ((cqe = STAILQ_FIRST(&control_queue_entries))) {
        STAILQ_REMOVE_HEAD(&control_queue_entries, next);

        qemu_chr_write(cqe->chr, (const uint8_t *)cqe->buf, cqe->len);

        free(cqe->buf);
    }
}

int
control_queue_ok(void *send_opaque, const char *command, const char *id,
                 const char *fmt, ...)
{
    va_list ap;
    int ret;

    if (fmt)
        va_start(ap, fmt);

    ret = dict_rpc_ok(control_queue, send_opaque, command, id, fmt,
                      fmt ? ap : NULL);

    if (fmt)
        va_end(ap);

    if (ret) {
        warnx("%s: dict_rpc_ok", __FUNCTION__);
        goto out;
    }

  out:
    return ret;
}

static int
control_command_save(void *opaque, const char *id, const char *opt,
                     dict d, void *command_opaque)
{
    struct control_desc *cd = (struct control_desc *)opaque;
    const char *filename;
    const char *c;

    filename = dict_get_string(d, "filename");

    vm_save_info.filename = filename ? strdup(filename) : NULL;

    vm_save_info.compress_mode = VM_SAVE_COMPRESS_NONE;
    c = dict_get_string(d, "compress");
    if (c) {
        if (!strcmp(c, "lz4"))
            vm_save_info.compress_mode = VM_SAVE_COMPRESS_LZ4;
#ifdef SAVE_CUCKOO_ENABLED
        else if (!strcmp(c, "cuckoo"))
          vm_save_info.compress_mode = VM_SAVE_COMPRESS_CUCKOO;
        else if (!strcmp(c, "cuckoo-simple"))
          vm_save_info.compress_mode = VM_SAVE_COMPRESS_CUCKOO_SIMPLE;
#endif
    }

    vm_save_info.single_page = dict_get_boolean(d, "single-page");
    vm_save_info.free_mem = dict_get_boolean(d, "free-mem");
    vm_save_info.high_compress = dict_get_boolean(d, "high-compress");

    vm_save_info.command_cd = cd;
    vm_save_info.command_id = id ? strdup(id) : NULL;

    vm_save();

    return 0;
}

void
control_command_save_finish(int ret, char *err_msg)
{

    if (ret)
	control_send_error(vm_save_info.command_cd, "save",
			   vm_save_info.command_id, ret,
			   err_msg);
    else
	control_send_ok(vm_save_info.command_cd, "save",
			vm_save_info.command_id, NULL);
    vm_save_info.command_cd = NULL;
    if (vm_save_info.command_id) {
	free(vm_save_info.command_id);
	vm_save_info.command_id = NULL;
    }
}

static int
control_command_resume(void *opaque, const char *id, const char *opt,
                       dict d, void *command_opaque)
{
    struct control_desc *cd = (struct control_desc *)opaque;

    vm_save_info.resume_delete = dict_get_boolean(d, "delete-savefile");

    vm_save_info.resume_cd = cd;
    vm_save_info.resume_id = id ? strdup(id) : NULL;

    vm_save_abort();

    return 0;
}

void
control_command_resume_finish(int ret, char *err_msg)
{

    if (ret)
        control_send_error(vm_save_info.resume_cd, "resume",
                           vm_save_info.resume_id, ret,
                           err_msg);
    else
        control_send_ok(vm_save_info.resume_cd, "resume",
                        vm_save_info.resume_id, NULL);
    vm_save_info.resume_cd = NULL;
    if (vm_save_info.resume_id) {
        free(vm_save_info.resume_id);
        vm_save_info.resume_id = NULL;
    }
}

static int
control_command_quit(void *opaque, const char *id, const char *opt,
                     dict d, void *command_opaque)
{
    struct control_desc *cd = (struct control_desc *)opaque;

    vm_quit_interrupt = dict_get_boolean(d, "interrupt");
    if (vm_get_run_mode() != RUNNING_VM || dict_get_boolean(d, "force"))
        vm_set_run_mode(DESTROY_VM);
    else
        vm_set_run_mode(POWEROFF_VM);

    control_queue_ok(cd, opt, id, NULL);

    return 0;
}

static int
control_command_pause(void *opaque, const char *id, const char *opt,
                      dict d, void *command_opaque)
{
    int ret;
    struct control_desc *cd = (struct control_desc *)opaque;

    critical_section_enter(&vm_pause_lock);
    ret = vm_pause();
    critical_section_leave(&vm_pause_lock);
    if (ret)
	control_send_error(cd, opt, id, ret, NULL);
    else
	control_send_ok(cd, opt, id, NULL);

    return 0;
}

static int
control_command_unpause(void *opaque, const char *id, const char *opt,
                        dict d, void *command_opaque)
{
    int ret;
    struct control_desc *cd = (struct control_desc *)opaque;

    critical_section_enter(&vm_pause_lock);
    ret = vm_unpause();
    critical_section_leave(&vm_pause_lock);
    if (ret)
	control_send_error(cd, opt, id, ret, NULL);
    else
	control_send_ok(cd, opt, id, NULL);

    return 0;
}

#ifdef _WIN32
static int
control_command_open_log(void *opaque, const char *id, const char *opt,
                         dict d, void *command_opaque)
{
    int ret = 0;
    struct control_desc *cd = (struct control_desc *)opaque;
    const char *logfile;
    HANDLE new_h;
    int new_fd;
    FILE* new_f;

    logfile = dict_get_string(d, "logfile");

    if (!strcmp(logfile, ".")) {
        rewind(stderr);
        if (ftruncate(fileno(stderr), 0)) {
            ret = errno;
            debug_printf("failed to clear log file\n");
        } else
            debug_printf("log file cleared\n");
    } else {

        /* freopen stderr (using Win32 file API, to allow sharing) */
        debug_printf("opening new log file: %s\n", logfile);
        new_h = CreateFile(logfile, FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (new_h == INVALID_HANDLE_VALUE) {
            ret = ENOENT;
            debug_printf("failed to open win handle\n");
        } else {
            new_fd = _open_osfhandle((intptr_t) new_h, O_TEXT);
            if (new_fd < 0) {
                ret = errno;
                debug_printf("failed to get descriptor on win handle, %d\n", new_fd);
            } else {
                new_f = _fdopen(new_fd, "w");
                if (new_f == NULL) {
                    ret = errno;
                    debug_printf("failed to open descriptor on win handle\n");
                } else {
                    /* We cannot free the current stderr struct, because other
                     * threads may still be relying on it, but we can extract
                     * the underlying file handle from it and close that. We do
                     * not want to syncronize all access to stderr, so we
                     * deliberately leak its old value. */
                    intptr_t old_h = _get_osfhandle(_fileno(stderr));
                    setvbuf(new_f, NULL, _IOFBF, 0x4000);
                    fflush(stderr);
                    *stderr = *new_f;
                    __sync_synchronize();
                    if (old_h != -1LL) {
                        _close(old_h);
                    }
                    debug_printf("log file cleared\n");
                }
            }
        }
    }

    if (ret)
        control_send_error(cd, opt, id, ret, NULL);
    else
        control_send_ok(cd, opt, id, NULL);

    return 0;
}

static int
control_command_reopen_char_files(void *opaque, const char *id, const char *opt,
                         dict d, void *command_opaque)
{
    int ret;
    struct control_desc *cd = (struct control_desc *)opaque;

    ret = qemu_chr_reopen_all();
    if (ret)
        control_send_error(cd, opt, id, ret, NULL);
    else
        control_send_ok(cd, opt, id, NULL);

    return 0;
}
#endif

static int
control_command_inject_trap(void *opaque, const char *id, const char *opt,
                            dict d, void *command_opaque)
{
    struct control_desc *cd = (struct control_desc *)opaque;
    int vcpu;
    uint32_t trap;
    uint32_t error_code;
    uint64_t cr2;
    int ret;

    vcpu = dict_get_integer(d, "vcpu");
    trap = dict_get_integer(d, "trap");
    error_code = dict_get_integer_default(d, "error_code", -1);
    cr2 = dict_get_integer_default(d, "cr2", 0);

    ret = xc_hvm_inject_trap(xc_handle, vm_id, vcpu, trap, error_code, cr2);
    if (ret)
	control_send_error(cd, opt, id, ret, NULL);
    else
	control_send_ok(cd, opt, id, NULL);

    return 0;
}

static int
collect_performance_data(void *opaque, const char *id, const char *opt,
                         dict d, void *command_opaque)
{
    int ret = -1;
    struct control_desc *cd = (struct control_desc *)opaque;

#if !defined (__APPLE__)
    ret = guest_agent_perf_collection(0xFULL, 1000, 60);
#endif
    if (ret)
        control_send_error(cd, opt, id, ret, NULL);
    else
        control_send_ok(cd, opt, id, NULL);

    return 0;
}

static int
control_command_set_key_forward(void *opaque, const char *id, const char *opt,
                     dict d, void *command_opaque)
{
    struct control_desc *cd = (struct control_desc *)opaque;
    int ret;

#if defined (__APPLE__)
    ret = -1;
#else
    ret = console_set_forwarded_keys(dict_get(d, "set"));
#endif
    if (ret)
        control_send_error(cd, opt, id, ret, NULL);
    else
        control_send_ok(cd, opt, id, NULL);
    return 0;
}

static int
control_command_set_balloon_size(void *opaque, const char *id, const char *opt,
                     dict d, void *command_opaque)
{
    struct control_desc *cd = (struct control_desc *)opaque;
    int ret;

    ret = uxen_platform_set_balloon_size(
            dict_get_integer(d, "min"),
            dict_get_integer(d, "max"));
    if (ret)
        control_send_error(cd, opt, id, ret, NULL);
    else
        control_send_ok(cd, opt, id, NULL);

    return 0;
}

#ifdef HAS_AUDIO
static int
control_command_audio_mute(void *opaque, const char *id, const char *opt,
                            dict d, void *command_opaque)
{
    struct control_desc *cd = (struct control_desc *)opaque;

    uxenaudio_mute(dict_get_integer(d, "mute"));
    control_send_ok(cd, opt, id, NULL);

    return 0;
}
#endif

#ifdef CONFIG_VBOXDRV
static int
control_command_clipboard_render(void *opaque, const char *id, const char *opt,
                        dict d, void *command_opaque)
{
#ifdef _WIN32
    int ret;
    struct control_desc *cd = (struct control_desc *)opaque;

    ret = vm_renderclipboard(TRUE);
    if (ret)
	control_send_error(cd, opt, id, ret, NULL);
    else
	control_send_ok(cd, opt, id, NULL);
#endif
    return 0;
}
#endif /* CONFIG_VBOXDRV */

#if defined(CONFIG_VBOXDRV)
#include <dm/shared-folders.h>

static int
control_command_sf_set_subfolder_scramble_mode(
    void *opaque,
    const char *id,
    const char *opt,
    dict d,
    void *command_opaque)
{
    struct control_desc *cd = (struct control_desc *)opaque;
    const char *name = dict_get_string(d, "name");
    const char *subfolder = dict_get_string(d, "subfolder");
    wchar_t *name_w = _utf8_to_wide(name);
    wchar_t *subfolder_w = _utf8_to_wide(subfolder);

    int mode = dict_get_integer(d, "mode");
    int rc;

    rc =  mode < 0
        ? sf_restore_opt(name_w, subfolder_w, SF_OPT_SCRAMBLE)
        : sf_mod_opt_dynamic(name_w, subfolder_w, SF_OPT_SCRAMBLE, mode ? 1:0);
    if (rc)
        control_send_error(cd, opt, id, rc, NULL);
    else
        control_send_ok(cd, opt, id, NULL);
    free(name_w);
    free(subfolder_w);
    return 0;
}

static int
control_command_sf_add_subfolder_opt(
    void *opaque,
    const char *id,
    const char *opt,
    dict d,
    void *command_opaque)
{
    struct control_desc *cd = (struct control_desc *)opaque;
    const char *name = dict_get_string(d, "name");
    const char *subfolder = dict_get_string(d, "subfolder");
    wchar_t *name_w = _utf8_to_wide(name);
    wchar_t *subfolder_w = _utf8_to_wide(subfolder);

    uint64_t vopt = dict_get_integer(d, "opt");
    uint64_t v = dict_get_integer(d, "value");
    int rc;

    rc = sf_mod_opt_dynamic(name_w, subfolder_w, vopt, v ? 1 : 0);
    if (rc)
        control_send_error(cd, opt, id, rc, NULL);
    else
        control_send_ok(cd, opt, id, NULL);
    free(name_w);
    free(subfolder_w);
    return 0;
}

static int
control_command_sf_del_subfolder_opt(
    void *opaque,
    const char *id,
    const char *opt,
    dict d,
    void *command_opaque)
{
    struct control_desc *cd = (struct control_desc *)opaque;
    const char *name = dict_get_string(d, "name");
    const char *subfolder = dict_get_string(d, "subfolder");
    wchar_t *name_w = _utf8_to_wide(name);
    wchar_t *subfolder_w = _utf8_to_wide(subfolder);

    uint64_t vopt = dict_get_integer(d, "opt");
    int rc;

    rc = sf_restore_opt(name_w, subfolder_w, vopt);
    if (rc)
        control_send_error(cd, opt, id, rc, NULL);
    else
        control_send_ok(cd, opt, id, NULL);
    free(name_w);
    free(subfolder_w);
    return 0;
}
#endif

#ifdef CONTROL_TEST
static int
control_command_test(void *opaque, const char *id, const char *opt,
                     dict d, void *command_opaque)
{
    struct control_desc *cd = (struct control_desc *)opaque;
    const char *key;
    dict val;
    unsigned int i;

    DICT_FOREACH(key, val, d, i) {
        switch (dict_typeof(val)) {
        case DICT_TYPE_STRING:
            debug_printf("%s: %s (string)\n", key, dict_get_string(d, key));
            break;
        case DICT_TYPE_NUMBER:
            debug_printf("%s: %"PRId64" (integer)\n", key,
                         dict_get_integer(d, key));
            break;
        default:
            debug_printf("%s: unsupported type\n", key);
            break;
        }
    }

    control_send_ok(cd, opt, id, NULL);
    return 0;
}
#endif  /* CONTROL_TEST */

static int
inject_ctrl_alt_delete(void *opaque, const char *id, const char *opt,
                       dict d, void *command_opaque)
{
    struct control_desc *cd = (struct control_desc *)opaque;
    struct input_event *ev;
    int i;
    BH *bh;
    int sc[6] = { 0x1D,     /* left ctrl down   */
                  0x38,     /* left alt down    */
                  0x53,     /* delete down      */
                  0xD3,     /* delete up        */
                  0xB8,     /* left alt up      */
                  0x9D };   /* left ctrl up     */


    for (i = 0; i < 6; i++) {
        bh = bh_new_with_data(input_event_cb, sizeof(struct input_event),
                              (void **)&ev);
        if (bh) {
            ev->type = KEYBOARD_INPUT_EVENT;
            ev->extended = 0;
            ev->keycode = sc[i];
            bh_schedule_one_shot(bh);
        }
    }

    control_send_ok(cd, opt, id, NULL);

    return 0;
}

static int
show_command_prompt(void *opaque, const char *id, const char *opt,
                    dict d, void *command_opaque)
{
    struct control_desc *cd = (struct control_desc *)opaque;
    int ret = -1;

#if !defined(__APPLE__)
    ret = guest_agent_cmd_prompt();
#endif
    if (ret)
        control_send_error(cd, opt, id, ret, NULL);
    else
        control_send_ok(cd, opt, id, NULL);

    return 0;
}

static int
remote_execute(void *opaque, const char *id, const char *opt,
               dict d, void *command_opaque)
{
    struct control_desc *cd = (struct control_desc *)opaque;
    int ret = -1;
    const char *command;

    command = dict_get_string(d, "command-line");
    if (!command) {
        control_send_error(cd, opt, id, -1, NULL);
        return -1;
    }

#if !defined(__APPLE__)
    ret = guest_agent_execute(command);
#endif
    if (ret)
        control_send_error(cd, opt, id, ret, NULL);
    else
        control_send_ok(cd, opt, id, NULL);

    return 0;
}

static struct Timer *stats_timer = NULL;

static void
stats_timer_cb(void *opaque)
{
    uint64_t now = get_clock_ms(rt_clock);
    int ret;
    xc_dominfo_t info;
    int balloon_cur, balloon_min, balloon_max;
    int priv, lowmem, highmem, vram;
    int pod, tmpl, zero;
    float cpu_u = 0.0f, cpu_k = 0.0f;
    uint64_t cpu_u_total_ms = 0, cpu_k_total_ms = 0;
    uint64_t blk_io_reads = 0, blk_io_writes = 0;
    unsigned int tcp_nb_conn = 0, tcp_nb_total = 0, net_last = 0,
        net_rx_rate = 0, net_tx_rate = 0;
    unsigned int net_nav_tx_rate = 0, net_nav_rx_rate = 0;

    ret = xc_domain_getinfo(xc_handle, vm_id, 1, &info);
    if (ret != 1 || info.domid != vm_id) {
        warn("xc_domain_getinfo failed");
        goto finish;
    }

    balloon_cur = balloon_min = balloon_max = 0;
    uxen_platform_get_balloon_size(&balloon_cur, &balloon_min, &balloon_max);
    priv = info.nr_pages * UXEN_PAGE_SIZE;
    vram = info.nr_host_mapped_pages * UXEN_PAGE_SIZE;
    highmem = info.nr_hidden_pages * UXEN_PAGE_SIZE;
    lowmem = priv - highmem;
    pod = info.nr_pod_pages * UXEN_PAGE_SIZE;
    tmpl = info.nr_tmpl_shared_pages * UXEN_PAGE_SIZE;
    zero = info.nr_zero_shared_pages * UXEN_PAGE_SIZE;
    cpu_usage(&cpu_u, &cpu_k, &cpu_u_total_ms, &cpu_k_total_ms);
    blockstats_getabs(&blk_io_reads, NULL, &blk_io_writes, NULL);
#if defined(CONFIG_NICKEL)
    ni_stats(&tcp_nb_conn, &tcp_nb_total, &net_last,
                &net_rx_rate, &net_tx_rate, &net_nav_rx_rate, &net_nav_tx_rate);
#endif

    ret = dict_rpc_status(control_send, &control,
        "iiiiiiiiiiiiiiiiiiiii",
        "mem", (int64_t)vm_mem_mb * (1024 * 1024),
        "balloon-cur", (int64_t)balloon_cur,
        "balloon-min", (int64_t)balloon_min,
        "balloon-max", (int64_t)balloon_max,
        "private-mem", (int64_t)priv,
        "vram-mem", (int64_t)vram,
        "lowmem", (int64_t)lowmem,
        "highmem", (int64_t)highmem,
        "on-demand-mem", (int64_t)pod,
        "template-mem", (int64_t)tmpl,
        "zero-mem", (int64_t)zero,
        "cpu-user", (int64_t)(cpu_u * 1000.0f), // 10x percent of one CPU usage
        "cpu-kernel", (int64_t)(cpu_k * 1000.0f),
        "cpu-user-total-ms", (int64_t)(cpu_u_total_ms),
        "cpu-kernel-total-ms", (int64_t)(cpu_k_total_ms),
        "io-reads", (int64_t)blk_io_reads,
        "io-writes", (int64_t)blk_io_writes,
        "tcp-nav", (int64_t)tcp_nb_conn,
        "tcp-conn", (int64_t)tcp_nb_total,
        "last-packet", (int64_t)net_last,
        "tx-nav", (int64_t)net_nav_tx_rate,
        "tx", (int64_t)net_tx_rate,
        "rx-nav", (int64_t)net_nav_rx_rate,
        "rx", (int64_t)net_rx_rate,
        NULL);

    if (ret)
        warnx("%s: dict_rpc_status", __FUNCTION__);

finish:
    if (stats_timer)
        mod_timer(stats_timer, now + 1000);
}


static void
collect_stats_start(void *opaque)
{
    int *start = opaque;

    if (*start && !stats_timer) {
        uint64_t now = get_clock_ms(rt_clock);

        stats_timer = new_timer_ms(rt_clock, stats_timer_cb, NULL);
        mod_timer(stats_timer, now);
    } else if (!*start && stats_timer) {
        free_timer(stats_timer);
        stats_timer = NULL;
    }
}

static int
collect_vm_stats_once(void *opaque, const char *id, const char *opt,
                 dict d, void *command_opaque)
{
    struct control_desc *cd = (struct control_desc *)opaque;

    stats_timer_cb(NULL);
    control_send_ok(cd, opt, id, 0, NULL);
    return 0;
}

static int
collect_vm_stats(void *opaque, const char *id, const char *opt,
                 dict d, void *command_opaque)
{
    int ret = -1;
    struct control_desc *cd = (struct control_desc *)opaque;
    int *start;
    BH *bh;

    bh = bh_new_with_data(collect_stats_start, sizeof(int),
                          (void **)&start);
    if (bh) {
        *start = dict_get_integer(d, "start");
        bh_schedule_one_shot(bh);
        control_send_ok(cd, opt, id, NULL);
    } else
        control_send_error(cd, opt, id, ret, NULL);

    return 0;
}

#define CONTROL_SUSPEND_OK 0x0001

/* must be strcmp sorted */
struct dict_rpc_command control_commands[] = {
#ifdef HAS_AUDIO
    { "audio-mute", control_command_audio_mute,
      .args = (struct dict_rpc_arg_desc[]) {
            { "mute", DICT_RPC_ARG_TYPE_INTEGER, .optional = 0 },
            { NULL, },
        }, },
#endif
#ifdef CONFIG_VBOXDRV
    { "clipboard-render", control_command_clipboard_render, },
#endif /* CONFIG_VBOXDRV */
    { "collect-performance-data", collect_performance_data, },
    { "collect-vm-stats", collect_vm_stats,
      .args = (struct dict_rpc_arg_desc[]) {
            { "start", DICT_RPC_ARG_TYPE_INTEGER, .optional = 0 },
            { NULL, },
        }, },
    { "collect-vm-stats-once", collect_vm_stats_once, .flags = CONTROL_SUSPEND_OK, },
    { "inject-ctrl-alt-delete", inject_ctrl_alt_delete, },
    { "inject-trap", control_command_inject_trap,
      .args = (struct dict_rpc_arg_desc[]) {
            { "trap", DICT_RPC_ARG_TYPE_INTEGER, .optional = 0 },
            { "vcpu", DICT_RPC_ARG_TYPE_INTEGER,
              .defval = DICT_RPC_ARG_DEFVAL_INTEGER(0) },
            { "error-code", DICT_RPC_ARG_TYPE_INTEGER, .optional = 1 },
            { "cr2", DICT_RPC_ARG_TYPE_INTEGER, .optional = 1 },
            { NULL, },
        }, },
#if defined(CONFIG_NICKEL)
    { "nc_AccessControlChange",  ni_rpc_ac_event,
      .args = (struct dict_rpc_arg_desc[]) {
            { "policy", DICT_RPC_ARG_TYPE_INTEGER, .optional = 1 },
            { "proxy-config", DICT_RPC_ARG_TYPE_INTEGER, .optional = 1 },
            { NULL, },
        }, },
#endif

#if defined(CONFIG_NICKEL)
    { "nc_GlobalPcapDump", ni_pcap_global_dump, },
    { "nc_NetworkPolicyRefresh", ni_rpc_ac_event, },
    { "nc_ProxyCacheFlush", ni_rpc_http_event, },
    { "nc_ProxyCredentialsChange", ni_rpc_http_event, },
#endif

#ifdef _WIN32
    { "open-log", control_command_open_log,
      .args = (struct dict_rpc_arg_desc[]) {
            { "logfile", DICT_RPC_ARG_TYPE_STRING, .optional = 0 },
            { NULL, },
        }, },
#endif

    { "parent-window-key-forward", control_command_set_key_forward,
      .args = (struct dict_rpc_arg_desc[]) {
            { "set", DICT_RPC_ARG_TYPE_ARRAY, .optional = 0 },
            { NULL, },
        }, },
    { "pause", control_command_pause, },
    { "quit", control_command_quit, .flags = CONTROL_SUSPEND_OK,
      .args = (struct dict_rpc_arg_desc[]) {
            { "force", DICT_RPC_ARG_TYPE_BOOLEAN,
              .defval = DICT_RPC_ARG_DEFVAL_BOOLEAN(true) },
            { "interrupt", DICT_RPC_ARG_TYPE_BOOLEAN,
              .defval = DICT_RPC_ARG_DEFVAL_BOOLEAN(false) },
            { NULL, },
        }, },
    { "remote-execute", remote_execute,
      .args = (struct dict_rpc_arg_desc[]) {
            { "command-line", DICT_RPC_ARG_TYPE_STRING, .optional = 0 },
            { NULL, },
        }, },
#ifdef _WIN32
    { "reopen-char-files", control_command_reopen_char_files, },
#endif
    { "resume", control_command_resume, .flags = CONTROL_SUSPEND_OK,
      .args = (struct dict_rpc_arg_desc[]) {
            { "delete-savefile", DICT_RPC_ARG_TYPE_BOOLEAN, .optional = 1,
              .defval = DICT_RPC_ARG_DEFVAL_BOOLEAN(true) },
            { NULL, },
        }, },
    { "save", control_command_save,
      .args = (struct dict_rpc_arg_desc[]) {
            { "filename", DICT_RPC_ARG_TYPE_STRING, .optional = 1 },
            { "compress", DICT_RPC_ARG_TYPE_STRING, .optional = 1 },
            { "high-compress", DICT_RPC_ARG_TYPE_BOOLEAN, .optional = 1,
              .defval = DICT_RPC_ARG_DEFVAL_BOOLEAN(false) },
            { "single-page", DICT_RPC_ARG_TYPE_BOOLEAN, .optional = 1,
              .defval = DICT_RPC_ARG_DEFVAL_BOOLEAN(true) },
            { "free-mem", DICT_RPC_ARG_TYPE_BOOLEAN, .optional = 1,
              .defval = DICT_RPC_ARG_DEFVAL_BOOLEAN(true) },
            { NULL, },
        }, },
    { "set-balloon-size", control_command_set_balloon_size,
      .args = (struct dict_rpc_arg_desc[]) {
            { "min", DICT_RPC_ARG_TYPE_INTEGER, .optional = 0 },
            { "max", DICT_RPC_ARG_TYPE_INTEGER, .optional = 0 },
            { NULL, },
      }, },
#if defined(CONFIG_VBOXDRV)
    { "sf-add-subfolder-opt", control_command_sf_add_subfolder_opt,
      .args = (struct dict_rpc_arg_desc[]) {
            { "name", DICT_RPC_ARG_TYPE_STRING, .optional = 0 },
            { "subfolder", DICT_RPC_ARG_TYPE_STRING, .optional = 0 },
            { "opt", DICT_RPC_ARG_TYPE_INTEGER, .optional = 0 },
            { "value", DICT_RPC_ARG_TYPE_INTEGER, .optional = 0 },
            { NULL, },
        }
    },
    { "sf-del-subfolder-opt", control_command_sf_del_subfolder_opt,
      .args = (struct dict_rpc_arg_desc[]) {
            { "name", DICT_RPC_ARG_TYPE_STRING, .optional = 0 },
            { "subfolder", DICT_RPC_ARG_TYPE_STRING, .optional = 0 },
            { "opt", DICT_RPC_ARG_TYPE_INTEGER, .optional = 0 },
            { NULL, },
        }
    },
    { "sf-set-subfolder-scramble-mode", control_command_sf_set_subfolder_scramble_mode,
      .args = (struct dict_rpc_arg_desc[]) {
            { "name", DICT_RPC_ARG_TYPE_STRING, .optional = 0 },
            { "subfolder", DICT_RPC_ARG_TYPE_STRING, .optional = 0 },
            { "mode", DICT_RPC_ARG_TYPE_INTEGER, .optional = 0 },
            { NULL, },
        }
    },
#endif
    { "show-command-prompt", show_command_prompt, },
#ifdef CONTROL_TEST
    { "test-int", control_command_test,
      .args = (struct dict_rpc_arg_desc[]) {
            { "arg1", DICT_RPC_ARG_TYPE_INTEGER, .optional = 0 },
            { "arg2", DICT_RPC_ARG_TYPE_INTEGER, .optional = 1 },
            { "arg3", DICT_RPC_ARG_TYPE_INTEGER,
              .defval = DICT_RPC_ARG_DEFVAL_INTEGER(132) },
            { "arg4", DICT_RPC_ARG_TYPE_INTEGER,
              .defval = DICT_RPC_ARG_DEFVAL_INTEGER(0) },
            { NULL, },
        }, },
    { "test-str", control_command_test,
      .args = (struct dict_rpc_arg_desc[]) {
            { "arg1", DICT_RPC_ARG_TYPE_STRING, .optional = 0 },
            { "arg2", DICT_RPC_ARG_TYPE_STRING, .optional = 1 },
            { "arg3", DICT_RPC_ARG_TYPE_STRING,
              .defval = DICT_RPC_ARG_DEFVAL_STRING("Hello, World") },
            { NULL, },
        }, },
#endif  /* CONTROL_TEST */
    { "unpause", control_command_unpause, },
};

static int
control_execute(dict_rpc_send_fn send_fn, void *send_opaque,
                struct dict_rpc_command *c, const char *id,
                dict d, void *fn_opaque)
{

    switch (vm_get_run_mode()) {
    case SUSPEND_VM:
        if (!(c->flags & CONTROL_SUSPEND_OK)) {
            dict_rpc_error(send_fn, send_opaque, c->command, id, EAGAIN,
                           "invalid state: command \"%s\" "
                           "not allowed while VM suspended",
                           c->command);
            return EAGAIN | DICT_EXECUTE_ERROR_SUPPRESS;
        }
        break;
    default:
        break;
    }

    return c->fn(fn_opaque, id, c->command, d, c->opaque);
}

static void
control_process_input(struct control_desc *cd)
{

    if (!cd->input)
        return;

    cd->input[cd->input_len] = 0;
    debug_printf("control: %s\n", cd->input);

    /* ret = */ dict_rpc_process_input_buffer(
        control_execute, control_send, cd, cd->input,
        control_commands, ARRAY_SIZE(control_commands), cd);
}

static int
control_can_receive(void *opaque)
{

    return CONTROL_MAX_LINE_LEN;
}

static void
control_receive(void *opaque, const uint8_t *buf, int size)
{
    struct control_desc *cd = opaque;
    const uint8_t *buf_end;
    int linesize;

    while (size > 0) {
	/* Find EOL */
	buf_end = memchr(buf, '\n', size);
	linesize = buf_end ? (buf_end - buf) : size;

	/* Try to add line to input buffer */
	if (!cd->discard) {
	    /* Increase until there's enough space */
	    while (cd->input_len + linesize > cd->input_size) {
		char *input;
		/* +1 for terminating \0 */
		input = realloc(cd->input, cd->input_size + 1 +
				CONTROL_INPUT_REALLOC_SIZE);
		if (!input) {
		    control_send_error(cd, NULL, NULL, ENOMEM, "out of memory");
		    cd->discard = 1;
		    break;
		}
                cd->input = input;
                cd->input_size += CONTROL_INPUT_REALLOC_SIZE;
	    }
	    if (!cd->discard) {
		memcpy(cd->input + cd->input_len, buf, linesize);
		cd->input_len += linesize;
	    }
	}
	/* Exit loop if there's no EOL character */
	if (!buf_end)
	    break;
	/* Adjust buf/size for next line */
	buf = buf_end + 1;
	size -= linesize + 1;
	/* Process input */
	if (!cd->discard)
	    control_process_input(cd);
	else
	    /* If we get here while discarding, then we're done */
	    cd->discard = 0;
	cd->input_len = 0;
    }
}

#if defined(_WIN32)
static DWORD WINAPI
control_thread_run(PVOID dummy)
#elif defined(__APPLE__)
static void *
control_thread_run(void *dummy)
#endif
{
    int timeout;

    debug_printf("%s: control thread started\n", __FUNCTION__);

    for (;;) {
        if (control_thread_exit)
            break;

        timeout = DEFAULT_TIMEOUT_MS;
        ioh_wait_for_objects(&control_io_handlers, &control_wait_objects, NULL,
                             &timeout, NULL);
    }

    debug_printf("%s: control thread exit\n", __FUNCTION__);

    return 0;
}

void
control_open(char *path)
{
#ifdef DEBUG
    int i;

    for (i = 1; i < ARRAY_SIZE(control_commands); i++) {
        if (strcmp(control_commands[i - 1].command,
                   control_commands[i].command) > 0)
            errx(1, "control_commands array is unsorted");
    }
#endif
    ioh_queue_init(&control_io_handlers);
    ioh_init_wait_objects(&control_wait_objects);

    control.chr = qemu_chr_open("control", path, NULL, &control_io_handlers);
    if (!control.chr)
	return;

    ioh_event_init(&control_ev);
    ioh_add_wait_object(&control_ev, NULL, NULL, &control_wait_objects);

    control.input = NULL;
    control.input_len = 0;
    control.input_size = 0;
    control.discard = 0;

    qemu_chr_add_handlers(control.chr, control_can_receive,
			  control_receive, NULL, &control);

    if (create_thread(&control_thread, control_thread_run, NULL) < 0)
        warnx("%s: cannot create control thread", __FUNCTION__);
}

void
control_command_exit(void)
{

    control_send_queued();

    dict_rpc_cb_exit();
}

void
control_exit(void)
{
    if (!control_thread)
        return;

    control_command_exit();
    control_flush();
    control_thread_exit = 1;
    ioh_event_set(&control_ev);

    wait_thread(control_thread);
    control_thread = NULL;
}
