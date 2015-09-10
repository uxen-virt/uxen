/*
 * Copyright 2012-2015, Bromium, Inc.
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
#include "console.h"
#include "control.h"
#include "dict.h"
#include "dm.h"
#include "hw/uxen_audio_ctrl.h"

#include <dm/qemu/readline.h>

critical_section monitor_lock;

// #define MONITOR_DEBUG 1

#ifdef MONITOR_DEBUG
#define monitor_debug(...) monitor_printf(cur_mon, __VA_ARGS__)
#else
#define monitor_debug(...) do { /* */ } while (0)
#endif

struct Monitor {
    CharDriverState *chr;
    ReadLineState *rs;
    int suspend_cnt;
    int reset_seen;
};

static Monitor _cur_mon = { NULL, };
Monitor *cur_mon = &_cur_mon;

typedef struct mon_cmd_t {
    const char *name;
    const char *args_type;
    const char *params;
    const char *help;
    /* void (*user_print)(Monitor *mon, const QObject *data); */
    union {
        void (*info)(Monitor *mon);
        void (*cmd)(Monitor *mon, const dict args);
        /* int  (*cmd_new)(Monitor *mon, const QDict *params, QObject **ret_data); */
        /* int  (*cmd_async)(Monitor *mon, const QDict *params, */
        /*                   MonitorCompletion *cb, void *opaque); */
    } mhandler;
    /* bool qapi; */
    /* int flags; */
} mon_cmd_t;

static mon_cmd_t mon_cmds[];
static mon_cmd_t info_cmds[];

static void sortcmdlist(void);
static mon_cmd_t *monitor_parse_command(Monitor *mon, const char *cmdline,
                                        dict args);

static void
handle_user_command(Monitor *mon, const char *cmdline)
{
    mon_cmd_t *cmd;
    dict args;

    args = dict_new();

    cmd = monitor_parse_command(mon, cmdline, args);

    if (cmd)
        cmd->mhandler.cmd(mon, args);

    dict_free(args);
}

static uint8_t term_outbuf[1024];
static int term_outbuf_index = 0;

void
monitor_flush(Monitor *mon)
{

    if (!mon->chr)
        return;

    critical_section_enter(&monitor_lock);
    if (term_outbuf_index > 0) {
        int n = 0;
        int ret;
        while (n < term_outbuf_index) {
            ret = qemu_chr_write(mon->chr, term_outbuf + n,
                                 term_outbuf_index - n);
            if (ret < 0)
                break;
            n += ret;
        }
        term_outbuf_index = 0;
    }
    critical_section_leave(&monitor_lock);
}

/* flush at every end of line or if the buffer is full */
void
monitor_puts(Monitor *mon, const char *str)
{
    char c;

    if (!mon->chr)
        return;

    critical_section_enter(&monitor_lock);
    for (;;) {
        c = *str++;
        if (c == '\0')
            break;
        if (c == '\n')
            term_outbuf[term_outbuf_index++] = '\r';
        term_outbuf[term_outbuf_index++] = c;
        if (term_outbuf_index >= (sizeof(term_outbuf) - 1) ||
            c == '\n' || c == '\r')
            monitor_flush(mon);
    }
    critical_section_leave(&monitor_lock);
}

void
monitor_vprintf(Monitor *mon, const char *fmt, va_list ap)
{
    char buf[4096];

    vsnprintf(buf, sizeof(buf), fmt, ap);
    monitor_puts(mon ? : cur_mon, buf);
}

void
monitor_printf(Monitor *mon, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    monitor_vprintf(mon, fmt, ap);
    va_end(ap);
}

void
monitor_print_filename(Monitor *mon, const char *filename)
{
    int i;

    for (i = 0; filename[i]; i++) {
	switch (filename[i]) {
	case ' ':
	case '"':
	case '\\':
	    monitor_printf(mon, "\\%c", filename[i]);
	    break;
	case '\t':
	    monitor_printf(mon, "\\t");
	    break;
	case '\r':
	    monitor_printf(mon, "\\r");
	    break;
	case '\n':
	    monitor_printf(mon, "\\n");
	    break;
	default:
	    monitor_printf(mon, "%c", filename[i]);
	    break;
	}
    }
}

int
monitor_suspend(Monitor *mon)
{
    if (!mon->rs)
        return -ENOTTY;
    mon->suspend_cnt++;
    return 0;
}

void
monitor_resume(Monitor *mon)
{
    if (!mon->rs)
        return;
    if (--mon->suspend_cnt == 0)
        readline_show_prompt(mon->rs);
}

static void
monitor_command_cb(Monitor *mon, const char *cmdline, void *opaque)
{
    monitor_suspend(mon);
    handle_user_command(mon, cmdline);
    monitor_resume(mon);
}

static int
monitor_can_read(void *opaque)
{
    Monitor *mon = opaque;

    return (mon->suspend_cnt == 0) ? 1 : 0;
}

static void
monitor_read_command(Monitor *mon, int show_prompt)
{
    if (!mon->rs)
        return;

    readline_start(mon->rs, "(uxendm) ", 0, monitor_command_cb, NULL);
    if (show_prompt)
        readline_show_prompt(mon->rs);
}

static void
monitor_find_completion(const char *cmdline)
{
}

static void
monitor_read(void *opaque, const uint8_t *buf, int size)
{
    Monitor *old_mon = cur_mon;
    int i;

    cur_mon = opaque;

    if (cur_mon->rs) {
        for (i = 0; i < size; i++)
            readline_handle_byte(cur_mon->rs, buf[i]);
    } else {
        if (size == 0 || buf[size - 1] != 0)
            monitor_printf(cur_mon, "corrupted command\n");
        else
            handle_user_command(cur_mon, (char *)buf);
    }

    cur_mon = old_mon;
}

static void
monitor_event(void *opaque, int event)
{
    Monitor *mon = opaque;

    switch (event) {
    case CHR_EVENT_OPENED:
        monitor_printf(mon, "uxendm %s monitor - type 'help' for more "
                       "information\n", UXENDM_VERSION);
        readline_show_prompt(mon->rs);
        mon->reset_seen = 1;
        break;
    }
}

void
monitor_init(CharDriverState *hd, int show_banner)
{

    critical_section_init(&monitor_lock);

    if (!hd)
        return;

    assert(!cur_mon->chr);
    cur_mon->chr = hd;

    cur_mon->rs = readline_init(cur_mon, monitor_find_completion);
    monitor_read_command(cur_mon, 0);

    qemu_chr_add_handlers(cur_mon->chr, monitor_can_read, monitor_read,
                          monitor_event, cur_mon);

    sortcmdlist();
}

static void mc_help(Monitor *mon, const dict args);
static void mc_info(Monitor *mon, const dict args);
static void mc_debug_break(Monitor *mon, const dict args);
static void mc_test_control_msg(Monitor *mon, const dict args);

static mon_cmd_t mon_cmds[] = {
    { .name = "help|?", .mhandler.cmd = mc_help,
      .help = "show list of commands" },
    { .name = "info", .mhandler.cmd = mc_info, .args_type = "?s:subsystem",
      .help = "show information about subsystem state" },
    { .name = "quit|q", .mhandler.cmd = mc_quit,
      .args_type = "?b:interrupt,?b:force", .help = "terminate the vm" },
    { .name = "savevm", .mhandler.cmd = mc_savevm,
      .args_type = "?s:filename,?s:compress,?b:high-compress,"
                   "?b:single-page,?b:free-mem",
      .help = "save the vm" },
    { .name = "resume", .mhandler.cmd = mc_resumevm,
      .args_type = "?b:delete-savefile",
      .help = "resume the vm" },
    { .name = "debug-break|xdbg", .mhandler.cmd = mc_debug_break,
      .help = "execute breakpoint instruction" },
    { .name = "xen-key|xk", .mhandler.cmd = mc_xen_key,
      .args_type = "s:keys", .help = "send keys to uXen" },
    { .name = "toggle-ioreq|xioreq", .mhandler.cmd = mc_toggle_ioreq,
      .help = "toggle ioreq dumping" },
    { .name = "toggle-hvm-tracking|xhvm",
      .mhandler.cmd = mc_toggle_hvm_tracking,
      .help = "toggle hvm dirty vram tracking" },
    { .name = "clear-stats", .mhandler.cmd = mc_clear_stats,
      .help = "clear stat counters" },
    { .name = "test-control-msg-strings|tcms",
      .mhandler.cmd = mc_test_control_msg,
      .args_type = "s:command,?s:arg1,?s:arg2,?s:arg3,?s:arg4",
      .help = "send message on control channel (string args)" },
    { .name = "test-control-msg-numbers|tcmn",
      .mhandler.cmd = mc_test_control_msg,
      .args_type = "s:command,?n:arg1,?n:arg2,?n:arg3,?n:arg4",
      .help = "send message on control channel (number args)" },
    { .name = "resize-screen", .mhandler.cmd = mc_resize_screen,
      .args_type = "n:w,n:h",
      .help = "resize screen" },
    { .name = "block-change", .mhandler.cmd = mc_block_change,
      .args_type = "s:id,?s:image" },
    { .name = "inject-trap", .mhandler.cmd = mc_inject_trap,
      .args_type = "n:vcpu,n:trap,?n:error_code,?n:cr2" },
    { .name = "pause", .mhandler.cmd = mc_vm_pause, .help = "pause VM" },
    { .name = "unpause", .mhandler.cmd = mc_vm_unpause, .help = "unpause VM" },
    { .name = "time-update", .mhandler.cmd = mc_vm_time_update,
      .help = "trigger VM time update" },
    { .name = "balloon-size", .mhandler.cmd = mc_vm_balloon_size,
      .args_type = "n:size", .help = "set balloon size" },
#ifdef HAS_AUDIO
    { .name ="audio-mute", .mhandler.cmd = mc_vm_audio_mute,
      .args_type = "n:mute", .help = "mute/unmute guest audio" },
#endif

};

static void ic_version(Monitor *mon);

static mon_cmd_t info_cmds[] = {
    { .name = "version", .mhandler.info = ic_version,
      .help = "show the version of QEMU" },
#ifndef OSX_NOT_YET
    { .name = "network", .mhandler.info = ic_network,
      .help = "show the network state" },
#endif
    { .name = "chardev", .mhandler.info = ic_chr,
      .help = "show the character devices" },
    { .name = "block", .mhandler.info = ic_block,
      .help = "show the block devices" },
    { .name = "blockstats", .mhandler.info = ic_blockstats,
      .help = "show block device statistics" },
    { .name = "uuid", .mhandler.info = ic_uuid,
      .help = "show the current VM UUID" },
    { .name = "ioreq", .mhandler.info = ic_ioreq,
      .help = "show ioreq statistics" },
#ifdef DEBUG_WAITOBJECTS
    { .name = "wo", .mhandler.info = ic_wo,
      .help = "show WaitObjects statistics" },
#endif
    { .name = "memcache", .mhandler.info = ic_memcache,
      .help = "show memcache statistics" },
    { .name = "physinfo", .mhandler.info = ic_physinfo,
      .help = "show system physinfo" },
};

static int
compare_mon_cmd(const void *a, const void *b)
{

    return strcmp(((const mon_cmd_t *)a)->name,
            ((const mon_cmd_t *)b)->name);
}

static void
sortcmdlist(void)
{

    qsort((void *)mon_cmds, ARRAY_SIZE(mon_cmds), sizeof(mon_cmd_t),
          compare_mon_cmd);

    qsort((void *)info_cmds, ARRAY_SIZE(info_cmds), sizeof(mon_cmd_t),
          compare_mon_cmd);
}

static inline int
get_word(const char *buf)
{

    return strcspn(buf, " ");
}

static mon_cmd_t *
match_mon_cmd(const char *cmd, mon_cmd_t *cmds, int nr_cmds)
{
    int i, clen, cmd_len;
    const char *c;

    cmd_len = strlen(cmd);

    for (i = 0; i < nr_cmds; i++) {
        c = cmds[i].name;
        while (*c) {
            clen = strcspn(c, "|");
            if (!clen)
                clen = strlen(c);
            if (clen == cmd_len && !strncmp(c, cmd, clen))
                return &cmds[i];
            c += clen;
            if (*c == '|')
                c++;
        }
    }

    return NULL;
}

static mon_cmd_t *
monitor_parse_command(Monitor *mon, const char *cmdline, dict args)
{
    mon_cmd_t *cmd;
    char *token, *arg, type;
    const char *args_type;
    int l;

    monitor_debug("command='%s'\n", cmdline);

    l = get_word(cmdline);
    if (l == 0)
        return NULL;

    asprintf(&token, "%.*s", l, cmdline);
    if (!token)
        return NULL;

    monitor_debug("  cmd name: %s\n", token);

    cmd = match_mon_cmd(token, mon_cmds, ARRAY_SIZE(mon_cmds));
    monitor_debug("  found cmd: %s\n", cmd ? cmd->name : "<not found>");
    if (!cmd) {
        monitor_printf(mon, "error: unknown command '%s'\n", token);
        goto out;
    }

    cmdline += l;

    if (*cmdline && !cmd->args_type) {
        monitor_printf(mon, "error: command '%s' has no arguments\n",
                       cmd->name);
        cmd = NULL;
        goto out;
    }

    args_type = cmd->args_type;

    while (*cmdline) {
        l = strspn(cmdline, " ");
        if (l) {
            cmdline += l;
            continue;
        }

        l = get_word(cmdline);
        assert(l);

        free(token);
        asprintf(&token, "%.*s", l, cmdline);

        monitor_debug("  arg: %s\n", token);

        cmdline += l;

        if (*args_type == 0) {
            monitor_printf(mon, "error: too many arguments for command '%s'\n",
                           cmd->name);
            cmd = NULL;
            goto out;
        }

        if (*args_type == '?')
            args_type++;

        type = *args_type;
        args_type++;
        assert(*args_type == ':');
        args_type++;
        assert(*args_type);

        l = strcspn(args_type, ",");
        if (!l)
            l = strlen(args_type);
        asprintf(&arg, "%.*s", l, args_type);
        if (!arg)
            goto out;

        switch (type) {
        case 's':
            dict_put_string(args, arg, token);
            break;
        case 'n':
            dict_put_number(args, arg, token);
            break;
        case 'b': {
            int b;

            b = dict_string_as_bool(token, -1);
            if (b == -1) {
                monitor_printf(mon, "error: command '%s' requires bool"
                               " argument '%s'\n", cmd->name, arg);
                cmd = NULL;
                goto out;
            }
            dict_put_boolean(args, arg, !!b);
            break;
        }
        default:
            assert(0 && type);
            break;
        }

        free(arg);

        args_type += l;
        if (*args_type == ',')
            args_type++;
    }

    if (args_type && *args_type && *args_type != '?') {
        monitor_printf(mon,
                       "error: command '%s' requires additional argument(s)\n",
                       cmd->name);
        cmd = NULL;
        goto out;
    }

  out:
    free(token);
    return cmd;
}

static void
mc_help(Monitor *mon, const dict args)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(mon_cmds); i++)
        monitor_printf(mon, "%s%s%s -- %s\n", mon_cmds[i].name,
                       mon_cmds[i].args_type ? " " : "",
                       mon_cmds[i].args_type ?: "", mon_cmds[i].help);
}

static void
mc_info(Monitor *mon, const dict args)
{
    mon_cmd_t *info;
    const char *subsys;
    int i;

    subsys = dict_get_string(args, "subsystem");
    if (!subsys) {
        for (i = 0; i < ARRAY_SIZE(info_cmds); i++)
            monitor_printf(mon, "info %s%s%s -- %s\n", info_cmds[i].name,
                           info_cmds[i].args_type ? " " : "",
                           info_cmds[i].args_type ?: "", info_cmds[i].help);
        return;
    }

    info = match_mon_cmd(subsys, info_cmds, ARRAY_SIZE(info_cmds));
    monitor_debug("  found info: %s\n", info ? info->name : "<not found>");
    if (!info) {
        monitor_printf(mon, "error: unknown subsystem '%s'\n", subsys);
        return;
    }

    info->mhandler.info(mon);
}

static void
mc_debug_break(Monitor *mon, const dict args)
{

    debug_break();
}

static void
ic_version(Monitor *mon)
{

    monitor_printf(mon, "uxendm devel\n");
}

static void
mc_test_control_msg_callback(void *opaque, dict d)
{
    Monitor *mon = (Monitor *)opaque;

    monitor_printf(mon, "%s\n", __FUNCTION__);

    dict_free(d);
}

static void
mc_test_control_msg(Monitor *mon, const dict args)
{
    const char *command;

    command = dict_get_string(args, "command");

    control_send_command(command, args, mc_test_control_msg_callback, mon);
}
