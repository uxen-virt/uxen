/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "base64.h"
#include "block.h"
#include "compiler.h"
#include "console.h"
#include "default.h"
#include "dev.h"
#include "dm.h"
#include "dmpdev.h"
#include "firmware.h"
#include "lib.h"
#include "net.h"
#include "vm.h"

#include "yajl.h"
#include "shared-folders.h"
#include "clipboard.h"

struct conffile {
    yajl_val parser_obj;
    const char *name;
    const char *config_buf;
    const char *config_string;
};

static struct conffile *cf_default = NULL;

struct conffile *
config_load(const char *name)
{
    int fd;
    struct stat sbuf;
    size_t rd;
    int ret;
    char errbuf[1024];
    struct conffile *cf;
    char *buf;

    fd = open(name, O_RDONLY | O_BINARY);
    if (fd < 0)
	err(1, "open %s", name);

    ret = fstat(fd, &sbuf);
    if (ret < 0)
	err(1, "stat");

    cf = calloc(1, sizeof(*cf));
    if (cf == NULL)
	err(1, "calloc");

    cf->name = strdup(name);
    if (cf->name == NULL)
	err(1, "stdrup");

    buf = malloc(sbuf.st_size + 1);
    if (buf == NULL)
	err(1, "malloc");

    rd = read(fd, buf, sbuf.st_size);
    if (rd != sbuf.st_size)
	err(1, "read");
    buf[sbuf.st_size] = 0;

    cf->config_buf = buf;

    errbuf[0] = 0;
    cf->parser_obj = yajl_tree_parse(cf->config_buf, errbuf, sizeof(errbuf));
    if (cf->parser_obj == NULL) {
	errx(1, "%s: parse error: %s", cf->name,
	     errbuf[0] ? errbuf : "unknown error");
    }

    if (!YAJL_IS_OBJECT(cf->parser_obj))
	errx(1, "%s: malformed -- top-level not an object", cf->name);

    if (fd >= 0)
        close(fd);

    return cf;
}

struct conffile *
config_string(const char *config)
{
    char errbuf[1024];
    struct conffile *cf;

    cf = calloc(1, sizeof(*cf));
    if (cf == NULL)
	err(1, "calloc");

    cf->name = strdup("string");
    if (cf->name == NULL)
	err(1, "stdrup");

    cf->config_string = config;

    errbuf[0] = 0;
    cf->parser_obj = yajl_tree_parse(cf->config_string, errbuf, sizeof(errbuf));
    if (cf->parser_obj == NULL) {
	errx(1, "%s: parse error: %s", cf->name,
	     errbuf[0] ? errbuf : "unknown error");
    }

    if (!YAJL_IS_OBJECT(cf->parser_obj))
	errx(1, "%s: malformed -- top-level not an object", cf->name);

    return cf;
}

struct conffile *
config_default(void)
{

    if (cf_default == NULL)
	cf_default = config_string(DM_DEFAULT_CONFIG);

    return cf_default;
}

void
config_free_input(struct conffile *cf)
{

    if (cf == cf_default)
	return;

    free((void *)cf->name);
    free((void *)cf->config_buf);
}

void
config_free(struct conffile *cf)
{

    if (cf == cf_default)
	return;

    yajl_tree_free(cf->parser_obj);
    config_free_input(cf);
    free(cf);
}

struct config_option {
    const char *name;
    int (*fn)(const char *opt, yajl_val arg, void *opaque);
    void *opaque;
};

struct config_option config_options[];

static int
co_set_string_opt(const char *opt, yajl_val arg, void *opaque)
{
    const char **string_opt = opaque;
    const char *s;

    s = YAJL_GET_STRING(arg);
    if (!s)
	errx(1, "config option %s: string", opt);

    *string_opt = strdup(s);

    return 0;
}

static int
co_set_integer_opt(const char *opt, yajl_val arg, void *opaque)
{
    uint64_t *integer_opt = opaque;

    if (!YAJL_IS_INTEGER(arg))
	errx(1, "config option %s: integer", opt);

    *integer_opt = YAJL_GET_INTEGER(arg);

    return 0;
}

static int
co_set_boolean_opt(const char *opt, yajl_val arg, void *opaque)
{
    uint64_t *integer_opt = opaque;

    if (YAJL_IS_TRUE(arg))
        *integer_opt = 1;
    else if (YAJL_IS_FALSE(arg))
        *integer_opt = 0;
    else
	errx(1, "config option %s: boolean", opt);

    return 0;
}

static int
co_set_dict_opt(const char *opt, yajl_val arg, void *opaque)
{
    dict *dict_opt = opaque;

    if (!YAJL_IS_OBJECT(arg))
	errx(1, "config option %s: map", opt);

    if (!(*dict_opt))
        *dict_opt = arg;
    else
        yajl_object_merge_objects(*dict_opt, arg);

    return 0;
}

static int comp(const void *a, const void *b) { return *(int *)a - *(int *)b; }

static int
co_set_disabled_keys(const char *opt, yajl_val arg, void *opaque)
{
    yajl_val v;
    unsigned int i;
    size_t len = 0;

    if (!YAJL_IS_ARRAY(arg))
	errx(1, "config option %s: array of integers", opt);

    YAJL_FOREACH_ARRAY_OR_OBJECT(v, arg, i) {
	if (!YAJL_IS_INTEGER(v))
	    errx(1, "config option %s: wrong type: integer expected", opt);
        len++;
    }

    disabled_keys = calloc(len, sizeof(int));
    if (!disabled_keys)
	errx(1, "config option %s: allocation failed", opt);

    YAJL_FOREACH_ARRAY_OR_OBJECT(v, arg, i)
        disabled_keys[i] = YAJL_GET_INTEGER(v);

    qsort(disabled_keys, len, sizeof(int), comp);

    disabled_keys_len = len;

    return 0;
}

static int
co_set_forwarded_keys(const char *opt, yajl_val arg, void *opaque)
{
    if (!YAJL_IS_ARRAY(arg))
        errx(1, "config option %s: array of integers", opt);

    return console_set_forwarded_keys(arg);
}

static int
co_set_block(const char *opt, yajl_val arg, void *opaque)
{
    yajl_val v;
    unsigned int i;
    int ret;

    if (!YAJL_IS_OBJECT(arg) && !YAJL_IS_ARRAY(arg))
	errx(1, "config option %s: map or array of map", opt);

    YAJL_FOREACH_ARRAY_OR_OBJECT(v, arg, i) {
	if (!YAJL_IS_OBJECT(v))
	    errx(1, "config option %s: wrong type: map expected", opt);
	ret = bdrv_add(v);
	if (ret)
	    break;
    }
    return ret;
}

static int
co_set_firmware(const char *opt, yajl_val arg, void *opaque)
{
    yajl_val v;
    unsigned int i;
    int ret = 0;

    if (!YAJL_IS_OBJECT(arg) && !YAJL_IS_ARRAY(arg))
	errx(1, "config option %s: map or array of map", opt);

    YAJL_FOREACH_ARRAY_OR_OBJECT(v, arg, i) {
        const char *slic;
        const char *msdm;
        const char *oem_id;
        const char *oem_table_id;
        const char *creator_id;
        char buf[8];

        yajl_val oem_revision;
        yajl_val creator_revision;
        yajl_val smbios, smbios_struct;
        yajl_val smbios_major, smbios_minor;
        yajl_val smc, smc_key;

        if (!YAJL_IS_OBJECT(v))
	    errx(1, "config option %s: wrong type: map expected", opt);

	slic = yajl_object_get_string(v, "slic");
	msdm = yajl_object_get_string(v, "msdm");
        oem_id = yajl_object_get_string(v, "oem_id");
        oem_table_id = yajl_object_get_string(v, "oem_table_id");
        oem_revision = yajl_object_get(v, "oem_revision");
        creator_id = yajl_object_get_string(v, "creator_id");
        creator_revision = yajl_object_get(v, "creator_revision");
        smbios_major = yajl_object_get(v, "smbios_version_major");
        smbios_minor = yajl_object_get(v, "smbios_version_minor");

        smbios = yajl_object_get(v, "smbios");
        smc = yajl_object_get(v, "smc");

        if (slic) {
            unsigned char *data;
            size_t len;

            data = base64_decode(slic, &len);
            if (!data)
                errx(1, "config firmware: failed to base64 decode data");

            ret = acpi_module_add(data, len);
            if (ret)
                break;
        }
        if (msdm) {
            unsigned char *data;
            size_t len;

            data = base64_decode(msdm, &len);
            if (!data)
                errx(1, "config firmware: failed to base64 decode data");

            ret = acpi_module_add(data, len);
            if (ret)
                break;
        }

        if (oem_id) {
            memset(buf, 0, 6);
            urldecode(oem_id, buf, 6);
            vm_set_oem_id(buf);
        }

        if (oem_table_id) {
            memset(buf, 0, 8);
            urldecode(oem_table_id, buf, 8);
            vm_set_oem_table_id(buf);
        }

        if (YAJL_IS_INTEGER(oem_revision)) {
            vm_set_oem_revision(YAJL_GET_INTEGER(oem_revision));
        }

        if (creator_id) {
            memset(buf, 0, 4);
            urldecode(creator_id, buf, 4);
            vm_set_oem_creator_id(buf);
        }

        if (YAJL_IS_INTEGER(creator_revision)) {
            vm_set_oem_creator_revision(YAJL_GET_INTEGER(creator_revision));
        }

        if (YAJL_IS_INTEGER(smbios_major)) {
            vm_set_smbios_version_major(YAJL_GET_INTEGER(smbios_major));
        }

        if (YAJL_IS_INTEGER(smbios_minor)) {
            vm_set_smbios_version_minor(YAJL_GET_INTEGER(smbios_minor));
        }

        YAJL_FOREACH_ARRAY_OR_OBJECT(smbios_struct, smbios, i) {
            const char *str = YAJL_GET_STRING(smbios_struct);
            unsigned char *data;
            size_t len;

            if (!str)
                errx(1, "config firmware: string expected");

            data = base64_decode(str, &len);
            if (!data)
                errx(1, "config firmware: failed to base64 decode data");

            ret = smbios_module_add(data, len);
            if (ret) {
                free(data);
                break;
            }
        }

        if (smc) {
            YAJL_FOREACH_ARRAY_OR_OBJECT(smc_key, smc, i) {
                const char *key;
                const char *val;
                unsigned char *data;
                size_t len;

                key = yajl_object_get_string(smc_key, "key");
                val = yajl_object_get_string(smc_key, "value");
                if (!key || !val)
                    errx(1, "config firmware: expected key/value pair");
                data = base64_decode(val, &len);
                if (!data)
                    errx(1, "config firmware: failed to base64 decode data");
                ret = smc_key_add(key, data, len);
                if (ret) {
                    free(data);
                    break;
                }
            }
        }
    }

    return ret;
}

static int
co_set_device(const char *opt, yajl_val arg, void *opaque)
{
    yajl_val v;
    unsigned int i;
    dict n;
    int ret;

    if (!YAJL_IS_OBJECT(arg) && !YAJL_IS_ARRAY(arg))
	errx(1, "config option %s: map or array of map", opt);

    YAJL_FOREACH_ARRAY_OR_OBJECT(v, arg, i) {
	if (!YAJL_IS_OBJECT(v))
	    errx(1, "config option %s: wrong type: map expected", opt);
        if (!config_devices) {
            config_devices = dict_array_new();
            if (!config_devices)
                errx(1, "config option %s: "
                     "failed to create config_devices dict", opt);
        }
        n = dict_new();
        ret = dict_merge(v, n);
        if (ret)
            errx(1, "config option %s: failed to copy entry", opt);
        _dict_array_put(config_devices, n);
    }
    
    return 0;
}

static int
co_set_dmpdev(const char *opt, yajl_val arg, void *opaque)
{
    const uint8_t max_max_log_events = 64;
    const uint8_t max_max_dumps = 64;
    const uint64_t max_max_dump_size = 1024 < 20;
    const char *dump_location;

    if (!YAJL_IS_OBJECT(arg))
	errx(1, "config option %s: map", opt);

    dmpdev_enabled = yajl_object_get_bool_default(arg,
                                                  "enable",
                                                  dmpdev_enabled);

    dump_location = yajl_object_get_string(arg, "location");
    if (dump_location)
        asprintf(&dmpdev_dump_location, "%s", dump_location);

    dmpdev_query = yajl_object_get_bool_default(arg,
                                                "query",
                                                dmpdev_query);

    dmpdev_overwrite = yajl_object_get_bool_default(arg,
                                                    "overwrite",
                                                    dmpdev_overwrite);

    dmpdev_max_log_events = yajl_object_get_integer_default(
        arg,
        "max_log_events",
        dmpdev_max_log_events);
    if (dmpdev_max_log_events >= max_max_log_events) {
        errx(1, "config option %s: max log events %d >= %d",
             opt, dmpdev_max_log_events, max_max_log_events);
    }

    dmpdev_max_dumps = yajl_object_get_integer_default(
        arg,
        "max_dumps",
        dmpdev_max_dumps);
    if (dmpdev_max_dumps > max_max_dumps) {
        errx(1, "config option %s: max dumps %d >= %d",
             opt, dmpdev_max_dumps, max_max_dumps);
    }

    dmpdev_max_dump_size = yajl_object_get_integer_default(
        arg,
        "max_dump_size",
        0) << 20;
    if (dmpdev_max_dump_size > max_max_dump_size) {
        errx(1, "config option %s: max dump size 0x%"PRIx64" >= 0x%"PRIx64,
             opt, dmpdev_max_dump_size, max_max_dump_size);
    }

    return 0;
}

static int
co_set_net(const char *opt, yajl_val arg, void *opaque)
{
#ifdef CONFIG_NET
    yajl_val v;
    unsigned int i;
    int ret;

    if (!YAJL_IS_OBJECT(arg) && !YAJL_IS_ARRAY(arg))
	errx(1, "config option %s: map or array of map", opt);

    YAJL_FOREACH_ARRAY_OR_OBJECT(v, arg, i) {
	if (!YAJL_IS_OBJECT(v))
	    errx(1, "config option %s: wrong type: map expected", opt);
	ret = net_client_init(NULL, v, 0);
	if (ret)
	    break;
    }

    return ret;
#else
    return 0;
#endif
}

static int 
co_set_net_lumps(const char *opt, yajl_val arg, void *opaque)
{
    extern unsigned slirp_mru, slirp_mtu;

    if (!YAJL_IS_OBJECT(arg))
	errx(1, "config option %s: map", opt);

    slirp_mtu = yajl_object_get_integer_default(arg,"mtu",1500);
    slirp_mru = yajl_object_get_integer_default(arg,"mru",1500);

    return 0;
}


static int
co_set_monitor(const char *opt, yajl_val arg, void *opaque)
{
#ifdef MONITOR
    int want_server;

    if (!YAJL_IS_OBJECT(arg))
	errx(1, "config option %s: map", opt);

    want_server = yajl_object_get_bool_default(arg, "server", 0);

    asprintf((char **)&monitor_device, "%s:%s:%"PRId64"%s",
	     yajl_object_get_string(arg, "proto"),
	     yajl_object_get_string(arg, "addr"),
	     yajl_object_get_integer(arg, "port"),
	     want_server ? ",server,nowait" : "");
#endif  /* MONITOR */

    return 0;
}

static int
co_set_serial(const char *opt, yajl_val arg, void *opaque)
{
    int want_server;
    const char *proto;
    int idx;

    if (!YAJL_IS_OBJECT(arg))
	errx(1, "config option %s: map", opt);

    idx = yajl_object_get_integer(arg, "idx");
    if (idx >= MAX_SERIAL_PORTS)
	errx(1, "config option %s: idx %d >= %d", opt, idx, MAX_SERIAL_PORTS);

    want_server = yajl_object_get_bool_default(arg, "server", 0);

    proto = yajl_object_get_string(arg, "proto");
    if (!proto)
	errx(1, "config option %s: idx %d: proto missing", opt, idx);

    if (!strcmp(proto, "pipe"))
	asprintf((char **)&serial_devices[idx], "%s:%s%s", proto,
		 yajl_object_get_string(arg, "addr"),
		 want_server ? ",server" : "");
    else if (!strcmp(proto, "pty") || !strcmp(proto, "null"))
        asprintf((char **)&serial_devices[idx], "%s", proto);
    else
	asprintf((char **)&serial_devices[idx], "%s:%s:%"PRId64"%s", proto,
		 yajl_object_get_string(arg, "addr"),
		 yajl_object_get_integer(arg, "port"),
		 want_server ? ",server,nowait" : "");

    return 0;
}

static int
co_set_shared_folders(const char *opt, yajl_val arg, void *opaque)
{
#if defined(CONFIG_VBOXDRV)
    extern int sf_parse_config(yajl_val config);
    return sf_parse_config(arg);
#else
    return 0;
#endif
}

static int
co_set_clipboard(const char *opt, yajl_val arg, void *opaque)
{
#if defined(CONFIG_VBOXDRV)
    return clip_parse_config(arg);
#else
    return 0;
#endif
}

static int
co_set_uuid(const char *opt, yajl_val arg, void *opaque)
{
    int ret;
    char *uuid;

    uuid = YAJL_GET_STRING(arg);
    if (!uuid)
	errx(1, "config option %s: string", opt);

    ret = uuid_parse(uuid, vm_uuid);
    if (ret)
      errx(1, "config option %s: invalid uuid", opt);

    return 0;
}

static int
co_ignore(const char *opt, yajl_val arg, void *opaque)
{

    return 0;
}

/* must be strcmp sorted */
struct config_option config_options[] = {
    { "", co_ignore, NULL },
    { "apic", co_set_integer_opt, &vm_apic },
    { "app-dump-command", co_set_string_opt, &app_dump_command },
    { "audio", co_set_dict_opt, &vm_audio },
    { "balloon-max-size", co_set_integer_opt, &balloon_max_mb },
    { "balloon-min-size", co_set_integer_opt, &balloon_min_mb },
    { "block", co_set_block, NULL },
    { "boot-order", co_set_string_opt, &boot_order },
    { "clipboard", co_set_clipboard, NULL },
    { "clipboard-formats-blacklist-host2vm", co_set_string_opt,
        &clipboard_formats_blacklist_host2vm },
    { "clipboard-formats-blacklist-vm2host", co_set_string_opt,
        &clipboard_formats_blacklist_vm2host },
    { "clipboard-formats-whitelist-host2vm", co_set_string_opt,
        &clipboard_formats_whitelist_host2vm },
    { "clipboard-formats-whitelist-vm2host", co_set_string_opt,
        &clipboard_formats_whitelist_vm2host },
    { "debugkey-level", co_set_integer_opt, &debugkey_level },
    { "deferred-clipboard", co_set_boolean_opt, &deferred_clipboard },
    { "device", co_set_device, NULL },
    { "disabled-keys", co_set_disabled_keys, NULL },
    { "dmpdev", co_set_dmpdev, NULL },
    { "event-service-mouse-moves", co_set_boolean_opt, &event_service_mouse_moves},
    { "firmware", co_set_firmware, NULL },
    { "guest_drivers_logmask", co_set_integer_opt, &guest_drivers_logmask },
#ifdef _WIN32
    { "hid-touch", co_set_boolean_opt, &hid_touch_enabled },
#else
    { "hid-touch", co_ignore, NULL },
#endif
    { "hidden-mem", co_set_boolean_opt, &vm_hidden_mem },
    { "hide-log-sensitive-data", co_set_boolean_opt, &hide_log_sensitive_data },
    { "hpet", co_set_integer_opt, &vm_hpet },
    { "hvm-params", co_set_dict_opt, &vm_hvm_params },
    { "lava", co_set_string_opt, &lava_options },
    { "lazy-load", co_set_boolean_opt, &vm_lazy_load },
    { "log-ratelimit-guest-burst", co_set_integer_opt,
      &log_ratelimit_guest_burst },
    { "log-ratelimit-guest-ms", co_set_integer_opt, &log_ratelimit_guest_ms },
    { "malloc-limit", co_set_integer_opt, &malloc_limit_bytes},
    { "memory", co_set_integer_opt, &vm_mem_mb },
    { "monitor", co_set_monitor, NULL },
    { "name", co_set_string_opt, &vm_name },
    { "net", co_set_net, NULL },
    { "netlumps", co_set_net_lumps,NULL },
    { "pae", co_set_integer_opt, &vm_pae },
    { "parent-window-key-forward", co_set_forwarded_keys, NULL },
#ifdef _WIN32
    { "process-shutdown-priority", co_set_integer_opt,
      &process_shutdown_priority },
#else
    { "process-shutdown-priority", co_ignore, NULL },
#endif
    { "ps2-fallback", co_set_boolean_opt, &ps2_fallback },
    { "restricted-pci-emul", co_set_boolean_opt, &vm_restricted_pci_emul },
    { "restricted-vga-emul", co_set_boolean_opt, &vm_restricted_vga_emul },
    { "restricted-x86-emul", co_set_integer_opt, &vm_restricted_x86_emul },
    { "save-file-prefix", co_set_string_opt, &save_file_prefix},
    { "serial", co_set_serial, NULL },
    { "shared-folders", co_set_shared_folders, NULL },
    { "timer-mode", co_set_integer_opt, &vm_timer_mode },
    { "tsc-mode", co_set_integer_opt, &vm_tsc_mode },
    { "use-v4v-disk", co_set_integer_opt, &vm_use_v4v_disk },
    { "use-v4v-net", co_set_integer_opt, &vm_use_v4v_net },
    { "uuid", co_set_uuid, NULL },
    { "v4v-storage", co_set_boolean_opt, &vm_v4v_storage },
    { "vcpus", co_set_integer_opt, &vm_vcpus },
    { "vga-memory", co_set_integer_opt, &vm_vga_mb },
    { "vga-memory-mapped", co_set_integer_opt, &vm_vga_mb_mapped },
    { "vga-shm-name", co_set_string_opt, &vm_vga_shm_name },
    { "viridian", co_set_integer_opt, &vm_viridian },
    { "virt-mode-change", co_set_integer_opt, &vm_virt_mode_change },
    { "vpt-align", co_set_boolean_opt, &vm_vpt_align },
    { "vpt-coalesce-period", co_set_integer_opt, &vm_vpt_coalesce_period },
    { "zero-page", co_set_boolean_opt, &vm_zero_page },
    { "zero-page-setup", co_set_boolean_opt, &vm_zero_page_setup },
};

static int
compco(const void *c1, const void *c2)
{
    struct config_option *co1 = (struct config_option *)c1;
    struct config_option *co2 = (struct config_option *)c2;
    return strcmp(co1->name, co2->name);
}

int
config_parse(struct conffile *cf)
{
    int i, ret;

#ifdef DEBUG
    for (i = 1; i < ARRAY_SIZE(config_options); i++) {
        if (strcmp(config_options[i - 1].name,
                   config_options[i].name) > 0)
            errx(1, "config_options array is unsorted");
    }
#endif

    assert(YAJL_IS_OBJECT(cf->parser_obj));

    for (i = 0; i < cf->parser_obj->u.object.len; i++) {
	struct config_option *co, key;

	key.name = cf->parser_obj->u.object.keys[i];

	co = bsearch(&key, config_options, ARRAY_SIZE(config_options),
		     sizeof(*co), compco);
	if (co) {
	    ret = co->fn(key.name, cf->parser_obj->u.object.values[i],
			 co->opaque);
	    if (ret < 0)
		return ret;
	} else
	    warnx("unknown config option: %s", key.name);
    }

    return 0;
}
