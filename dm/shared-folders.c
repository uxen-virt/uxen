/*
 * Copyright 2015-2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "config.h"
#include "debug.h"
#include "dm.h"
#include "vmstate.h"
#include "file.h"
#include "yajl.h"
#include "shared-folders.h"
#include <dm/vbox-drivers/heap.h>
#include <dm/vbox-drivers/shared-folders/redir.h>
#include <dm/hw/uxen_v4v.h>

#define SF_PORT 44444
#define RING_SIZE 262144
#define SF_TIMEOUT 10000

struct sf_msg {
    v4v_datagram_t dgram;
    char data[RING_SIZE];
};

struct sf_state {
    v4v_context_t v4v;
    uint32_t partner_id;
    critical_section lock;
    struct io_handler_queue ioh_queue;
    WaitObjects wait_objects;
    ioh_event io_ev, pause_ev;
    int paused;
    v4v_async_t async;

    uxen_thread thread;
    bool quit_thread;
    bool init_done;
    bool running;

    struct sf_msg *request, *response;
    int request_bytes, response_bytes;
};

static struct sf_state _state;
static void sf_save(QEMUFile *f, void *opaque);
static int sf_load(QEMUFile *f, void *opaque, int version);
static void sf_service_stop_processing(void);
static void sf_service_free(void);
void sf_service_stop(void);

static int
__init(void)
{
    struct sf_state *s = &_state;
    if (!s->init_done) {
        if (sf_init()) {
            warnx("shared folders init failed");
            return -1;
        }
        critical_section_init(&s->lock);

        register_savevm(NULL, "shared-folders", 0, 1, sf_save, sf_load, s);
        s->init_done = 1;
    }
    return 0;
}

static uint64_t
parse_folder_opts(yajl_val v)
{
    uint64_t opts = 0;

    if ((opts = yajl_object_get_integer_default(v, "opts", 0)))
        return opts;

    if (yajl_object_get_integer_default(v, "scramble", 0))
        opts |= SF_OPT_SCRAMBLE;
    if (yajl_object_get_integer_default(v, "hide", 0))
        opts |= SF_OPT_HIDE;
    if (yajl_object_get_integer_default(v, "no-flush", 0))
        opts |= SF_OPT_NO_FLUSH;
    if (yajl_object_get_integer_default(v, "no-quota", 0))
        opts |= SF_OPT_NO_QUOTA;
    if (yajl_object_get_integer_default(v, "scramble-filenames", 0))
        opts |= SF_OPT_SCRAMBLE_FILENAMES;

    return opts;
}

static int
sf_parse_subfolder_config(const char *folder_name, yajl_val folder,
                          uint64_t parent_opts)
{
    const char* subfolders_path[] = {"subfolders", NULL};
    yajl_val subfolders, v;
    int i;
    uint64_t opts;

    subfolders = yajl_tree_get(folder, subfolders_path, yajl_t_array);
    if (!subfolders)
        return 0;

    if (!YAJL_IS_OBJECT(subfolders) && !YAJL_IS_ARRAY(subfolders)) {
        warnx("shared-folders: wrong type");
        return -1;
    }
    YAJL_FOREACH_ARRAY_OR_OBJECT(v, subfolders, i) {
        const char *path;

        if (!YAJL_IS_OBJECT(v))
            continue;
        path  = yajl_object_get_string(v, "path");
        if (!path) {
            warnx("subfolder arg missing path");
            return -1;
        }

        opts = parse_folder_opts(v);
        if (opts != parent_opts) {
            wchar_t *folder_name_w = _utf8_to_wide(folder_name);
            wchar_t *path_w = _utf8_to_wide(path);

            sf_set_opt(folder_name_w, path_w, opts);
            free(folder_name_w);
            free(path_w);
        }
    }

    return 0;
}

static int
sf_parse_redirect_config(const char *folder_name, yajl_val folder)
{
    const char * redirect_path[] = {"redirect", NULL};
    yajl_val redirect, v;
    int i, rc;

    redirect = yajl_tree_get(folder, redirect_path, yajl_t_array);
    if (!redirect)
        return 0;

    if (!YAJL_IS_OBJECT(redirect) && !YAJL_IS_ARRAY(redirect)) {
        warnx("shared-folders: wrong type");
        return -1;
    }

    YAJL_FOREACH_ARRAY_OR_OBJECT(v, redirect, i) {
        const char *src, *dst;
        wchar_t *folder_name_w, *src_w, *dst_w;

        if (!YAJL_IS_OBJECT(v))
            continue;

        src = yajl_object_get_string(v, "src");
        if (!src) {
            warnx("redirect missing src");
            return -1;
        }
        dst = yajl_object_get_string(v, "dst");
        if (!dst) {
            warnx("redirect missing dst");
            return -1;
        }

        folder_name_w = _utf8_to_wide(folder_name);
        src_w = _utf8_to_wide(src);
        dst_w = _utf8_to_wide(dst);

        rc = sf_redirect_add(folder_name_w, src_w, dst_w);
        if (rc) {
            warnx("failed to add redirect: %d", rc);
            return -1;
        }

        free(folder_name_w);
        free(src_w);
        free(dst_w);
    }

    return 0;
}

int
sf_parse_config(yajl_val config)
{
    yajl_val folders, v;
    int i;
    int rc;
    const char *name, *folder, *file_suffix;
    const char* folders_path[] = {"folders", NULL};
    int writable;
    uint64_t quota;
    uint64_t opts = 0;

    __init();

    folders = yajl_tree_get(config, folders_path, yajl_t_array);
    if (!YAJL_IS_OBJECT(folders) && !YAJL_IS_ARRAY(folders)) {
        warnx("vmfwd arg wrong type: expect map or array of map");
        return -1;
    }
    else {
        YAJL_FOREACH_ARRAY_OR_OBJECT(v, folders, i) {
            if (!YAJL_IS_OBJECT(v)) {
                warnx("folder arg wrong type: expect map");
                continue;
            }
            folder = yajl_object_get_string(v, "path");
            name = yajl_object_get_string(v, "name");
            if (!folder || !name) {
                warnx("folder arg missing path or name attribute");
                return -1;
            }
            file_suffix = yajl_object_get_string(v, "file-suffix");
            writable = yajl_object_get_integer_default(v, "writable", 0);
            opts = parse_folder_opts(v);
            quota = yajl_object_get_integer_default(v, "quota", 0);
            rc = sf_add_mapping(folder, name, file_suffix, writable, opts, quota * 1024 * 1024);
            if (rc) {
                warnx("sf_add_mapping folder=%s name=%s error %d", 
                    folder, name, rc);
                return -1;
            }
            rc = sf_parse_subfolder_config(name, v, opts);
            if (rc)
                return -1;
            rc = sf_parse_redirect_config(name, v);
            if (rc)
                return -1;
        }
    }
    return 0;
}

void
sf_vm_pause(void)
{
    struct sf_state *s = &_state;

    s->paused = 1;
    ioh_event_set(&s->pause_ev);
    debug_printf("sf: paused\n");
}

void
sf_vm_unpause(void)
{
    struct sf_state *s = &_state;

    s->paused = 0;
    ioh_event_set(&s->pause_ev);
    debug_printf("sf: unpaused\n");
}

static int
send_bytes(struct sf_state *state, struct sf_msg *msg, int len)
{
    size_t bytes = 0;
    int err;

    memset(&msg->dgram, 0, sizeof(msg->dgram));
    msg->dgram.addr.port = SF_PORT;
    msg->dgram.addr.domain = state->partner_id;
    //msg->dgram.flags = V4V_DATAGRAM_FLAG_IGNORE_DLO;

    ioh_event_reset(&state->io_ev);
    dm_v4v_async_init(&state->v4v, &state->async, state->io_ev);
    err = dm_v4v_send(&state->v4v, (v4v_datagram_t*)msg,
        len, &state->async);
    if (err && err != ERROR_IO_PENDING) {
        debug_printf("%s:%d: error sending = %d\n", __FILE__, __LINE__, err);
        return err;
    }
    err = dm_v4v_async_get_result(&state->async, &bytes, true);
    if (err) {
        debug_printf("%s:%d: error getting result = %d\n", __FILE__, __LINE__, err);
        return err;
    }
    assert(bytes == len);

    return 0;
}

static int
respond(struct sf_state *state)
{
    int ret;

    if (!state->response_bytes)
        return 0;

    ret = send_bytes(
        state,
        state->response,
        sizeof(v4v_datagram_t) + state->response_bytes);
    if (!ret)
        state->response_bytes = 0;
    return ret;
}

static void
handle_req(struct sf_state *state, char *data, int len)
{
    struct sf_msg *msg = state->response;
    int resp_size = RING_SIZE;

    sf_server_process_request(data, len, msg->data, &resp_size);

    assert(resp_size < RING_SIZE - 4096);

    state->response_bytes = resp_size;
}

static int
receive_req(struct sf_state *state)
{
    size_t bytes = 0;
    int err;

    ioh_event_reset(&state->io_ev);
    dm_v4v_async_init(&state->v4v, &state->async, state->io_ev);
    err = dm_v4v_recv(&state->v4v, (v4v_datagram_t*)state->request,
        sizeof(struct sf_msg), &state->async);
    if (err && err != ERROR_IO_PENDING) {
        debug_printf("%s:%d: error receiving = %d\n", __FILE__, __LINE__, err);
        return err;
    }
    err = dm_v4v_async_get_result(&state->async, &bytes, true);
    if (err) {
        debug_printf("%s:%d: error getting result = %d\n", __FILE__, __LINE__, err);
        return err;
    }
    assert(bytes < RING_SIZE - 4096);
    state->request_bytes = bytes - sizeof(v4v_datagram_t);

    return 0;
}

static void
do_recv_ev(void *opaque)
{
    struct sf_state *s = (struct sf_state*) opaque;

    s->request_bytes = 0;
    receive_req(s);
}


#ifdef _WIN32
static DWORD WINAPI __run_thread(void *_s)
#else
static void *__run_thread(void *_s)
#endif
{
    struct sf_state *s = (struct sf_state*)_s;
    int ret;
    int timeout = SF_TIMEOUT;

    critical_section_enter(&s->lock);
    for (;;) {
        if (s->quit_thread) {
            critical_section_leave(&s->lock);
            debug_printf("sf: quitting processing thread\n");
            break;
        }
        if (s->paused) {
            critical_section_leave(&s->lock);
            ioh_event_wait(&s->pause_ev);
            ioh_event_reset(&s->pause_ev);
            critical_section_enter(&s->lock);
            continue;
        }
        ret = respond(s);
        if (ret == ERROR_VC_DISCONNECTED) {
            debug_printf("sf: remote end disconnected, quitting thread\n");
            s->quit_thread = 1;
        } else if (ret)
            debug_printf("sf: failed to send response, error %d\n", ret);
        critical_section_leave(&s->lock);
        ioh_wait_for_objects(&s->ioh_queue, &s->wait_objects, NULL, &timeout, NULL);
        critical_section_enter(&s->lock);
        if (s->request_bytes) {
            handle_req(s, s->request->data, s->request_bytes);
            s->request_bytes = 0;
        }
    }
    s->quit_thread = 0;
    return 0;
}

static void
sf_save(QEMUFile *f, void *opaque)
{
    struct sf_state *s = (struct sf_state*)opaque;

    critical_section_enter(&s->lock);
    debug_printf("sf save, resp=%d req=%d\n", s->response_bytes, s->request_bytes);
    qemu_put_be32(f, s->request_bytes);
    qemu_put_buffer(f, (uint8_t*)s->request, sizeof(struct sf_msg));
    qemu_put_be32(f, s->response_bytes);
    qemu_put_buffer(f, (uint8_t*)s->response, sizeof(struct sf_msg));
    critical_section_leave(&s->lock);
}

static int
sf_load(QEMUFile *f, void *opaque, int version)
{
    struct sf_state *s = (struct sf_state*)opaque;

    critical_section_enter(&s->lock);
    s->request_bytes = qemu_get_be32(f);
    qemu_get_buffer(f, (uint8_t*)s->request, sizeof(struct sf_msg));
    s->response_bytes = qemu_get_be32(f);
    qemu_get_buffer(f, (uint8_t*)s->response, sizeof(struct sf_msg));
    debug_printf("sf load, resp=%d req=%d\n", s->response_bytes, s->request_bytes);
    critical_section_leave(&s->lock);
    return 0;
}

static int
connect_v4v(struct sf_state *s, int domain, int port)
{
    v4v_bind_values_t bind = { };
    int err = 0;

    ioh_event_reset(&s->io_ev);
    if ((err = dm_v4v_open(&s->v4v, RING_SIZE))) {
        debug_printf("%s: v4v_open failed (%d)\n",
            __FUNCTION__, err);
        return -1;
    }

    bind.ring_id.addr.port = port;
    bind.ring_id.addr.domain = V4V_DOMID_ANY;
    bind.ring_id.partner = V4V_DOMID_UUID;
    memcpy(&bind.partner, v4v_idtoken, sizeof(bind.partner));

    ioh_event_reset(&s->io_ev);
    if ((err = dm_v4v_bind(&s->v4v, &bind))) {
        debug_printf("%s: v4v_bind failed (%d)\n",
                     __FUNCTION__, err);
        dm_v4v_close(&s->v4v);
        return -1;
    }

    s->partner_id = bind.ring_id.partner;

    return 0;
}

int
sf_service_start(void)
{
    struct sf_state *s = &_state;

    if (!s->init_done)
        return 0;

    if (connect_v4v(s, vm_id, SF_PORT)) {
        warnx("%s: connect_v4v failed", __FUNCTION__);
        return -1;
    }

    ioh_queue_init(&s->ioh_queue);
    ioh_init_wait_objects(&s->wait_objects);
    ioh_event_init(&s->io_ev);
    ioh_event_init(&s->pause_ev);

    ioh_add_wait_object(&s->io_ev, NULL, s, &s->wait_objects);
    ioh_add_wait_object(&s->pause_ev, NULL, s, &s->wait_objects);
    ioh_add_wait_object(&s->v4v.recv_event, do_recv_ev, s, &s->wait_objects);

    s->quit_thread = 0;

    s->request = hgcm_calloc(1, sizeof(struct sf_msg));
    s->response= hgcm_calloc(1, sizeof(struct sf_msg));
    if (!s->request || !s->response) {
        warnx("%s: allocation failed", __FUNCTION__);
        return -1;
    }

    if ( create_thread(&s->thread, __run_thread, s) < 0 ) {
        warnx("%s: create_thread", __FUNCTION__);
        dm_v4v_close(&s->v4v);
        hgcm_free(s->request);
        hgcm_free(s->response);
        return -1;
    }
    elevate_thread(s->thread);
    s->running = 1;
    debug_printf("sf v4v service started\n");
    return 0;
}

static void
sf_service_stop_processing(void)
{
    struct sf_state *s = &_state;

    if (s->running) {
        debug_printf("sf v4v service stopping\n");

        s->quit_thread = 1;
        dm_v4v_async_cancel(&s->async);
        ioh_event_set(&s->io_ev);
        ioh_event_set(&s->pause_ev);
        wait_thread(s->thread);

        dm_v4v_close(&s->v4v);
        ioh_cleanup_wait_objects(&s->wait_objects);
        ioh_event_close(&s->io_ev);
        ioh_event_close(&s->pause_ev);
        sf_quit();

        debug_printf("sf v4v service stopped\n");
        s->running = 0;
    }
}

static void
sf_service_free(void)
{
    struct sf_state *s = &_state;

    if (s->request) {
        hgcm_free(s->request);
        s->request = NULL;
    }
    if (s->response) {
        hgcm_free(s->response);
        s->response = NULL;
    }
}

void
sf_service_stop(void)
{
    sf_service_stop_processing();
    sf_service_free();
}
