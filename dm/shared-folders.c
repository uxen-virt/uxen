/*
 * Copyright 2015, Bromium, Inc.
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

#include <windowsx.h>
#include <winioctl.h>
#define V4V_USE_INLINE_API
#include <windows/uxenv4vlib/gh_v4vapi.h>

#define SF_PORT 44444
#define RING_SIZE 262144

typedef enum {
    SF_WAIT,
    SF_RECEIVE,
    SF_HANDLE,
    SF_RESPOND
} sf_req_state;

struct sf_msg {
    v4v_datagram_t dgram;
    char data[RING_SIZE];
};

struct sf_state {
    v4v_context_t v4v;
    critical_section lock;
    uxen_thread thread;
    bool quit_thread;
    bool init_done;
    bool running;

    sf_req_state req_state;

    struct sf_msg *request, *response;
    int request_bytes, response_bytes;
};

static struct sf_state _state;
static void sf_save(QEMUFile *f, void *opaque);
static int sf_load(QEMUFile *f, void *opaque, int version);
static void sf_service_stop_processing(void);
static void sf_service_free(void);
void sf_service_stop(void);

static int __init(void)
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

static int
sf_parse_subfolder_config(const char *folder_name, yajl_val folder)
{
    const char* subfolders_path[] = {"subfolders", NULL};
    yajl_val subfolders, v;
    int i;

    subfolders = yajl_tree_get(folder, subfolders_path, yajl_t_array);
    if (!subfolders)
        return 0;

    if (!YAJL_IS_OBJECT(subfolders) && !YAJL_IS_ARRAY(subfolders)) {
        warnx("shared-folders: wrong type");
        return -1;
    }
    YAJL_FOREACH_ARRAY_OR_OBJECT(v, subfolders, i) {
        const char *path;
        int crypt;

        if (!YAJL_IS_OBJECT(v))
            continue;
        path  = yajl_object_get_string(v, "path");
        if (!path) {
            warnx("subfolder arg missing path");
            return -1;
        }

        crypt = yajl_object_get_integer_default(v, "scramble", 0);
        sf_add_subfolder_crypt((char*)folder_name, (char*)path, crypt);
    }

    return 0;
}

int sf_parse_config(yajl_val config)
{
    yajl_val folders, v;
    int i;
    int rc;
    const char *name, *folder;
    const char* folders_path[] = {"folders", NULL};
    int writable, crypt_mode;

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
            writable = yajl_object_get_integer_default(v, "writable", 0);
            crypt_mode = yajl_object_get_integer_default(v, "scramble", 0);
            rc = sf_add_mapping(folder, name, writable, crypt_mode);
            if (rc) {
                warnx("sf_add_mapping folder=%s name=%s error %d", 
                    folder, name, rc);
                return -1;
            }
            rc = sf_parse_subfolder_config(name, v);
            if (rc)
                return -1;
        }
    }
    return 0;
}

static int __send_bytes(struct sf_state *state, struct sf_msg *msg, int len)
{
    DWORD bytes = 0;

    if (!WriteFile(state->v4v.v4v_handle, (void *)msg, len, &bytes, NULL)) {
        warnx("%s: WriteFile", __FUNCTION__);
        return -1;
    }

    assert(bytes == len);

    return 0;
}

static void __respond(struct sf_state *state)
{
    __send_bytes(state,
                 state->response,
                 sizeof(v4v_datagram_t) + state->response_bytes);
}

static void __handle_req(struct sf_state *state, char *data, int len)
{
    struct sf_msg *msg = state->response;
    int resp_size = RING_SIZE;

    sf_server_process_request(data, len, msg->data, &resp_size);

    assert(resp_size < RING_SIZE - 4096);

    msg->dgram.addr.port = SF_PORT;
    msg->dgram.addr.domain = vm_id;
    msg->dgram.flags = V4V_DATAGRAM_FLAG_IGNORE_DLO;
    state->response_bytes = resp_size;
}

static int __receive_req(struct sf_state *state)
{
    DWORD bytes = 0;
    if (!ReadFile(state->v4v.v4v_handle,
                  state->request,
                  sizeof(struct sf_msg),
                  &bytes, NULL)) {
        warnx("%s: ReadFile", __FUNCTION__);
        return -1;
    }
    assert(bytes < RING_SIZE - 4096);
    state->request_bytes = bytes - sizeof(v4v_datagram_t);
    return 0;

}

#ifdef _WIN32
static DWORD WINAPI __run_thread(void *_s)
#else
static void *__run_thread(void *_s)
#endif
{
    struct sf_state *s = (struct sf_state*)_s;

    while ( !s->quit_thread ) {

        critical_section_enter(&s->lock);
        switch (s->req_state) {
        case SF_WAIT:
            critical_section_leave(&s->lock);
            ioh_event_wait( &s->v4v.recv_event );
            critical_section_enter(&s->lock);
            if ( !s->quit_thread )
                s->req_state = SF_RECEIVE;
            break;
        case SF_RECEIVE:
            if (__receive_req(s) == 0)
                s->req_state = SF_HANDLE;
            else
                s->req_state = SF_WAIT;
            break;
        case SF_HANDLE:
            __handle_req(s, s->request->data, s->request_bytes);
            s->req_state = SF_RESPOND;
            break;
        case SF_RESPOND:
            __respond(s);
            s->req_state = SF_WAIT;
            break;
        }
        critical_section_leave(&s->lock);
    }

    s->quit_thread = 0;
    return 0;
}

static void sf_save(QEMUFile *f, void *opaque)
{
    struct sf_state *s = (struct sf_state*)opaque;

    sf_service_stop_processing();

    critical_section_enter(&s->lock);
    debug_printf("sf save, request state %d\n", s->req_state);
    qemu_put_be32(f, s->req_state);
    qemu_put_be32(f, s->request_bytes);
    qemu_put_buffer(f, (uint8_t*)s->request, sizeof(struct sf_msg));
    qemu_put_be32(f, s->response_bytes);
    qemu_put_buffer(f, (uint8_t*)s->response, sizeof(struct sf_msg));
    critical_section_leave(&s->lock);

    sf_service_free();
}

static int sf_load(QEMUFile *f, void *opaque, int version)
{
    struct sf_state *s = (struct sf_state*)opaque;

    critical_section_enter(&s->lock);
    s->req_state = qemu_get_be32(f);
    debug_printf("sf load, request state %d\n", s->req_state);
    s->request_bytes = qemu_get_be32(f);
    qemu_get_buffer(f, (uint8_t*)s->request, sizeof(struct sf_msg));
    s->response_bytes = qemu_get_be32(f);
    qemu_get_buffer(f, (uint8_t*)s->response, sizeof(struct sf_msg));
    critical_section_leave(&s->lock);

    return 0;
}

int sf_service_start(void)
{
    struct sf_state *s = &_state;
    int ret;
    v4v_ring_id_t id;

    if (!s->init_done)
        return 0;

    ret = v4v_open(&s->v4v, RING_SIZE, NULL);
    if (!ret) {
        warnx("%s: v4v_open", __FUNCTION__);
        return -1;
    }

    id.addr.port = SF_PORT;
    id.addr.domain = V4V_DOMID_ANY;
    id.partner = vm_id;

    ret = v4v_bind(&s->v4v, &id, NULL);
    if (!ret) {
        warnx("%s: v4v_bind", __FUNCTION__);
        v4v_close(&s->v4v);
        return -1;
    }

    s->req_state = SF_WAIT;
    s->quit_thread = 0;

    s->request = hgcm_calloc(1, sizeof(struct sf_msg));
    s->response= hgcm_calloc(1, sizeof(struct sf_msg));
    if (!s->request || !s->response) {
        warnx("%s: allocation failed", __FUNCTION__);
        return -1;
    }

    if ( create_thread(&s->thread, __run_thread, s) < 0 ) {
        warnx("%s: create_thread", __FUNCTION__);
        v4v_close(&s->v4v);
        hgcm_free(s->request);
        hgcm_free(s->response);
        return -1;
    }
    elevate_thread(s->thread);
    s->running = 1;
    debug_printf("sf v4v service started\n");
    return 0;
}

static void sf_service_stop_processing(void)
{
    struct sf_state *s = &_state;

    if (s->running) {
        debug_printf("sf v4v service stopping\n");

        s->quit_thread = 1;
        ioh_event_set(&s->v4v.recv_event);
        wait_thread(s->thread);

        v4v_close(&s->v4v);

        sf_quit();

        debug_printf("sf v4v service stopped\n");
        s->running = 0;
    }
}

static void sf_service_free(void)
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

void sf_service_stop(void)
{
    sf_service_stop_processing();
    sf_service_free();
}
