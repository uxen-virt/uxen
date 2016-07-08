/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/debug.h>
#include <dm/dm.h>
#include <dm/vmstate.h>
#include <dm/file.h>
#include <dm/yajl.h>
#include <dm/vbox-drivers/heap.h>
#include <dm/vbox-drivers/shared-clipboard/clipboard-interface.h>
#include <dm/clipboard-protocol.h>

#define DEFAULT_CLIPBOARD_FORMAT_WHITELIST "CF_DIB,CF_DIBV5,CF_TEXT,CF_UNICODETEXT,Rich Text Format,Csv,Art::GVML ClipFormat"

struct req {
    void *data;
    int bytes;
};

struct clip_state {
    struct clip_ctx *conn, *notify_conn;
    uxen_thread thread, notify_thread;
    bool quit;
    bool init_done;
    bool running;
    bool guest_connected;

    struct req request;
    struct req response;
    struct req notify, notify_next;
    critical_section notify_lock;
    ioh_event notify_ev;
};

static struct clip_state _state;
static void clip_service_stop_processing(void);
static void clip_service_free(void);
void clip_service_stop(void);

static void *
__hgcm_malloc(size_t sz)
{
    return hgcm_malloc(sz);
}

static void
__hgcm_free(void *p)
{
    return hgcm_free(p);
}

static void
reqfree(struct req *r)
{
    if (r->data)
        hgcm_free(r->data);
    r->data = NULL;
}

static void
clip_save(QEMUFile *f, void *opaque)
{
    struct clip_state *s = (struct clip_state*)opaque;

    qemu_put_be32(f, s->guest_connected);
}

static int
clip_load(QEMUFile *f, void *opaque, int version)
{
    struct clip_state *s = (struct clip_state*)opaque;

    s->guest_connected = qemu_get_be32(f);
    uxen_clipboard_resume();
    return 0;
}

static int
__init(void)
{
    struct clip_state *s = &_state;

    if (!s->init_done) {
        s->guest_connected = 0;
        critical_section_init(&s->notify_lock);
        ioh_event_init(&s->notify_ev);

        if (uxen_clipboard_init()) {
            warnx("clipboard init failed");
            return -1;
        }
        register_savevm(NULL, "clipboard-service", 0, 1, clip_save, clip_load, s);
        uxen_clipboard_connect();

        clipboard_formats_whitelist_host2vm = strdup(DEFAULT_CLIPBOARD_FORMAT_WHITELIST);
        clipboard_formats_whitelist_vm2host = strdup(DEFAULT_CLIPBOARD_FORMAT_WHITELIST);

        s->init_done = 1;
    }
    return 0;
}

int
clip_parse_config(yajl_val config)
{
    const char *policy = yajl_object_get_string(config, "policy");

    __init();

    if (policy) {
        debug_printf("clipboard policy: %s\n", policy);
        uxen_clipboard_set_policy(policy);
    }
    return 0;
}

static int
__respond(struct clip_state *state)
{
    int ret;

    assert(state->response.data != NULL);
    ret = clip_send_bytes(state->conn,
                          state->response.data, state->response.bytes);
    if (ret)
        debug_printf("clipboard: error sending response %d %p %d\n",
                     ret, state->response.data, state->response.bytes);
    hgcm_free(state->response.data);
    state->response.data = NULL;
    return ret;
}

static void
__handle_req(struct clip_state *state)
{
    void *resp_data = NULL;
    int resp_size = 0;

    assert(state->request.data != NULL);

    uxen_clipboard_process_request(
        (uint8_t*)state->request.data, state->request.bytes,
        (uint8_t**)&resp_data, &resp_size);
    hgcm_free(state->request.data);
    state->request.data = NULL;
    state->response.data = resp_data;
    state->response.bytes = resp_size;
}

static int
__receive_req(struct clip_state *state)
{
    void *data;
    int len;
    int ret;

    ret = clip_recv_bytes(state->conn,
                          &data, &len);
    if (ret) {
        debug_printf("clipboard: error receiving request: %d\n", ret);
        return ret;
    }
    state->request.data = data;
    state->request.bytes = len;
    return 0;
}

static DWORD WINAPI
clipboard_thread(void *_s)
{
    struct clip_state *s = (struct clip_state*)_s;
    int ret;

    while (!s->quit) {
        clip_wait_io(s->conn);
        if (s->quit)
            break;
        ret = __receive_req(s);
        if (s->quit)
            break;
        if (ret == 0) {
            __handle_req(s);
            __respond(s);
        }
    }

    return 0;
}

static void
send_notify(struct clip_state *s)
{
    int ret;
    uint32_t *p;

    critical_section_enter(&s->notify_lock);
    while (s->notify_next.data) {
        s->notify = s->notify_next;
        s->notify_next.data = NULL;
        critical_section_leave(&s->notify_lock);
        p = s->notify.data;
        debug_printf("clipboard: sending host notification type %d len %d\n",
                     *p, s->notify.bytes);
        ret = clip_send_bytes(s->notify_conn,
                              s->notify.data, s->notify.bytes);
        debug_printf("clipboard: notification sent\n");
        if (ret)
            debug_printf("clipboard: error sending notification: %d (len %d)\n",
                         ret, s->notify.bytes);
        critical_section_enter(&s->notify_lock);
        reqfree(&s->notify);
    }
    critical_section_leave(&s->notify_lock);
}

static DWORD WINAPI
notify_thread(void *_s)
{
    struct clip_state *s = (struct clip_state*)_s;
    void *data = NULL;
    int len;

    /* wait for guest to connect */
    if (!s->guest_connected) {
        debug_printf("clipboard: wait for guest to connect..\n");
        clip_wait_io(s->notify_conn);
        if (!s->quit) {
            clip_recv_bytes(s->notify_conn, &data, &len);
            hgcm_free(data);
            debug_printf("clipboard: guest connected\n");
            s->guest_connected = 1;
        } else
            debug_printf("clipboard: no connection\n");
    }

    while (!s->quit) {
        send_notify(s);
        ioh_event_wait(&s->notify_ev);
        ioh_event_reset(&s->notify_ev);
    }

    return 0;
}

/* uxen_clipboard_notify_guest is called from the message loop for the
   clipboard window, so asynchronously with all the rest, therefore
   the need for lock */
void
uxen_clipboard_notify_guest(int type, char *data, int len)
{
    struct clip_state *s = &_state;
    struct clip_notify_data *ndata;
    
    critical_section_enter(&s->notify_lock);
    reqfree(&s->notify_next);
    s->notify_next.bytes = len + sizeof(struct clip_notify_data);
    s->notify_next.data = hgcm_malloc(s->notify_next.bytes);
    if (!s->notify_next.data) {
        debug_printf("uxen_clipboard_notify_guest malloc fail len 0x%x\n", len);
        goto out;
    }
    ndata = (struct clip_notify_data*) s->notify_next.data;
    ndata->type = type;
    ndata->len = len;
    memcpy(ndata->data, data, len);

    debug_printf("clipboard: queue notify guest type %d len %d\n",
                 type, len);
    if (s->notify.data)
        debug_printf("clipboard: guest busy...\n");
    ioh_event_set(&s->notify_ev);
out:
    critical_section_leave(&s->notify_lock);
}

int
clip_service_start(void)
{
    struct clip_state *s = &_state;

    if (!s->init_done)
        return 0;

    s->quit = 0;
    s->response.data = NULL;
    s->request.data = NULL;
    s->notify.data = NULL;
    s->conn = clip_open(vm_id, CLIP_PORT, __hgcm_malloc, __hgcm_free);
    if (!s->conn)
        return -1;
    s->notify_conn = clip_open(vm_id, CLIP_NOTIFY_PORT, __hgcm_malloc, __hgcm_free);
    if (!s->notify_conn)
        return -1;
    if (create_thread(&s->thread, clipboard_thread, s)) {
        warnx("%s: create_thread", __FUNCTION__);
        return -1;
    }
    if (create_thread(&s->notify_thread, notify_thread, s)) {
        warnx("%s: create_thread", __FUNCTION__);
        return -1;
    }
    s->running = 1;
    debug_printf("clipboard service started\n");
    return 0;
}

static void
clip_service_stop_processing(void)
{
    struct clip_state *s = &_state;

    if (s->running) {
        debug_printf("clipboard service stopping\n");

        s->quit = 1;
        clip_cancel_io(s->conn);
        clip_cancel_io(s->notify_conn);
        ioh_event_set(&s->notify_ev);
        wait_thread(s->thread);
        wait_thread(s->notify_thread);
        clip_close(s->conn);
        clip_close(s->notify_conn);
        s->conn = NULL;
        s->notify_conn = NULL;
        debug_printf("clipboard service stopped\n");
        s->running = 0;
    }
}

static void
clip_service_free(void)
{
    struct clip_state *s = &_state;

    reqfree(&s->request);
    reqfree(&s->response);
    reqfree(&s->notify);
    reqfree(&s->notify_next);
}

void
clip_service_stop(void)
{
    clip_service_stop_processing();
    clip_service_free();
}
