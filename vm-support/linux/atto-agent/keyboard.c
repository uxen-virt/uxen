/*
 * Copyright 2019, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/uhid.h>

#include <uxen-v4vlib.h>
#include <ax_attovm.h>
#include <ax_attovm_stub.h>
#include <attocall_dev.h>

#include <uxenkbddefs.h>

#include "atto-agent.h"
#include "winlayouts.h"

#define MAX_NUMBER_KEYBOARDS  128

#define MIN_TIME_KEY_RELEASE_FOCUS_MS 800

#define CURRENT_VERSION 1

#undef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#undef BUILD_BUG_ON
#define BUILD_BUG_ON(condition) ((void)sizeof(struct { int:-!!(condition); }))

ssize_t write_retry(int fd, const void *buf, size_t count)
{
    ssize_t ret = -1;

    do {
        ret = write (fd, buf, count);
        if (ret >= 0)
            return ret;
    } while (errno == EINTR);

    return ret;
}

struct attovm_keyboard_event_pk {
      struct attovm_keyboard_event header;
        uint8_t _data[ATTOVM_KBD_V4V_MAX_DATA_LEN];
} __attribute__ ((packed));

typedef struct {
    int valid;
    int created;
    uint32_t id;
    uint32_t device_id;
    uint32_t interface_type;
    uint8_t  last_hid_report[256];
    struct uhid_event hid_create_event;
    uint64_t last_keys_evt;
    int emul;
    int release;

    int fd_uhid;

} keyboard_t;

static int use_protected_keyboard = 0;
static int uxen_fd_v4v = -1;
static int prot_fd_v4v = -1;
static int attocall_fd = -1;
static keyboard_t keyboards[MAX_NUMBER_KEYBOARDS];
static int pvm_keys_dirty = 0;
static int focus_release_request = 0;
static int new_kbd_reset_layout = 0;

static const uint8_t ps2hid[] = {
    0, 41, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 45, 46, 42, 43,
    20, 26, 8, 21, 23, 28, 24, 12, 18, 19, 47, 48, 40, 224, 4, 22,
    7, 9, 10, 11, 13, 14, 15, 51, 52, 53, 225, 50, 29, 27, 6, 25,
    5, 17, 16, 54, 55, 56, 229, 85, 226, 44, 57, 58, 59, 60, 61, 62,
    63, 64, 65, 66, 67, 83, 71, 95, 96, 97, 86, 92, 93, 94, 87, 89,
    90, 91, 98, 99, 0, 148, 100, 68, 69, 135, 146, 147, 138, 136, 139, 140,
    88, 228, 84, 70, 230, 0, 74, 82, 75, 80, 79, 77, 81, 78, 73, 76,
    0, 127, 129, 128, 102, 103, 0, 72, 0, 133, 144, 145, 137, 227, 231, 101,

    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 74, 82, 75, 84, 80, 0, 79, 0, 77,
    81, 78, 89, 76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static const uint8_t ps2mod[8] = { 29, 42, 56, 219, 157, 54, 184, 126, };

static const uint8_t ps2hid_desc_report[] = {
    0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x08,
    0x19, 0x01, 0x29, 0x03, 0x15, 0x00, 0x25, 0x01,
    0x75, 0x01, 0x95, 0x03, 0x91, 0x02, 0x95, 0x05,
    0x91, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7,
    0x95, 0x08, 0x81, 0x02, 0x75, 0x08, 0x95, 0x01,
    0x81, 0x01, 0x19, 0x00, 0x29, 0x91, 0x26, 0xff,
    0x00, 0x95, 0x06, 0x81, 0x00, 0xc0,
};


static inline void
compiler_mb (void)
{
    asm volatile ("":::"memory");
}

static uint64_t get_timestamp_ms(void)
{
    struct timeval tv = { 0 };
    uint64_t ret;

    gettimeofday(&tv, NULL);
    ret = ((uint64_t) tv.tv_sec * 1000) + ((uint64_t) tv.tv_usec / 1000);
    if (!ret)
        ret++;

    return ret;
}

static void reset_keyboard (keyboard_t *kbd)
{
    struct uhid_event ev;

    if (!kbd->valid || !kbd->created)
        return;

    memset (&ev, 0, sizeof (ev));
    ev.type = UHID_DESTROY;
    write_retry (kbd->fd_uhid, &ev, sizeof (ev));
    compiler_mb();
    write_retry (kbd->fd_uhid, &kbd->hid_create_event, sizeof (kbd->hid_create_event));

    kbd->last_keys_evt = 0;
    kbd->emul = 0;
    kbd->release = 0;
    memset (kbd->last_hid_report, 0, sizeof (kbd->last_hid_report));
    new_kbd_reset_layout = 1;
}

static void switch_focus (int release)
{
    if (pvm_keys_dirty && release) {
        int i;

        for (i = 0; i < ARRAY_SIZE(keyboards); i++) {
            keyboard_t *kbd = &keyboards[i];

            if (!kbd->valid)
                continue;
            reset_keyboard (kbd);
        }
        pvm_keys_dirty = 0;
    }

    compiler_mb();
    focus_release_request = 0;
    user_attocall_kbd_op(attocall_fd, release ? ATTOVM_KBCALL_FOCUS_RELEASE :
                         ATTOVM_KBCALL_FOCUS_GRANT, 0);
}

static keyboard_t *
get_keyboard_by_id (uint32_t id)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(keyboards); i++) {
       if (keyboards[i].valid && keyboards[i].id == id)
           return &keyboards[i];
    }

    return NULL;
}

static void fix_kbd_layout(void)
{
    if (!new_kbd_reset_layout)
        return;
    new_kbd_reset_layout = 0;
    atto_agent_reset_kbd_layout();
}

static int ax_keyboard_release_focus_ms (void)
{
#if 1
    // NOTE(tomsci): The delay/refusal to release focus logic is disabled
    // temporarily, because it's causing problems where the host can fail to
    // regain the keyboard at all. Hopefully we can get to the bottom of that
    // soon.
    int ret = 0;
#else
    int i, ret = 0;
    uint64_t now;

    now = get_timestamp_ms();
    for (i = 0; i < ARRAY_SIZE(keyboards); i++) {
        keyboard_t *kbd = &keyboards[i];

        if (!kbd->valid)
            continue;

        if (kbd->last_keys_evt && now < kbd->last_keys_evt +
                                  MIN_TIME_KEY_RELEASE_FOCUS_MS) {
            int diff;

            diff = (int) (kbd->last_keys_evt + MIN_TIME_KEY_RELEASE_FOCUS_MS - now);
            if (diff < 0)
                diff = 0;
            if (ret < diff)
                ret = diff;
        }
    }
#endif

    return ret;
}

static int process_keyboard_removed (keyboard_t *kbd)
{
    if (kbd->valid && kbd->fd_uhid >= 0) {
        pollfd_remove (kbd->fd_uhid);
        fprintf (stderr, "kbd %u removed\n", (unsigned) kbd->id);
        close(kbd->fd_uhid);
        kbd->fd_uhid = -1;
    }

    return 0;
}

static int process_hid_descriptor (keyboard_t *kbd, const uint8_t *buf, size_t len)
{
    int fd;
    size_t len_descriptor = len;
    struct uhid_event ev;

    if (kbd->created)
        return 0;

    kbd->fd_uhid = -1;
    fd = open ("/dev/uhid", O_RDWR|O_NONBLOCK|O_CLOEXEC);
    if (fd < 0) {
      fprintf (stderr, "error opening uhid device %d\n", (int) errno);
      return -1;
    }

    kbd->fd_uhid = fd;
    pollfd_add (fd);

    memset (&ev, 0, sizeof (ev));
    ev.type = UHID_CREATE2;
    sprintf ((char *) ev.u.create2.name, "attokbd-%u", (unsigned) kbd->id);
    if (len_descriptor > HID_MAX_DESCRIPTOR_SIZE)
        len_descriptor = HID_MAX_DESCRIPTOR_SIZE;
    memcpy (&ev.u.create2.rd_data[0], buf, len_descriptor);
    ev.u.create2.rd_size = len_descriptor;
    ev.u.create2.bus = BUS_USB;
    ev.u.create2.vendor = 0x1f00;
    ev.u.create2.product = kbd->id;
    ev.u.create2.version = 0;
    ev.u.create2.country = 0;

    memcpy (&kbd->hid_create_event, &ev, sizeof (ev));
    write_retry (fd, &ev, sizeof (ev));

    kbd->created = 1;
    return 0;
}

static void process_hid_report (keyboard_t *kbd, uint32_t ep_id, uint8_t *buf, size_t len)
{
  struct uhid_event ev;

  if (kbd->fd_uhid < 0)
    return;

  memset (&ev, 0, sizeof (ev));
  ev.type = UHID_INPUT2;
  ev.u.input2.size = len;
  memcpy (&ev.u.input2.data[0], buf, len);

  write_retry (kbd->fd_uhid, &ev, sizeof (ev));
  pvm_keys_dirty = 1;

  if (len <= sizeof (kbd->last_hid_report))
    memcpy (kbd->last_hid_report, buf, len);

  kbd->last_keys_evt = get_timestamp_ms();
}

static void process_ps2_scancode (keyboard_t *kbd, uint8_t sc)
{
    uint8_t report[8], hid_code;
    int ifree, i, k;

    if (sc == 0xe0 || sc == 0xe1) {
        kbd->emul = (sc - 0xe0 + 1);
        return;
    }

    memcpy (report, kbd->last_hid_report, sizeof (report));

    if (sc & 0x80)
        kbd->release = 1;

    sc &= 0x7f;
    if (sc > 0x70)
      goto out;

    if (kbd->emul == 1)
        sc |= 0x80;

    if (kbd->emul && --kbd->emul)
        goto out;

    for (i = 0; i < 8; i++) {
        if (sc == ps2mod[i])
            break;
    }

    if (i < 8) {
        if (kbd->release)
            report[0] &= ~((uint8_t) (1U << i));
        else
            report[0] |= (1U << i);

        goto send;
    }

    hid_code = ps2hid[sc];
    if (kbd->release) {
        for (i = 2; i < 8; i++) {
            if (report[i] == hid_code) {
                report[i] = 0;
                for (k = i; k < 7; k++)
                    report[k] = report[k+1];
                break;
            }
        }

        goto send;
    }

    ifree = 0;
    for (i = 2; i < 6; i++) {
        if (!ifree && report[i] == 0)
            ifree = i;
        if (report[i] == hid_code)
            break;
    }

    if (i == 6) {
        memset (report + 2, 0, 8 - 2);
        ifree = 2;
    }

    if (ifree)
        report[ifree] = hid_code;

    send:
    process_hid_report (kbd, 1, report, 8);

out:
    kbd->release = 0;
}

static int uxen_v4v_event (void)
{
    ssize_t len;
    struct ns_event_msg_kbd_input kdata;

    for (;;) {
        len = recv(uxen_fd_v4v, (void*) &kdata, sizeof (kdata), 0);
        if (len < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
            fprintf (stderr, "atto-kbd: uxen ring recv failure errno %d\n", (int) errno);
            return -1;
        }

        if (kdata.hdr.proto != NS_EVENT_MSG_KBD_INPUT || kdata.hdr.len != sizeof(struct ns_event_msg_kbd_input)) {
            // Ignore non-keyboard events
            return 0;
        }

        if (len < UXEN_MIN_KBD_PKT_LEN) {
            fprintf (stderr, "atto-kbd: uxen ring too short dgram!\n");
            return -1;
        }

        break;
    }

    if (!use_protected_keyboard) {
        fix_kbd_layout();
        if ((kdata.flags & 1) /* the key is an extended key */)
            process_ps2_scancode (&keyboards[0], 0xe0);
        process_ps2_scancode (&keyboards[0], kdata.scancode);
    }

    return 0;
}

static int prot_v4v_event (void)
{
    int i;
    ssize_t len;
    struct attovm_keyboard_event_pk evt_pk;
    struct attovm_keyboard_event *evt = NULL;
    keyboard_t *kbd = NULL;

    BUILD_BUG_ON (CURRENT_VERSION != ATTOVM_KBEVT_CURRENT_VERSION);

    for (;;) {
        len = recv(prot_fd_v4v, (void*) &evt_pk, sizeof (evt_pk), 0);
        if (len < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
            fprintf (stderr, "atto-kbd: recv failure errno %d\n", (int) errno);
            return -1;
        }

        if (len < sizeof (uint32_t)) {
            fprintf (stderr, "atto-kbd: too short dgram!\n");
            return -1;
        }

        if (evt_pk.header.version != CURRENT_VERSION) {
            fprintf (stderr, "atto-kbd: bad evt_pk version %u!\n", (unsigned) evt_pk.header.version);
            return -1;
        }

        if (len < sizeof (evt_pk.header)) {
            fprintf (stderr, "atto-kbd: too short packet!\n");
            return -1;
        }

        break;
    }

    evt = &evt_pk.header;

    switch (evt->type) {
    case ATTOVM_KBEVT_INSERTED:
        new_kbd_reset_layout = 1;
        for (i = 0; i < ARRAY_SIZE(keyboards); i++) {
           if (!keyboards[i].valid) {
                if (!kbd)
                    kbd = &keyboards[i];
                continue;
           }
           if (keyboards[i].id == evt->device_id) {
               fprintf(stderr, "%s: strange, kbd inserted already exists %u\n",
                       __FUNCTION__, (unsigned) evt->device_id);
               kbd = &keyboards[i];
               break;
           }
        }

        if (!kbd) {
            fprintf(stderr, "%s: exhausted number of keyboards !\n", __FUNCTION__);
            break;
        }

        if (!kbd->valid) {
            struct attovm_keyboard_inserted *ins;

            if (evt->data_len < sizeof (*ins)) {
                fprintf(stderr, "%s: bad event len !\n", __FUNCTION__);
                break;
            }
            ins = (struct attovm_keyboard_inserted *) &evt->data[0];
            memset (kbd, 0, sizeof (*kbd));
            kbd->id = evt->device_id;
            kbd->interface_type = ins->interface_type;
            kbd->valid = 1;
            fprintf(stdout, "%s: keyboard %u if type %u inserted\n", __FUNCTION__,
                    (unsigned) kbd->id, (unsigned) kbd->interface_type);
            if (kbd->interface_type == ATTOVM_KBIFT_PS2)
                process_hid_descriptor (kbd, ps2hid_desc_report, sizeof (ps2hid_desc_report));
            break;
        }

        break;
    case ATTOVM_KBEVT_REMOVED:
        kbd = get_keyboard_by_id(evt->device_id);

        if (!kbd) {
            fprintf(stderr, "%s: could not find keyboard id %u\n", __FUNCTION__,
                    (unsigned) evt->device_id);
            break;
        }
        process_keyboard_removed (kbd);
        fprintf(stdout, "%s: keyboard %u removed\n", __FUNCTION__, (unsigned) kbd->id);
        kbd->valid = 0;
        break;
    case ATTOVM_KBEVT_HID_REPORT:
        kbd = get_keyboard_by_id(evt->device_id);
        if (!kbd) {
            fprintf(stderr, "%s: could not find keyboard id %u\n", __FUNCTION__,
                    (unsigned) evt->device_id);
            break;
        }
        fix_kbd_layout();
        process_hid_report (kbd, evt->endpoint_id, &evt->data[0], evt->data_len);
        break;
    case ATTOVM_KBEVT_FOCUS_REVOKED:
        fprintf(stdout, "%s: focus revoked\n", __FUNCTION__);
        break;

    case ATTOVM_KBEVT_PS2_SCANCODE:
        kbd = get_keyboard_by_id(evt->device_id);
        if (!kbd) {
            fprintf(stderr, "%s: could not find PS2 keyboard id %u\n", __FUNCTION__,
                    (unsigned) evt->device_id);
            break;
        }

        if (kbd->interface_type != ATTOVM_KBIFT_PS2)
            fprintf(stderr, "%s: strange, interface type not PS2!\n", __FUNCTION__);

        if (evt->data_len == 0) {
            fprintf(stderr, "%s: zero scancode data len\n", __FUNCTION__);
            break;
        }
        fix_kbd_layout();
        process_ps2_scancode (kbd, evt->data[0]);
        break;

    case ATTOVM_KBEVT_HID_DESCRIPTORS:
        kbd = get_keyboard_by_id(evt->device_id);
        if (!kbd) {
            fprintf(stderr, "%s: could not find keyboard id %u\n", __FUNCTION__,
                    (unsigned) evt->device_id);
            break;
        }
        process_hid_descriptor (kbd, &evt->data[0], evt->data_len);
        break;

    default:
        fprintf(stderr, "%s: unknown kbd event type %u\n", __FUNCTION__,
                (unsigned) evt->type);
        break;
    }

    return 0;
}

static int uhid_event_received (int fd)
{
  ssize_t rc;
  struct uhid_event ev;

  rc = read (fd, &ev, sizeof (ev));
  if (rc != sizeof (ev)) {
    fprintf (stderr, "%s: received len %d\n", __FUNCTION__, (int) rc);
    return - 1;
  }


  // fprintf (stderr, "%s: fd %d got event %d\n", __FUNCTION__, fd, (int) ev.type);
  return 0;
}

kbd_layout_t get_active_kbd_layout(void)
{
    return shared_state->active_layout;
}

int set_active_kbd_layout(kbd_layout_t layout)
{
    shared_state->active_layout = layout;
    return sync_shared_state();
}

int get_x_update_kbd_layout_command(kbd_layout_t layout, char *buf, size_t bufsz)
{
    int i, ret = -1;

    for (i = 0;; i++) {
        WinKBLayoutRec *lrec;

        lrec = &winKBLayouts[i];
        if (lrec->winlayout == (unsigned int) (-1) ||
            lrec->xkbmodel == NULL) {

            break;
        }

        if (lrec->winlayout == layout) {
            if (lrec->xkblayout && lrec->xkbvariant) {
                snprintf(buf, bufsz,
                         "/usr/bin/setxkbmap -model %s -layout %s -variant %s",
                         lrec->xkbmodel, lrec->xkblayout, lrec->xkbvariant);
            } else if (lrec->xkblayout) {
                snprintf(buf, bufsz,
                         "/usr/bin/setxkbmap -model %s -layout %s",
                         lrec->xkbmodel, lrec->xkblayout);
            } else {
                snprintf(buf, bufsz,
                         "/usr/bin/setxkbmap -model %s", lrec->xkbmodel);
            }
            ret = 0;
            break;
        }
    }

    return ret;
}

static int is_uhid_fd(int fd)
{
    int i;

    for (i = 0; i < MAX_NUMBER_KEYBOARDS; i++) {
        keyboard_t *k = &keyboards[i];
        if (k->valid && k->fd_uhid == fd)
            return 1;
    }

    return 0;
}

int kbd_event (int fd)
{
    if (fd == uxen_fd_v4v)
        return uxen_v4v_event();

    if (use_protected_keyboard && fd == prot_fd_v4v)
        return prot_v4v_event();

    if (is_uhid_fd(fd))
        return uhid_event_received(fd);

    return 0;
}

void kbd_focus_request (unsigned offer)
{
    if (!use_protected_keyboard)
        return;

    if (offer) {
        switch_focus(0);
        return;
    }

    if (ax_keyboard_release_focus_ms() == 0) {
        switch_focus(1);
        return;
    }
    focus_release_request = 1;
}

void kbd_wakeup (int *polltimeout)
{
    int diff_release_ms;

    if (!focus_release_request)
        return;

    diff_release_ms = ax_keyboard_release_focus_ms();
    if (!diff_release_ms) {
        switch_focus(1);
        return;
    }

    diff_release_ms += 5;

    if (*polltimeout < 0 || *polltimeout > diff_release_ms)
        *polltimeout = diff_release_ms;
}

int kbd_init (int protkbd)
{
    struct sockaddr_vm addr;
    keyboard_t *kbd = NULL;

    fprintf (stdout, "atto keyboard init\n");
    memset (&keyboards, 0, sizeof (keyboards));

    use_protected_keyboard = protkbd;

    uxen_fd_v4v = socket(AF_VSOCK, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (uxen_fd_v4v < 0)
        err(1, "socket");

    memset(&addr, 0, sizeof(addr));
    addr.family = AF_VSOCK;
    addr.partner = V4V_DOMID_DM;
    addr.v4v.domain = V4V_DOMID_DM;
    addr.v4v.port = UXEN_KBD_V4V_PORT;

    if (bind(uxen_fd_v4v, (const struct sockaddr *) &addr, sizeof(addr)) < 0)
        err(1, "bind %d", (int) errno);

    pollfd_add (uxen_fd_v4v);

    if (use_protected_keyboard) {
        attocall_fd = open ("/dev/attocall", O_WRONLY | O_CLOEXEC);
        if (attocall_fd < 0)
            err(1, "open /dev/attocall");

        prot_fd_v4v = socket(AF_VSOCK, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (prot_fd_v4v < 0)
            err(1, "socket");

        memset(&addr, 0, sizeof(addr));
        addr.family = AF_VSOCK;
        addr.partner = V4V_DOMID_HV;
        addr.v4v.domain = V4V_DOMID_HV;
        addr.v4v.port = ATTOVM_KBD_V4V_PORT;

        if (bind(prot_fd_v4v, (const struct sockaddr *) &addr, sizeof(addr)) < 0)
            err(1, "bind %d", (int) errno);

        compiler_mb();
        user_attocall_kbd_op(attocall_fd, ATTOVM_KBCALL_READY, 0);
        compiler_mb();

        pollfd_add (prot_fd_v4v);
    } else {
        kbd = &keyboards[0];
        memset (kbd, 0, sizeof (*kbd));
        kbd->id = 1;
        kbd->valid = 1;
        kbd->interface_type = ATTOVM_KBIFT_PS2;
        new_kbd_reset_layout = 1;
        fprintf(stderr, "%s: keyboard %u if type %u inserted\n", __FUNCTION__,
                (unsigned) kbd->id, (unsigned) kbd->interface_type);
        process_hid_descriptor (kbd, ps2hid_desc_report, sizeof (ps2hid_desc_report));
    }

    return 0;
}
