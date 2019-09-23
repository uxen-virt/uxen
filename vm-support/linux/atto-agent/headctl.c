/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <inttypes.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <pthread.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/Xdamage.h>
#include <X11/extensions/Xfixes.h>
#include <uxen-v4vlib.h>
#include "atto-agent.h"

/* dr tracking */
#include "../../../common/include/uxendisp-common.h"


#ifndef DEFAULT_USER_NAME
#define DEFAULT_USER_NAME "user"
#endif

#ifndef DEFAULT_VT
#define DEFAULT_VT "1"
#endif

#define DEFAULT_XORG_PARAMS "-wr -pn"

#define X_CONNECT_TIMEOUT_MS 5000

/* fb ioctl */
#define UXEN_FB_IO_HEAD_IDENTIFY 0x5000
#define UXEN_FB_IO_HEAD_INIT 0x5001

#define HEADCTL_ERROR(fmt, ...) { fprintf(stderr, fmt, ## __VA_ARGS__); fflush(stderr); }

static void headctl_usage(void)
{
    fprintf(stderr, "usage: atto-agent headctl [list|create <head>|initx <head> [xorg params...]|device <head>|activate <head>]\n");
    exit(1);
}

static head_id_t str_to_head_id(const char *s)
{
    return (head_id_t) atoi(s);
}

static void update_heads(void)
{
    int i, fd, ret;
    volatile head_t *heads;

    lock_shared_state();
    heads = &shared_state->heads[0];

    /* scan only new heads */
    for (i = shared_state->heads_num; i < HEADMAX; i++) {
        head_t h;
        memset(&h, 0, sizeof(h));
        snprintf(h.dev, sizeof(h.dev), "/dev/fb%d", i);
        fd = open(h.dev, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
            break;
        ret = ioctl(fd, UXEN_FB_IO_HEAD_IDENTIFY, &h.id);
        if (ret)
            err(1, "head identify failed: %d", ret);
        close(fd);

        heads[i] = h;
    }
    shared_state->heads_num = i;
    sync_shared_state();
    unlock_shared_state();
}

static head_t *get_head_by_id(head_id_t id)
{
    int i;

    for (i = 0; i < shared_state->heads_num; i++) {
        if (shared_state->heads[i].id == id)
            return (head_t *) &shared_state->heads[i];
    }

    return NULL;
}

static int x_toggleinput(head_id_t head, int enable)
{
    char cmd[256];
    int err;

    snprintf(cmd, sizeof(cmd),
        "DISPLAY=:%d.0 xinput %s 6", head, enable ? "enable" : "disable");
    err = system(cmd);
    if (err)
        goto out;
    snprintf(cmd, sizeof(cmd),
        "DISPLAY=:%d.0 xinput %s 7", head, enable ? "enable" : "disable");
    err = system(cmd);

out:
    return err;
}

/* sync keyboard layout for given head with currently active global one */
static int x_sync_kb_layout(head_id_t head)
{
    char cmd[256];
    int err;

    kbd_layout_t layout = get_active_kbd_layout();
    if (layout == KBD_LAYOUT_INVALID)
        return -EINVAL;
    err = get_x_update_kbd_layout_command(layout, cmd, sizeof(cmd));
    if (err)
        return err;

    /* note: input needs to be enabled on that X for layout change to work */

    return headctl_system_cmd(head, cmd);
}

static void x_run_server(head_id_t head, char *extra_params)
{
    char cmd[512];
    char vtopt[64] = { 0 };
    struct head *h;

    h = get_head_by_id(head);
    if (!h) {
        HEADCTL_ERROR("head not found\n");
        exit(1);
    }

    if (head != 0)
        /* head > 0 need sharevt */
        strncpy(vtopt, "-novtswitch -sharevts", sizeof(vtopt));
    else
        strncpy(vtopt, "-novtswitch", sizeof(vtopt));

    /* into /dev/null it goes because it spams setxbmap compiler warnings */
    snprintf(cmd, sizeof(cmd),
        "ATTO_HEAD_ID=%d FRAMEBUFFER=%s xinit /etc/X11/Xsession -- "
        "/usr/bin/Xorg :%d %s vt%s %s -logfile /var/log/%s/Xorg.%d.log &> /dev/null",
        head, h->dev, head, extra_params, DEFAULT_VT, vtopt, DEFAULT_USER_NAME, head);

    printf("starting x server: %s\n", cmd);
    fflush(stdout);

    execl("/bin/sh", "sh", "-c", cmd, (char *) NULL);

    /* if we're here it means execl failed */
    HEADCTL_ERROR("error starting X: %d\n", errno);
    exit(1);
}

/* execute command on display corresponding to given head */
int headctl_system_cmd(head_id_t head, const char *cmd)
{
    char buf[256];

    snprintf(buf, sizeof(buf), "DISPLAY=:%d.0 %s", (int) head, cmd);

    int ret = system(buf);

    return ret;
}

int headctl_activate(head_id_t new)
{
    head_id_t old;
    struct head *h;
    int err = 0;

    if (!(new >= 0 && new < HEADMAX))
        return -EINVAL;

    err = lock_shared_state();
    if (err)
        return err;

    /* mark pending active head even if it doesn't exist yet */
    shared_state->active_head_request = new;
    sync_shared_state();

    h = get_head_by_id(new);
    if (!h) {
        err = -EINVAL;
        goto out;
    }

    old = shared_state->active_head;
    if (old == new)
        goto out; /* nothing to do  */

    /* toggle input old -> new */
    err = x_toggleinput(old, 0);
    if (err)
        goto out;

    err = x_toggleinput(new, 1);
    if (err)
        goto out;

    /* sync kb layout */
    x_sync_kb_layout(new);

    /* update state */
    shared_state->active_head = new;
    sync_shared_state();

out:
    unlock_shared_state();

    if (err)
        HEADCTL_ERROR("activate head %d failed: %d\n", new, err);

    return err;
}

void headctl_for_each_head(void (*f)(head_id_t head, void *opaque), void *opaque)
{
    int i;

    for (i = 0; i < shared_state->heads_num; i++) {
        head_id_t id = shared_state->heads[i].id;
        f(id, opaque);
    }
}

static Display *connectx(head_id_t head)
{
    char display_str[32];

    sprintf(display_str, ":%d", head);

    Display *d = XOpenDisplay(display_str);

    return d;
}

static Display *connectx_timeout(head_id_t head, int timeout_ms)
{
    int iters = (timeout_ms + 99) / 100;
    Display *d;

    for (;;) {
        d = connectx(head);
        if (d)
            return d;
        iters--;
        if (iters <= 0)
            break;
        // wait 100 ms
        usleep(100 * 1000);
    }

    return NULL;
}

static void cmd_headctl_list(void)
{
    int i;

    head_id_t active = shared_state->active_head;
    char actstr[32];
    strcpy(actstr, "            ");
    printf("%10s | %10s | %10s\n", "HEADID", "DEVICE", "ACTIVE");
    printf("-----------------------------------\n");
    for (i = 0 ; i < shared_state->heads_num; i++) {
        int id = shared_state->heads[i].id;
        actstr[6] = (active == id) ? '*' : ' ';
        printf("%10d | %10s | %10s\n", id, shared_state->heads[i].dev, actstr);
    }
}

static void cmd_headctl_create(char *headstr)
{
    head_id_t head = str_to_head_id(headstr);
    int fd, ret, iters;

    if (head >= 0 && head < HEADMAX) {
        fd = open("/dev/fb0", O_RDONLY|O_CLOEXEC);
        if (fd < 0)
            err(1, "fb open");
        ret = ioctl(fd, UXEN_FB_IO_HEAD_INIT, &head);
        if (ret)
            err(1, "head %d init failed: %d", (int) head, ret);
        close(fd);

        // wait until new device node appears
        iters = 100;
        for (;;) {
            update_heads();
            struct head *hnew = get_head_by_id(head);
            if (hnew)
                break;
            iters--;
            if (iters == 0)
                errx(1, "head %d init failed: couldn't open device", (int) head);
            usleep(20 * 1000);
        }
    } else
        errx(1, "head id out of range\n");
}

static void stringify_params(char *buf, int bufsz, int count, char **params)
{
    int i = 0;

    while (count) {
        char *par  = params[i];
        int parlen = strlen(par);

        if (parlen >= bufsz - 1)
            break;

        sprintf(buf, "%s ", par);

        buf   += parlen + 1;
        bufsz -= parlen + 1;

        count--;
        i++;
    }
}

static void cmd_headctl_initx(char *headstr, int num_x_params, char **x_params)
{
    head_id_t head = str_to_head_id(headstr);
    char x_params_str[256] = { 0 };
    Display *d;
    int err;

    if (num_x_params > 0)
      stringify_params(x_params_str, sizeof(x_params_str), num_x_params, x_params);
    else
      strncpy(x_params_str, DEFAULT_XORG_PARAMS, sizeof(x_params_str));

    cmd_headctl_create(headstr);

    d = connectx(head);
    if (d) {
        XCloseDisplay(d);
        printf("X already running on head %s\n", headstr);
        exit(0);
    }

    pid_t child = fork();
    if (child == 0) {
        child = fork();
        if (child == 0)
            exit(0);
        x_run_server(head, x_params_str);
    } else {
        /* in parent, wait for X to init */
        d = connectx_timeout(head, X_CONNECT_TIMEOUT_MS);
        if (d) {
            /* setup default kbd layout */
            err = x_sync_kb_layout(head);
            if (err)
                HEADCTL_ERROR("FAILED to setup x kb layout: %d\n", err);
            /* input off by default if not active already */
            err = lock_shared_state();
            if (err)
                HEADCTL_ERROR("FAILED to lock shared state\n");
            if (shared_state->active_head != head) {
                err = x_toggleinput(head, 0);
                if (err)
                    HEADCTL_ERROR("FAILED to toggle xinput: %d\n", err);
            }
            unlock_shared_state();
            XCloseDisplay(d);
        } else {
            HEADCTL_ERROR("FAILED to connect to X server head %d\n", head);
            exit(1);
        }
    }
}

static void cmd_headctl_activate(char *headstr)
{
    head_id_t head = str_to_head_id(headstr);
    int err;

    err = headctl_activate(head);
    if (err) {
        HEADCTL_ERROR("FAILED to activate head %d: %d\n",
            head, err);
        exit(err);
    }
}

static void cmd_headctl_device(char *headstr)
{
    head_id_t head = str_to_head_id(headstr);
    struct head *h;
    
    h = get_head_by_id(head);

    if (h) {
        printf("%s\n", h->dev);
    } else {
        HEADCTL_ERROR("invalid head id\n");
        exit(1);
    }
}

static void* run_dr_(void *head_)
{
    struct head *head = head_;
    Display *d = NULL;

    d = connectx_timeout(head->id, X_CONNECT_TIMEOUT_MS);
    if (!d) {
        HEADCTL_ERROR("FAILED to connect to X server for head %d\n", head->id);
        return 0;
    }

    Window root = DefaultRootWindow(d);
    int damage_event_base, damage_error;
    XDamageQueryExtension(d, &damage_event_base, &damage_error);
    Damage damage = XDamageCreate(d, root, XDamageReportNonEmpty);

    for (;;) {
        XEvent ev;
        XNextEvent(d, &ev);
        if (ev.type == damage_event_base + XDamageNotify) {
            XDamageNotifyEvent *dev = (XDamageNotifyEvent*) &ev;

            if (dev->damage != damage)
                continue; // not ours

            XserverRegion region = XFixesCreateRegion(d, NULL, 0);
            XDamageSubtract(d, damage, None, region);
            XSync(d, False); /* sync before we start copying or will artifact */
            int count;
            XRectangle bounds;
            XRectangle *rects = XFixesFetchRegionAndBounds(d, region, &count, &bounds);
            if (rects && count) {
                int x0 = 0xffff;
                int y0 = 0xffff;
                int x1 = 0;
                int y1 = 0;

                for (int i = 0; i < count; i++) {
                    int rx0 = rects[i].x;
                    int ry0 = rects[i].y;

                    int rx1 = rx0 + rects[i].width  - 1;
                    int ry1 = ry0 + rects[i].height - 1;

                    if (rx0 < x0) x0 = rx0;
                    if (ry0 < y0) y0 = ry0;
                    if (rx1 > x1) x1 = rx1;
                    if (ry1 > y1) y1 = ry1;
                }

                XFree(rects);

                /* send dr to backend */
                struct dirty_rect_msg msg;
                memset(&msg, 0, sizeof(msg));
                msg.left = x0;
                msg.top = y0;
                msg.right = x1 + 1;
                msg.bottom = y1 + 1;
                msg.rect_id = __atomic_fetch_add(&shared_state->rect_id, 1, __ATOMIC_SEQ_CST);
                msg.head_id = head->id;
                sync_shared_state();
                ssize_t len = send(shared_state->dr_fd, &msg, sizeof(msg), 0);
                if (len < 0)
                    err(1, "send error %d\n", errno);
            }
            XFixesDestroyRegion(d, region);
        }
    }
}

static void run_dr(volatile struct head *h)
{
    pthread_t tid;

    int err = pthread_create(&tid, NULL, run_dr_, (void*)h);
    if (err) {
        HEADCTL_ERROR("couldn't create dr thread for head %d: %d\n", h->id, err);
    }
}

void headctl_wakeup(int *timeout)
{
    int t = *timeout, i, num;

    if (shared_state->active_head_request != shared_state->active_head) {
        int err = headctl_activate(shared_state->active_head_request);

        if (err) {
            /* try to activate it again later */
            if (t == -1 || t > 50)
                t = 50;
        }
    }

    if (t == -1 || t > 1000)
        t = 1000;

    *timeout = t;

    /* check for missing head dr and run dr tracking if needed */
    num = shared_state->heads_num;
    for (i = 0; i < num; i++) {
        if (!shared_state->heads[i].dr) {
            shared_state->heads[i].dr = 1;
            sync_shared_state();
            run_dr(&shared_state->heads[i]);
        }
    }
}

void headctl_init(void)
{
    struct sockaddr_vm addr;

    update_heads();

    /* connect DR tracking port */
    int fd = socket(AF_VSOCK, SOCK_DGRAM, 0);
    if (fd < 0)
        err(1, "socket");

    memset(&addr, 0, sizeof(addr));
    addr.family = AF_VSOCK;
    addr.partner = V4V_DOMID_DM;
    addr.v4v.domain = V4V_DOMID_DM;
    addr.v4v.port = UXENDISP_PORT;

    if (bind(fd, (const struct sockaddr *) &addr, sizeof(addr)) < 0)
        err(1, "bind %d", (int) errno);

    if (connect(fd, (const struct sockaddr *) &addr, sizeof(addr)) < 0)
        err(1, "connect %d", (int) errno);

    shared_state->dr_fd = fd;
    shared_state->rect_id = 0;
    sync_shared_state();
}

void headctl(int argc, char **argv)
{
    char *cmd;

    if (argc < 3)
        headctl_usage();

    cmd = argv[2];

    if (!strcmp(cmd, "list"))
        cmd_headctl_list();
    else if (!strcmp(cmd, "create")) {
        if (argc < 4)
            headctl_usage();
        cmd_headctl_create(argv[3]);
    } else if (!strcmp(cmd, "device")) {
        if (argc < 4)
            headctl_usage();
        cmd_headctl_device(argv[3]);
    } else if (!strcmp(cmd, "initx")) {
        if (argc < 4)
            headctl_usage();
        cmd_headctl_initx(argv[3], argc - 4, argv + 4);
    } else if (!strcmp(cmd, "activate")) {
        if (argc < 4)
            headctl_usage();
        cmd_headctl_activate(argv[3]);
    } else
        headctl_usage();
}

