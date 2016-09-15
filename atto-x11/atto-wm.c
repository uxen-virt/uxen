/*
 * Copyright 2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <X11/X.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xatom.h>
#include <X11/Xproto.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "queue.h"

#ifdef DEBUG
#define DBG(fmt, ...) fprintf(stderr, "(secvm-wm) %s - " fmt "\n", __FUNCTION__, ## __VA_ARGS__)
#else
#define DBG(fmt, ...) do { } while (1 == 0)
#endif

struct secwin {
    LIST_ENTRY(secwin) entry;
    Window win;
    int transient;
    Window transient_for;
    int x, y, width, height;
};

static LIST_HEAD(, secwin) secwin_list = LIST_HEAD_INITIALIZER(&secwin_list);
static Atom atm_win_type_dialog;
static int full_width = 0, full_height = 0;
Window root_window;

static struct secwin *
find_secwin(Window win)
{
    struct secwin *sw;

    LIST_FOREACH(sw, &secwin_list, entry)
        if (sw->win == win)
            return sw;
    return NULL;
}


static void maximize_window(Display *display, struct secwin *sw)
{
    if (sw->transient)
        return;
    if (sw->width == full_width && sw->height == full_height)
        return;
    DBG("window %dx%d -> %dx%d", sw->width, sw->height, full_width, full_height);
    sw->width = full_width;
    sw->height = full_height;
    XMoveResizeWindow(display, sw->win, 0, 0,
                      full_width, full_height);
    XSync(display, False);
}

static void maximize_all(Display *display)
{
    struct secwin *sw;

    LIST_FOREACH(sw, &secwin_list, entry)
        maximize_window(display, sw);
}

static void map_request(Display *display, XEvent *ev)
{
    struct secwin *sw;

    XMapWindow(display, ev->xmap.window);
    sw = find_secwin(ev->xmap.window);
    if (!sw) {
        DBG("strange, window not found!");
        return;
    }
    maximize_window(display, sw);
}

static void screen_update(Display *display, int width, int height)
{
    DBG("%dx%d", width, height);

    full_width = width;
    full_height = height;
    maximize_all(display);
}

static void new_window(Display *display, XCreateWindowEvent *ev)
{
    struct secwin *sw;
    XWindowAttributes attr;

    if (ev->override_redirect)
        return;

    if (!ev->window)
        return;

    if (find_secwin(ev->window))
        return;

    sw = calloc(1, sizeof(*sw));
    sw->win = ev->window;
    memset(&attr, 0, sizeof(attr));
    XGetWindowAttributes(display, sw->win, &attr);
    sw->x = attr.x;
    sw->y = attr.y;
    sw->width = attr.width;
    sw->height = attr.height;
    sw->transient = XGetTransientForHint(display, sw->win, &sw->transient_for);
    if (!sw->transient) {
        Atom type = None;
        int format;
        unsigned long nitems;
        unsigned long bytes_left;
        unsigned char *data;

        if (XGetWindowProperty(display, sw->win, atm_win_type_dialog, 0, 1L,
                           False, XA_ATOM, &type, &format,
                           &nitems, &bytes_left, &data) == Success && nitems > 0) {


            if (*((Atom *) data) == atm_win_type_dialog)
                sw->transient = 1;
            XFree(data);
        }
    }
    DBG("transient %d", sw->transient);
    LIST_INSERT_HEAD(&secwin_list, sw, entry);
}

static void remove_window(Display *display, XDestroyWindowEvent *ev)
{
    struct secwin *sw;

    sw = find_secwin(ev->window);
    if (!sw)
        return;
    LIST_REMOVE(sw, entry);
    free(sw);
}

static void event(Display *display, XEvent *ev)
{
    switch(ev->type) {
    case MapRequest:
        map_request(display, ev);
        break;
    case ConfigureNotify:
        if (root_window == ev->xconfigure.window)
            screen_update(display, ev->xconfigure.width, ev->xconfigure.height);
        break;
    case CreateNotify:
        new_window(display, &ev->xcreatewindow);
        break;
    case DestroyNotify:
        remove_window(display, &ev->xdestroywindow);
        break;
    default:
        //DBG("other event (%d) received", (int) ev->type);
        break;
    }
}

static void events_loop(Display *display)
{
    DBG("events loop");
    for (;;) {
        XEvent ev;

        XNextEvent (display, &ev);
        event(display, &ev);
    }
}

static int x_error_handler(Display *d, XErrorEvent *e)
{
    char msg[128];

    memset(msg, 0, sizeof(msg));
    XGetErrorText(d, e->error_code, msg, sizeof(msg) - 1);
    fprintf(stderr, "%s: ERROR %s\n", __FUNCTION__, msg);

    return 0;
}


int main(int argc, char *argv[])
{
    Display *display;
    XColor color, unused;

    display = XOpenDisplay(NULL);
    if (!display) {
        fprintf (stderr, "fatal: can't open display\n");
        return 1;
    }

    XSetErrorHandler(x_error_handler);
    signal(SIGALRM, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    atm_win_type_dialog = XInternAtom(display, "_NET_WM_WINDOW_TYPE_DIALOG", False);

    root_window = RootWindow(display, 0);
    full_width = DisplayWidth(display, 0);
    full_height = DisplayHeight(display, 0);
    XSelectInput(display, root_window,
                 PropertyChangeMask | ColormapChangeMask |
	         SubstructureRedirectMask | SubstructureNotifyMask |
	         StructureNotifyMask);
    XSync(display, False);

    if (XAllocNamedColor(display, DefaultColormap(display, 0), "white", &color, &unused)) {
        XSetWindowBackground(display, root_window, color.pixel);
        XClearWindow(display, root_window);
    }

    events_loop(display);
    return 0;
}
