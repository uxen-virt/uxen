/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Michael Dales <michael@digitalflapjack.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"
#import <AppKit/AppKit.h>

#include <sys/time.h>
#include <sys/posix_shm.h>

#include "console.h"
#include "dm.h"
#include "vm.h"
#include "base64.h"
#include "uxen.h"
#include "vram.h"

#import "osx-app-delegate.h"
#import "osx-vm-view.h"

struct osx_surface
{
    struct display_surface s; /* Must be first */
    uint8_t *data;
    int linesize;
};

struct osx_gui_state {
    struct gui_state state; /* Must be first */
    int vram_handle;
    void *vram_view;
    size_t vram_len;
    struct osx_surface *surface;
    struct display_state *ds;
};

static int
osx_surface_lock(struct display_surface *s, uint8_t **data, int *linesize)
{
    struct osx_surface *surface = (void *)s;

    *data = surface->data;
    *linesize = surface->linesize;

    return 0;
}

static void
osx_surface_unlock(struct display_surface *s)
{

}

static struct osx_surface *
osx_create_surface(struct osx_gui_state *s,
                   int width, int height, void *data)
{
    struct osx_surface *surface;

    surface = calloc(1, sizeof(struct osx_surface));
    if (surface == NULL) {
        fprintf(stderr, "%s: calloc failed\n", __FUNCTION__);
        exit(1);
    }

    surface->s.width = width;
    surface->s.height = height;

    surface->s.pf = default_pixelformat(32);

    surface->s.lock = osx_surface_lock;
    surface->s.unlock = osx_surface_unlock;

    surface->linesize = width * 4;
    surface->data = data;

    dispatch_sync(dispatch_get_main_queue(), ^{
            UXENAppDelegate *delegate = (UXENAppDelegate*)[NSApp delegate];
            UXENVirtualMachineView *vmView = delegate.vmView;

            [vmView setBackingStoreBitmap: data
                                    width: width
                                   height: height];
    });

    s->surface = surface;

    return surface;
}

static struct display_surface *
create_surface(struct gui_state *state, int width, int height)
{
    struct osx_gui_state *s = (void *)state;
    void *data;
    struct osx_surface *surface;

    data = calloc(1, width * height * 4);
    if (!data)
        err(1, "%s: calloc failed", __FUNCTION__);

    surface = osx_create_surface(s, width, height, data);

    return &surface->s;
}

static struct display_surface *
create_vram_surface(struct gui_state *state,
                    int width, int height,
                    int depth, int linesize,
                    void *vram_ptr,
                    unsigned int vram_offset)
{
    struct osx_gui_state *s = (void *)state;
    struct osx_surface *surface;
    uint8_t *data;

    if (vram_ptr != s->vram_view ||
        depth != 32 ||
        linesize != (width * 4))
        return NULL;

    data = (uint8_t *)vram_ptr + vram_offset;
    surface = osx_create_surface(s, width, height, data);

    return &surface->s;
}

static void
free_surface(struct gui_state *state, struct display_surface *surface)
{
    struct osx_gui_state *s = (void *)state;
    struct osx_surface *surf = (void *)surface;
    int width = surf->s.width;
    int height = surf->s.height;

    s->surface = NULL;

    dispatch_sync(dispatch_get_main_queue(), ^{
            UXENAppDelegate *delegate = (UXENAppDelegate*)[NSApp delegate];
            UXENVirtualMachineView *vmView = delegate.vmView;

            [vmView setBackingStoreBitmap: NULL
                                    width: width
                                   height: height];
    });

    if (!(surf->s.flags & DISPLAYSURFACE_VRAM))
        free(surf->data);
    free(surf);
}


static void
osx_update(struct gui_state *state, int x, int y, int w, int h)
{
    struct osx_gui_state *s = (void *)state;
    NSRect rect = NSMakeRect(x, ds_get_height(s->ds) - y - h, w, h);

    dispatch_async(dispatch_get_main_queue(), ^{
            UXENAppDelegate *delegate = (UXENAppDelegate*)[NSApp delegate];
            UXENVirtualMachineView *vmView = delegate.vmView;
            [vmView setNeedsDisplayInRect: rect];
    });
}

static void
osx_resize(struct gui_state *state, int w, int h)
{
    NSSize size = NSMakeSize(w, h);

    dispatch_sync(dispatch_get_main_queue(), ^{
            UXENAppDelegate *delegate = (UXENAppDelegate*)[NSApp delegate];
            NSWindow *window = delegate.window;
            [window setContentSize: size];
    });
}

static void
osx_refresh(struct gui_state *state)
{
    struct osx_gui_state *s = (void *)state;

    vga_hw_update(s->ds);
}

static NSCursor *
osx_create_cursor(uint8_t *data, int w, int h, int hot_x, int hot_y)
{
    CGColorSpaceRef colorspace;
    CGBitmapInfo info;
    CGDataProviderRef provider;
    CGImageRef image_ref;
    NSCursor *ret = nil;
    NSSize cursor_size;
    NSPoint cursor_hotspot;
    NSImage *cursor_image;

    info = kCGBitmapByteOrder32Little | kCGImageAlphaFirst;
    colorspace = CGColorSpaceCreateWithName(kCGColorSpaceGenericRGB);
    if (!colorspace)
        goto err_colorspace;

    provider = CGDataProviderCreateWithData(NULL, data, w * 4 * h, NULL);
    if (!provider)
        goto err_provider;

    image_ref = CGImageCreate(w, h, 8, 32, w * 4,
                              colorspace, info, provider,
                              NULL, 0,
                              kCGRenderingIntentDefault);
    if (!image_ref)
        goto err_image_ref;

    cursor_size = NSMakeSize(w, h);
    cursor_hotspot = NSMakePoint(hot_x, hot_y);

    cursor_image = [[NSImage alloc] initWithCGImage: image_ref
                                    size: cursor_size];
    ret = [[NSCursor alloc] initWithImage: cursor_image
                            hotSpot: cursor_hotspot];


    CGImageRelease(image_ref);
err_image_ref:
    CGDataProviderRelease(provider);
err_provider:
    CGColorSpaceRelease(colorspace);
err_colorspace:
    return ret;
}

static void
osx_cursor_shape(struct gui_state *state,
                 int w, int h,
                 int hot_x, int hot_y,
                 uint8_t *mask, uint8_t *color)
{
    NSCursor *cursor = nil;

    if (w == 0 || h == 0) {
        dispatch_sync(dispatch_get_main_queue(), ^{
                UXENAppDelegate *delegate = (UXENAppDelegate*)[NSApp delegate];
                UXENVirtualMachineView *vmView = delegate.vmView;
                [vmView setCursor: nil];
        });
        return;
    }

    /* Sanity check */
    if (w > 128 || w < 0 || h > 128 || h < 0 ||
        hot_x >= w || hot_y >= h)
        return;

    if (color) {
        cursor = osx_create_cursor(color, w, h, hot_x, hot_y);
    } else {
        warnx("%s: monochrome pointers not implemented", __FUNCTION__);
    }

    if (cursor) {
        dispatch_sync(dispatch_get_main_queue(), ^{
                UXENAppDelegate *delegate = (UXENAppDelegate*)[NSApp delegate];
                UXENVirtualMachineView *vmView = delegate.vmView;
                [vmView setCursor: cursor];
        });
    }
}

static int
gui_init(char *optstr)
{
    return 0;
}

static void
gui_exit(void)
{
}

static int
gui_create(struct gui_state *state, struct display_state *ds)
{
    struct osx_gui_state *s = (void *)state;

    s->ds = ds;
    s->vram_handle = -1;
    s->vram_view = NULL;
    s->vram_len = 0;
    s->state.width = 640;
    s->state.height = 480;

    return 0;
}

static void
gui_destroy(struct gui_state *state)
{
    struct osx_gui_state *s = (void *)state;

    (void)s;

    dispatch_sync(dispatch_get_main_queue(), ^{
        UXENAppDelegate *delegate = (UXENAppDelegate*)[NSApp delegate];
        NSWindow *window = delegate.window;
        if (window) {
            [window performClose:nil];
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                     beforeDate:[NSDate date]];
        }
    });
}

static void
gui_start(struct gui_state *state)
{
    struct osx_gui_state *s = (void *)state;

    dispatch_sync(dispatch_get_main_queue(), ^{
            UXENAppDelegate *delegate = (UXENAppDelegate*)[NSApp delegate];
            [delegate createVMWindowWithFrame: NSMakeRect(0.0, 0.0,
                                                          (CGFloat)s->state.width,
                                                          (CGFloat)s->state.height)];
    });
}

static void
vram_changed(struct gui_state *state, struct vram_desc *v)
{
    struct osx_gui_state *s = (void *)state;

    dispatch_sync(dispatch_get_main_queue(), ^{
            UXENAppDelegate *delegate = (UXENAppDelegate*)[NSApp delegate];
            UXENVirtualMachineView *vmView = delegate.vmView;

            [vmView setBackingStoreBitmap: NULL
                                    width: 0
                                   height: 0];
    });

    s->vram_view = v->view;
    s->vram_handle = (int)v->hdl;
    s->vram_len = v->shm_len;

    do_dpy_trigger_refresh(NULL);
}

static struct gui_info osx_gui_info = {
    .name = "osx",
    .size = sizeof(struct osx_gui_state),
    .init = gui_init,
    .start = gui_start,
    .exit = gui_exit,
    .create = gui_create,
    .destroy = gui_destroy,
    .create_surface = create_surface,
    .create_vram_surface = create_vram_surface,
    .free_surface = free_surface,
    .vram_change = vram_changed,
    .update = osx_update,
    .resize = osx_resize,
    .refresh = osx_refresh,
    .cursor_shape = osx_cursor_shape,
};

console_gui_register(osx_gui_info)
