/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _CONSOLE_H_
#define _CONSOLE_H_

#include <stdint.h>

#define MOUSE_EVENT_LBUTTON 0x01
#define MOUSE_EVENT_RBUTTON 0x02
#define MOUSE_EVENT_MBUTTON 0x04

enum DisplayCreateFlags {
    DCF_NONE      = 0x0,
    DCF_START_GUI = 0x1,
};

struct PixelFormat {
    uint8_t bits_per_pixel;
    uint8_t bytes_per_pixel;
    uint8_t depth; /* color depth in bits */
    uint32_t rmask, gmask, bmask, amask;
    uint8_t rshift, gshift, bshift, ashift;
    uint8_t rmax, gmax, bmax, amax;
    uint8_t rbits, gbits, bbits, abits;
};
typedef struct PixelFormat PixelFormat;

typedef unsigned long console_ch_t;

#define DISPLAYSURFACE_VRAM 0x1

struct display_surface {
    uint8_t flags;
    int width;
    int height;
    struct PixelFormat pf;
    int (*lock)(struct display_surface *, uint8_t **, int *);
    void (*unlock)(struct display_surface *);
};

struct console_hw_ops {
    void (*update)(void *);
    void (*invalidate)(void *);
    void (*text_update)(void *, console_ch_t *);
};

struct display_state {
    struct display_surface *surface;
    critical_section resize_lock;
    TAILQ_ENTRY(display_state) link;
    struct gui_state *gui;
    struct console_hw_ops *hw_ops;
    void *hw;
    int desktop_x;
    int desktop_y;
};
TAILQ_HEAD(display_list, display_state);

struct display_surface *create_displaysurface(struct display_state *ds,
                                              int width, int height);
struct display_surface *resize_displaysurface(struct display_state *ds,
                                              struct display_surface *surface,
                                              int width, int height);
void free_displaysurface(struct display_state *ds, struct display_surface *surface);
struct display_surface *create_vram_displaysurface(struct display_state *ds,
                                                   int width, int height,
                                                   int depth, int linesize,
                                                   void *vram_ptr,
                                                   unsigned int vram_offset);

struct vram_desc;

void dpy_update(struct display_state *s, int x, int y, int w, int h);
void dpy_desktop_update(int x, int y, int w, int h);
void dpy_resize(struct display_state *s);
void dpy_refresh(struct display_state *s);
void dpy_cursor_shape(struct display_state *s,
                      int w, int h, int hot_x, int hot_y,
                      uint8_t *mask, uint8_t *color);
void dpy_cursor(struct display_state *s, int x, int y);
void dpy_vram_change(struct display_state *ds, struct vram_desc *v);

PixelFormat default_pixelformat(int bpp);

static inline int is_surface_bgr(struct display_surface *surface)
{
    if (surface->pf.bits_per_pixel == 32 && surface->pf.rshift == 0)
        return 1;
    else
        return 0;
}

static inline int ds_vram_surface(struct display_surface *surface)
{
    return surface->flags & DISPLAYSURFACE_VRAM;
}

static inline int ds_surface_lock(struct display_state *ds, uint8_t **data,
                                  int *linesize)
{
    if (!ds || !ds->surface)
        return -1;

    return ds->surface->lock(ds->surface, data, linesize);
}

static inline void ds_surface_unlock(struct display_state *ds)
{
    ds->surface->unlock(ds->surface);
}

static inline int ds_get_width(struct display_state *ds)
{
    int w;

    if (!ds || !ds->surface)
        return 0;

    critical_section_enter(&ds->resize_lock);
    w = ds->surface->width;
    critical_section_leave(&ds->resize_lock);

    return w;
}

static inline int ds_get_height(struct display_state *ds)
{
    int h;

    if (!ds || !ds->surface)
        return 0;

    critical_section_enter(&ds->resize_lock);
    h = ds->surface->height;
    critical_section_leave(&ds->resize_lock);

    return h;
}

static inline int ds_get_bits_per_pixel(struct display_state *ds)
{
    int bpp;

    if (!ds || !ds->surface)
        return 0;

    critical_section_enter(&ds->resize_lock);
    bpp = ds->surface->pf.bits_per_pixel;
    critical_section_leave(&ds->resize_lock);

    return bpp;
}

static inline void console_write_ch(console_ch_t *dest, uint32_t ch)
{
    if (!(ch & 0xff))
        ch |= ' ';
    *dest = ch;
}

struct display_state *display_create(struct console_hw_ops *ops, void *opaque,
                                     enum DisplayCreateFlags flags);
void display_destroy(struct display_state *ds);
void display_resize(struct display_state *ds, int width, int height);
void display_resize_from(struct display_state *ds, int width, int height,
                         int depth, int linesize,
                         void *vram_ptr,
                         unsigned int vram_offset);
void display_move(struct display_state *ds, int desktop_x, int desktop_y);
extern int desktop_width;
extern int desktop_height;

void vga_hw_update(struct display_state *ds);
void vga_hw_invalidate(struct display_state *ds);


int console_init(const char *name);
void console_start(void);
void console_exit(void);

void do_dpy_trigger_refresh(void *opaque);
void do_dpy_setup_refresh(void);

enum { FORWARD_CONTROL_KEYS = 1, };
extern uint32_t forwarded_keys;
struct yajl_val_s;
int console_set_forwarded_keys(struct yajl_val_s *val);

struct gui_state {
    int width;
    int height;
};

struct gui_info {
    const char *name;
    size_t size;

    int (*init)(char *optstr);
    void (*exit)(void);
    int (*create)(struct gui_state *s, struct display_state *ds);
    void (*destroy)(struct gui_state *s);
    void (*start)(struct gui_state *s);
    struct display_surface *(*create_surface)(struct gui_state *s,
                                              int width, int height);
    struct display_surface *(*create_vram_surface)(struct gui_state *s,
                                                   int width, int height,
                                                   int depth, int linesize,
                                                   void *vram_ptr,
                                                   unsigned int vram_offset);
    void (*free_surface)(struct gui_state *s,
                         struct display_surface *surface);
    void (*vram_change)(struct gui_state *s, struct vram_desc *v);
#ifdef MONITOR
    void (*mon_resize_screen)(struct gui_state *s,
                              Monitor *mon, const dict args);
#endif
    void (*update)(struct gui_state *s, int x, int y, int w, int h);
    void (*resize)(struct gui_state *s, int w, int h);
    void (*refresh)(struct gui_state *s);
    void (*cursor)(struct gui_state *s, int x, int y);
    void (*cursor_shape)(struct gui_state *s,
                         int w, int h, int hot_x, int hot_y,
                         uint8_t *mask, uint8_t *color);
    struct gui_info *next;
};

void gui_register_info(struct gui_info *info);

#define console_gui_register(gui)               \
    initcall(console_gui_register_##gui)        \
    {                                           \
        gui_register_info(&(gui));              \
    }

#endif  /* _CONSOLE_H_ */
