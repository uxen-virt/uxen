/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENCONSOLELIB_H_
#define _UXENCONSOLELIB_H_

#ifdef __cplusplus
extern "C" {
#endif

#define CURSOR_UPDATE_FLAG_HIDE         0x1
#define CURSOR_UPDATE_FLAG_MONOCHROME   0x2

#define MOUSE_EVENT_FLAG_LBUTTON_DOWN   0x1
#define MOUSE_EVENT_FLAG_RBUTTON_DOWN   0x2
#define MOUSE_EVENT_FLAG_MBUTTON_DOWN   0x10
#define MOUSE_EVENT_FLAG_XBUTTON1_DOWN  0x20
#define MOUSE_EVENT_FLAG_XBUTTON2_DOWN  0x40

#define KEYBOARD_EVENT_FLAG_EXTENDED    0x1
#define KEYBOARD_EVENT_FLAG_UCS2        0x10000

#define CLIPBOARD_PERMIT_COPY           0x1
#define CLIPBOARD_PERMIT_PASTE          0x2

#ifndef QEMU_UXEN
typedef void *uxenconsole_context_t;
typedef void *hid_context_t;

#if defined(_WIN32)
typedef HANDLE file_handle_t;
#elif defined(__APPLE__)
typedef int file_handle_t;
#endif

typedef struct uxenconsole_ops {
    void (*resize_surface)(void *priv,
                           unsigned int width,
                           unsigned int height,
                           unsigned int linesize,
                           unsigned int length,
                           unsigned int bpp,
                           unsigned int offset,
                           file_handle_t shm_handle);
    void (*invalidate_rect)(void *priv,
                            int x,
                            int y,
                            int w,
                            int h);
    void (*show_cursor)(void *priv,
                        unsigned int show);
    void (*update_cursor)(void *priv,
                          unsigned int width,
                          unsigned int height,
                          unsigned int hot_x,
                          unsigned int hot_y,
                          unsigned int mask_offset,
                          unsigned int flags,
                          file_handle_t shm_handle);
    void (*keyboard_ledstate)(void *priv,
                              int state);

    void (*enable_write_event)(void *priv, file_handle_t handle, int enable);
    void (*disconnected)(void *priv);
} ConsoleOps;

typedef enum uxenconsole_resize_flags {
    CONSOLE_RESIZE_FLAG_NONE  = 0x0,
    CONSOLE_RESIZE_FLAG_FORCE = 0x1
} ConsoleResizeFlags;

uxenconsole_context_t   uxenconsole_init(ConsoleOps *console_ops,
                                         void *console_priv,
                                         char *filename);
file_handle_t           uxenconsole_connect(uxenconsole_context_t ctx);
void                    uxenconsole_channel_event(uxenconsole_context_t ctx,
                                                  file_handle_t event,
                                                  int is_write);
void                    uxenconsole_disconnect(uxenconsole_context_t ctx);
void                    uxenconsole_cleanup(uxenconsole_context_t ctx);

int                     uxenconsole_mouse_event(uxenconsole_context_t ctx,
                                                unsigned int x,
                                                unsigned int y,
                                                int dv,
                                                int dh,
                                                unsigned int flags);

int                     uxenconsole_keyboard_event(uxenconsole_context_t ctx,
                                                   unsigned int keycode,
                                                   unsigned int repeat,
                                                   unsigned int scancode,
                                                   unsigned int flags,
                                                   void *chars,
                                                   unsigned int nchars);

int                     uxenconsole_request_resize(uxenconsole_context_t ctx,
                                                   unsigned int width,
                                                   unsigned int height,
                                                   ConsoleResizeFlags flags);

int                     uxenconsole_clipboard_permit(uxenconsole_context_t ctx,
                                                     int permit_type);

int                     uxenconsole_touch_device_hotplug(uxenconsole_context_t ctx,
                                                         int plug);

hid_context_t           uxenconsole_hid_init(int vm_id);
void                    uxenconsole_hid_cleanup(hid_context_t context);
int                     uxenconsole_hid_mouse_report(hid_context_t context,
                                                     int buttons, int x, int y,
                                                     int wheel, int hwheel);
int                     uxenconsole_hid_pen_report(hid_context_t context,
                                                   int x, int y, int flags,
                                                   int pressure);
int                     uxenconsole_hid_touch_report(hid_context_t context,
                                                     int contact_count,
                                                     int contact_id,
                                                     int x, int y,
                                                     int width, int height,
                                                     int flags);
#endif /* !QEMU_UXEN */

typedef void *disp_context_t;
typedef void (*invalidate_rect_t)(void *priv, int x, int y, int w, int h);

disp_context_t          uxenconsole_disp_init(int vm_id,
                                              void *priv,
                                              invalidate_rect_t inv_rect);
void                    uxenconsole_disp_cleanup(disp_context_t context);

#ifdef __cplusplus
}
#endif

#endif /* _UXENCONSOLELIB_H_ */
