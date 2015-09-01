/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _INPUT_H_
#define _INPUT_H_

typedef void input_kbd_fn(void *opaque, int keycode);

void input_set_kbd_handler(input_kbd_fn *fn, void *opaque);

void input_kbd_event(int keycode);
void input_kbd_ledstate(int ledstate);

int input_get_kbd_ledstate(void);
void input_kbd_ledstate_register(void (*fn)(int ledstate, void *opaque),
                                 void *opaque);

typedef void input_mouse_fn(void *opaque, int dx, int dy, int dz,
			    int button_state);

void input_set_mouse_handler(input_mouse_fn *fn, int absolute, void *opaque);

void input_mouse_event(int dx, int dy, int dz, int button_state);
int input_mouse_is_absolute(void);

enum input_event_type {
    KEYBOARD_INPUT_EVENT,
    MOUSE_INPUT_EVENT,
};

struct input_event {
    enum input_event_type type;
    union {
        struct {
            int keycode;
            int extended;
        };
        struct {
            int x;
            int y;
            int dz;
            int button_state;
        };
    };
};

void input_event_cb(void *opaque);

#endif	/* _INPUT_H_ */
