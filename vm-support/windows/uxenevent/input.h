/*
 * Copyright 2013-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _INPUT_H_
#define _INPUT_H_

#ifndef WM_MOUSEHWHEEL
#define WM_MOUSEHWHEEL 0x020E
#endif
#ifndef MOUSEEVENTF_HWHEEL
#define MOUSEEVENTF_HWHEEL 0x01000
#endif

int input_key_event(uint8_t keycode, uint16_t repeat, uint8_t scancode,
                    uint8_t flags, int nchars, wchar_t *chars,
                    int nchars_bare, wchar_t *chars_bare);
int input_mouse_event(uint32_t x, uint32_t y, int32_t dv, int32_t dh,
                      uint32_t flags);
int input_wm_mouse_event(UINT message, WPARAM wParam, LPARAM lParam);

#define MAX_TOUCH_CONTACTS 10

int input_touch_event(int count, struct ns_event_touch_contact *contacts);
int input_touch_init(void);

#endif /* _INPUT_H_ */
