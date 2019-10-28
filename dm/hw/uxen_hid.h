/*
 * Copyright 2015-2019, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_HID_
#define _UXEN_HID_

struct display_state;

/* scale mouse coordinates from raw x,y into values in range uxenhid expects */
void uxenhid_scale_mouse_pos(struct display_state *ds, uint16_t x, uint16_t y,
                             int *scaled_x, int *scaled_y);
int uxenhid_send_mouse_report(uint8_t buttons, uint16_t x, uint16_t y,
                              int8_t wheel, int8_t hwheel);
int uxenhid_send_pen_report(uint16_t x, uint16_t y, uint8_t flags,
                            uint16_t pressure);
int uxenhid_send_touch_report(uint8_t contact_count, uint16_t contact_id,
                              uint16_t x, uint16_t y,
                              uint16_t width, uint16_t height,
                              uint8_t flags);
int uxenhid_is_touch_ready(void);

#endif /* _UXEN_HID_ */
