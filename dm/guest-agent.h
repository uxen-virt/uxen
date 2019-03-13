/*
 * Copyright 2015-2019, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _GUEST_AGENT_H_
#define _GUEST_AGENT_H_

int guest_agent_perf_collection(uint64_t mask, uint32_t interval, uint32_t samples);
int guest_agent_execute(const char *command);
int guest_agent_cmd_prompt(void);
int guest_agent_kbd_event(uint8_t keycode, uint16_t repeat, uint8_t scancode,
                          uint8_t flags, int16_t nchars, wchar_t *chars,
                          int16_t nchars_bare, wchar_t *chars_bare);
int guest_agent_mouse_event(uint32_t x, uint32_t y, int32_t dv, int32_t dh,
                            uint32_t flags);
int guest_agent_window_event(uint64_t hwnd, uint64_t message,
                             uint64_t wParam, uint64_t lParam, int dlo);
int guest_agent_set_dynamic_time_zone(void *dtzi);
int guest_agent_user_draw_enable(int enable);

int guest_agent_cleanup(void);
int guest_agent_init(void);

#endif
