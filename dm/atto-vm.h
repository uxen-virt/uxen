/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _ATTO_VM_H_
#define _ATTO_VM_H_

void attovm_set_current_cursor(void);
void attovm_check_kbd_layout_change(void);
void attovm_set_x11_cursor(uint64_t x11_ptr);
void attovm_map_x11_cursor(int x11_type, uint64_t x11_ptr);
void attovm_unmap_x11_cursor(uint64_t x11_ptr);
void attovm_create_custom_cursor(uint64_t x11_ptr, int xhot, int yhot,
                                 int x11_nx, int x11_ny,
                                 int nbytes,
                                 uint8_t *x11_and, uint8_t *x11_xor);
void attovm_set_keyboard_focus(int offer_focus);
void attovm_check_keyboard_focus(void);
int is_attovm_image(const char *file);

#endif
