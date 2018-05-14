/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef CONSOLE_DR_H_
#define CONSOLE_DR_H_

typedef void (*inv_rect_t)(void *priv, int x, int y, int w, int h, uint64_t rect_id);

typedef void *console_dr_context_t;

#define DISP_FLAG_MANUAL_ACK_RECT       0x1

console_dr_context_t console_dr_init(
  int vm_id, const unsigned char *idtoken,
  void *priv, inv_rect_t inv_rect,
  uint32_t flags);
void console_dr_ack_rect(console_dr_context_t ctx, uint64_t rect_id);
void console_dr_cleanup(console_dr_context_t ctx);


#endif
