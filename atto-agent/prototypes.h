/*
 * Copyright 2019, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _ATTO_AGENT__H_
#define _ATTO_AGENT__H_

void atto_agent_reset_kbd_layout(void);
int kbd_init(int protkbd);
int kbd_event(int fd);
int pollfd_add(int fd);
int pollfd_remove(int fd);
void kbd_focus_request (unsigned offer);
void kbd_wakeup (int *polltimeout);
#endif
