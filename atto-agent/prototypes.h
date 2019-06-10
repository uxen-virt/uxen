/*
 * Copyright 2019, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _ATTO_AGENT__H_
#define _ATTO_AGENT__H_

int prot_kbd_init(void);
int prot_kbd_event(int fd);
int pollfd_add(int fd);
int pollfd_remove(int fd);
void prot_kbd_focus_request (unsigned offer);
void prot_kbd_wakeup (int *polltimeout);
#endif
