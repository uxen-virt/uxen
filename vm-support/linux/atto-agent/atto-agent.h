/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _ATTO_AGENT__H_
#define _ATTO_AGENT__H_

typedef uint32_t head_id_t;
typedef uint32_t kbd_layout_t;

#define KBD_LAYOUT_INVALID ((kbd_layout_t)-1)
#define HEADMAX 32

struct drc {
    int x0, x1, y0, y1;
};

typedef struct head {
    head_id_t id;
    char dev[64];
    int index;
} head_t;

/* state shared between agent daemon and command instances, also persistent across restarts */
typedef struct shared_state {
    head_id_t active_head_request;
    head_id_t active_head;
    kbd_layout_t active_layout;
    struct head heads[HEADMAX];
    int heads_num;
    int dr_fd;
    uint64_t rect_id;
} shared_state_t;

#define SHARED_STATE_FILE "/tmp/atto-agent-state"

extern volatile shared_state_t *shared_state;

int sync_shared_state(void);
int lock_shared_state(void);
void unlock_shared_state(void);

int kbd_init(int protkbd);
int kbd_event(int fd);
int pollfd_add(int fd);
int pollfd_remove(int fd);
void kbd_focus_request (unsigned offer);
void kbd_wakeup (int *polltimeout);

void headctl_init(void);
void headctl_event(int fd);
void headctl(int argc, char **argv);
void headctl_wakeup(int *timeout);
int headctl_activate(head_id_t head);
int headctl_system_cmd(head_id_t head, const char *cmd);
void headctl_for_each_head(void (*f)(head_id_t head, void *opaque), void *opaque);

void atto_agent_reset_kbd_layout(void);
int get_x_update_kbd_layout_command(kbd_layout_t layout, char *buf, size_t bufsz);
kbd_layout_t get_active_kbd_layout(void);
int set_active_kbd_layout(kbd_layout_t layout);
int get_x_update_kbd_layout_command(kbd_layout_t layout, char *buf, size_t bufsz);

#endif
