/*
 * Copyright 2019, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _AX_ATTOCALL_H_
#define _AX_ATTOCALL_H_

struct attocallev_t{
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
} __attribute__((packed));


#ifndef __KERNEL__
static inline int user_attocall_kbd_op(int fd, uint32_t type, uint32_t extra)
{
    struct attocallev_t ev;

    ev.arg0 = ATTOCALL_KBD_OP;
    ev.arg1 = (uint64_t) type;
    ev.arg2 = (uint64_t) extra;
    ev.arg3 = 0;
    ev.arg4 = 0;

    return (int) write(fd, (void*) &ev, sizeof (ev));
}

#endif /* __KERNEL__ */

#endif /* _AX_ATTOCALL_H_ */
