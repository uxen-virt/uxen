/*
 * Copyright (c) 1995 Danny Gasparovski.
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

#ifndef _MISC_H_
#define _MISC_H_

struct tos_t {
    uint16_t lport;
    uint16_t fport;
    uint8_t tos;
};

void fd_nonblock(int);
void fd_block(int);

#endif
