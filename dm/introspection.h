/*
 * Copyright 2013-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _INTROSPECTION_H_
#define _INTROSPECTION_H_

void lava_check_mbr_vbr_write(int64_t sector_num);
struct ioreq;
void send_introspection_event(struct ioreq *req);
int introspection_get_module_name(uint64_t addr, uint64_t* offset,
    char* basename, char* fullname, int buffer_size);
void introspection_dump_kernel_modules();
int introspection_run_hidden_process_detector(uint64_t gsbase, uint64_t cr3,
    unsigned char *imagename);
#endif  /* _INTROSPECTION_H_ */
