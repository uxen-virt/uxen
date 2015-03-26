/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _VM_SAVE_H_
#define _VM_SAVE_H_

struct control_desc;

struct vm_save_info {
    int awaiting_suspend;
    int save_requested;

    char *filename;

    struct control_desc *command_cd;
    char *command_id;

    int compress;
    int single_page;
};

extern struct vm_save_info vm_save_info;

void vm_save(void);
struct xc_dominfo;
int vm_process_suspend(struct xc_dominfo *info);
void vm_save_execute(void);
int vm_load(const char *, int);
int vm_load_finish(void);

#endif	/* _VM_SAVE_H_ */
