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
    int save_abort;

    char *filename;
    struct filebuf *f;

    struct control_desc *command_cd;
    char *command_id;
    struct control_desc *resume_cd;
    char *resume_id;

    int compress;
    int single_page;
    int free_mem;

    off_t page_batch_offset;
};

extern struct vm_save_info vm_save_info;

void vm_save(void);
struct xc_dominfo;
int vm_process_suspend(struct xc_dominfo *info);
void vm_save_execute(void);
void vm_save_finalize(void);

int vm_resume(void);

int vm_load(const char *, int);
int vm_load_finish(void);

#endif	/* _VM_SAVE_H_ */
