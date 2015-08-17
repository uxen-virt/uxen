/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _VM_SAVE_H_
#define _VM_SAVE_H_

struct control_desc;

enum vm_save_compress_mode {
    VM_SAVE_COMPRESS_NONE = 1,
    VM_SAVE_COMPRESS_LZ4,
};

#define _m(v) (1 << (v))
#define vm_save_compress_mode_batched(m)                                \
    (!!(_m(m) & (_m(VM_SAVE_COMPRESS_NONE) | _m(VM_SAVE_COMPRESS_LZ4))))

struct vm_save_info {
    int awaiting_suspend;
    int save_requested;
    int save_abort;

    char *filename;
    struct filebuf *f;
    off_t dm_offset;

    struct control_desc *command_cd;
    char *command_id;
    struct control_desc *resume_cd;
    char *resume_id;

    enum vm_save_compress_mode compress_mode;
    int single_page;
    int free_mem;
    int high_compress;

    int resume_delete;

    off_t page_batch_offset;
};

extern struct vm_save_info vm_save_info;

void vm_save(void);
struct xc_dominfo;
int vm_process_suspend(struct xc_dominfo *info);
void vm_save_execute(void);
void vm_save_finalize(void);
int vm_save_read_dm_offset(void *dst, off_t offset, size_t size);

int vm_resume(void);

int vm_load(const char *, int);
int vm_load_finish(void);

int vm_lazy_load_page(uint32_t gpfn, uint8_t *va, int compressed);

#endif	/* _VM_SAVE_H_ */
