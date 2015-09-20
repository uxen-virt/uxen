/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _VRAM_H_
#define _VRAM_H_

#include "vmstate.h"

struct vram_desc {
    uintptr_t hdl;
    uint8_t *view;
    size_t len;
    size_t mapped_len;
    uint32_t gfn;
    uint32_t last_gfn;
    size_t lz4_len;
    int64_t file_offset;

    void (*notify)(struct vram_desc *, void *);
    void *priv;
};

int vram_init(struct vram_desc *v, size_t len);
int vram_alloc(struct vram_desc *v, size_t mapped_len);
int vram_release(struct vram_desc *v);
int vram_suspend(struct vram_desc *v);
int vram_resume(struct vram_desc *v);
int vram_unmap(struct vram_desc *v);
int vram_map(struct vram_desc *v, uint32_t gfn);
int vram_resize(struct vram_desc *v, uint32_t new_mapped_len);

void vram_register_change(struct vram_desc *v,
                     void (*notify)(struct vram_desc *, void *),
                     void *priv);

extern const VMStateInfo vmstate_info_vram;

#define VMSTATE_VRAM(_field, _state) {                          \
    .name         = (stringify(_field)),                        \
    .info         = &vmstate_info_vram,                         \
    .flags        = VMS_SINGLE,                                 \
    .offset       = vmstate_offset_value(_state, _field,        \
                                         struct vram_desc),     \
    .size         = sizeof(struct vram_desc),                   \
}

#define VMSTATE_VRAM_ARRAY(_field, _state, _num) {              \
    .name         = (stringify(_field)),                        \
    .info         = &vmstate_info_vram,                         \
    .flags        = VMS_ARRAY,                                  \
    .num          = (_num),                                     \
    .offset       = vmstate_offset_array(_state, _field,        \
                                         struct vram_desc,      \
                                         _num),                 \
    .size         = sizeof(struct vram_desc),                   \
}

#endif /* _VRAM_H_ */
