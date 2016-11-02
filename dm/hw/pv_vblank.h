/*
 * Copyright 2016, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef PV_VBLANK_H_
#define PV_VBLANK_H_

#define PV_VBLANK_OFF 0
#define PV_VBLANK_NATIVE 1
#define PV_VBLANK_SMOOTH 2
#define PV_VBLANK_EFFICIENT 3

struct uxendisp_state;
struct vblank_ctx;

struct vblank_ctx *pv_vblank_init(struct uxendisp_state *ds, int method);
void pv_vblank_cleanup(struct vblank_ctx*);
void pv_vblank_start(struct vblank_ctx*);
void pv_vblank_stop(struct vblank_ctx*);
int  pv_vblank_get_reported_vsync_hz(void);

#endif
