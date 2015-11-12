/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _MONITOR_CMDS_H_
#define _MONITOR_CMDS_H_

#include "dict.h"

void mc_quit(Monitor *mon, const dict args);
void mc_savevm(Monitor *mon, const dict args);
void mc_resumevm(Monitor *mon, const dict args);
void mc_xen_key(Monitor *mon, const dict args);
void mc_toggle_ioreq(Monitor *mon, const dict args);
void mc_toggle_hvm_tracking(Monitor *mon, const dict args);
void mc_clear_stats(Monitor *mon, const dict args);
void mc_resize_screen(Monitor *mon, const dict args);
void mc_block_change(Monitor *mon, const dict args);
void mc_inject_trap(Monitor *mon, const dict args);
void mc_vm_pause(Monitor *mon, const dict args);
void mc_vm_unpause(Monitor *mon, const dict args);
void mc_vm_time_update(Monitor *mon, const dict args);
void mc_vm_balloon_size(Monitor *mon, const dict args);
void mc_vm_audio_mute(Monitor *mon, const dict args);
void mc_touch_unplug(Monitor *mon, const dict args);
void mc_touch_plug(Monitor *mon, const dict args);

void ic_network(Monitor *mon);
void ic_chr(Monitor *mon);
void ic_block(Monitor *mon);
void ic_blockstats(Monitor *mon);
void ic_uuid(Monitor *mon);
void ic_slirp(Monitor *mon);
void ic_ioreq(Monitor *mon);
void ic_wo(Monitor *mon);
void ic_memcache(Monitor *mon);
void ic_physinfo(Monitor *mon);

#endif  /* _MONITOR_CMDS_H_ */
