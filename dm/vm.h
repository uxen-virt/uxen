/*
 * Copyright 2012-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _VM_H_
#define _VM_H_

#include "dict.h"

extern dict vm_audio;
extern uint64_t vm_restricted_pci_emul;
extern uint64_t vm_restricted_vga_emul;
extern uint64_t vm_restricted_x86_emul;
extern uint64_t vm_viridian_crash_domain;
extern uint64_t vm_vpt_align;
extern uint64_t vm_vpt_coalesce_period;
extern critical_section vm_pause_lock;

extern uint64_t seed_generation;
extern uint64_t surf_copy_reduction;
extern bool vm_run_patcher;

extern bool vm_quit_interrupt;

void vm_create(int restore_mode);
void vm_init(const char *loadvm, int restore_mode);
void vm_start_run(void);
enum vm_run_mode {
    RUNNING_VM = 0,
    PAUSE_VM,
    SUSPEND_VM,
    POWEROFF_VM,
    DESTROY_VM,
    SETUP_VM
};
void vm_set_run_mode(enum vm_run_mode r);
enum vm_run_mode vm_get_run_mode(void);
void vm_set_vpt_coalesce(int onoff);
void vm_poweroff(void);
void vm_shutdown_sync(void);
void vm_time_update(void);
int vm_pause(void);
int vm_unpause(void);
int vm_is_paused(void);
int vm_renderclipboard(int wait);

#define VM_RESTORE_NONE 0
#define VM_RESTORE_NORMAL 1
#define VM_RESTORE_TEMPLATE 2
#define VM_RESTORE_CLONE 3
#define VM_RESTORE_VALIDATE 4

void vm_inject_nmi();

void vm_set_oem_id(const char *oem_id);
void vm_set_oem_table_id(const char *oem_table_id);
void vm_set_oem_revision(uint32_t revision);
void vm_set_oem_creator_id(const char *creator_id);
void vm_set_oem_creator_revision(uint32_t revision);
void vm_set_smbios_version_major(uint8_t major);
void vm_set_smbios_version_minor(uint8_t minor);

#endif	/* _VM_H_ */
