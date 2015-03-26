/*
 * Copyright 2012-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _TMP_GLUE_H_
#define _TMP_GLUE_H_

#include <stdio.h>

#include "char.h"
#include "file.h"
#include "opts.h"
#include "queue.h"
#include "xen.h"

extern FILE *logfile;

extern int slirp_is_inited(void);
void slirp_check_timeout(void);

#include "net.h"

PCIDevice *pci_nic_init_nofail(NICInfo *nd, const char *default_model,
                               const char *default_devaddr);

void dma_helper_init(void);

void xen_init_fv(uint64_t ram_size, int vga_ram_size,
                 const char *boot_device,
                 const char *kernel_filename,const char *kernel_cmdline,
                 const char *initrd_filename, const char *cpu_model,
                 const char *direct_pci, const char *loadvm,
                 int cloneid);

void vm_start(void);

int main_loop(void);

void do_uxenvm_process_suspend(void);
void do_uxenvm_save_execute(void);

void destroy_hvm_domain(void);

void handle_ioreq(void *opaque);

void pc_init_pci(uint64_t ram_size, int vga_ram_size,
		 const char *boot_device, const char *kernel_filename,
		 const char *kernel_cmdline, const char *initrd_filename,
		 const char *cpu_model, const char *direct_pci);

extern int restore;

#endif	/* _TMP_GLUE_H_ */
