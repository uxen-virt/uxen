/*
 * Copyright 2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef QEMU_CPU_H
#define QEMU_CPU_H

#define NEED_CPU_H
#define TARGET_X86_64

#define TARGET_SHORT_ALIGNMENT 2
#define TARGET_INT_ALIGNMENT 4
#define TARGET_LONG_ALIGNMENT 4
#define TARGET_LLONG_ALIGNMENT 8

struct CPUX86State;
typedef struct CPUX86State CPUState;

#include <dm/qemu/target-i386/cpu.h>

/* Flags for use in ENV->INTERRUPT_PENDING.

   The numbers assigned here are non-sequential in order to preserve
   binary compatibility with the vmstate dump.  Bit 0 (0x0001) was
   previously used for CPU_INTERRUPT_EXIT, and is cleared when loading
   the vmstate dump.  */

/* External hardware interrupt pending.  This is typically used for
   interrupts from devices.  */
#define CPU_INTERRUPT_HARD        0x0002

/* Exit the current TB.  This is typically used when some system-level device
   makes some change to the memory mapping.  E.g. the a20 line change.  */
#define CPU_INTERRUPT_EXITTB      0x0004

/* Halt the CPU.  */
#define CPU_INTERRUPT_HALT        0x0020

/* Debug event pending.  */
#define CPU_INTERRUPT_DEBUG       0x0080

#define CPU_INTERRUPT_TGT_EXT_0   0x0008
#define CPU_INTERRUPT_TGT_EXT_1   0x0010
#define CPU_INTERRUPT_TGT_EXT_2   0x0040
#define CPU_INTERRUPT_TGT_EXT_3   0x0200
#define CPU_INTERRUPT_TGT_EXT_4   0x1000

#define CPU_INTERRUPT_TGT_INT_0   0x0100
#define CPU_INTERRUPT_TGT_INT_1   0x0400
#define CPU_INTERRUPT_TGT_INT_2   0x0800
#define CPU_INTERRUPT_TGT_INT_3   0x2000

/* i386-specific interrupt pending bits.  */
#define CPU_INTERRUPT_POLL      CPU_INTERRUPT_TGT_EXT_1
#define CPU_INTERRUPT_SMI       CPU_INTERRUPT_TGT_EXT_2
#define CPU_INTERRUPT_NMI       CPU_INTERRUPT_TGT_EXT_3
#define CPU_INTERRUPT_MCE       CPU_INTERRUPT_TGT_EXT_4
#define CPU_INTERRUPT_VIRQ      CPU_INTERRUPT_TGT_INT_0
#define CPU_INTERRUPT_SIPI      CPU_INTERRUPT_TGT_INT_1
#define CPU_INTERRUPT_INIT      CPU_INTERRUPT_TGT_INT_2
#define CPU_INTERRUPT_TPR       CPU_INTERRUPT_TGT_INT_3

#define APIC_DEFAULT_ADDRESS 0xfee00000

/* various glue */
#define CPUArchState CPUX86State
#define X86CPU CPUX86State
#define X86_CPU(x) ((X86CPU*)(x))

#include <dm/whpx/cpu_glue.h>

extern CPUState *first_cpu;

#endif
