/*
 * Copyright 2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _AX_ATTOVM_H_
#define _AX_ATTOVM_H_

/* ax vm definition */
#define ATTOVM_HASH_BYTES 512
#define ATTOVM_HASHSIG_BYTES 512
#define ATTOVM_MAX_PAGERANGES 64

#define ATTOVM_MAX_VCPU_CONTEXT_SIZE_V1 2048
#define ATTOVM_MAX_VCPU 4

#if defined(_MSC_VER)
#define ATTOVM_API_PACKED
#pragma pack(push, 1)
#else
#define ATTOVM_API_PACKED __attribute__ ((packed))
#endif

enum attovm_hash_type {
  ATTOVM_HASHTYPE_NONE,
  ATTOVM_HASHTYPE_SHA256
};

enum attovm_sign_type {
  ATTOVM_SIGNTYPE_NONE
};

struct attovm_pagerange {
  uint64_t pfn;
  uint64_t count;
} ATTOVM_API_PACKED;

struct attovm_cpu_context_v1 {
  uint32_t version;
  uint32_t length;
  uint8_t data[ATTOVM_MAX_VCPU_CONTEXT_SIZE_V1];
} ATTOVM_API_PACKED;

/* parts of the ax vm definition which need to be measured
 * along the non-zero memory contents (such as the layout of said memory) */
struct attovm_definition_measured_v1 {
  uint32_t version;
  uint32_t num_vcpus;
  uint64_t num_pages; /* total number of pages (vm memory size) */
  uint64_t num_pageranges; /* number of non-zero pageranges */
  uint32_t has_vcpu_context;
  uint8_t pad[4];
  struct attovm_pagerange pagerange[ATTOVM_MAX_PAGERANGES];
  struct attovm_cpu_context_v1 vcpu[ATTOVM_MAX_VCPU];
} ATTOVM_API_PACKED;

struct attovm_definition_v1 {
  uint32_t version;
  uint8_t debug; /* doesn't measure, allows debug operations (memory read/vcpu read) on vm */
  uint8_t pad[3];
  enum attovm_hash_type hash_type;
  enum attovm_sign_type sign_type;
  uint8_t hash[ATTOVM_HASH_BYTES];
  uint8_t hashsig[ATTOVM_HASHSIG_BYTES];
  struct attovm_definition_measured_v1 m;
} ATTOVM_API_PACKED;

/* ax -> uxen assist op */
enum attovm_assist_op {
  ATTOVM_ASSIST_NONE = 0,
  ATTOVM_ASSIST_SIGNAL_DOMAIN,
  ATTOVM_ASSIST_QUERY_TSC_KHZ,
  ATTOVM_ASSIST_READ_RTC,
  ATTOVM_ASSIST_LAPIC_READ_MEM,
  ATTOVM_ASSIST_LAPIC_WRITE_MEM,
  ATTOVM_ASSIST_IOAPIC_READ_MEM,
  ATTOVM_ASSIST_IOAPIC_WRITE_MEM,
  ATTOVM_ASSIST_TSC_DEADLINE_RDMSR,
  ATTOVM_ASSIST_TSC_DEADLINE_WRMSR,
  ATTOVM_ASSIST_SUSPEND,
};

struct attovm_assist_signal_domain {
    uint64_t domain_id;
} ATTOVM_API_PACKED;

struct attovm_assist_query_tsc_khz {
    uint64_t tsc_khz;
} ATTOVM_API_PACKED;

struct attovm_assist_read_rtc {
    uint64_t reg;
    uint64_t value;
} ATTOVM_API_PACKED;

struct attovm_assist_readwrite_lapic {
    uint64_t reg;
    uint64_t value;
} ATTOVM_API_PACKED;

struct attovm_assist_readwrite_ioapic {
    uint64_t reg;
    uint64_t value;
} ATTOVM_API_PACKED;

struct attovm_assist_readwrite_tsc_deadline {
    uint64_t value;
} ATTOVM_API_PACKED;

/* ax -> uxen assist request */
struct attovm_assist {
    enum attovm_assist_op op;
    uint8_t pad[4];

    union {
        struct attovm_assist_signal_domain signal_domain;
        struct attovm_assist_query_tsc_khz query_tsc_khz;
        struct attovm_assist_read_rtc read_rtc;
        struct attovm_assist_readwrite_lapic readwrite_lapic;
        struct attovm_assist_readwrite_ioapic readwrite_ioapic;
        struct attovm_assist_readwrite_tsc_deadline readwrite_tsc_deadline;
    } x;
} ATTOVM_API_PACKED;

/* analog of vmcs for running/serving reqs from ax vms, to be exposed to uxen */
struct attovm_control {
    uint32_t revision_id;
    uint32_t pad1;

    uint64_t domain_id;
    uint32_t vcpu_id;
    uint32_t pad2;
    struct attovm_assist assist;

    uint8_t  pending_timer;
    uint8_t  pending_irq_vector;
    uint8_t  is_irq_vector_pending;
    uint8_t  pad3[5];

    /* cpu state leaked to uxen */
    uint64_t guest_rflags; /* helpful to know whether HLT was with ints disabled */
    uint64_t vm_exit_reason;
    uint64_t vm_exit_instruction_len;
    uint64_t vm_exit_intr_info;
    uint64_t vm_exit_intr_error_code;

    /* cpu state provided from uxen - saved host state before vmenter & ept pointer */
    uint64_t tsc_offset;
    uint64_t ept_pointer;
    uint64_t host_es_selector;
    uint64_t host_cs_selector;
    uint64_t host_ss_selector;
    uint64_t host_ds_selector;
    uint64_t host_fs_selector;
    uint64_t host_gs_selector;
    uint64_t host_tr_selector;
    uint64_t host_pat;
    uint64_t host_efer;
    uint64_t host_sysenter_cs;
    uint64_t host_cr0;
    uint64_t host_cr3;
    uint64_t host_cr4;
    uint64_t host_fs_base;
    uint64_t host_gs_base;
    uint64_t host_tr_base;
    uint64_t host_gdtr_base;
    uint64_t host_idtr_base;
    uint64_t host_sysenter_esp;
    uint64_t host_sysenter_eip;
    uint64_t host_rsp;
    uint64_t host_rip;
} ATTOVM_API_PACKED;

#undef ATTOVM_API_PACKED
#if defined(_MSC_VER)
#pragma pack(pop)
#endif

// Attocalls

#define ATTOCALL_VM_CREATE 0x37f1527b
// create atto vm
// RCX - domain id

#define ATTOCALL_VM_DESTROY 0x371f4b0d
// destroy atto vm
// RCX - domain id

#define ATTOCALL_VM_VCPU_INIT 0x37aee3e9
// create atto vm vcpu
// RCX - domain id
// RDX - vcpu id

#define ATTOCALL_VM_SEAL 0x37d457d7
// seal ax vm
// RCX - domain id
// RDX - virtual address of the ax_vm_definition structure
// OUTPUT:
// RAX - error code (or 0 on success)

#define ATTOCALL_VM_DEBUG_GET_GUEST_PAGES 0x37f68f1d
// RCX - domain id
// RDX - pfn
// R8  - pfn count
// R9  - target vaddr

#define ATTOCALL_VM_DEBUG_GET_GUEST_CPU_STATE 0x37b6416e
// RCX - domain id
// RDX - vcpu id
// R8  - target vaddr
// R9  - sizeof buffer @ target vaddr

#define ATTOCALL_VM_ASSIGN_TOKEN 0x371791ff
// RCX - domain id
// RDX - vaddr of token (128 bits)

#define ATTOCALL_VM_KBD_FOCUS 0x37faae18
// offer/release keyboard/mouse focus
// RCX - domain id
// RDX - offer_focus value
// OUTPUT:
// RAX - error code (or 0 on success)

#define ATTOCALL_QUERYOP 0x37bffbef
// query a parameter
// RCX - parameter
// RDX, R8, R9 - other inputs
// OUTPUT: RAX, maybe others depending on param

#define ATTOCALL_APICOP 0x37307d68
// apic operation
// RCX - operation
// RDX - arg1 (addr)
// R8  - arg2 (value)
// OUTPUT: RAX

#define ATTOCALL_V4VOP 0x3717ac0f
// v4v hypercall
// RDI - opcode
// RSI - arg1
// RDX - arg2
// r10 - arg3
// r8  - arg4
// r9  - arg5
// OUTPUT:
// RAX - status code
// RDI - domain id to wake (-1 if no domain to wake)

#define ATTOCALL_SUSPENDOP 0x3738cb10
// suspend itself
// RCX - suspend type

#define ATTOCALL_STARTUP_IPI 0x370d24a7
// startup IPI hook to setup target processor state
// RCX - apicid
// RDX - startup addr
// R8  - stack addr
// R9  - per cpu offset

#define ATTOCALL_QUERYOP_TSC_KHZ      1
#define ATTOCALL_QUERYOP_SESSION_KEY  2
#define ATTOCALL_QUERYOP_FEATURES     3

#define ATTOCALL_QUERYOP_FEATURES_PROT_KBD     (1 << 0)
#define ATTOCALL_QUERYOP_FEATURES_DEBUG_GUEST  (1 << 1)

#define ATTOCALL_APICOP_LAPIC_READ_MEM    1
#define ATTOCALL_APICOP_LAPIC_WRITE_MEM   2
#define ATTOCALL_APICOP_IOAPIC_READ_MEM   3
#define ATTOCALL_APICOP_IOAPIC_WRITE_MEM  4

#define EXIT_REASON_PV_AX_ASSIST 0xff

#endif
