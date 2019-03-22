/*
 * Copyright 2018-2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef QEMU_WHPX_H
#define QEMU_WHPX_H

/* whpx high level API include'able elsewhere in qemu so need to be careful to not introduce OS deps */

#if defined (_WIN32)

#include <dm/irq.h>

//#define DEBUG_IRQ
//#define DEBUG_CPU
//#define DEBUG_IOPORT
//#define DEBUG_MMIO
//#define DEBUG_EMULATE

#define WHPX_DOMAIN_ID_SELF 1

#define WHPX_MAX_VCPUS 8

#define WHPX_RAM_PCI              0x00001
#define WHPX_RAM_EXTERNAL         0x00002
#define WHPX_RAM_NO_DECOMMIT      0x10000
#define WHPX_RAM_FLAGS_SAVE_MASK  0x0FFFF

struct CPUX86State;
typedef struct CPUX86State CPUState;

#define whpx_panic(fmt, ...)                                           \
  {                                                                    \
    debug_printf("%s:%d: "fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    assert(0);                                                         \
  }

/**
 * PCI / IRQ
 */

int whpx_register_pcidev(PCIDevice*);
qemu_irq *whpx_interrupt_controller_init(void);
void whpx_piix3_set_irq(void *opaque, int irq_num, int level);
void whpx_piix_pci_write_config_client(uint32_t address, uint32_t val, int len);

/**
 * MEMORY
 */

int whpx_ram_init(void);
void whpx_ram_uninit(void);

/* populate guest ram range with preexisting virtual memory */
int whpx_ram_populate_with(uint64_t phys_addr, uint64_t len, void *va, uint32_t flags);
/* allocate pages & populate guest ram range */
int whpx_ram_populate(uint64_t phys_addr, uint64_t len, uint32_t flags);
/* depopulate guest ram range, will also free pages if allocated by us */
int whpx_ram_depopulate(uint64_t phys_addr, uint64_t len, uint32_t flags);

/* map guest ram into uxendm process - mostly no-op since using persistent mappings */
void *whpx_ram_map(uint64_t phys_addr, uint64_t *len);
void whpx_ram_unmap(void *ptr);

void whpx_copy_from_guest_va(CPUState *cpu, void *dst, uint64_t src_va, uint64_t len);
void whpx_copy_to_guest_va(CPUState *cpu, uint64_t dst_va, void *src, uint64_t len);

void whpx_register_iorange(uint64_t start, uint64_t length, int is_mmio);
void whpx_unregister_iorange(uint64_t start, uint64_t length, int is_mmio);

struct filebuf;
int whpx_memory_balloon_grow(unsigned long nr_pfns, uint64_t *pfns);
int whpx_clone_memory(char *template_file);
int whpx_read_memory(struct filebuf *f, int layout_only);
int whpx_write_memory(struct filebuf *f);

/**
 * LIFECYCLE
 */

/* shutdown reason values match uxen */
#define WHPX_SHUTDOWN_POWEROFF 0
#define WHPX_SHUTDOWN_REBOOT 1
#define WHPX_SHUTDOWN_SUSPEND 2
#define WHPX_SHUTDOWN_CRASH 3
#define WHPX_SHUTDOWN_PAUSE 100

int whpx_early_init(void);

int whpx_vm_init(int restore_mode);
int whpx_vm_start(void);
int whpx_vm_resume(void);
int whpx_vm_shutdown(int reason);
int whpx_vm_shutdown_wait(void);
int whpx_vm_get_context(void *buffer, size_t buffer_sz);
int whpx_vm_set_context(void *buffer, size_t buffer_sz);

int whpx_vm_is_paused(void);
int whpx_vm_pause(void);
int whpx_vm_unpause(void);
void whpx_destroy(void);

/**
 * MISC
 */

CPUState *whpx_get_cpu(int cpu);
CPUState *whpx_get_current_cpu(void);
void whpx_lock_iothread(void);
void whpx_unlock_iothread(void);
void whpx_debug_char(char data);
int whpx_inject_trap(int cpu, int trap, int error_code, int cr2);
void whpx_set_dm_features(uint64_t features);
void whpx_set_random_seed(uint64_t lo, uint64_t hi);

/* memory capture definitions match uxen's */
#define WHPX_MCGI_FLAGS_VM         0x0000
#define WHPX_MCGI_FLAGS_TEMPLATE   0x0001
#define WHPX_MCGI_FLAGS_REMOVE_PFN 0x0010

#define WHPX_MCGI_TYPE_NOT_PRESENT 0x0000
#define WHPX_MCGI_TYPE_NORMAL      0x0001
#define WHPX_MCGI_TYPE_ZERO        0x0003

typedef struct whpx_memory_capture_gpfn_info {
    union {
        struct {                /* in */
            uint32_t gpfn;
            uint32_t flags;
        };
        struct {                /* out */
            uint32_t type;
            uint32_t offset;
        };
    };
} whpx_memory_capture_gpfn_info_t;

int whpx_memory_capture(unsigned long nr_pfns, whpx_memory_capture_gpfn_info_t *pfns,
    unsigned long *nr_done, void *buffer, uint32_t buffer_size);
int whpx_memory_populate_from_buffer(unsigned long nr_pfns, uint64_t *pfns, void *buffer);

#else /* _WIN32 */

#define WHPX_UNSUPPORTED errx(1, "whpx unsupported on this platform\n");

static inline int whpx_vm_init(void) { WHPX_UNSUPPORTED; return -1; }
static inline int whpx_vm_start(void) { WHPX_UNSUPPORTED; return -1; }
static inline void whpx_destroy(void) { WHPX_UNSUPPORTED; }
static inline void whpx_lock_iothread(void) { WHPX_UNSUPPORTED; }
static inline void whpx_unlock_iothread(void) { WHPX_UNSUPPORTED; }
static inline void whpx_register_iorange(uint64_t start, uint64_t length, int is_mmio) { WHPX_UNSUPPORTED; }
static inline void whpx_unregister_iorange(uint64_t start, uint64_t length, int is_mmio) { WHPX_UNSUPPORTED; }
static inline void *whpx_ram_map(uint64_t phys_addr, uint64_t *len) { WHPX_UNSUPPORTED; return 0; }
static inline void whpx_ram_unmap(void *ptr) { WHPX_UNSUPPORTED; }
static inline int whpx_ram_populate_with(uint64_t phys_addr, uint64_t len, void *va) { WHPX_UNSUPPORTED; return -1; }
static inline int whpx_ram_populate(uint64_t phys_addr, uint64_t len) { WHPX_UNSUPPORTED; return -1; }
static inline int whpx_ram_depopulate(uint64_t phys_addr, uint64_t len) { WHPX_UNSUPPORTED; return -1; }
static inline int whpx_clone_memory(char *template_file) { WHPX_UNSUPPORTED; return -1; }
static inline int whpx_read_memory(struct filebuf *f, int layout_only) { WHPX_UNSUPPORTED; return -1; }
static inline int whpx_write_memory(struct filebuf *f) { WHPX_UNSUPPORTED; return -1; }

#endif /* _WIN32 */

#endif /* QEMU_WHPX_H */


