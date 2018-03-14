/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef QEMU_WHPX_H
#define QEMU_WHPX_H

/* whpx high level API include'able elsewhere in qemu so need to be careful to not introduce OS deps */

#if defined (_WIN32)

//#define DEBUG_IRQ
//#define DEBUG_CPU
//#define DEBUG_IOPORT
//#define DEBUG_MMIO
//#define DEBUG_EMULATE

#define WHPX_RAM_PCI 0x1

struct CPUX86State;
typedef struct CPUX86State CPUState;

#define whpx_panic(fmt, ...) errx(1, "%s:%d: "fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)

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

/* populate guest ram range with preexisting virtual memory */
int whpx_ram_populate_with(uint64_t phys_addr, uint64_t len, void *va, uint32_t flags);
/* allocate pages & populate guest ram range */
int whpx_ram_populate(uint64_t phys_addr, uint64_t len, uint32_t flags);
/* depopulate guest ram range, will also free pages if allocated by us */
int whpx_ram_depopulate(uint64_t phys_addr, uint64_t len, uint32_t flags);

/* map guest ram into uxendm process - mostly no-op since using persistent mappings */
void *whpx_ram_map(uint64_t phys_addr, uint64_t *len);
void whpx_ram_unmap(void *ptr);

void whpx_register_iorange(uint64_t start, uint64_t length, int is_mmio);
void whpx_unregister_iorange(uint64_t start, uint64_t length, int is_mmio);

/**
 * LIFECYCLE
 */

int whpx_vm_init(void);
int whpx_vm_start(void);
void whpx_destroy(void);

/**
 * MISC
 */

void whpx_lock_iothread(void);
void whpx_unlock_iothread(void);

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

#endif /* _WIN32 */

#endif /* QEMU_WHPX_H */


