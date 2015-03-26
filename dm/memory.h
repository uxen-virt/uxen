/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _MEMORY_H_
#define _MEMORY_H_

void vm_memory_rw(uint64_t addr, uint8_t *buf, int len, int is_write);
void vm_memory_rw_direct(uint64_t addr, uint8_t *buf, int len, int is_write);

uint64_t vm_memory_read(uint64_t addr, uint32_t size);
void vm_memory_write(uint64_t addr, uint64_t val, uint32_t size);

void *vm_memory_map(uint64_t phys_addr, uint64_t *len, int is_write, int lock);
void vm_memory_unmap(uint64_t phys_addr, uint64_t len, int is_write, int lock,
		     void *map_addr, uint64_t access_len);

#define VM_MEMORY_MAP_PROT_READ 1
#define VM_MEMORY_MAP_PROT_WRITE 2

uint8_t *vm_memory_map_perm(uint64_t guest_addr, uint32_t len, int prot);

#endif	/* _MEMORY_H_ */
