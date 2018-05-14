/*
 * Copyright 2012-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <stdint.h>

#include "dm.h"
#include "iomem.h"
#include "mapcache.h"
#include "memory.h"
#include <dm/whpx/whpx.h>

#include <xenctrl.h>

/*
 * Replace the standard byte memcpy with a word memcpy for appropriately sized
 * memory copy operations.  Some users (USB-UHCI) can not tolerate the possible
 * word tearing that can result from a guest concurrently writing a memory
 * structure while the qemu device model is modifying the same location.
 * Forcing a word-sized read/write prevents the guest from seeing a partially
 * written word-sized atom.
 */
static inline void
memcpy_words(void *dst, void *src, size_t n)
{
    asm volatile (
        "   movl %%edx,%%ecx \n"
#ifdef __x86_64__
        "   shrl $3,%%ecx    \n"
        "   rep  movsq       \n"
        "   test $4,%%edx    \n"
        "   jz   1f          \n"
        "   movsl            \n"
#else /* __i386__ */
        "   shrl $2,%%ecx    \n"
        "   rep  movsl       \n"
#endif
        "1: test $2,%%edx    \n"
        "   jz   1f          \n"
        "   movsw            \n"
        "1: test $1,%%edx    \n"
        "   jz   1f          \n"
        "   movsb            \n"
        "1:                  \n"
        : "+S" (src), "+D" (dst) : "d" (n) : "ecx", "memory" );
}

static void warn_mmio_access(uint64_t addr, int len, int is_write)
{
    if (whpx_enable)
        debug_printf("UNHANDLED MMIO %s @ %"PRIx64"/%d\n",
            is_write ? "write" : "read", addr, len);
}
void vm_memory_rw(uint64_t addr, uint8_t *buf, 
		  int len, int is_write)
{
    int ret;
    uint8_t *ptr;
    uint32_t val;
    uint64_t l, map_len;

    mapcache_lock();

    while (len > 0) {
        l = UXEN_PAGE_SIZE - (addr & ~UXEN_PAGE_MASK); 
        if (l > len)
            l = len;

        if (is_write) {
	    if (l >= 4 && ((addr & 3) == 0)) {
		/* 32 bit write access */
		ret = mmio_write(addr, *(uint32_t *)buf, 2);
		l = 4;
	    } else if (l >= 2 && ((addr & 1) == 0)) {
		/* 16 bit write access */
		ret = mmio_write(addr, *(uint16_t *)buf, 1);
		l = 2;
	    } else {
		/* 8 bit write access */
		ret = mmio_write(addr, *(uint8_t *)buf, 0);
		l = 1;
	    }
	    if (ret == -1) {
		map_len = l;
		ptr = mapcache_map(addr, &map_len, 0);
		if (ptr) {
		    l = map_len;
		    /* Writing to RAM */
		    memcpy_words(ptr, buf, l);
		    mapcache_unmap(addr, map_len, 0);

		    if (xen_logdirty_enabled)
			xc_hvm_modified_memory(xc_handle, vm_id,
					       addr >> UXEN_PAGE_SHIFT, 1);
		} else
                    warn_mmio_access(addr, len, is_write);
	    }
        } else {
	    if (l >= 4 && ((addr & 3) == 0)) {
		/* 32 bit read access */
		ret = mmio_read(addr, 2, &val);
		if (ret == 0)
		    *(uint32_t *)buf = val;
		l = 4;
	    } else if (l >= 2 && ((addr & 1) == 0)) {
		/* 16 bit read access */
		ret = mmio_read(addr, 1, &val);
		if (ret == 0)
		    *(uint16_t *)buf = val;
		l = 2;
	    } else {
		/* 8 bit access */
		ret = mmio_read(addr, 0, &val);
		if (ret == 0)
		    *(uint8_t *)buf = val;
		l = 1;
	    }
	    if (ret == -1) {
		map_len = l;
		ptr = mapcache_map(addr, &map_len, 0);
		if (ptr) {
		    l = map_len;
		    /* Reading from RAM */
		    memcpy_words(buf, ptr, l);
		    mapcache_unmap(addr, map_len, 0);
		} else {
		    /* Neither RAM nor known MMIO space */
		    memset(buf, 0xff, l); 
                    warn_mmio_access(addr, len, is_write);
		}
	    }
        }
        len -= l;
        buf += l;
        addr += l;
    }

    mapcache_unlock();
}

void vm_memory_rw_direct(uint64_t addr, uint8_t *buf, 
			 int len, int is_write)
{
    uint8_t *ptr;
    uint64_t l, map_len;

    mapcache_lock();

    while (len > 0) {
        l = UXEN_PAGE_SIZE - (addr & ~UXEN_PAGE_MASK); 
        if (l > len)
            l = len;

        if (is_write) {
	    map_len = l;
	    ptr = mapcache_map(addr, &map_len, 0);
	    if (ptr) {
		l = map_len;
		/* Writing to RAM */
		memcpy_words(ptr, buf, l);
		mapcache_unmap(addr, map_len, 0);

		if (xen_logdirty_enabled)
		    xc_hvm_modified_memory(xc_handle, vm_id,
					   addr >> UXEN_PAGE_SHIFT, 1);
	    }
        } else {
	    map_len = l;
	    ptr = mapcache_map(addr, &map_len, 0);
	    if (ptr) {
		l = map_len;
		/* Reading from RAM */
		memcpy_words(buf, ptr, l);
		mapcache_unmap(addr, map_len, 0);
	    } else {
		/* Neither RAM nor known MMIO space */
		memset(buf, 0xff, l); 
	    }
        }
        len -= l;
        buf += l;
        addr += l;
    }

    mapcache_unlock();
}

uint64_t
vm_memory_read(uint64_t addr, uint32_t len)
{
    uint64_t val = 0;

    vm_memory_rw(addr, (uint8_t *)&val, len, 0);
    return val;
}

void
vm_memory_write(uint64_t addr, uint64_t val, uint32_t len)
{

    vm_memory_rw(addr, (uint8_t *)&val, len, 1);
}

void *
vm_memory_map(uint64_t phys_addr, uint64_t *len, int is_write, int lock)
{

    /* XXX xc_hvm_modified_memory */
    return mapcache_map(phys_addr, len, lock);
}

void
vm_memory_unmap(uint64_t phys_addr, uint64_t len, int is_write, int lock,
		void *map_addr, uint64_t access_len)
{

    mapcache_unmap(phys_addr, len, lock);
}

uint8_t *
vm_memory_map_perm(uint64_t guest_addr, uint32_t len, int prot)
{
    uint8_t *va;

    switch (prot) {
    case VM_MEMORY_MAP_PROT_READ:
	prot = PROT_READ;
	break;
    case VM_MEMORY_MAP_PROT_WRITE:
	prot = PROT_WRITE;
	break;
    default:
	warn("vm_memory_map_perm invalid prot %d", prot);
	return NULL;
    }

    if (!whpx_enable) {
        va = xc_map_foreign_range(xc_handle, vm_id,
            (len + UXEN_PAGE_SIZE - 1) & UXEN_PAGE_MASK,
            prot, guest_addr >> UXEN_PAGE_SHIFT);
        if (va == NULL)
            return NULL;

        return va + (guest_addr & ~UXEN_PAGE_MASK);
    } else {
        uint64_t len_ = len;

        va = whpx_ram_map(guest_addr, &len_);
        assert(!va || len_ == len);

        return va;
    }

}
