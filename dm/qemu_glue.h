
#ifndef _QEMU_GLUE_H_
#define _QEMU_GLUE_H_

#include "config.h"
#include "opts.h"

#define QEMU_VERSION "uXen"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include "tmp_glue.h"

#include "bitops.h"
#undef test_bit
#define test_bit qemu_test_bit
static inline int test_bit(uint8_t *map, int bit)
{
    return ( map[bit / 8] & (1 << (bit % 8)) );
}

#undef set_bit
#define set_bit qemu_set_bit
static inline void set_bit(uint8_t *map, int bit)
{
    map[bit / 8] |= (1 << (bit % 8));
}

#undef clear_bit
#define clear_bit qemu_clear_bit
static inline void clear_bit(uint8_t *map, int bit)
{
    map[bit / 8] &= ~(1 << (bit % 8));
}

#include "xen.h"
#define xen_enabled() 1

typedef uint64_t ram_addr_t;
typedef uint32_t pio_addr_t;

#include "mr.h"

#include "iomem.h"
typedef struct iomem_region MemoryRegionMmio;
typedef IOMemWriteFunc CPUWriteMemoryFunc;
typedef IOMemReadFunc CPUReadMemoryFunc;

#define cpu_register_io_memory(index, mem_read, mem_write, opaque)	\
    register_iomem(index, mem_read, mem_write, opaque)
#define cpu_unregister_io_memory(index)		\
    unregister_iomem(index)
#define cpu_get_io_memory_write(index)		\
    get_iomem_write(index)
#define cpu_get_io_memory_read(index)		\
    get_iomem_read(index)

#define cpu_register_physical_memory(addr, size, index) \
    register_mmio(addr, size, index)
#define iomem_index(addr)			\
    mmio_index(addr)

#include "ioport.h"
typedef struct ioport_region MemoryRegionPortio;
#define PORTIO_END_OF_LIST() { }
typedef struct ioport_region_list PortioList;
#define portio_list_init(list, ports, opaque, name)	\
    ioport_region_list_init(list, ports, opaque, name)
#define portio_list_add(list, space, offset)	\
    ioport_region_list_map(list, space, offset)
#define portio_list_del(list)

#include "memory.h"
#define cpu_physical_memory_rw vm_memory_rw
#define cpu_physical_memory_read(addr, buf, len) vm_memory_rw(addr, buf, len, 0)
#define cpu_physical_memory_write(addr, buf, len) vm_memory_rw(addr, buf, len, 1)
#define cpu_register_map_client(opaque, callback)	\
    (({ (void)&(callback); NULL; }))
#define cpu_unregister_map_client(client) do { ; } while(0)

#include "dm.h"
#define domid vm_id

#include "vm.h"
#define vm_stop(reason) do { ; } while (0)

#include "aio.h"
#define qemu_aio_flush aio_flush
#define qemu_aio_get aio_get
#define qemu_aio_release aio_release

#include "mapcache.h"

#define cpu_handle_ioreq handle_ioreq

#include "vm-save.h"
#define xen_pause_requested save_requested

#define qemu_register_coalesced_mmio(addr, size) do { ; } while(0)
#define qemu_unregister_coalesced_mmio(addr, size) do { ; } while(0)
#define qemu_flush_coalesced_mmio_buffer() do { ; } while(0)

typedef uint64_t target_phys_addr_t;
#define TARGET_PHYS_ADDR_MAX UINT64_MAX
#define TARGET_PAGE_BITS UXEN_PAGE_SHIFT
#define TARGET_PAGE_MASK UXEN_PAGE_MASK
#define TARGET_PAGE_SIZE UXEN_PAGE_SIZE
#define TARGET_FMT_plx "%" PRIx64

#include "dma.h"

#include "sg.h"
typedef SGList QEMUSGList;
#define qemu_sglist_init sglist_init
#define qemu_sglist_add sglist_add
#define qemu_sglist_add_completion sglist_add_completion
#define qemu_sglist_destroy sglist_destroy

#include "iovec.h"
typedef IOVector QEMUIOVector;
#define qemu_iovec_init iovec_init
#define qemu_iovec_init_external iovec_init_external
#define qemu_iovec_add(qiov, ptr, len) iovec_add(qiov, ptr, len, 0)
#define qemu_iovec_destroy iovec_destroy
#define qemu_iovec_reset iovec_reset
#define qemu_iovec_to_buffer iovec_to_buffer
#define qemu_iovec_from_buffer iovec_from_buffer

#include "irq.h"

#include "qemu_bswap.h"

#include "compiler.h"
#define QEMU_PACKED PACKED

#define win2k_install_hack 0

#include "clock.h"
#define qemu_get_clock get_clock
#define qemu_get_clock_ms(clock) (get_clock_ns(clock) / SCALE_MS)
#define qemu_get_clock_ns get_clock_ns

#include "timer.h"
#define QEMUTimer Timer
#define QEMUTimerCB TimerCB
#define qemu_mod_timer mod_timer
#define qemu_new_timer new_timer
#define qemu_new_timer_ms new_timer_ms
#define qemu_new_timer_ns new_timer_ns
#define qemu_del_timer del_timer

#include <err.h>
#define error_report(...) warnx(__VA_ARGS__)
#define qerror_report(fmt, ...) warnx("%s", #fmt)

/* qemu_glue.c */
void pstrcpy(char *buf, int buf_size, const char *str);
char *pstrcat(char *buf, int buf_size, const char *s);
void QEMU_NORETURN hw_error(const char *fmt, ...)
    __attribute__ ((__format__ (__printf__, 1, 2)));

#define qemu_memalign align_alloc
#define qemu_memfree align_free
#define qemu_vfree align_free

#include "block.h"
#define qemu_blockalign bdrv_blockalign

#define g_malloc(size) malloc(size)
#define g_malloc0(size) calloc(1, size)
#define g_realloc(addr, size) realloc(addr, size)
#define g_free(addr) free(addr)
#define g_strdup(str) strdup(str)
#define g_new(type, nr) calloc(nr, sizeof(type))

#include "qemu_queue.h"

#include "dev.h"
#define qdev_create dev_create
#define qdev_free dev_free
#define qdev_try_create dev_try_create
#define qdev_init dev_init
#define qdev_init_nofail dev_init_nofail
#define qdev_register dev_register
#define qdev_get_parent_bus dev_get_parent_bus
#define qdev_unplug dev_unplug
#define qbus_create_inplace bus_create_inplace
#define qbus_create bus_create
#define qdev_reset_all dev_reset_all
#define qbus_free bus_free

#define FROM_QBUS(type, dev) DO_UPCAST(type, qbus, dev)

#include "qemu_qdev-prop.h"

#define msi_enabled(x) ({ (void)(x); 0; })
#define msi_notify(x, y) ({ (void)(x); debug_break(); })

#include "file.h"

#include "console.h"

#define default_mon cur_mon

#define cpu_synchronize_all_states() do { ; } while(0)
#define cpu_synchronize_all_post_init() do { ; } while(0)

#ifndef ENOTSUP
#define ENOTSUP EINVAL
#endif

#define qemu_isdigit(c)		isdigit((unsigned char)(c))
#define qemu_isxdigit(c)	isxdigit((unsigned char)(c))

#define qemu_isspace(c)         isspace((unsigned char)(c))

#if defined(__APPLE__)
int qemu_socket(int domain, int type, int protocol);
#else
#define qemu_socket socket
#endif
#ifdef _WIN32
#define qemu_recv(sockfd, buf, len, flags) recv(sockfd, (void *)buf, len, flags)
#else
#define qemu_recv(sockfd, buf, len, flags) recv(sockfd, buf, len, flags)
#endif

int qemu_chr_write(CharDriverState *s, const uint8_t *buf, int len);
#define qemu_chr_fe_write qemu_chr_write

#define qemu_toupper(c) toupper((unsigned char)(c))

#define qemu_system_shutdown_request vm_set_run_mode
#define qemu_system_reset_request vm_set_run_mode
#define qemu_system_powerdown_request vm_set_run_mode

#include "input.h"

#define qemu_register_reset(fn, opaque) fn(opaque)
#define qemu_system_reset() do { } while (0)

#define QEMUSerialSetParams SerialSetParams

#define qemu_console_resize(ds, width, height) console_resize(ds, width, height)

#define hw_error(...) errx(1, ## __VA_ARGS__)

#include "bh.h"
#define QEMUBH BH
#define qemu_bh_delete bh_delete
#define qemu_bh_new bh_new
#define qemu_bh_schedule bh_schedule

#endif	/* _QEMU_GLUE_H_ */
