/*
 * Copyright 2013-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "config.h"
#include <err.h>
#include <stdint.h>
#include "dm.h"
#include "xen.h"
#include <xenctrl.h>
#include "dmpdev.h"
#include "dm/clock.h"

#include "introspection_info.h"
#include "memory-virt.h"

#ifdef __x86_64__
#define guest_word_t uint64_t
#else
#define guest_word_t uint32_t
#endif

#define USHORT uint16_t
#define ULONG  guest_word_t
#define PVOID  guest_word_t

typedef struct _LIST_ENTRY_U {
      guest_word_t Flink;
      guest_word_t Blink;
} LIST_ENTRY_U, *PLIST_ENTRY_U;

typedef struct _LSA_UNICODE_STRING {
      USHORT Length;
      USHORT MaximumLength;
      guest_word_t  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef struct _LDR_MODULE {

      LIST_ENTRY_U              InLoadOrderModuleList;
      LIST_ENTRY_U              InMemoryOrderModuleList;
      LIST_ENTRY_U              InInitializationOrderModuleList;
      PVOID                   BaseAddress;
      PVOID                   EntryPoint;
      ULONG                   SizeOfImage;
      UNICODE_STRING          FullDllName;
      UNICODE_STRING          BaseDllName;
      ULONG                   Flags;
      USHORT                  LoadCount;
      USHORT                  TlsIndex;
      LIST_ENTRY_U            HashTableEntry;
      ULONG                   TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

static int is_kernel_address(uint64_t addr)
{
#ifdef __x86_64__
    return (addr>>48) == 0xffff;
#else
    return addr>0x80000000;
#endif
}

#define WORKING_XC_PAGE_MASK (~0xfffULL)

/* do we need full wide2utf8 implementation here ? */
static void naive_unicode_to_ascii(unsigned char *s)
{
    unsigned short *w = (unsigned short *)s;
    int i;
    for (i = 0; w[i]; i++)
        s[i] = w[i] & 0x7f;
    s[i] = 0;
}
static int get_unicode_string(UNICODE_STRING * s, unsigned char * buf, int size)
{
    unsigned int cpsize = size - 2;
    buf[0] = 0;
    if (size < 2)
        return -1;
    if (!is_kernel_address(s->Buffer))
        return -1;
    if (cpsize > s->Length)
        cpsize = s->Length;
    cpsize &= -2; /* make sure it is even */
    if (virt_read(s->Buffer, buf, cpsize))
        return -1;
    buf[cpsize] = 0;
    buf[cpsize + 1] = 0;
    naive_unicode_to_ascii(buf);
    return 0;
}

/* If we had C++, we would not need these ugly fixed arrays */
struct Section {
    char name[9];
    unsigned char writable, discardable;
    uint64_t base;
    uint64_t size;
};
#define MAX_SECTIONS 64
struct DriverInfo {
    uint64_t base;
    char name[256];
    int nsections;
    struct Section sections[MAX_SECTIONS];
};
static int ndrivers;

/* The array of guest kernel drivers information */
static struct DriverInfo drivers[256];

/* Some drivers are broken, sections are not page aligned. Trim overlapping
pages from the section range. */
static void driver_trim_edge_rw_pages(struct DriverInfo * driver)
{
    int i, j;
    for (i = 0; i < driver->nsections; i++) {
        if (driver->sections[i].writable || 
            driver->sections[i].discardable || driver->sections[i].size == 0)
            continue;
        for (j = 0; j < driver->nsections; j++) {
            if (!driver->sections[j].writable || driver->sections[j].size == 0)
                continue;
            if (driver->sections[i].base + driver->sections[i].size - XC_PAGE_SIZE == driver->sections[j].base) {
                warnx("driver %s, end of section %s overlaps with section %s",
                    driver->name, driver->sections[i].name, driver->sections[j].name);
                driver->sections[i].size -= XC_PAGE_SIZE;
                if (!driver->sections[i].size)
                    break;
            }
            if (driver->sections[i].base == driver->sections[j].base + driver->sections[j].size - XC_PAGE_SIZE) {
                warnx("driver %s, start of section %s overlaps with section %s",
                    driver->name, driver->sections[i].name, driver->sections[j].name);
                driver->sections[i].size -= XC_PAGE_SIZE;
                if (!driver->sections[i].size)
                    break;
                driver->sections[i].base += XC_PAGE_SIZE;
            }
        }
    }
}

static int get_single_driver_info(uint64_t base, unsigned char * name)
{
    struct DriverInfo * driver;
    int i;
    uint64_t image_offset;
    IMAGE_DOS_HEADER imageDosHeader;
    IMAGE_FILE_HEADER imageFileHeader;
//    IMAGE_OPTIONAL_HEADER imageOptionalHeader;
    IMAGE_SECTION_HEADER imageSectionHeader[MAX_SECTIONS];
    int nsections;
    if (ndrivers == ARRAY_SIZE(drivers))
        return -1;
    if (virt_read_type(base, imageDosHeader))
        return -1;
    if (imageDosHeader.e_magic != *(unsigned short*)"MZ")
        return -1;
    image_offset = imageDosHeader.e_lfanew + sizeof(IMAGE_NT_SIGNATURE);
    if (virt_read_type(base + image_offset, imageFileHeader))
        return -1;
#ifdef __x86_64__
    if (imageFileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
#else
    if (imageFileHeader.Machine != IMAGE_FILE_MACHINE_I386)
#endif
        return -1;
    image_offset += sizeof(IMAGE_FILE_HEADER) + imageFileHeader.SizeOfOptionalHeader;
    if (imageFileHeader.NumberOfSections > MAX_SECTIONS)
        nsections = MAX_SECTIONS;
    else
        nsections = imageFileHeader.NumberOfSections;
    if (virt_read(base + image_offset, imageSectionHeader, 
        sizeof(IMAGE_SECTION_HEADER) * nsections))
        return -1;
    driver = drivers + ndrivers;
    ndrivers++;
    driver->base = base;
    driver->nsections = nsections;
    strncat(driver->name, (char*)name, sizeof(driver->name));
    for (i = 0; i < nsections; i++) {
        uint64_t page_end;
        IMAGE_SECTION_HEADER * h = imageSectionHeader + i;
        struct Section * s = driver->sections + i;
        memcpy(s->name, h->Name, 8);
        s->name[8] = 0;
//        warnx("    found section %s, virt 0x%x, size 0x%x", 
//            s->name, (unsigned int)h->VirtualAddress, (unsigned int)h->SizeOfRawData);
        s->writable = (h->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        s->discardable = (h->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0;
        /* Page-align section base and size */
        page_end = base + h->VirtualAddress + h->SizeOfRawData;
        page_end = (page_end + 0xfff)&WORKING_XC_PAGE_MASK;
        s->base = (base + h->VirtualAddress)&WORKING_XC_PAGE_MASK;
        if (h->SizeOfRawData)
            s->size = page_end - s->base;
        else
            s->size = 0;
        /* Something (patchguard perhaps) modifies NT headers of a module */
        if (s->size && s->base == base) {
            s->base += XC_PAGE_SIZE;
            s->size -= XC_PAGE_SIZE;
        }
    }
    driver_trim_edge_rw_pages(driver);
    return 0;
}

#define SANE_MAX_DRIVERS 300
static int get_drivers_info(guest_word_t head)
{
    LDR_MODULE currmodule;
    guest_word_t curr_addr;
    int module_count = 0;
    unsigned char name[256];

    if (virt_read_type(head, curr_addr))
        return -1;
    while (curr_addr != head && module_count < SANE_MAX_DRIVERS) {
        if (virt_read_type(curr_addr, currmodule))
            return -1;
        module_count++;
        get_unicode_string(&currmodule.BaseDllName, name, sizeof(name));
        warnx("getting sections for %s", name);
        get_single_driver_info(currmodule.BaseAddress, name);
        curr_addr = currmodule.InLoadOrderModuleList.Flink;
    } 
    if (curr_addr != head) {
        warnx("get_drivers_info: more than 300 drivers found?");
        return -1;
    }
    return 0;
}

/* I need std::vector and I can only cry */
unsigned int pages_current_size;
unsigned int pages_buffer_size;
uint64_t *immutable_pages; 

static int compare_uint64(const void *a, const void *b)
{
    uint64_t x = *(uint64_t*)a, y = *(uint64_t*)b;
    /* returning x-y is not the best idea due to type size difference */
    if (x < y)
        return -1;
    else if (x == y)
        return 0;
    else
        return 1;
}

static int
convert_list_to_ranges(uint64_t *list, int nitems,
                       struct immutable_range *ranges)
{
    uint64_t base = list[0];
    int size = 1;
    int i;
    int nranges = 0;

    for (i = 1; i < nitems; i++) {
        if (list[i] == base + size - 1)
            continue; /* duplicate item */
        if (list[i] == base + size)
            size++;
        else {
            ranges[nranges].base = base;
            ranges[nranges].size = size;
            nranges++;
            base = list[i];
            size = 1;
        }
    }
    ranges[nranges].base = base;
    ranges[nranges].size = size;
    nranges++;
    return nranges;
}

static void dump_ranges(char *prefix, struct immutable_range *ranges,
                        int count)
{
    int i;
    for (i = 0; i < count; i++)
        warnx("%s range base %016"PRIx64" size %016"PRIx64,
            prefix, ranges[i].base, ranges[i].size);
}

#define SANE_MAX_SECTION_SIZE (40*1024*1024)
static void get_immutable_pages_section(char * driver, struct Section * s)
{
    struct immutable_range *tmprange;
    int nranges;
    uint64_t *pfnbuf;
    int size_needed;

    if (s->writable || s->discardable || s->size == 0 || s->size > SANE_MAX_SECTION_SIZE)
        return;
    /* KeGetBugMessageText calls MmMakeKernelResourceSectionWritable
           and writes there */
    if (!strcmp(driver, "ntoskrnl.exe") && !strcmp(s->name, ".rsrc"))
        return;
    /* peauth.sys calls MmMapLockedPagesSpecifyCache, and writes to its
           PAGE section */
    /* on win10, it is in PAGEwx1. Blacklist all PAGE* */
    if (!strcmp(driver, "peauth.sys") && !strncmp(s->name, "PAGE", 4))
        return;
    /* clipsp.sys writes over frames assigned for its ro sections 
           (PAGEwx4 etc) */ 
    if (!strcmp(driver, "clipsp.sys"))
        return;
#ifdef I_HAVE_PLENTY_OF_TIME_TO_REPRODUCE_AND_DEBUG_SPSYS_WEIRDNESS
    /* spsys.sys also messes with its own PAGE section */
    if (!strcmp(driver, "spsys.sys") && !strcmp(s->name, "PAGE"))
        return;
#else
    /* Almost every page of spsys.sys is sometimes written to - but why.
    A bold theory is that it gets unloaded and its pages recycled. Not
    able to reproduce now.*/
    if (!strcmp(driver, "spsys.sys"))
        return;
#endif
    /* The following 4 modules get unloaded in win 8.1 clones */
    if (!strcmp(driver, "monitor.sys"))
        return;
    if (!strcmp(driver, "dump_storport.sys"))
        return;
    if (!strcmp(driver, "dump_storahci.sys"))
        return;
    if (!strcmp(driver, "dump_dumpfve.sys"))
        return;

    warnx("    section %s base=%016"PRIx64" size=%016"PRIx64,
        s->name, s->base, s->size);
    size_needed = s->size / XC_PAGE_SIZE * sizeof(uint64_t) + pages_current_size;
    if (size_needed > pages_buffer_size) {
        int new_size = 2 * pages_buffer_size;
        if (new_size < size_needed)
            new_size = size_needed;
        immutable_pages = realloc(immutable_pages, new_size);
        pages_buffer_size = new_size;
    }

    pfnbuf = immutable_pages + pages_current_size / sizeof(uint64_t);
    xc_translate_foreign_address_range(xc_handle, vm_id, 0, s->base,
                                       s->size / XC_PAGE_SIZE, pfnbuf);
    qsort((void*)pfnbuf, s->size / XC_PAGE_SIZE, sizeof(uint64_t), compare_uint64);
    tmprange = alloca(s->size / XC_PAGE_SIZE * sizeof(struct immutable_range));
    nranges = convert_list_to_ranges(pfnbuf, s->size / XC_PAGE_SIZE, tmprange);
    dump_ranges("    phys", tmprange, nranges);

    pages_current_size = size_needed;
}


static struct guest_introspect_info_t guest_introspect_info;

static void get_immutable_ranges()
{
    struct immutable_range *ranges;
    int i, j;
    unsigned int npages;
    immutable_pages = malloc(0);
    for (i = 0; i < ndrivers; i++) {
        warnx("immutable ranges for driver %s:", drivers[i].name);
        for (j = 0; j < drivers[i].nsections; j++)
            get_immutable_pages_section(drivers[i].name, 
                drivers[i].sections + j);
    }
    npages = pages_current_size/sizeof(uint64_t);
    qsort((void*)immutable_pages, npages, sizeof(uint64_t), compare_uint64);
    warnx("number of pages 0x%x", npages);
    ranges = malloc(npages * sizeof(struct immutable_range));
    if (!ranges)
        return;
    guest_introspect_info.hdr.n_immutable_ranges = 
        convert_list_to_ranges(immutable_pages, npages, ranges);
    guest_introspect_info.ranges = ranges;
    dump_ranges("", ranges, guest_introspect_info.hdr.n_immutable_ranges);
    free(immutable_pages);
}

struct guest_introspect_info_t *get_guest_introspect_info()
{
    warnx("get_guest_introspect_info start, ms=%016"PRIx64, os_get_clock_ms());
    if (!dmpdev_PsLoadedModulesList) {
        warnx("get_guest_introspect_info: dmpdev_PsLoadedModulesList=0?");
        return NULL;
    }
    guest_introspect_info.hdr.PsLoadedModulesList = dmpdev_PsLoadedModulesList;
    guest_introspect_info.hdr.PsActiveProcessHead = dmpdev_PsActiveProcessHead;
    get_drivers_info(dmpdev_PsLoadedModulesList);
    get_immutable_ranges();
    warnx("get_guest_introspect_info end, ms=%016"PRIx64, os_get_clock_ms());
    return &guest_introspect_info;
}

int introspection_get_module_name_or_log(uint64_t addr, uint64_t *offset,
    char *basename, char *fullname, int buffer_size, int log_req)
{
    uint64_t head = dmpdev_PsLoadedModulesList;
    LDR_MODULE currmodule;
    guest_word_t curr_addr;
    int module_count = 0;
    int addr_found;

    *basename = 0;
    *fullname = 0;
    *offset = -1ULL;

    if (log_req)
        warnx("loaded kernel modules:\n");
    if (!head || addr == -1ULL)
        return -1;
    if (virt_read_type(head, curr_addr))
        return -1;
    while (curr_addr != head && module_count < SANE_MAX_DRIVERS) {
        if (virt_read_type(curr_addr, currmodule))
            return -1;
        module_count++;
        addr_found = (currmodule.BaseAddress <= addr &&
            currmodule.BaseAddress + (currmodule.SizeOfImage&0xffffffff) > addr);
        if (log_req || addr_found) {
            get_unicode_string(&currmodule.BaseDllName, (unsigned char*)basename, buffer_size);
            get_unicode_string(&currmodule.FullDllName, (unsigned char*)fullname, buffer_size);
        }
        if (addr_found) {
            *offset = addr - currmodule.BaseAddress;
            return 0;
        }
        if (log_req) {
            warnx("%016"PRIx64" size 0x%x basename %s fullname %s",
                (uint64_t)(currmodule.BaseAddress),
                (unsigned int)(currmodule.SizeOfImage&0xffffffff),
                basename, fullname);
        }
        curr_addr = currmodule.InLoadOrderModuleList.Flink;
    }
    if (curr_addr != head) {
        warnx("introspection_get_module_name: more than 300 drivers found?");
        return -1;
    }
    if (log_req)
        warnx("end of kernel modules\n");
    return -1;
}

int introspection_get_module_name(uint64_t addr, uint64_t *offset,
    char *basename, char *fullname, int buffer_size)
{
    return introspection_get_module_name_or_log(addr, offset,
        basename, fullname, buffer_size, 0);
}

#define MAX_STRING_SIZE 256
void introspection_dump_kernel_modules()
{
    uint64_t offset;
    char basename[MAX_STRING_SIZE];
    char fullname[MAX_STRING_SIZE];

    introspection_get_module_name_or_log(0, &offset,
        basename, fullname, MAX_STRING_SIZE, 1);
}

/* Hidden process detection.
The basic algorithm is: if the current process (determined by dereferencing
gsbase->ETHREAD_OFFSET->EPROCESS_OFFSET) is not in the PsActiveProcessHead
list, then it is a suspicious event. We run this check at each context switch
(we configure vtx to do vmexit on each fourth cr3 change).
Unfortunately, it appears that during early phase of process creation, cr3
is assigned to the new process directory table, but the process is not yet
inserted into PsActiveProcessHead list. Even worse, similarly on process
teardown.
So, in order to avoid FP, we count the suspicious events per EPROCESS, plus
require them to be TIMEDELTA ms spaced. We alert only if we see 3 such events.
*/

/* Offsets of relevant fields in ntoskrnl structures */
#ifdef __x86_64__
/* In EPROCESS: */
#define ACTIVEPROCESSLINKS_OFFSET   0x188
#define PID_OFFSET                  0x180
#define IMAGEFILENAME_OFFSET        0x2e0

/* In KPRCB */
#define ETHREAD_OFFSET  0x188
/* In ETHREAD */
#define EPROCESS_OFFSET 0x70
#else /* __x86_64__ */
/* In EPROCESS: */
#define ACTIVEPROCESSLINKS_OFFSET   0xb8
#define PID_OFFSET                  0xb4
#define IMAGEFILENAME_OFFSET        0x16c

/* In KPRCB */
#define ETHREAD_OFFSET  0x124
/* In ETHREAD */
#define EPROCESS_OFFSET 0x50
#endif /* __x86_64__ */

#define IMAGEFILENAME_SIZE          15
#define MAX_PROCESSES 512
#define STATUS_PROCESS_FOUND 0
#define STATUS_PROCESS_NOT_FOUND 1

static guest_word_t eprocess_from_list(guest_word_t head)
{
    return head - ACTIVEPROCESSLINKS_OFFSET;
}

static int walk_process_list(guest_word_t eprocess)
{
    guest_word_t curr_head = dmpdev_PsActiveProcessHead;
    int count;

    for (count = 0; count < MAX_PROCESSES; count++) {
        if (!is_kernel_address(curr_head))
            return -3;
        if (virt_read_type(curr_head, curr_head))
            return -1;
        if (curr_head == dmpdev_PsActiveProcessHead)
            return STATUS_PROCESS_NOT_FOUND;
        if (eprocess_from_list(curr_head) == eprocess)
            return STATUS_PROCESS_FOUND;
    }

    return -2;
}

static int get_current_eprocess(guest_word_t gsbase, guest_word_t *eprocess)
{
    guest_word_t ethread;
    guest_word_t _eprocess;

    if (!is_kernel_address(gsbase))
        return -1;
    if (virt_read_type(gsbase + ETHREAD_OFFSET, ethread))
        return -1;
    if (virt_read_type(ethread + EPROCESS_OFFSET, _eprocess))
        return -1;
    *eprocess = _eprocess;
    return 0;
}

#define TIMEDELTA 400
#define ALERT_THRESHOLD 4
#define SUSPICIOUS_PROCESS_TABLE_SIZE 32
static struct _suspicious_entry {
        uint64_t eprocess;
        uint64_t tstamp;
        int count;
} suspicious_process_table[SUSPICIOUS_PROCESS_TABLE_SIZE];
static int suspicious_process_table_entries;

#define IDX_NOT_FOUND -1
int lookup_suspicious_process(uint64_t eprocess)
{
    int i;
    for (i = 0; i < suspicious_process_table_entries &&
        i < SUSPICIOUS_PROCESS_TABLE_SIZE; i++) {
        if (suspicious_process_table[i].eprocess == eprocess)
            return i;
    }
    return IDX_NOT_FOUND;
}

static int update_process_status(uint64_t eprocess, int status)
{
    uint64_t now;
    int idx = lookup_suspicious_process(eprocess);
    if (idx == IDX_NOT_FOUND) {
        if (status == STATUS_PROCESS_FOUND)
            return 0;
        idx = suspicious_process_table_entries % SUSPICIOUS_PROCESS_TABLE_SIZE;
        suspicious_process_table[idx].eprocess = eprocess;
        suspicious_process_table[idx].tstamp = os_get_clock_ms();
        suspicious_process_table[idx].count = 1;
        suspicious_process_table_entries++;
//        debug_printf("[pshid] suspicious_process_table_entries=0x%x\n",
//            suspicious_process_table_entries);
        return 0;
    }
    if (status == STATUS_PROCESS_FOUND) {
        if (suspicious_process_table[idx].count > ALERT_THRESHOLD)
            debug_printf("[pshid] already alerted process %016"PRIx64" becomes visible\n", eprocess);
        suspicious_process_table[idx].eprocess = 0;
//        debug_printf("[pshid] suspicious_process_table_entries--\n");
        return 0;
    }
    if (suspicious_process_table[idx].count > ALERT_THRESHOLD)
        return 0; /* Already alerted on this one */
    now = os_get_clock_ms();
    if (now - suspicious_process_table[idx].tstamp > TIMEDELTA) {
        suspicious_process_table[idx].count++;
        suspicious_process_table[idx].tstamp = now;
    }
    if (suspicious_process_table[idx].count > ALERT_THRESHOLD) {
        guest_word_t pid;
        if (virt_read_type(eprocess + PID_OFFSET, pid))
            pid = -1;
        debug_printf("[pshid] hidden process found, pid %d, eprocess %016"PRIx64"\n", (int)pid, eprocess);
        return (int)pid;
    }
    return 0;
}

#define LOG_MAX_COUNT 100
int introspection_run_hidden_process_detector(uint64_t gsbase, uint64_t cr3,
    unsigned char *imagename)
{
    guest_word_t eprocess;
    int ret, i;
    int pid = 0;
    static int log_killswitch;

    set_cached_cr3(cr3);
    if (!dmpdev_PsActiveProcessHead || get_current_eprocess(gsbase, &eprocess))
        return 0;
    ret = walk_process_list(eprocess);
    if (ret < 0) {
        /* This should not happen at all, indicates an internal error. */
        log_killswitch++;
        if (log_killswitch < LOG_MAX_COUNT)
            debug_printf("introspection_run_hidden_process_detector, walk=%d,"
            "gsbase = %016"PRIx64"\n", ret, gsbase);
            return 0;
    }
    pid = update_process_status(eprocess, ret);
    if (!pid)
        return 0;
    virt_read(eprocess + IMAGEFILENAME_OFFSET, imagename, IMAGEFILENAME_SIZE);
    imagename[IMAGEFILENAME_SIZE - 1] = 0;
    for (i = 0; i < IMAGEFILENAME_SIZE && imagename[i]; i++)
        if (imagename[i] > 127 || imagename[i] < 32)
            imagename[i] = '?';

    return pid;
}
