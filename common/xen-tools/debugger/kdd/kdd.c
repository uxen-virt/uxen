/*
 * kdd.c -- stub for debugging guest OSes with the windows kernel debugger.
 *
 * Tim Deegan <Tim.Deegan@citrix.com>
 * 
 * Copyright (c) 2007-2010, Citrix Systems Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <ctype.h>
#include <err.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "kdd.h"
#include "pe.h"
#include "winsyms.h"

#define PIPE_PREFIX "\\\\.\\pipe\\"

#if defined(_WIN32)
DECLARE_PROGNAME;
#endif	/* _WIN32 */

void *memmem(const void *haystack_start, size_t haystack_len,
             const void *needle_start, size_t needle_len);

/* Windows version details */

#define KDD_OSNAME_LEN 32

typedef struct {
    uint32_t build;             
    int w64;
    int mp;
    char name[KDD_OSNAME_LEN];
    uint64_t base;              /* KernBase: start looking here */
    uint64_t range;             /* |         and search an area this size */
    uint32_t version;           /* +-> NtBuildNumber */
    uint32_t modules;           /* +-> PsLoadedModuleList */
    uint32_t prcbs;             /* +-> KiProcessorBlock */
    uint32_t dbg_data;          /* +-> KdpDebuggerDataListHead */
    uint32_t prcb_thread;       /* OffsetPrcbCurrentThread */
    uint32_t pcr_prcbs;         /* OffsetPcrInitialStack (?) */
} kdd_os;

/* State of the debugger stub */
typedef struct {
    union {
        uint8_t txb[sizeof (kdd_hdr) + 65536];   /* Marshalling area for tx */
        kdd_pkt txp;                 /* Also readable as a packet structure */
    };
    union {
        uint8_t rxb[sizeof (kdd_hdr) + 65536];   /* Marshalling area for rx */
        kdd_pkt rxp;                 /* Also readable as a packet structure */
    };
    unsigned int cur;       /* Offset into rx where we'll put the next byte */
    uint32_t next_id;                     /* ID of next packet we will send */
    int running;                      /* Are the guest's processors active? */
    int cpuid;                                      /* Current selected CPU */
    HANDLE hpipe;                            /* named pipe for client comms */
    FILE *log;                                        /* For tracing output */
    int verbosity;                              /* How much detail to trace */
    kdd_guest *guest;              /* Arch-specific state for guest control */
    kdd_os os;                                 /* OS-specific magic numbers */
} kdd_state;

/*****************************************************************************
 *  Utility functions
 */

/* Get the instruction pointer */
static uint64_t kdd_get_ip(kdd_state *s)
{
    kdd_regs r;
    if (!s->os.w64 && kdd_get_regs(s->guest, s->cpuid, &r, 0) == 0)
        return r.r32.eip;
    else if (s->os.w64 && kdd_get_regs(s->guest, s->cpuid, &r, 1) == 0)
        return r.r64.rip;
    else
        return -1ULL;
}

/* Turn write(2) into a proper blocking write. */
static size_t blocking_write(HANDLE hpipe, const void *buf, size_t count)
{
    OVERLAPPED ov;
    DWORD done;
    int ret;

    memset(&ov, 0, sizeof(OVERLAPPED));

    ret = WriteFile(hpipe, buf, count, &done, &ov);
    if (!ret && GetLastError() != ERROR_IO_PENDING)
        return 0;
    if (!ret) {
        ret = GetOverlappedResult(hpipe, &ov, &done, TRUE);
        if (!ret)
            return 0;
    }
    return done;
}

static size_t pipe_read(HANDLE hpipe, void *buf, size_t count)
{
    OVERLAPPED ov;
    DWORD done;
    int ret;

    memset(&ov, 0, sizeof(OVERLAPPED));

    ret = ReadFile(hpipe, buf, count, &done, &ov);
    if (!ret && GetLastError() != ERROR_IO_PENDING)
        return -1;
    if (!ret) {
        ret = GetOverlappedResult(hpipe, &ov, &done, TRUE);
        if (!ret)
            return 0;
    }
    return done;
}

/* Dump the contents of a complete serial packet into a log file. */
static void kdd_log_pkt(kdd_state *s, char *name, kdd_pkt *p)
{
    uint32_t sum = 0;
    unsigned int i, j;
    uint8_t ascii[17] = {0};
    FILE *f = s->log;

    if (s->verbosity < 2)
        return;

    /* Re-check the checksum */
    for (i = 0; i < p->h.len; i++)
        sum += p->payload[i];

    fprintf(f, "\n"
            "%s: %s type 0x%4.4"PRIx16" len 0x%4.4"PRIx16
            " id 0x%8.8"PRIx32" sum 0x%"PRIx32" (%s: 0x%"PRIx32")\n",
            name,
            p->h.dir == KDD_DIR_PKT ? "pkt" :
            p->h.dir == KDD_DIR_ACK ? "ack" : "???",
            (unsigned) p->h.type, p->h.len, p->h.id, p->h.sum,
            sum == p->h.sum ? "OK" : "BAD", sum);

    /* Hexdump the payload in "canonical" format*/
    for (i = 0; i < p->h.len; i ++) {
        if (i % 16 == 0) {
            memset(ascii, 0, 17);
            fprintf(f, "%8.8x ", i);
        } else if (i % 8 == 0)
            fprintf(f, " ");
        fprintf(f, " %2.2x", p->payload[i]);
        ascii[i % 16] = (isprint(((int)p->payload[i])) ? p->payload[i] : 0x2e);
        if (i % 16 == 15)
            fprintf(f, "  |%s|\n", ascii);
    }
    if (i % 16 != 0) {
        for (j = i % 16 ; j < 16; j++) {
            fprintf(f, "%s", (j == 8) ? "    " : "   ");
        }
        fprintf(f, "  |%s|\n%8.8x\n", ascii, i);
    }

    fprintf(f, "\n");
    (void) fflush(f);
}


/*****************************************************************************
 *  Memory access: virtual addresses and syntactic sugar.
 */

#define PAGE_SHIFT (12)
#define PAGE_SIZE (1ULL << PAGE_SHIFT)

static uint32_t kdd_read_physical(kdd_state *s, uint64_t addr,
                                  uint32_t len, void *buf)
{
    return kdd_access_physical(s->guest, addr, len, buf, 0);
}

static uint32_t kdd_write_physical(kdd_state *s, uint64_t addr,
                                   uint32_t len, void *buf)
{
    return kdd_access_physical(s->guest, addr, len, buf, 1);
}


/* VA->PA conversion.  Returns -1ULL for failure. */
static uint64_t v2p(kdd_state *s, int cpuid, uint64_t va)
{
    int pg, pae, pse, lma;
    int levels, width, bits, shift, offset, i;
    uint64_t efer, entry = 0, mask, pa;
    kdd_ctrl ctrl;

    /* For simplicity and earlier use,
       always use 64-bit ctrl structure. */
    if (kdd_get_ctrl(s->guest, cpuid, &ctrl, 1) != 0
        || kdd_rdmsr(s->guest, cpuid, 0xc0000080, &efer) != 0)
        return -1ULL;

    pg = !!(ctrl.c64.cr0 & 0x80000000);
    lma = !!(efer & 0x00000400);
    pae = !!(ctrl.c64.cr4 & 0x00000020);
    pse = !!(ctrl.c64.cr4 & 0x00000010) || pae || lma;
    pa = ctrl.c64.cr3 & ~0x0fULL;

    KDD_DEBUG(s, "w64 = %u, pg = %u, pae = %u, pse = %u, lma = %u\n",
              s->os.w64, pg, pae, pse, lma);

    /* Paging disabled? */
    if (!pg)
        return va;
    
    /* 32/PAE64? */
    if (lma) {
        va &= (1ULL<<48) - 1;
        width = 8; levels = 4; bits = 9;
    } else {
        va &= (1ULL<<32) - 1;
        if (pae) {
            width = 8; levels = 3; bits = 9;
        } else {
            width = 4; levels = 2; bits = 10;
        }
    }
    KDD_DEBUG(s, "%i levels, va 0x%16.16"PRIx64"\n", levels, va);

    /* Walk the appropriate number of levels */
    for (i = levels; i > 0; i--) {
        shift = PAGE_SHIFT + bits * (i-1);
        mask = ((1ULL << bits) - 1) << shift;
        offset = ((va & mask) >> shift) * width;
        KDD_DEBUG(s, "level %i: mask 0x%16.16"PRIx64" pa 0x%16.16"PRIx64
                  " offset %i\n",i, mask, pa, offset);
        if (kdd_read_physical(s, pa + offset, width, &entry) != width)
            return -1ULL; // Bad entry PA
        KDD_DEBUG(s, "level %i: entry 0x%16.16"PRIx64"\n", i, entry);
        if (!(entry & 0x1))
            return -1ULL; // Not present
        pa = entry & 0x000ffffffffff000ULL;
        if (pse && (i == 2) && (entry & 0x80)) { // Superpage
            mask = ((1ULL << (PAGE_SHIFT + bits)) - 1);
            return (pa & ~mask) + (va & mask);
        }
    }

    return pa + (va & (PAGE_SIZE - 1));
}

static uint32_t kdd_access_virtual(kdd_state *s, int cpuid, uint64_t addr,
                                   uint32_t len, void *buf, int write)
{
    uint64_t pa;
    uint32_t chunk, rv, done = 0;
    
    /* Process one page at a time */
    while (len > 0) {
        chunk = PAGE_SIZE - (addr & (PAGE_SIZE - 1));
        if (chunk > len)
            chunk = len;
        pa = v2p(s, cpuid, addr);
        KDD_DEBUG(s, "va 0x%"PRIx64" -> pa 0x%"PRIx64"\n", addr, pa);
        if (pa == (uint64_t) -1ULL)
            return done;
        rv = kdd_access_physical(s->guest, pa, chunk, buf, write);
        done += rv;
        if (rv != chunk)
            return done;
        addr += chunk;
        buf += chunk;
        len -= chunk;
    }
    return done;
}

static uint32_t kdd_read_virtual(kdd_state *s, int cpuid, uint64_t addr,
                                 uint32_t len, void *buf)
{
    return kdd_access_virtual(s, cpuid, addr, len, buf, 0);
}

static uint32_t kdd_write_virtual(kdd_state *s, int cpuid, uint64_t addr,
                                  uint32_t len, void *buf)
{
    return kdd_access_virtual(s, cpuid, addr, len, buf, 1);
}

/*****************************************************************************
 * GUID search functions.
 */


int
peheader_search(kdd_state *s, uint64_t *pehdr, uint64_t *kernptr, int *w64)
{
    int i, len, x64 = 0;
    char exename[13];
    uint64_t addr, peaddr, kernbase;
    uint16_t data16;
    uint32_t data32;

    for (i = 0; i < 1<<24; i++) {
        addr = 0xfffff80000000000LL + ((uint64_t)i << PAGE_SHIFT);

        len = kdd_read_virtual(s, 0, addr, 2, &data16);
        if (len != 2 || data16 != PE_DOSSTUB_MAGIC)
            continue;

        kernbase = addr;
        addr = v2p(s, 0, kernbase);

        len = kdd_read_physical(s, addr + PE_NTSIGN_PTR, 4, &data32);
        if (len != 4)
            continue;

        peaddr = addr + data32;

        len = kdd_read_physical(s, peaddr, 4, &data32);
        if (len != 4 || data32 != PE_NTSIGN_MAGIC)
            continue;

        len = kdd_read_physical(s, peaddr + PE_OPTHDR_OFFSET, 2, &data16);
        if (len != 2 || (data16 != PE_OPTHDR_PE32
                         && data16 != PE_OPTHDR_PE32P))
            continue;

        if (data16 == PE_OPTHDR_PE32P)
            x64 = 1;
        else
            x64 = 0;

        if (x64)
            len = kdd_read_physical(s, peaddr + PEOFF_EXPORTTBL_PE32P,
                                    4, &data32);
        else
            len = kdd_read_physical(s, peaddr + PEOFF_EXPORTTBL_PE32,
                                    4, &data32);
        if (len != 4)
            continue;

        len = kdd_read_physical(s, addr + data32 + EXPORTTBLOFF_NAME,
                                4, &data32);
        if (len != 4)
            continue;

        len = kdd_read_physical(s, addr + data32, 13, exename);
        if (len != 13 || strncmp(exename, "ntoskrnl.exe", 13))
            continue;

        /* Found a DOS PE executable, page aligned, sequential in
         * physical memory whose name is declared to be ntoskrnl.exe.
         */

        *w64 = !!x64;
        *kernptr = kernbase;
        *pehdr = peaddr;
        return 1;
    }
    return 0;
}


/*****************************************************************************
 * KDBG search functions.
 */

struct _DBGKD_DEBUG_DATA_HEADER64 {
    uint64_t List[2];
    uint32_t OwnerTag;
    uint32_t Size;
} PACKED;
typedef struct _DBGKD_DEBUG_DATA_HEADER64 DBGKD_DEBUG_DATA_HEADER64;

struct _KDDEBUGGER_DATA64 {
    DBGKD_DEBUG_DATA_HEADER64 Header;
#define _FLD16(_x) uint16_t _x;
#define _FLD64(_x) uint64_t _x;
#include "kdbg_fld.h"
#undef _FLD16
#undef _FLD64
} PACKED;
typedef struct _KDDEBUGGER_DATA64 KDDEBUGGER_DATA64;
static KDDEBUGGER_DATA64 kdbg;
static char kdbg64sign[] = "\xf8\xff\xffKDBG";
static char kdbg32sign[] = "\x00\x00\x00\x00\x00\x00\x00\x00KDBG";

void
kdbg_dump(kdd_state *s)
{
    KDD_LOG(s, "List: %"PRIx64", %"PRIx64"\n",
           kdbg.Header.List[0], kdbg.Header.List[1]);
    KDD_LOG(s, "Owner: %x\n", kdbg.Header.OwnerTag);
    KDD_LOG(s, "Size: %d\n", kdbg.Header.Size);
#define _FLD64(_x) KDD_LOG(s, "\t"#_x": %"PRIx64"\n", kdbg._x);
#define _FLD16(_x) KDD_LOG(s, "\t"#_x": %x\n", kdbg._x);
#include "kdbg_fld.h"
#undef _FLD64
#undef _FLD16
}

int
kdbg_populate(kdd_state *s, uint64_t addr, int w64)
{
    uint32_t len;
    uint64_t amask = !w64 ? (-1ULL << 32) : 0;
    char name[KDD_OSNAME_LEN];

    len = kdd_read_physical(s, addr, sizeof(kdbg), &kdbg);
    if ( len < sizeof(kdbg) ) {
        KDD_LOG(s, "error reading KDBG pa %"PRIx64"\n", addr);
        return 0;
    }

    /* XXX: Run basic KDBG checks. */

    s->os.w64 = w64;
    s->os.mp = 1;

    s->os.base = kdbg.KernBase | amask;
    s->os.modules = kdbg.PsLoadedModuleList - kdbg.KernBase;
    s->os.prcbs = kdbg.KiProcessorBlock - kdbg.KernBase;
    s->os.dbg_data = kdbg.Header.List[0] - kdbg.KernBase;
    s->os.prcb_thread = kdbg.OffsetPrcbCurrentThread;
    s->os.pcr_prcbs = kdbg.OffsetPcrInitialStack;

    len = kdd_read_virtual(s, 0, kdbg.NtBuildLab, 32, name);
    name[KDD_OSNAME_LEN - 1] = '\0';
    memcpy(s->os.name, name, KDD_OSNAME_LEN);
    s->os.build = atoi(name);

    KDD_DEBUG(s, "name = %s\n", name);
    KDD_DEBUG(s, "build = %x\n", s->os.build);
    KDD_DEBUG(s, "modules = %x\n", s->os.modules);
    KDD_DEBUG(s,  "prcbs = %x\n", s->os.prcbs);
    KDD_DEBUG(s, "dbgdata = %x\n", s->os.dbg_data);

    return 1;
}

#define rotl(_v, _s) (((_v) << (_s)) | ((_v) >> (64 - (_s))))

uint64_t decode(uint64_t e, uint64_t a, uint64_t n, uint64_t p)
{
    uint64_t d;

    d = e^n;
    d = rotl(d, n & 0xff);
    d ^= p;
    d = __builtin_bswap64(d);
    d ^= a;

    return d;
}

int
kdbg_search(kdd_state *s)
{
    void *ptr;
    uint32_t len;
    uint64_t limit;
    char buf[PAGE_SIZE];

    /* Limit search arbitrarily to 4Gb. Or add get_max_pfn to interface */
    for (limit = 0; limit < (uint64_t)4 << 30; limit+=PAGE_SIZE) {
        /* The structure shouldn't be cross-page. */
        len = kdd_read_physical(s, limit, PAGE_SIZE, buf);
        if (len < PAGE_SIZE) {
            fprintf(stderr, "Error reading pa %"PRIx64"\n", limit);
            continue;
        }

        ptr = memmem(buf, PAGE_SIZE, kdbg32sign, 12);
        if (ptr) {
            uint64_t addr = limit + (uintptr_t)ptr - (uintptr_t)buf - 8;

            KDD_LOG(s, "found 32-bit KDBG signature at addr %"PRIx64"\n", addr);
            if (kdbg_populate(s, addr, 0))
                return 1;
        }

        ptr = memmem(buf, PAGE_SIZE, kdbg64sign, 7);
        if (ptr) {
            uint64_t addr = limit + (uintptr_t)ptr - (uintptr_t)buf - 13;

            KDD_LOG(s, "found 64-bit KDBG signature at addr %"PRIx64"\n",
                    addr);
            if (kdbg_populate(s, addr, 1))
                return 1;
        }
    }

    return 0;
}


/*****************************************************************************
 * Version information and related runes for different Windows flavours
 */


static void dllwarn(void)
{
    fprintf(stderr,
            "\nkdd was unable to fetch symbols for the VM's kernel from\n"
            "the Symbol Server.\n"
            "You should run kdd in the $DDK\\Debuggers\\ directory or\n"
            "speak to Gianluca if you volunteer to fix this.\n\n");
}


static int scan_os(kdd_state *s)
{
    void *symid = NULL;
    int len, w64 = 0, ret = 0;
    uint8_t encoded_block, zero = 0;
    uint32_t timestamp, imagesize;
    uint64_t pehdr, kernbase, addr, dbgdata;

    if (!peheader_search(s, &pehdr, &kernbase, &w64))
        return 0;

    len = kdd_read_physical(s, pehdr + PEOFF_TIMEDATESTAMP, 4, &timestamp);
    if (len != 4)
        return 0;

    len = kdd_read_physical(s, pehdr + PEOFF_IMAGESIZE, 4, &imagesize);
    if (len != 4)
        return 0;

    symid = GetCurrentProcess();

    ret = winsym_init(symid, "ntoskrnl.exe",
                      timestamp, imagesize,
                      NULL, kernbase);
    if (!ret)
        ret = winsym_init(symid, "ntkrnlmp.exe",
                          timestamp, imagesize,
                          NULL, kernbase);
    if (!ret) {
        KDD_LOG(s, "Can't find symbols for binary ntoskrnl.exe,%x%x,1\n",
                timestamp,imagesize);
        dllwarn();
        return 0;
    }

    ret = winsym_resolve(symid, "KdpDataBlockEncoded", &addr);
    if (!ret)
        goto out;

    len = kdd_read_virtual(s, 0, addr, 1, &encoded_block);
    if (len != 1)
        goto out;

    ret = winsym_resolve(symid, "KdDebuggerDataBlock", &dbgdata);
    if (!ret)
        goto out;

    if (encoded_block) {
        int i;
        uint64_t *kbuf;
        uint64_t a, n, p;
        struct _DBGKD_DEBUG_DATA_HEADER64 kdbghdr;

        ret = winsym_resolve(symid, "KiWaitAlways", &addr);
        if (!ret)
            goto out;

        len = kdd_read_virtual(s, 0, addr, 8, &a);
        if (len != 8)
            goto out;

        ret = winsym_resolve(symid, "KiWaitNever", &addr);
        if (!ret)
            goto out;

        len = kdd_read_virtual(s, 0, addr, 8, &n);
        if (len != 8)
            goto out;

        ret = winsym_resolve(symid, "KdpDataBlockEncoded", &p);
        if (!ret)
            goto out;

        len = kdd_read_virtual(s, 0, dbgdata, sizeof(kdbghdr), &kdbghdr);
        if (len != sizeof(kdbghdr))
            goto out;

        for (i = 0; i < sizeof(kdbghdr)/8; i++) {
            uint64_t *ptr = ((uint64_t *)&kdbghdr) + i;

            *ptr = decode(*ptr, a, n, p);
        }

        kbuf = malloc(kdbghdr.Size);
        if (kbuf == NULL)
            goto out;

        len = kdd_read_virtual(s, 0, dbgdata, kdbghdr.Size, kbuf);
        if (len != kdbghdr.Size) {
            free(kbuf);
            goto out;
        }

        for (i = 0; i < kdbghdr.Size/8; i++)
            kbuf[i] = decode(kbuf[i], a, n, p);

        len = kdd_write_virtual(s, 0, p, 1, &zero);
        if (len != 1) {
            free(kbuf);
            goto out;
        }

        len = kdd_write_virtual(s, 0, dbgdata, kdbghdr.Size, kbuf);
        free(kbuf);
        if (len != kdbghdr.Size)
            goto out;
    }

    ret = kdbg_populate(s, v2p(s, 0, dbgdata), w64);
    kdbg_dump(s);
    winsym_fin(symid);
    return 1;

 out:
    fprintf(stderr, ":-(\n");
    winsym_fin(symid);
    return 0;
}

static kdd_os os[] = {
 /* Build  64 MP Name                 &Kernel search base    Range                  +Version    +Modules    +PRCBs(64b) +debug data */

    // Win 8
    {9200, 1, 1, "win8 sp0 x64",      0xfffff80010000000ULL, 0x0000000f00000000ULL, 0x0007f548, 0x002caa60, 0x00356c80, 0x2808d0, 8, 0x180},
                                               
    // Win 7
    {7601, 1, 1, "win7 sp1 x64",      0xfffff80001000000ULL, 0x000000000f000000ULL, 0x001b5770, 0x00244670, 0x002aea40, 0x0, 8, 0x180},
    {7601, 1, 1, "win7 sp1 x64",      0xfffff80001000000ULL, 0x000000000f000000ULL, 0x001b2770, 0x00240e90, 0x002ab900, 0x0, 8, 0x180},
    {7601, 0, 1, "win7 sp1 x32p",     0xffffffff81800000ULL, 0x000000000f000000ULL, 0x000524c4, 0x00149850, 0x00000000, 0x0, 8, 0x180},
    {7600, 1, 1, "win7 sp0 x64",      0xfffff80001000000ULL, 0x000000000f000000ULL, 0x001af770, 0x0023de50, 0x002a8900, 0x0, 8, 0x180},

    // Srv 2008
    {6001, 1, 1, "w2k8 sp0 x64",      0xfffff80001000000ULL, 0x000000000f000000ULL, 0x00140bf0, 0x001c5db0, 0x00229640, 0x0, 8, 0x180},

    // Vista
    {6001, 0, 1, "vista sp1 x32p",    0xffffffff81000000ULL, 0x000000000f000000ULL, 0x000af0c4, 0x00117c70, 0x00000000, 0x0, 8, 0x180},
    {6000, 0, 1, "vista sp0 x32p",    0xffffffff81800000ULL, 0x0000000000000000ULL, 0x000a4de4, 0x00111db0, 0x00000000, 0x0, 8, 0x180},

    // Srv 2003
    {3790, 0, 0, "w2k3 sp2 x32 UP",   0xffffffff80800000ULL, 0x0000000000000000ULL, 0x00097128, 0x000a8e48, 0x00000000, 0x0, 8, 0x180},
    {3790, 0, 1, "w2k3 sp2 x32 SMP",  0xffffffff80800000ULL, 0x0000000000000000ULL, 0x0009d128, 0x000af9c8, 0x00000000, 0x0, 8, 0x180},
    {3790, 0, 0, "w2k3 sp2 x32p UP",  0xffffffff80800000ULL, 0x0000000000000000ULL, 0x0008e128, 0x0009ffa8, 0x00000000, 0x0, 8, 0x180},
    {3790, 0, 1, "w2k3 sp2 x32p SMP", 0xffffffff80800000ULL, 0x0000000000000000ULL, 0x00094128, 0x000a6ea8, 0x00000000, 0x0, 8, 0x180},
    {3790, 1, 0, "w2k3 sp2 x64 UP",   0xfffff80001000000ULL, 0x0000000000000000ULL, 0x001765d0, 0x0019aae0, 0x0017b100, 0x0, 8, 0x180},
    {3790, 1, 1, "w2k3 sp2 x64 SMP",  0xfffff80001000000ULL, 0x0000000000000000ULL, 0x001b05e0, 0x001d5100, 0x001b5300, 0x0, 8, 0x180},

    // XP
    {2600, 0, 0, "xp sp3 x32 UP",     0xffffffff804d7000ULL, 0x0000000000000000ULL, 0x00075be8, 0x000841c0, 0x00000000, 0x0, 8, 0x180},
    {2600, 0, 1, "xp sp3 x32 SMP",    0xffffffff804d7000ULL, 0x0000000000000000ULL, 0x0007c0e8, 0x0008c4c0, 0x00000000, 0x0, 8, 0x180},
    {2600, 0, 0, "xp sp3 x32p UP",    0xffffffff804d7000ULL, 0x0000000000000000ULL, 0x0006e8e8, 0x0007cfc0, 0x00000000, 0x0, 8, 0x180},
    {2600, 0, 1, "xp sp3 x32p SMP",   0xffffffff804d7000ULL, 0x0000000000000000ULL, 0x000760e8, 0x00086720, 0x00000000, 0x0, 8, 0x180},

    {2600, 0, 0, "xp sp2 x32 UP",     0xffffffff804d7000ULL, 0x0000000000000000ULL, 0x00075568, 0x00083b20, 0x00000000, 0x0, 8, 0x180},
    {2600, 0, 1, "xp sp2 x32 SMP",    0xffffffff804d7000ULL, 0x0000000000000000ULL, 0x0007d0e8, 0x0008d4a0, 0x00000000, 0x0, 8, 0x180},
    // PAE/UP, PAE/SMP

    // Win 2000
    {2195, 0, 0, "w2k sp4 x32 UP",    0xffffffff80400000ULL, 0x0000000000000000ULL, 0x0006d57c, 0x0006e1b8, 0x00000000, 0x0, 8, 0x180},
    {2195, 0, 1, "w2k sp4 x32 SMP",   0xffffffff80400000ULL, 0x0000000000000000ULL, 0x0006fa1c, 0x00084520, 0x00000000, 0x0, 8, 0x180},
    // PAE/UP, PAE/SMP
};

// 1381, 0, 0, "NT4 sp?", 0xffffffff80100000, ?, ?

static kdd_os unknown_os = {0, 0, 0, "unknown OS", 0, 0, 0, 0, 0};

static int check_os(kdd_state *s)
{
    kdd_os *v = &s->os;
    uint64_t addr, val;
    uint32_t width;
    int i;

    /* Kernel address must be a DOS executable */
    val = 0;
    if (kdd_read_virtual(s, 0, v->base, 2, &val) != 2 || val != 0x5a4d) {
        KDD_DEBUG(s, "not %s: krnl 0x%"PRIx64"\n", v->name, val);
        return 0;
    }

    /* OS version must match. */
    val = 0;
    if (kdd_read_virtual(s, 0, v->base + v->version, 4, &val) != 4
        || val != (v->build | 0xf0000000) ) {
        KDD_DEBUG(s, "not %s: version 0x%"PRIx64"\n", v->name, val);
        return 0;
    }
    
    /* Module list address must be a circular linked list */
    addr = v->base + v->modules;
    val = 0;
    width = v->w64 ? 8 : 4;
    for (i = 0; val != v->base + v->modules && i < 250; i++) {
        val = 0;
        if (kdd_read_virtual(s, 0, addr, width, &val) != width) {
            KDD_DEBUG(s, "not %s: bad module list\n", v->name);
            return 0;
        }
        addr = val;
    }

    return 1;
}

/* Figure out what OS we're dealing with */
static void find_os(kdd_state *s)
{
    int i;
    uint64_t limit;

    /* We may already have the right one */
    if (check_os(s))
        return;

    /* Search for PEHeader and fetch symbols */
    if (scan_os(s))
        return;

    /* Search for the kdbg structure in memory */
    if (kdbg_search(s))
        return;

    /* Try each OS we know about */
    for (i = 0; i < (sizeof os / sizeof os[0]); i++) {
        s->os = os[i];
        /* Try each page in the potential range of kernel load addresses */
        for (limit = s->os.base + s->os.range;
             s->os.base <= limit;
             s->os.base += PAGE_SIZE)
            if (check_os(s))
                return;
    }
    s->os = unknown_os;
}


/*****************************************************************************
 *  How to send packets and acks.
 */


/* Send a serial packet */
static void kdd_tx(kdd_state *s)
{
    uint32_t sum = 0;
    size_t len;
    int i;

    /* Fix up the checksum before we send */
    for (i = 0; i < s->txp.h.len; i++)
        sum += s->txp.payload[i];
    s->txp.h.sum = sum;

    kdd_log_pkt(s, "TX", &s->txp);

    len = s->txp.h.len + sizeof (kdd_hdr);
    if (s->txp.h.dir == KDD_DIR_PKT)
        /* Append the mysterious 0xaa byte to each packet */
        s->txb[len++] = 0xaa;

    (void)blocking_write(s->hpipe, s->txb, len);
}


/* Send an acknowledgement to the client */
static void kdd_send_ack(kdd_state *s, uint32_t id, uint16_t type)
{
    s->txp.h.dir = KDD_DIR_ACK;
    s->txp.h.type = type;
    s->txp.h.len = 0;
    s->txp.h.id = id;
    s->txp.h.sum = 0;
    kdd_tx(s);
}

/* Send a command_packet to the client */
static void kdd_send_cmd(kdd_state *s, uint32_t subtype, size_t extra)
{
    s->txp.h.dir = KDD_DIR_PKT;
    s->txp.h.type = KDD_PKT_CMD;
    s->txp.h.len = sizeof (kdd_cmd) + extra;
    s->txp.h.id = (s->next_id ^= 1);
    s->txp.h.sum = 0;
    s->txp.cmd.subtype = subtype;
    kdd_tx(s);
}

/* Cause the client to print a string */
static void kdd_send_string(kdd_state *s, char *fmt, ...)
{
    uint32_t len = 0xffff - sizeof (kdd_msg);
    char *buf = (char *) s->txb + sizeof (kdd_hdr) + sizeof (kdd_msg);
    va_list ap;
    
    va_start(ap, fmt);
    len = vsnprintf(buf, len, fmt, ap);
    va_end(ap);

    s->txp.h.dir = KDD_DIR_PKT;
    s->txp.h.type = KDD_PKT_MSG;
    s->txp.h.len = sizeof (kdd_msg) + len;
    s->txp.h.id = (s->next_id ^= 1);
    s->txp.h.sum = 0;
    s->txp.msg.subtype = KDD_MSG_PRINT;
    s->txp.msg.length = len;
    kdd_tx(s);
}


/* Stop the guest and prepare for debugging */
static void kdd_break(kdd_state *s)
{
    uint16_t ilen;
    KDD_LOG(s, "Break\n");

    if (s->running)
        kdd_halt(s->guest);
    s->running = 0;

    {
        unsigned int i;
        /* XXX debug pattern */
        for (i = 0; i < 0x100 ; i++) 
            s->txb[sizeof (kdd_hdr) + i] = i;
    }

    /* Send a state-change message to the client so it knows we've stopped */
    s->txp.h.dir = KDD_DIR_PKT;
    s->txp.h.type = KDD_PKT_STC;
    s->txp.h.len = sizeof (kdd_stc);
    s->txp.h.id = (s->next_id ^= 1);
    s->txp.stc.subtype = KDD_STC_STOP;
    s->txp.stc.stop.cpu = s->cpuid;
    s->txp.stc.stop.ncpus = kdd_count_cpus(s->guest); 
    s->txp.stc.stop.kthread = 0; /* Let the debugger figure it out */
    s->txp.stc.stop.status = KDD_STC_STATUS_BREAKPOINT;
    s->txp.stc.stop.rip1 = s->txp.stc.stop.rip2 = kdd_get_ip(s);
    s->txp.stc.stop.nparams = 0;
    s->txp.stc.stop.first_chance = 1;
    ilen = kdd_read_virtual(s, s->cpuid, s->txp.stc.stop.rip1,
                            sizeof s->txp.stc.stop.inst, s->txp.stc.stop.inst);
    s->txp.stc.stop.ilen = ilen;
    /* XXX other fields */

    kdd_tx(s);
}

/* Handle an acknowledgement received from the client */
static void kdd_handle_ack(kdd_state *s, uint32_t id, uint16_t type)
{
    switch (type) {
    case KDD_ACK_OK:
    case KDD_ACK_BAD:
        break;
    case KDD_ACK_RST:
        if (id == 0) {
            KDD_LOG(s, "Client requests a reset\n");
            kdd_send_ack(s, 0xdeadbeef, KDD_ACK_RST);
            kdd_send_string(s, "[kdd: connected to %s]\r\n", 
                            kdd_guest_identify(s->guest));
            kdd_break(s);
        }
        break;
    default:
        KDD_LOG(s, "Unhandled ACK type 0x%4.4x\n", type);
        break;
    }
}

/*****************************************************************************
 *  Handlers for each kind of client packet
 */


/* Handle the initial handshake */
static void kdd_handle_handshake(kdd_state *s)
{
    /* Figure out what we're looking at */
    find_os(s);
    kdd_send_string(s, "[kdd: %s @0x%"PRIx64"]\r\n", s->os.name, s->os.base);

    /* Respond with some details about the debugger stub we simulate */
    s->txp.cmd.shake.u1        = 0x01010101;
    s->txp.cmd.shake.status    = KDD_STATUS_SUCCESS;
    s->txp.cmd.shake.u2        = 0x02020202;
    s->txp.cmd.shake.v_major   = 0xf;
    s->txp.cmd.shake.v_minor   = s->os.build;
    s->txp.cmd.shake.proto     = 6;
    s->txp.cmd.shake.flags     = (0x02 /* ??? */
                                  | (s->os.mp ? KDD_FLAGS_MP : 0)
                                  | (s->os.w64 ? KDD_FLAGS_64 : 0));
    s->txp.cmd.shake.machine   = s->os.w64 ? KDD_MACH_x64 : KDD_MACH_x32;
    s->txp.cmd.shake.pkts      = KDD_PKT_MAX;
    s->txp.cmd.shake.states    = 0xc; /* ??? */
    s->txp.cmd.shake.manips    = 0x2e; /* ??? */
    s->txp.cmd.shake.u3[0]     = 0x33;
    s->txp.cmd.shake.u3[1]     = 0x44;
    s->txp.cmd.shake.u3[2]     = 0x55;
    s->txp.cmd.shake.kern_addr = s->os.base;
    s->txp.cmd.shake.mods_addr = s->os.base + s->os.modules;
    s->txp.cmd.shake.data_addr = s->os.dbg_data
                                 ? s->os.base + s->os.dbg_data : 0;

    KDD_LOG(s, "Client initial handshake: %s\n", s->os.name);
    kdd_send_cmd(s, KDD_CMD_SHAKE, 0);
}

/* Handle set-cpu command */
static void kdd_handle_setcpu(kdd_state *s)
{
    KDD_LOG(s, "Switch to CPU %u\n", s->rxp.cmd.setcpu.cpu);

    /* This command doesn't get a direct response; instead we send a STOP. */
    s->cpuid = s->rxp.cmd.setcpu.cpu;
    kdd_break(s);

    /* XXX find out whether kd will  be happier if we respond to this command after the break. */
}

/* Handle breakpoint commands */
static void kdd_handle_soft_breakpoint(kdd_state *s)
{
    KDD_LOG(s, "Soft breakpoint %#"PRIx32" op %#"PRIx32"/%#"PRIx32"\n",
            s->rxp.cmd.sbp.bp, s->rxp.cmd.sbp.u1, s->rxp.cmd.sbp.u2);
    
    /* Pretend we did something */
    s->txp.cmd.sbp.u1     = s->rxp.cmd.sbp.u1;
    s->txp.cmd.sbp.status = KDD_STATUS_SUCCESS;    
    s->txp.cmd.sbp.u2     = s->rxp.cmd.sbp.u2;
    s->txp.cmd.sbp.bp     = s->rxp.cmd.sbp.bp;
    kdd_send_cmd(s, KDD_CMD_SOFT_BP, 0);
}

static void kdd_handle_hard_breakpoint(kdd_state *s)
{
    KDD_LOG(s, "Hard breakpoint @%#"PRIx64"\n", s->rxp.cmd.hbp.address);

    kdd_send_string(s, "[kdd: breakpoints aren't implemented yet]\r\n");

    s->txp.cmd.hbp.status = KDD_STATUS_FAILURE;
    s->txp.cmd.hbp.address = s->rxp.cmd.hbp.address;    
    kdd_send_cmd(s, KDD_CMD_HARD_BP, 0);
}

/* Register access */
static void kdd_handle_read_regs(kdd_state *s)
{
    kdd_regs regs;
    uint32_t len = s->os.w64 ? sizeof regs.r64 : sizeof regs.r32;
    int cpuid = s->rxp.cmd.regs.cpu;

    KDD_LOG(s, "Read CPU %i register state\n", cpuid);
    if (kdd_get_regs(s->guest, cpuid, &regs, s->os.w64) == 0) {
        memcpy(s->txb + sizeof (kdd_hdr) + sizeof (kdd_cmd), &regs, len);
        s->txp.cmd.regs.status = KDD_STATUS_SUCCESS;
    } else {
        len = 0;
        s->txp.cmd.regs.status = KDD_STATUS_FAILURE;
    }
    s->txp.cmd.regs.cpu = cpuid;
    kdd_send_cmd(s, KDD_CMD_READ_REGS, len);
}

static void kdd_handle_write_regs(kdd_state *s)
{
    kdd_regs regs;
    uint32_t len = s->rxp.h.len - sizeof (kdd_cmd);
    uint32_t regsz = s->os.w64 ? sizeof regs.r64 : sizeof regs.r32;
    int cpuid = s->rxp.cmd.regs.cpu;

    KDD_LOG(s, "Write CPU %i register state\n", cpuid);
    s->txp.cmd.regs.status = KDD_STATUS_FAILURE;
    if (len >= regsz) {
        memcpy(&regs, s->rxb + sizeof (kdd_hdr) + sizeof (kdd_cmd), regsz);
        if (kdd_set_regs(s->guest, cpuid, &regs, s->os.w64) == 0)
            s->txp.cmd.regs.status = KDD_STATUS_SUCCESS;
    }
    s->txp.cmd.regs.cpu = cpuid;
    kdd_send_cmd(s, KDD_CMD_WRITE_REGS, 0);
}

/* Report control state to the guest */
static void kdd_handle_read_ctrl(kdd_state *s)
{
    int i;
    kdd_ctrl ctrl;
    uint8_t *buf = s->txb + sizeof (kdd_hdr) + sizeof (kdd_cmd);
    uint32_t len = s->rxp.cmd.mem.length_req;
    uint64_t val, addr = s->rxp.cmd.mem.addr;
    KDD_LOG(s, "Read control state: %"PRIu32" bytes @ 0x%"PRIx64"\n",
            len, addr);

    if (len > (65536 - sizeof(kdd_cmd)))
        len = 65536 - sizeof(kdd_cmd);

    /* Default contents: a debug-friendly pattern */
    for (i = 0; i < len; i++)
        ((uint8_t*)buf)[i] = (uint8_t) (addr + i);

    if (kdd_get_ctrl(s->guest, s->cpuid, &ctrl, s->os.w64)) {
        len = 0;
    } else if (s->os.w64) {
        /* Annoyingly, 64-bit kd relies on the kernel to point it at
         * datastructures it could easily find itself with VA reads. */
        switch (addr) {
        case 0x0: /* KPCR */
        case 0x1: /* KPRCB */
        case 0x3: /* KTHREAD */
            /* First find the PRCB's address */
            len = kdd_read_virtual(s, s->cpuid, 
                                   s->os.base + s->os.prcbs + 8 * s->cpuid, 
                                   8, &val);
            if (len != 8)
                break;
            /* The PCR lives 0x180 bytes before the PRCB */
            if (addr == 0) 
                val -= s->os.pcr_prcbs;
            /* The current thread's address is at offset 0x8 into the PRCB. */
            else if (addr == 3)
                len = kdd_read_virtual(s, s->cpuid,
                                       val + s->os.prcb_thread, 8, &val);
            *(uint64_t *)buf = val; 
            break;
        case 0x2: /* Control registers */
            if (len > sizeof ctrl.c64) 
                len = sizeof ctrl.c64;
            memcpy(buf, (uint8_t *)&ctrl, len);
            break;
        default:
            KDD_LOG(s, "Unknown control space 0x%"PRIx64"\n", addr);
            len = 0;
        }
    } else {
        /* 32-bit control-register space starts at 0x[2]cc, for 84 bytes */
        uint64_t offset = addr;
        if (offset > 0x200)
            offset -= 0x200;
        offset -= 0xcc;
        if (offset > sizeof ctrl.c32 || offset + len > sizeof ctrl.c32) {
            KDD_LOG(s, "Request outside of known control space\n");
            len = 0;
        } else {
            memcpy(buf, ((uint8_t *)&ctrl.c32) + offset, len);
        }
    }

    s->txp.cmd.mem.addr = addr;
    s->txp.cmd.mem.length_req = s->rxp.cmd.mem.length_req;
    s->txp.cmd.mem.length_rsp = len;
    s->txp.cmd.mem.status = ((len) ? KDD_STATUS_SUCCESS : KDD_STATUS_FAILURE);
    kdd_send_cmd(s, KDD_CMD_READ_CTRL, len);
}

/* MSR access */
static void kdd_handle_read_msr(kdd_state *s)
{
    uint32_t msr = s->rxp.cmd.msr.msr;
    int ok;
    KDD_LOG(s, "Read MSR 0x%"PRIx32"\n", msr);

    ok = (kdd_rdmsr(s->guest, s->cpuid, msr, &s->txp.cmd.msr.val) == 0);
    s->txp.cmd.msr.msr = msr;
    s->txp.cmd.msr.status = (ok ? KDD_STATUS_SUCCESS : KDD_STATUS_FAILURE);
    kdd_send_cmd(s, KDD_CMD_READ_MSR, 0);
}

static void kdd_handle_write_msr(kdd_state *s)
{
    uint32_t msr = s->rxp.cmd.msr.msr;
    uint64_t val = s->rxp.cmd.msr.val;
    int ok;
    KDD_LOG(s, "Write MSR 0x%"PRIx32" = 0x%"PRIx64"\n", msr, val);

    ok = (kdd_wrmsr(s->guest, s->cpuid, msr, val) == 0);
    s->txp.cmd.msr.msr = msr;
    s->txp.cmd.msr.status = (ok ? KDD_STATUS_SUCCESS : KDD_STATUS_FAILURE);
    kdd_send_cmd(s, KDD_CMD_WRITE_MSR, 0);
}

/* Read and write guest memory */
static void kdd_handle_memory_access(kdd_state *s)
{
    uint32_t len = s->rxp.cmd.mem.length_req;
    uint64_t addr = s->rxp.cmd.mem.addr;
    uint8_t *buf;

    KDD_LOG(s, "Memory access \"%c%c\" (%s): %"PRIu32" bytes"
            " @ 0x%"PRIx64"\n", 
            s->rxp.cmd.subtype & 0xff, (s->rxp.cmd.subtype >>8) & 0xff, 
            s->rxp.cmd.subtype == KDD_CMD_READ_VA ? "read virt" :
            s->rxp.cmd.subtype == KDD_CMD_WRITE_VA ? "write virt" :
            s->rxp.cmd.subtype == KDD_CMD_READ_PA ? "read phys" :
            s->rxp.cmd.subtype == KDD_CMD_WRITE_PA ? "write phys" : "unknown",
            len, addr);

    if (len > (65536 - sizeof(kdd_cmd)))
        len = 65536 - sizeof(kdd_cmd);

    switch(s->rxp.cmd.subtype) {
    case KDD_CMD_READ_VA:
        buf = s->txb + sizeof (kdd_hdr) + sizeof (kdd_cmd);
        len = kdd_read_virtual(s, s->cpuid, addr, len, buf);
        break;
    case KDD_CMD_WRITE_VA:
        buf = s->rxb + sizeof (kdd_hdr) + sizeof (kdd_cmd);
        len = kdd_write_virtual(s, s->cpuid, addr, len, buf);
        break;
    case KDD_CMD_READ_PA:
        buf = s->txb + sizeof (kdd_hdr) + sizeof (kdd_cmd);
        len = kdd_read_physical(s, addr, len, buf);
        break;
    case KDD_CMD_WRITE_PA:
        buf = s->rxb + sizeof (kdd_hdr) + sizeof (kdd_cmd);
        len = kdd_write_physical(s, addr, len, buf);
        break;
    }
    KDD_DEBUG(s, "access returned %"PRIu32"\n", len);

    s->txp.cmd.mem.addr = addr;
    s->txp.cmd.mem.length_req = s->rxp.cmd.mem.length_req;
    s->txp.cmd.mem.length_rsp = len;
    s->txp.cmd.mem.status = (len) ? KDD_STATUS_SUCCESS : KDD_STATUS_FAILURE;
    kdd_send_cmd(s, s->rxp.cmd.subtype, len);
}


/* Handle a packet received from the client */
static void kdd_handle_pkt(kdd_state *s, kdd_pkt *p)
{
    uint32_t sum = 0;
    int i;

    /* Simple checksum: add all the bytes */
    for (i = 0; i < p->h.len; i++)
        sum += p->payload[i];
    if (p->h.sum != sum) {
        kdd_send_ack(s, p->h.id, KDD_ACK_BAD);
        return;
    }

    /* We only understand one kind of packet from the client */
    if (p->h.type != KDD_PKT_CMD) {
        KDD_LOG(s, "Unhandled PKT type 0x%4.4x\n", p->h.type);
        kdd_send_ack(s, p->h.id, KDD_ACK_BAD);
        return;
    }

    /* Ack the packet */
    kdd_send_ack(s, p->h.id, KDD_ACK_OK);

    /* Clear the TX buffer just for sanity */
    memset(s->txb, 0, sizeof(s->txb));

    switch (p->cmd.subtype) {
    case KDD_CMD_CONT1:
    case KDD_CMD_CONT2:
        KDD_LOG(s, "Continue: 0x%8.8"PRIx32"\n", p->cmd.cont.reason1);
        if (!s->running)
            kdd_run(s->guest);
        s->running = 1;
        /* No reply, just carry on running */
        break;
    case KDD_CMD_SHAKE:
        kdd_handle_handshake(s);
        break;
    case KDD_CMD_SOFT_BP:
        kdd_handle_soft_breakpoint(s);
        break;
    case KDD_CMD_HARD_BP:
        kdd_handle_hard_breakpoint(s);
        break;
    case KDD_CMD_READ_REGS:
        kdd_handle_read_regs(s);
        break;
    case KDD_CMD_WRITE_REGS:
        kdd_handle_write_regs(s);
        break;
    case KDD_CMD_READ_CTRL:
        kdd_handle_read_ctrl(s);
        break;
    case KDD_CMD_READ_MSR:
        kdd_handle_read_msr(s);
        break;
    case KDD_CMD_WRITE_MSR:
        kdd_handle_write_msr(s);
        break;
    case KDD_CMD_READ_VA:
    case KDD_CMD_WRITE_VA:
    case KDD_CMD_READ_PA:
    case KDD_CMD_WRITE_PA:
        kdd_handle_memory_access(s);
        break;
    case KDD_CMD_WRITE_Z:
        /* No response */
        break;
    case KDD_CMD_SETCPU:
        kdd_handle_setcpu(s);
        break;
    case KDD_CMD_WRITE_CTRL:
    default:
        KDD_LOG(s, "Unhandled CMD subtype 0x%8.8x\n", p->cmd.subtype);
        /* Send back a mirror of the request saying we failed to do
         * whatever it was. */
        memcpy(s->txb, p, sizeof (kdd_hdr) + sizeof (kdd_cmd));
        s->txp.h.len = sizeof (kdd_cmd);
        s->txp.cmd.mem.status = KDD_STATUS_FAILURE;
        s->txp.h.id = (s->next_id ^= 1);
        kdd_tx(s);
        break;
    }
}


/*****************************************************************************
 *  Scaffolding to get packets from the client.
 */


/* Set up the debugger state ready for use.  Returns a file descriptor and
 * a state pointer for use in select() loops. */
static HANDLE kdd_init(kdd_state **sp, char *pipe, 
                       kdd_guest *guest, FILE *log, int verbosity)
{
    kdd_state *s = NULL;
    char *pipename = NULL;
    HANDLE hpipe = NULL;
    int ret;

    s = malloc(sizeof *s);
    if (s == NULL) {
        fprintf(stderr, "Could not allocate state for kdd: %s\n", 
                strerror(errno));
        goto fail;
    }
    memset(s, 0, sizeof *s);
    s->log = log;
    s->verbosity = verbosity;

    pipename = calloc(1,sizeof(PIPE_PREFIX) + strlen(pipe) + 1);
    if (!pipename) {
        fprintf(stderr, "Could not allocate memory for full pipename: %s\n",
                strerror(errno));
        goto fail;
    }
    sprintf(pipename, "%s%s", PIPE_PREFIX, pipe);

#define NSENDBUF 65536
#define NRECVBUF 65536
#define MAXCONNECT 1
#define NTIMEOUT 5000
    hpipe = CreateNamedPipe(pipename,
                            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE |
                            PIPE_WAIT,
                            MAXCONNECT, NSENDBUF, NRECVBUF, NTIMEOUT,
                            NULL);
    if (hpipe == INVALID_HANDLE_VALUE) {
        KDD_LOG(s, "Could not create named pipe for kdd\n");
        goto fail;
    }
    ret = ConnectNamedPipe(hpipe, NULL);
    if (!ret) {
        KDD_LOG(s, "Could not connect named pipe for kdd\n");
        goto fail;
    }

    s->next_id = 0x80800001;
    s->hpipe = hpipe;
    s->running = 1;
    s->cpuid = 0;
    s->guest = guest;
    s->os = unknown_os;

    *sp = s;
    KDD_LOG(s, "KDD starts\n");

    kdd_break(s);

    free(pipename);

    return hpipe;

 fail:
    free(pipename);
    free(s);
    return NULL;
}

/* Callback when the fd is readable, to parse packet data from the byte
 * stream.  When a complete packet is seen, handle it.  The packet can
 * then be read in the marshalling buffer, but only until the next call
 * to kdd_parse_byte(). */
void kdd_select_callback(kdd_state *s)
{
    kdd_pkt *p = &s->rxp;
    unsigned int pkt_len = (unsigned) -1;
    ssize_t rc, to_read;

    /* For easy parsing, read single bytes until we can check the packet
     * length, then read in one go to the end. */
    if (s->cur < 8
        || (p->h.dir != KDD_DIR_PKT && p->h.dir != KDD_DIR_ACK))
        to_read = 1;
    else {
        /* Extract payload length from the header */
        pkt_len = p->h.len + sizeof (kdd_hdr);

        /* For some reason, packets always have a trailing 0xAA byte */
        if (p->h.dir == KDD_DIR_PKT)
            pkt_len++;

        to_read = pkt_len - s->cur;
    }

    rc = pipe_read(s->hpipe, s->rxb + s->cur, to_read);

    KDD_DEBUG(s, "read(%i) returns %i\n", (int) to_read, (int) rc);

    if (!rc) {
        perror("pipe closed");
        exit(0);
    } else if (rc < 0)
        return;

    /* Break command comes as a single byte */
    if (s->cur == 0 && s->rxb[0] == 'b') {
        kdd_break(s);
        return;
    }

    /* Remember the bytes we just read */
    s->cur += rc;

    /* Sync to packet start, which will be "0000" or "iiii" */
    if (s->cur < 4)
        return;
    if (p->h.dir != KDD_DIR_PKT && p->h.dir != KDD_DIR_ACK) {
        KDD_LOG(s, "Bad hdr 0x%8.8x: resyncing\n", p->h.dir);
        memmove(s->rxb, s->rxb + 1, --s->cur);
        return;
    }

    /* Process complete packets/acks */
    if (s->cur >= pkt_len) {
        kdd_log_pkt(s, "RX", p);
        if (p->h.dir == KDD_DIR_PKT)
            kdd_handle_pkt(s, p);
        else
            kdd_handle_ack(s, p->h.id, p->h.type);
        s->cur = 0;
    }
}


static void usage(void)
{
    fprintf(stderr, 
            "usage: kdd [-v] [-savefile] <uuid>|<savefile> <pipe>\n"
            "\n"
            "\tOpens a named pipe <pipe> and speaks the kd serial\n"
            "\tprotocol over it, to debug Xen domain <uuid>.\n"
            "\tTo connect a debugger, start windbg or kd with:\n"
            "\t\t-k com:pipe,port=" PIPE_PREFIX "<pipe>,resets=0\n\n");
    exit(1);
}


int main(int argc, char **argv)
{
    HANDLE hpipe;
    int verbosity = 0;
    int savefile = 0;
    kdd_state *s;
    kdd_guest *g;
    HANDLE h[1];
    int ret;

#if defined(_WIN32)
    setprogname(argv[0]);
#endif	/* _WIN32 */

    while (argc > 3 && !strcmp(argv[1], "-v")) {
        verbosity++;
        argc--;
        argv++;
    }

    if (argc > 3 && !strcmp(argv[1], "-savefile")) {
        savefile++;
        argc--;
        argv++;
    }

    if (argc != 3
        || !(g = kdd_guest_init(argv[1], savefile, stdout, verbosity))
        || !(hpipe = kdd_init(&s, argv[2], g, stdout, verbosity)))
        usage();

    h[0] = hpipe;

    while (1) {
        ret = WaitForMultipleObjectsEx(1, h, FALSE, INFINITE, TRUE);
        if (ret == WAIT_OBJECT_0)
            kdd_select_callback(s);
        else
            break;
    }

    return 0;
}
