/*
 * Copyright 2018-2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/qemu_glue.h>
#include <dm/debug.h>
#include <dm/bitops.h>
#include <dm/memory.h>
#include "cpu.h"
#include "x86_emulate.h"
#include "whpx.h"
#include "core.h"
#include "WinHvGlue.h"
#include "WinHvPlatform.h"
#include "emulate.h"
#include "util.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#define X86_CR0_PE (1 << 0)
#define X86_EFLAGS_DF 0x00000400
#define EFER_LMA (1 << 10)
#define HVM_DELIVER_NO_ERROR_CODE -1
#define TRAP_gp_fault 13
#define TRAP_page_fault 14

#define NONFATAL_UNMAPPED_IO

const int EMU_PERF_TEST = 0;

struct hvm_emu_cpu_regs {
    struct x86_cpu_user_regs uregs;

    /* cs, ss, es, ds, fs, gs */
    struct segment_register seg_reg[6];
    uint64_t efer;
    uint64_t cr[8];
};

struct hvm_emu_cpu {
    struct hvm_emu_cpu_regs regs;
    CPUState *state;
    int index;
};

struct hvm_emu_ctx {
    struct x86_emulate_ctxt x86_ctx;

    struct hvm_emu_cpu *cpu;
    uint64_t instr_rip;
    void*    instr;
    uint8_t  instr_buf[16];
    uint32_t instr_max_len;

    uint32_t seg_reg_accessed;

    int exn_pending;
    int exn_vector;
    int exn_error_code;
    int exn_insn_len;
};

enum hvm_access_type {
    hvm_access_insn_fetch,
    hvm_access_none,
    hvm_access_read,
    hvm_access_write
};

/* emulation reads from these registers */
static WHV_REGISTER_NAME emu_read_register_names[] = {
    /* X64 General purpose registers */
    WHvX64RegisterRax,
    WHvX64RegisterRcx,
    WHvX64RegisterRdx,
    WHvX64RegisterRbx,
    WHvX64RegisterRsp,
    WHvX64RegisterRbp,
    WHvX64RegisterRsi,
    WHvX64RegisterRdi,
    WHvX64RegisterR8,
    WHvX64RegisterR9,
    WHvX64RegisterR10,
    WHvX64RegisterR11,
    WHvX64RegisterR12,
    WHvX64RegisterR13,
    WHvX64RegisterR14,
    WHvX64RegisterR15,
    WHvX64RegisterRip,
    WHvX64RegisterRflags,

    /* X64 Control Registers */
    WHvX64RegisterCr0,
    WHvX64RegisterCr3,
    WHvX64RegisterCr4,
    WHvX64RegisterEfer,

    /* X64 Segment registers */
    WHvX64RegisterEs,
    WHvX64RegisterCs,
    WHvX64RegisterSs,
    WHvX64RegisterDs,
    WHvX64RegisterFs,
    WHvX64RegisterGs,
};

/* emulation writes to these registers */
static WHV_REGISTER_NAME emu_write_register_names[] = {
    /* X64 General purpose registers */
    WHvX64RegisterRax,
    WHvX64RegisterRcx,
    WHvX64RegisterRdx,
    WHvX64RegisterRbx,
    WHvX64RegisterRsp,
    WHvX64RegisterRbp,
    WHvX64RegisterRsi,
    WHvX64RegisterRdi,
    WHvX64RegisterR8,
    WHvX64RegisterR9,
    WHvX64RegisterR10,
    WHvX64RegisterR11,
    WHvX64RegisterR12,
    WHvX64RegisterR13,
    WHvX64RegisterR14,
    WHvX64RegisterR15,
    WHvX64RegisterRip,
    WHvX64RegisterRflags,
};

static whpx_reg_list_t emu_read_registers;
static whpx_reg_list_t emu_write_registers;

#define hvm_long_mode_enabled(v)                \
    ((v)->regs.efer & EFER_LMA)

static int hvmemul_virtual_to_linear(
    enum x86_segment seg,
    uint64_t offset,
    unsigned int bytes_per_rep,
    uint64_t *reps,
    enum hvm_access_type access_type,
    struct hvm_emu_ctx *hvmemul_ctxt,
    uint64_t *paddr);

static int hvmemul_gva_to_gpa(
    struct hvm_emu_ctx *hvmemul_ctxt,
    enum hvm_access_type access,
    uint64_t gva,
    uint64_t *gpa,
    int *unmapped);

extern WHV_PARTITION_HANDLE whpx_get_partition(void);

struct qsr_attrs {
    uint16_t type:4;    /* 0;  Bit 40-43 */
    uint16_t s:   1;    /* 4;  Bit 44 */
    uint16_t dpl: 2;    /* 5;  Bit 45-46 */
    uint16_t p:   1;    /* 7;  Bit 47 */
    uint16_t pad: 4;
    uint16_t avl: 1;    /* 8;  Bit 52 */
    uint16_t l:   1;    /* 9;  Bit 53 */
    uint16_t db:  1;    /* 10; Bit 54 */
    uint16_t g:   1;    /* 11; Bit 55 */
};

static void
qemusr_to_sr(CPUState *cpu, SegmentCache *qs, struct segment_register *seg)
{
    uint16_t flags = (uint16_t)(qs->flags >> DESC_TYPE_SHIFT);

    seg->base = qs->base;
    seg->limit = qs->limit;
    seg->sel = qs->selector;
    seg->attr.bytes = flags;
}

static struct segment_register*
hvmemul_get_seg_reg(enum x86_segment seg,
                    struct hvm_emu_ctx *ctx)
{
    return &ctx->cpu->regs.seg_reg[seg];
}

void dump_hex(void *ptr, int count)
{
    uint8_t *bytes = ptr;
    int i;
    for (i = 0; i < count; ++i) {
        debug_printf("%02X ", bytes[i]);
    }
    debug_printf("\n");
}

int emu_simple_port_io(int is_write, unsigned int port, unsigned int bytes, uint64_t *val)
{
    int width = ioport_width(bytes, "emu_write_io: bad size: 0x%x\n", (int)bytes);
    uint64_t mask = 0;
    switch (width) {
    case 0: mask = 0xff; break;
    case 1: mask = 0xffff; break;
    case 2: mask = 0xffffffff; break;
    default: whpx_panic("bad width %d\n", width);
    }
    if (is_write) {
        uint64_t v = *val & mask;
#ifdef DEBUG_IOPORT
        if (port != DEBUG_PORT_NUMBER)
            debug_printf("emu write IOPORT 0x%x size=%d value=0x%"PRIx64"\n", port, bytes, v);
#endif
        ioport_write(width, port, v);
    } else {
        *val = (*val & ~mask) | (ioport_read(width, port) & mask);
#ifdef DEBUG_IOPORT
        if (port != DEBUG_PORT_NUMBER)
            debug_printf("emu read IOPORT 0x%x size=%d value=0x%"PRIx64"\n", port, bytes, *val);
#endif
    }
    return X86EMUL_OKAY;
}

static int emu_read(
    enum x86_segment seg,
    uint64_t offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt
    )
{
    struct hvm_emu_ctx *ec = container_of(ctxt, struct hvm_emu_ctx, x86_ctx);
    uint64_t addr, paddr, reps = 1;
    int rc;
    int unmapped = 0;

    rc = hvmemul_virtual_to_linear(
        seg, offset, bytes, &reps, hvm_access_read, ec, &addr);
    if ( rc != X86EMUL_OKAY )
        return rc;
    rc = hvmemul_gva_to_gpa(ec, hvm_access_read, addr, &paddr, &unmapped);
    if ( rc != X86EMUL_OKAY )
        return rc;

#ifdef DEBUG_EMULATE
    debug_printf("emu read guest linear addr: %"PRIx64", paddr: %"PRIx64", bytes %d\n", addr, paddr, bytes);
#endif
    vm_memory_rw(paddr, p_data, bytes, 0);
#ifdef DEBUG_EMULATE
    dump_hex(p_data, bytes);
#endif
    return X86EMUL_OKAY;
}

static int emu_write(
    enum x86_segment seg,
    uint64_t offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt
    )
{
    struct hvm_emu_ctx *ec = container_of(ctxt, struct hvm_emu_ctx, x86_ctx);
    uint64_t addr, paddr, reps = 1;
    int rc;
    int unmapped;

    rc = hvmemul_virtual_to_linear(
        seg, offset, bytes, &reps, hvm_access_write, ec, &addr);
    if ( rc != X86EMUL_OKAY )
        return rc;
    rc = hvmemul_gva_to_gpa(ec, hvm_access_write, addr, &paddr, &unmapped);
    if ( rc != X86EMUL_OKAY )
        return rc;

#ifdef DEBUG_EMULATE
    debug_printf("emu write guest linear addr: %"PRIx64", paddr: %"PRIx64", nbytes %d\n", addr, paddr, bytes);
    dump_hex(p_data, bytes);
#endif

    vm_memory_rw(paddr, p_data, bytes, 1);

    return X86EMUL_OKAY;
}

static int emu_insn_fetch(
    enum x86_segment seg,
    uint64_t offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emu_ctx *ec = container_of(ctxt, struct hvm_emu_ctx, x86_ctx);
    int64_t buf_off = offset - ec->instr_rip;

    if (!ec->instr || !(buf_off >= 0 && buf_off + bytes <= ec->instr_max_len)) {
        uint64_t addr, paddr, reps = 1;
        int unmapped;
        int rc;

        /* prefetch to instruction cache */
        rc = hvmemul_virtual_to_linear(
            seg, offset, bytes, &reps, hvm_access_insn_fetch, ec, &addr);
        if ( rc != X86EMUL_OKAY )
            return rc;
        rc = hvmemul_gva_to_gpa(ec, hvm_access_insn_fetch, addr, &paddr, &unmapped);
        if ( rc != X86EMUL_OKAY )
            return rc;

        ec->instr_rip = offset;
        ec->instr_max_len = sizeof(ec->instr_buf);
        vm_memory_rw(paddr, ec->instr_buf, sizeof(ec->instr_buf), 0);
        ec->instr = ec->instr_buf;

        buf_off = offset - ec->instr_rip;
    }

#ifdef DEBUG_EMULATE
    debug_printf("emu insn fetch offset=%"PRIx64
                 " bytes %d instr=%02x%02x%02x%02x...\n",
                 offset, bytes,
                 ec->instr_buf[0], ec->instr_buf[1],
                 ec->instr_buf[2], ec->instr_buf[3]);
#endif

    if (buf_off >= 0 && buf_off + bytes <= ec->instr_max_len) {
        memcpy(p_data, ec->instr + buf_off, bytes);
        return X86EMUL_OKAY;
    }

    debug_printf("insn_fetch failed offset %"PRIx64" instr_rip %"PRIx64
        " len %d bytes %d buf_off %"PRIx64"\n",
        offset, ec->instr_rip, ec->instr_max_len, bytes, buf_off);

    return X86EMUL_UNHANDLEABLE;
}

#define EMU_UNSUPPORTED \
  whpx_dump_cpu_state(whpx_get_current_cpu()->cpu_index); \
  whpx_panic("%s: emulation unsupported!\n", __FUNCTION__); \
  return X86EMUL_UNHANDLEABLE;

static int emu_cmpxchg(
    enum x86_segment seg,
    uint64_t offset,
    void *p_old,
    void *p_new,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    EMU_UNSUPPORTED;
}

static int emu_rep_ins(
    uint16_t src_port,
    enum x86_segment dst_seg,
    uint64_t dst_offset,
    unsigned int bytes_per_rep,
    uint64_t *reps,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emu_ctx *ec = container_of(ctxt, struct hvm_emu_ctx, x86_ctx);
    uint64_t daddr;
    uint64_t dgpa;
    uint64_t n;
    int rc;
    int width;
    int unmapped;

    rc = hvmemul_virtual_to_linear(
        dst_seg, dst_offset, bytes_per_rep, reps, hvm_access_write, ec, &daddr);
    if ( rc != X86EMUL_OKAY )
        return rc;
    rc = hvmemul_gva_to_gpa(ec, hvm_access_write, daddr, &dgpa, &unmapped);
    if ( rc != X86EMUL_OKAY )
        return rc;
#ifdef DEBUG_EMULATE
    debug_printf("emu rep ins to linear addr: %"PRIx64" (gpa %"PRIx64") from ioport 0x%x "
                 "bytes-per-rep %d reps %"PRId64"\n",
                 daddr, dgpa,
                 (int)src_port,
                 bytes_per_rep,
                 *reps);
#endif
    n = *reps;
    width = ioport_width(bytes_per_rep, "rep ins: bad rep size: 0x%x\n", (int)bytes_per_rep);
    if (bytes_per_rep > sizeof(uint64_t))
        whpx_panic("bad bytes per rep: %d\n", bytes_per_rep);
    while (n) {
        uint64_t v = ioport_read(width, src_port);
        vm_memory_rw(dgpa, (uint8_t*)&v, bytes_per_rep, 1);
        dgpa += bytes_per_rep;
        --n;
    }
    return X86EMUL_OKAY;
}

static int emu_rep_outs(
    enum x86_segment src_seg,
    uint64_t src_offset,
    uint16_t dst_port,
    unsigned int bytes_per_rep,
    uint64_t *reps,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emu_ctx *ec = container_of(ctxt, struct hvm_emu_ctx, x86_ctx);
    uint64_t saddr;
    uint64_t sgpa;
    uint64_t n;
    uint64_t buf;
    int rc;
    int width;
    int unmapped;
    
    rc = hvmemul_virtual_to_linear(
        src_seg, src_offset, bytes_per_rep, reps, hvm_access_read, ec, &saddr);
    if ( rc != X86EMUL_OKAY )
        return rc;
    rc = hvmemul_gva_to_gpa(ec, hvm_access_read, saddr, &sgpa, &unmapped);
    if ( rc != X86EMUL_OKAY )
        return rc;
#ifdef DEBUG_EMULATE
    debug_printf("emu rep outs from linear addr: %"PRIx64" (gpa %"PRIx64") to ioport 0x%x "
                 "bytes-per-rep %d reps %"PRId64"\n",
                 saddr, sgpa,
                 (int)dst_port,
                 bytes_per_rep,
                 *reps);
#endif
    n = *reps;
    width = ioport_width(bytes_per_rep, "rep outs: bad rep size: 0x%x\n", (int)bytes_per_rep);
    if (bytes_per_rep > sizeof(buf))
        whpx_panic("bad bytes per rep: %d\n", bytes_per_rep);
    while (n) {
        buf = 0;
        vm_memory_rw(sgpa, (uint8_t*)&buf, bytes_per_rep, 0);
#ifdef DEBUG_IOPORT
        if (dst_port != DEBUG_PORT_NUMBER)
            debug_printf("emu rep write IOPORT 0x%x size=%d value=0x%"PRIx64"\n", dst_port, bytes_per_rep, buf);
#endif
        ioport_write(width, dst_port, buf);
        sgpa += bytes_per_rep;
        --n;
    }
    return X86EMUL_OKAY;
}

static int emu_rep_movs(
    enum x86_segment src_seg,
    uint64_t src_offset,
    enum x86_segment dst_seg,
    uint64_t dst_offset,
    unsigned int bytes_per_rep,
    uint64_t *reps,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emu_ctx *ec = container_of(ctxt, struct hvm_emu_ctx, x86_ctx);
    uint64_t saddr, daddr;
    uint64_t sgpa, dgpa;
    uint64_t n;
    uint64_t buf;
    int rc;
    int unmapped_s, unmapped_d;

    rc = hvmemul_virtual_to_linear(
        src_seg, src_offset, bytes_per_rep, reps, hvm_access_read, ec, &saddr);
    if ( rc != X86EMUL_OKAY )
        return rc;
    rc = hvmemul_virtual_to_linear(
        dst_seg, dst_offset, bytes_per_rep, reps, hvm_access_write, ec, &daddr);
    if ( rc != X86EMUL_OKAY )
        return rc;
    rc = hvmemul_gva_to_gpa(ec, hvm_access_read, saddr, &sgpa, &unmapped_s);
    if ( rc != X86EMUL_OKAY )
        return rc;
    rc = hvmemul_gva_to_gpa(ec, hvm_access_write, daddr, &dgpa, &unmapped_d);
    if ( rc != X86EMUL_OKAY )
        return rc;
#ifdef DEBUG_EMULATE
    debug_printf("emu rep movs from linear addr: %"PRIx64" (gpa %"PRIx64") to linear addr: %"PRIx64" (gpa %"PRIx64") "
                 "bytes-per-rep %d reps %"PRId64"\n",
                 saddr, sgpa,
                 daddr, dgpa,
                 bytes_per_rep,
                 *reps);
#endif
    n = *reps;
    if (bytes_per_rep > sizeof(buf))
        whpx_panic("bad bytes per rep: %d\n", bytes_per_rep);
    while (n) {
        vm_memory_rw(sgpa, (uint8_t*)&buf, bytes_per_rep, 0);
        vm_memory_rw(dgpa, (uint8_t*)&buf, bytes_per_rep, 1);
        sgpa += bytes_per_rep;
        dgpa += bytes_per_rep;
        --n;
    }
    return X86EMUL_OKAY;
}

static int emu_read_segment(
    enum x86_segment seg,
    struct segment_register *reg,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emu_ctx *ec = container_of(ctxt, struct hvm_emu_ctx, x86_ctx);
    struct segment_register *sreg = hvmemul_get_seg_reg(seg, ec);

    memcpy(reg, sreg, sizeof(struct segment_register));
    return X86EMUL_OKAY;
}

static int emu_write_segment(
    enum x86_segment seg,
    struct segment_register *reg,
    struct x86_emulate_ctxt *ctxt)
{
    EMU_UNSUPPORTED;
}

static int emu_read_io(
    unsigned int port,
    unsigned int bytes,
    uint64_t *val,
    struct x86_emulate_ctxt *ctxt)
{
    return emu_simple_port_io(0, port, bytes, val);
}

static int emu_write_io(
    unsigned int port,
    unsigned int bytes,
    uint64_t val,
    struct x86_emulate_ctxt *ctxt)
{
    return emu_simple_port_io(1, port, bytes, &val);
}

static int emu_read_cr(
        unsigned int reg,
        uint64_t *val,
        struct x86_emulate_ctxt *ctxt)
{
    EMU_UNSUPPORTED;
}

static int emu_write_cr(
    unsigned int reg,
    uint64_t val,
    struct x86_emulate_ctxt *ctxt)
{
    EMU_UNSUPPORTED;
}

static int emu_read_dr(
    unsigned int reg,
    uint64_t *val,
    struct x86_emulate_ctxt *ctxt)
{
    EMU_UNSUPPORTED;
}

static int emu_write_dr(
    unsigned int reg,
    uint64_t val,
    struct x86_emulate_ctxt *ctxt)
{
    EMU_UNSUPPORTED;
}

static int emu_read_msr(
    uint64_t reg,
    uint64_t *val,
    struct x86_emulate_ctxt *ctxt)
{
    EMU_UNSUPPORTED;
}

static int emu_write_msr(
    uint64_t reg,
    uint64_t val,
    struct x86_emulate_ctxt *ctxt)
{
    EMU_UNSUPPORTED;
}

static int emu_wbinvd(
    struct x86_emulate_ctxt *ctxt)
{
    EMU_UNSUPPORTED;
}

static int emu_cpuid(
    unsigned int *eax,
    unsigned int *ebx,
    unsigned int *ecx,
    unsigned int *edx,
    struct x86_emulate_ctxt *ctxt)
{
    EMU_UNSUPPORTED;
}

static int emu_inject_hw_exception(
    uint8_t vector,
    int32_t error_code,
    struct x86_emulate_ctxt *ctxt)
{
    EMU_UNSUPPORTED;
}

static int emu_inject_sw_interrupt(
    uint8_t vector,
    uint8_t insn_len,
    struct x86_emulate_ctxt *ctxt)
{
    EMU_UNSUPPORTED;
}

static int emu_get_fpu(
    void (*exception_callback)(void *, struct x86_cpu_user_regs *),
    void *exception_callback_arg,
    enum x86_emulate_fpu_type type,
    struct x86_emulate_ctxt *ctxt)
{
    EMU_UNSUPPORTED;
}

static void emu_put_fpu(
    struct x86_emulate_ctxt *ctxt)
{
    debug_printf("%s: emulation unsupported\n", __FUNCTION__);
}

static int emu_invlpg(
    enum x86_segment seg,
    uint64_t offset,
    struct x86_emulate_ctxt *ctxt
    )
{
    EMU_UNSUPPORTED;
}

static struct x86_emulate_ops emulate_ops = {
    .read = emu_read,
    .write = emu_write,
    .insn_fetch = emu_insn_fetch,
    .cmpxchg = emu_cmpxchg,
    .rep_ins = emu_rep_ins,
    .rep_outs = emu_rep_outs,
    .rep_movs = emu_rep_movs,
    .read_segment = emu_read_segment,
    .write_segment = emu_write_segment,
    .read_io = emu_read_io,
    .write_io = emu_write_io,
    .read_cr = emu_read_cr,
    .write_cr = emu_write_cr,
    .read_dr = emu_read_dr,
    .write_dr = emu_write_dr,
    .read_msr = emu_read_msr,
    .write_msr = emu_write_msr,
    .wbinvd = emu_wbinvd,
    .cpuid = emu_cpuid,
    .inject_hw_exception = emu_inject_hw_exception,
    .inject_sw_interrupt = emu_inject_sw_interrupt,
    .get_fpu = emu_get_fpu,
    .put_fpu = emu_put_fpu,
    .invlpg = emu_invlpg,
    
};

#define from_sreg(r, v) qemusr_to_sr(s, r, v);

void readwrite_regs(struct hvm_emu_cpu *cpu, int write)
{
    CPUState *s = cpu->state;
    struct hvm_emu_cpu_regs *r = &cpu->regs;
    struct x86_cpu_user_regs *ur = &r->uregs;
    
    if (!write) {
        ur->r15 = s->regs[15];
        ur->r14 = s->regs[14];
        ur->r13 = s->regs[13];
        ur->r12 = s->regs[12];
        ur->rbp = s->regs[R_EBP];
        ur->rbx = s->regs[R_EBX];
        ur->r11 = s->regs[11];
        ur->r10 = s->regs[10];
        ur->r9 = s->regs[9];
        ur->r8 = s->regs[8];
        ur->rax = s->regs[R_EAX];
        ur->rcx = s->regs[R_ECX];
        ur->rdx = s->regs[R_EDX];
        ur->rsi = s->regs[R_ESI];
        ur->rdi = s->regs[R_EDI];
        ur->rip = s->eip;
        ur->rflags = s->eflags;
        ur->rsp = s->regs[R_ESP];

        from_sreg(&s->segs[R_CS], &r->seg_reg[x86_seg_cs]);
        from_sreg(&s->segs[R_SS], &r->seg_reg[x86_seg_ss]);
        from_sreg(&s->segs[R_ES], &r->seg_reg[x86_seg_es]);
        from_sreg(&s->segs[R_DS], &r->seg_reg[x86_seg_ds]);
        from_sreg(&s->segs[R_FS], &r->seg_reg[x86_seg_fs]);
        from_sreg(&s->segs[R_GS], &r->seg_reg[x86_seg_gs]);

        r->efer = s->efer;
        r->cr[0] = s->cr[0];
        r->cr[3] = s->cr[3];
        r->cr[4] = s->cr[4];
    } else {
        s->regs[15] = ur->r15;
        s->regs[14] = ur->r14;
        s->regs[13] = ur->r13;
        s->regs[12] = ur->r12;
        s->regs[R_EBP] = ur->rbp;
        s->regs[R_EBX] = ur->rbx;
        s->regs[11] = ur->r11;
        s->regs[10] = ur->r10;
        s->regs[9] = ur->r9;
        s->regs[8] = ur->r8;
        s->regs[R_EAX] = ur->rax;
        s->regs[R_ECX] = ur->rcx;
        s->regs[R_EDX] = ur->rdx;
        s->regs[R_ESI] = ur->rsi;
        s->regs[R_EDI] = ur->rdi;
        s->eip = ur->rip;
        s->eflags = ur->rflags;
        s->regs[R_ESP] = ur->rsp;

        /* emulation should've not modified cr0,cr3,cr4,efer */
        // assert (s->cr[0] == r->cr[0]);
        // assert (s->cr[3] == r->cr[3]);
        // assert (s->cr[4] == r->cr[4]);
        // assert (s->efer  == r->efer);

        /* emulation won't set segment regs */
    }
}

#define is_canonical_address(x) (((int64_t)(x) >> 47) == ((int64_t)(x) >> 63))

int hvm_virtual_to_linear_addr(
    struct hvm_emu_cpu *cpu,
    enum x86_segment seg,
    struct segment_register *reg,
    uint64_t offset,
    unsigned int bytes,
    enum hvm_access_type access_type,
    unsigned int addr_size,
    uint64_t *linear_addr)
{
    uint64_t addr = offset;
    uint32_t last_byte;

    if ( !(cpu->regs.cr[0] & X86_CR0_PE) )
    {
        /*
         * REAL MODE: Don't bother with segment access checks.
         * Certain of them are not done in native real mode anyway.
         */
        addr = (uint32_t)(addr + reg->base);
    }
    else if ( addr_size != 64 )
    {
        /*
         * COMPATIBILITY MODE: Apply segment checks and add base.
         */
        switch ( access_type )
        {
        case hvm_access_read:
            if ( (reg->attr.fields.type & 0xa) == 0x8 )
                goto gpf; /* execute-only code segment */
            break;
        case hvm_access_write:
            if ( (reg->attr.fields.type & 0xa) != 0x2 )
                goto gpf; /* not a writable data segment */
            break;
        default:
            break;
        }

        last_byte = offset + bytes - 1;

        /* Is this a grows-down data segment? Special limit check if so. */
        if ( (reg->attr.fields.type & 0xc) == 0x4 )
        {
            /* Is upper limit 0xFFFF or 0xFFFFFFFF? */
            if ( !reg->attr.fields.db )
                last_byte = (uint16_t)last_byte;

            /* Check first byte and last byte against respective bounds. */
            if ( (offset <= reg->limit) || (last_byte < offset) )
                goto gpf;
        }
        else if ( (last_byte > reg->limit) || (last_byte < offset) )
            goto gpf; /* last byte is beyond limit or wraps 0xFFFFFFFF */

        /*
         * Hardware truncates to 32 bits in compatibility mode.
         * It does not truncate to 16 bits in 16-bit address-size mode.
         */
        addr = (uint32_t)(addr + reg->base);
    }
    else
    {
        /*
         * LONG MODE: FS and GS add segment base. Addresses must be canonical.
         */

        if ( (seg == x86_seg_fs) || (seg == x86_seg_gs) )
            addr += reg->base;

        if ( !is_canonical_address(addr) )
            goto gpf;
    }

    *linear_addr = addr;
    return 1;

 gpf:
    return 0;
}

static int hvmemul_gva_to_gpa(
    struct hvm_emu_ctx *hvmemul_ctxt,
    enum hvm_access_type access,
    uint64_t gva,
    uint64_t *gpa,
    int *unmapped
    )
{
    struct hvm_emu_cpu *cpu = hvmemul_ctxt->cpu;

    *unmapped = 0;
    if (whpx_translate_gva_to_gpa(cpu->state, access == hvm_access_write, gva, gpa, unmapped) != 0) {
#ifdef NONFATAL_UNMAPPED_IO
        if (*unmapped)
            return X86EMUL_OKAY;
#else
        if (*unmapped) {
            whpx_panic("unmapped MMIO %s gva %"PRIx64" gpa %"PRIx64"\n",
                access == hvm_access_write ? "write":"read", gva, *gpa);
        }
#endif
        hvmemul_ctxt->exn_pending = 1;
        hvmemul_ctxt->exn_vector = TRAP_gp_fault;
        hvmemul_ctxt->exn_error_code = 0;
        hvmemul_ctxt->exn_insn_len = 0;

        return X86EMUL_EXCEPTION;
    }
    return X86EMUL_OKAY;
}

static int hvmemul_virtual_to_linear(
    enum x86_segment seg,
    uint64_t offset,
    unsigned int bytes_per_rep,
    uint64_t *reps,
    enum hvm_access_type access_type,
    struct hvm_emu_ctx *hvmemul_ctxt,
    uint64_t *paddr)
{
    struct segment_register *reg;
    struct hvm_emu_cpu_regs *regs = &hvmemul_ctxt->cpu->regs;
    int okay;

    if ( seg == x86_seg_none )
    {
        *paddr = offset;
        return X86EMUL_OKAY;
    }

    /*
     * Clip repetitions to avoid overflow when multiplying by @bytes_per_rep.
     * The chosen maximum is very conservative but it's what we use in
     * hvmemul_linear_to_phys() so there is no point in using a larger value.
     */
    if (*reps > 4096)
        *reps = 4096;

    reg = hvmemul_get_seg_reg(seg, hvmemul_ctxt);

    if ( (regs->uregs.rflags & X86_EFLAGS_DF) && (*reps > 1) )
    {
        /*
         * x86_emulate() clips the repetition count to ensure we don't wrap
         * the effective-address index register. Hence this assertion holds.
         */
        assert(offset >= ((*reps - 1) * bytes_per_rep));
        okay = hvm_virtual_to_linear_addr(
            hvmemul_ctxt->cpu,
            seg, reg, offset - (*reps - 1) * bytes_per_rep,
            *reps * bytes_per_rep, access_type,
            hvmemul_ctxt->x86_ctx.addr_size, paddr);
        *paddr += (*reps - 1) * bytes_per_rep;
        if ( hvmemul_ctxt->x86_ctx.addr_size != 64 )
            *paddr = (uint32_t)*paddr;
    }
    else
    {
        okay = hvm_virtual_to_linear_addr(
            hvmemul_ctxt->cpu,
            seg, reg, offset, *reps * bytes_per_rep, access_type,
            hvmemul_ctxt->x86_ctx.addr_size, paddr);
    }

    if ( okay )
        return X86EMUL_OKAY;

    /* If this is a string operation, emulate each iteration separately. */
    if ( *reps != 1 )
        return X86EMUL_UNHANDLEABLE;

    /* This is a singleton operation: fail it with an exception. */
    hvmemul_ctxt->exn_pending = 1;
    hvmemul_ctxt->exn_vector = TRAP_gp_fault;
    hvmemul_ctxt->exn_error_code = 0;
    hvmemul_ctxt->exn_insn_len = 0;

    return X86EMUL_EXCEPTION;
}

static
void inject_exception(int cpu, int trap, int error_code)
{
    // TODO: implement
}

whpx_reg_list_t *
emu_get_read_registers(void)
{
    return &emu_read_registers;
}

whpx_reg_list_t *
emu_get_write_registers(void)
{
    return &emu_write_registers;
}


void
emu_registers_hv_to_cpustate(CPUState *cpu, WHV_REGISTER_VALUE *values)
{
    int idx, i;

    /* Indexes for first 16 registers match between HV and QEMU definitions */
    for (idx = 0; idx < CPU_NB_REGS64; idx += 1)
        cpu->regs[idx] = values[idx].Reg64;

    /* Same goes for RIP and RFLAGS */
    cpu->eip = values[idx++].Reg64;
    cpu->eflags = values[idx++].Reg64;

    /* cr0,cr3,cr4,efer is necessary for whpx_translate_gva_to_gpa to work */
    cpu->cr[0] = values[idx++].Reg64;
    cpu->cr[3] = values[idx++].Reg64;
    cpu->cr[4] = values[idx++].Reg64;
    cpu->efer  = values[idx++].Reg64;

    /* Translate 6+4 segment registers. HV and QEMU order matches  */
    for (i = 0; i < 6; i += 1, idx += 1)
        cpu->segs[i] = whpx_seg_h2q(&values[idx].Segment);
}

int
emu_registers_cpustate_to_hv(CPUState *cpu, size_t maxregs, WHV_REGISTER_NAME *names, WHV_REGISTER_VALUE *values)
{
    int idx;
    whpx_reg_list_t *regs = emu_get_write_registers();

    assert(maxregs >= regs->num);
    assert(sizeof(regs->reg[0]) == sizeof(WHV_REGISTER_NAME));

    memcpy(names, &regs->reg[0], regs->num * sizeof(WHV_REGISTER_NAME));

    /* Indexes for first 16 registers match between HV and QEMU definitions */
    for (idx = 0; idx < CPU_NB_REGS64; idx += 1)
        values[idx].Reg64 = cpu->regs[idx];

    /* Same goes for RIP and RFLAGS */
    values[idx++].Reg64 = cpu->eip;
    values[idx++].Reg64 = cpu->eflags;

    /* emulation doesn't modify cr0,cr3,cr4,efer */

    /* emulation doesn't modify segment regs */

    return idx;
}

static
void emu_prepare(struct hvm_emu_ctx *ctx)
{
    struct segment_register *cs = hvmemul_get_seg_reg(x86_seg_cs, ctx);

    if (hvm_long_mode_enabled(ctx->cpu) && cs->attr.fields.l)
        ctx->x86_ctx.addr_size = ctx->x86_ctx.sp_size = 64;
    else {
        struct segment_register *ss = hvmemul_get_seg_reg(x86_seg_ss, ctx);
        ctx->x86_ctx.addr_size = cs->attr.fields.db ? 32 : 16;
        ctx->x86_ctx.sp_size = ss->attr.fields.db ? 32 : 16;
    }

    ctx->x86_ctx.force_writeback = 1;
}

static uint64_t tsum;
static uint64_t iters;

void emu_one(CPUState *cpu_s, void *instr, int instr_max_len)
{
    struct hvm_emu_ctx ctx = { };
    struct hvm_emu_cpu cpu = { };
    int rv;
    uint64_t t0;

    if (EMU_PERF_TEST)
        t0 = _rdtsc();

    cpu.state = cpu_s;
    cpu.index = cpu_s->cpu_index;

    readwrite_regs(&cpu, 0);

    ctx.cpu = &cpu;
    ctx.x86_ctx.regs = &cpu.regs.uregs;
    if (instr && instr_max_len) {
        ctx.instr = instr;
        ctx.instr_rip = cpu_s->eip;
        ctx.instr_max_len = instr_max_len;
    }
    emu_prepare(&ctx);

#ifdef DEBUG_EMULATE
    debug_printf("EMULATION START RIP=%"PRIx64"\n", cpu.regs.uregs.rip);
#endif
    rv = x86_emulate(&ctx.x86_ctx, &emulate_ops);
    if (rv == X86EMUL_EXCEPTION) {
        debug_printf("X86 CPU EXCEPTION IN EMULATION %x\n", ctx.exn_vector);
        inject_exception(cpu.index, ctx.exn_vector, ctx.exn_error_code);
        ctx.exn_pending = 0;
    } else if (rv) {
        whpx_panic("x86_emulate failed with %d\n", rv);
    }
    /* upload modified registers */
    readwrite_regs(&cpu, 1);

    if (EMU_PERF_TEST) {
        tsum += _rdtsc() - t0;
        iters++;
        if (iters % 10000 == 0) {
            debug_printf("avg cycles in emulation %"PRId64"\n", tsum / iters);
            tsum = 0;
            iters = 0;
        }
    }
#ifdef DEBUG_EMULATE
    debug_printf("EMULATION DONE RIP=%"PRIx64"\n", cpu.regs.uregs.rip);
#endif
}

void
emu_init(void)
{
    whpx_reg_list_init(&emu_read_registers, emu_read_register_names);
    whpx_reg_list_init(&emu_write_registers, emu_write_register_names);
}
