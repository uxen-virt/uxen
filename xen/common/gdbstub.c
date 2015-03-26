/*
 * Copyright (C) 2005 Jimi Xenidis <jimix@watson.ibm.com>, IBM Corporation
 * Copyright (C) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan. K.K.
 * 
 * gdbstub arch neutral part
 * Based on x86 cdb (xen/arch/x86/cdb.c) and ppc gdbstub(xen/common/gdbstub.c)
 * But extensively modified.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */
/*
 * uXen changes:
 *
 * Copyright 2011-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * gdbstub: implements the architecture independant parts of the
 * gdb remote protocol.
 */

/* We try to avoid assuming much about what the rest of the system is
   doing.  In particular, dynamic memory allocation is out of the
   question. */

/* Resuming after we've stopped used to work, but more through luck
   than any actual intention.  It doesn't at the moment. */

#include <xen/lib.h>
#include <xen/spinlock.h>
#include <xen/serial.h>
#include <xen/irq.h>
#include <asm/debugger.h>
#include <xen/init.h>
#include <xen/smp.h>
#include <xen/console.h>
#include <xen/errno.h>
#include <xen/delay.h>
#include <xen/init.h>
#include <asm/byteorder.h>

/* Printk isn't particularly safe just after we've trapped to the
   debugger. so avoid it. */
#define dbg_printk(...)
/*#define dbg_printk(...)   printk(__VA_ARGS__)*/

#define GDB_RETRY_MAX   10

struct gdb_cpu_info
{
    atomic_t paused;
    atomic_t ack;
};

static struct gdb_cpu_info gdb_cpu[NR_CPUS];
static atomic_t gdb_smp_paused_count;

static DEFINE_PER_CPU(struct cpu_user_regs *, gdb_regs);
static struct cpu_user_regs *gdb_regs = NULL;

static void
set_gdb_regs(int cpu)
{
    static struct cpu_user_regs null_regs;

    gdb_regs = per_cpu(gdb_regs, cpu);
    if (!gdb_regs) {
        memset(&null_regs, 0, sizeof(struct cpu_user_regs));
        gdb_regs = &null_regs;
    }
}

static void gdb_smp_pause(void);
static void gdb_smp_resume(void);

static char __initdata opt_gdb[30];
string_param("gdb", opt_gdb);

static void gdbstub_console_puts(const char *str);

/* value <-> char (de)serialzers */
static char
hex2char(unsigned long x)
{
    const char array[] = "0123456789abcdef";
    return array[x & 15];
}

static unsigned int
char2hex(unsigned char c)
{
    if ( (c >= '0') && (c <= '9') )
        return c - '0';
    else if ( (c >= 'a') && (c <= 'f') )
        return c - 'a' + 10;
    else if ( (c >= 'A') && (c <= 'F') )
        return c - 'A' + 10;
    return -1;
}

static unsigned char
str2hex(const char *str)
{
    return (char2hex(str[0]) << 4) | char2hex(str[1]);
}

static unsigned long
str2ulong(const char *str, unsigned long bytes)
{
    unsigned long x = 0;
    unsigned long i = 0;

    while ( *str && (i < (bytes * 2)) )
    {
        x <<= 4;
        x += char2hex(*str);
        ++str;
        ++i;
    }

    return x;
}

static unsigned long
str_to_native_ulong(const char *str)
{
    unsigned long x = 0, i = 0;

    while ( *str && (i < BYTES_PER_LONG) )
    {
#ifdef __BIG_ENDIAN
        x <<= 8;
        x += str2hex(str);
#elif defined(__LITTLE_ENDIAN)
        x += (unsigned long)str2hex(str) << (i*8);
#else
# error unknown endian
#endif
        str += 2;
        i++;
    }

    return x;
}

/* gdb io wrappers */
static signed long
gdb_io_write(const char *buf, unsigned long len, struct gdb_context *ctx)
{
    int i;
    for ( i = 0; i < len; i++ )
        serial_putc(ctx->serhnd, buf[i]);
    return i;
}

static int
gdb_io_write_char(u8 data, struct gdb_context *ctx)
{
    return gdb_io_write((char*)&data, 1, ctx);
}

static unsigned char
gdb_io_read(struct gdb_context *ctx)
{
    return serial_getc(ctx->serhnd);
}

/* Receive a command.  Returns -1 on csum error, 0 otherwise. */
/* Does not acknowledge. */
static int 
attempt_receive_packet(struct gdb_context *ctx)
{
    u8 csum;
    u8 received_csum;
    u8 ch;

    /* Skip over everything up to the first '$' */
    while ( (ch = gdb_io_read(ctx)) != '$' )
        continue;

    csum = 0;
    for ( ctx->in_bytes = 0;
          ctx->in_bytes < sizeof(ctx->in_buf);
          ctx->in_bytes++ )
    {
        ch = gdb_io_read(ctx);
        if ( ch == '#' )
            break;
        ctx->in_buf[ctx->in_bytes] = ch;
        csum += ch;
    }

    if ( ctx->in_bytes == sizeof(ctx->in_buf) )
    {
        dbg_printk("WARNING: GDB sent a stupidly big packet.\n");
        return -1;
    }

    ctx->in_buf[ctx->in_bytes] = '\0';
    received_csum = char2hex(gdb_io_read(ctx)) * 16 +
        char2hex(gdb_io_read(ctx));

    return (received_csum == csum) ? 0 : -1;
}

/* Receive a command, discarding up to ten packets with csum
 * errors.  Acknowledges all received packets. */
static int 
receive_command(struct gdb_context *ctx)
{
    int r, count = 0;

    count = 0;
    do {
        r = attempt_receive_packet(ctx);
        gdb_io_write_char((r < 0) ? '-' : '+', ctx);
        count++;
    } while ( (r < 0) && (count < GDB_RETRY_MAX) );

    return r;
}

/* routines to send reply packets */

static void 
gdb_start_packet(struct gdb_context *ctx)
{
    ctx->out_buf[0] = '$';
    ctx->out_offset = 1;
    ctx->out_csum = 0;
}

static void 
gdb_write_to_packet_char(u8 data, struct gdb_context *ctx)
{
    ctx->out_csum += data;
    ctx->out_buf[ctx->out_offset] = data;
    ctx->out_offset++;
}

void 
gdb_write_to_packet(const char *buf, int count, struct gdb_context *ctx)
{
    int x;
    for ( x = 0; x < count; x++ )
        gdb_write_to_packet_char(buf[x], ctx);
}

void 
gdb_write_to_packet_str(const char *buf, struct gdb_context *ctx)
{
    gdb_write_to_packet(buf, strlen(buf), ctx);
}

void
gdb_write_to_packet_hex(unsigned long x, int int_size, struct gdb_context *ctx)
{
    char buf[sizeof(unsigned long) * 2 + 1];
    int i, width = int_size * 2;

    buf[sizeof(unsigned long) * 2] = 0;

    switch ( int_size )
    {
    case sizeof(u8):
    case sizeof(u16):
    case sizeof(u32):
    case sizeof(u64):
        break;
    default:
        dbg_printk("WARNING: %s x: 0x%lx int_size: %d\n",
                   __func__, x, int_size);
        break;
    }

#ifdef __BIG_ENDIAN
    i = sizeof(unsigned long) * 2;
    do {
        buf[--i] = hex2char(x & 15);
        x >>= 4;
    } while ( x );

    while ( (i + width) > (sizeof(unsigned long) * 2) )
        buf[--i] = '0';

    gdb_write_to_packet(&buf[i], width, ctx);
#elif defined(__LITTLE_ENDIAN)
    i = 0;
    while ( i < width )
    {
        buf[i++] = hex2char(x>>4);
        buf[i++] = hex2char(x);
        x >>= 8;
    }
    gdb_write_to_packet(buf, width, ctx);
#else
# error unknown endian
#endif
}

void
gdb_write_to_packet_nhex(unsigned long x, int int_size, struct gdb_context *ctx)
{
    char buf[sizeof(unsigned long) * 2 + 1];
    int i, width = int_size * 2;

    buf[sizeof(unsigned long) * 2] = 0;

    switch ( int_size )
    {
    case sizeof(u8):
    case sizeof(u16):
    case sizeof(u32):
    case sizeof(u64):
        break;
    default:
        dbg_printk("WARNING: %s x: 0x%lx int_size: %d\n",
                   __func__, x, int_size);
        break;
    }

#ifdef __LITTLE_ENDIAN
    i = sizeof(unsigned long) * 2;
    do {
        buf[--i] = hex2char(x & 15);
        x >>= 4;
    } while ( x );

    while ( (i + width) > (sizeof(unsigned long) * 2) )
        buf[--i] = '0';

    gdb_write_to_packet(&buf[i], width, ctx);
#elif defined(__BIG_ENDIAN)
    i = 0;
    while ( i < width )
    {
        buf[i++] = hex2char(x>>4);
        buf[i++] = hex2char(x);
        x >>= 8;
    }
    gdb_write_to_packet(buf, width, ctx);
#else
# error unknown endian
#endif
}

static int
gdb_check_ack(struct gdb_context *ctx)
{
    u8 c = gdb_io_read(ctx);

    switch ( c )
    {
    case '+':
        return 1;
    case '-':
        return 0;
    default:
        printk("Bad ack: %c\n", c);
        return 0;
    }
}

/* Return 0 if the reply was successfully received, !0 otherwise. */
void 
gdb_send_packet(struct gdb_context *ctx)
{
    char buf[3];
    int count;

    snprintf(buf, sizeof(buf), "%.02x\n", ctx->out_csum);

    gdb_write_to_packet_char('#', ctx);
    gdb_write_to_packet(buf, 2, ctx);

    count = 0;
    do {
        gdb_io_write(ctx->out_buf, ctx->out_offset, ctx);
    } while ( !gdb_check_ack(ctx) && (count++ < GDB_RETRY_MAX) );

    if ( count == GDB_RETRY_MAX )
        dbg_printk("WARNING: %s reached max retry %d\n",
                   __func__, GDB_RETRY_MAX);
}

void 
gdb_send_reply(const char *buf, struct gdb_context *ctx)
{
    gdb_start_packet(ctx);
    gdb_write_to_packet_str(buf, ctx);
    gdb_send_packet(ctx);
}

/* arch neutral command handlers */

static void 
gdb_cmd_signum(struct gdb_context *ctx)
{
    gdb_write_to_packet_char('S', ctx);
    gdb_write_to_packet_hex(ctx->signum, sizeof(ctx->signum), ctx);
    gdb_send_packet(ctx);
}

static void 
gdb_cmd_read_mem(unsigned long addr, unsigned long length,
                 struct gdb_context *ctx)
{
    int x, r;
    unsigned char val;

    dbg_printk("Memory read starting at %lx, length %lx.\n", addr,
               length);

    for ( x = 0; x < length; x++ )
    {
        r = gdb_arch_copy_from_user(&val, (void *)(addr + x), 1);
        if ( r != 0 )
        {
            dbg_printk("Error reading from %lx.\n", addr + x);
            break;
        }
        gdb_write_to_packet_hex(val, sizeof(val), ctx);
    }

    if ( x == 0 )
        gdb_write_to_packet_str("E05", ctx);

    dbg_printk("Read done.\n");

    gdb_send_packet(ctx);
}

static void 
gdb_cmd_write_mem(unsigned long addr, unsigned long length,
                  const char *buf, struct gdb_context *ctx)
{
    int x, r;
    unsigned char val;

    dbg_printk("Memory write starting at %lx, length %lx.\n", addr, length);

    for ( x = 0; x < length; x++, addr++, buf += 2 )
    {
        val = str2ulong(buf, sizeof(val));
        r = gdb_arch_copy_to_user((void*)addr, (void*)&val, 1);
        if ( r != 0 )
        {
            dbg_printk("Error writing to %lx.\n", addr);
            break;
        }
    }

    if (x == length)
        gdb_write_to_packet_str("OK", ctx);
    else
        gdb_write_to_packet_str("E11", ctx);

    dbg_printk("Write done.\n");

    gdb_send_packet(ctx);
}

static void
gdbstub_attach(struct gdb_context *ctx)
{
    if ( ctx->currently_attached )
        return;    
    ctx->currently_attached = 1;
    ctx->console_steal_id = console_steal(ctx->serhnd, gdbstub_console_puts);
}

static void
gdbstub_detach(struct gdb_context *ctx)
{
    if ( !ctx->currently_attached )
        return;
    ctx->currently_attached = 0;
    console_giveback(ctx->console_steal_id);
}

static void
gdbstub_handle_query(struct gdb_context *ctx)
{
    static int thread_enum_cursor = 0;

    gdb_start_packet(ctx);

    if (!strcmp("qC", ctx->in_buf)) {
        gdb_write_to_packet_str("QC", ctx);
        gdb_write_to_packet_nhex((int)smp_processor_id() + 1, sizeof(int), ctx);
    } else if (!strcmp("qfThreadInfo", ctx->in_buf)) {
        thread_enum_cursor = cpumask_first(&cpu_online_map);
        gdb_write_to_packet_str("m", ctx);
        gdb_write_to_packet_nhex((int)thread_enum_cursor + 1, sizeof(int), ctx);
    } else if (!strcmp("qsThreadInfo", ctx->in_buf)) {
        thread_enum_cursor = cpumask_next(thread_enum_cursor, &cpu_online_map);
        if (thread_enum_cursor < nr_cpu_ids) {
            gdb_write_to_packet_str("m", ctx);
            gdb_write_to_packet_nhex((int)thread_enum_cursor + 1, sizeof(int),
                                     ctx);
        } else
            gdb_write_to_packet_str("l", ctx);
    } else if (!strcmp("qOffsets", ctx->in_buf)) {
        gdb_write_to_packet_str("Text=", ctx);
        gdb_write_to_packet_hex((uintptr_t)_text_start, sizeof(uintptr_t), ctx);
        gdb_write_to_packet_str(";Data=", ctx);
        gdb_write_to_packet_hex((uintptr_t)_data_start, sizeof(uintptr_t), ctx);
        gdb_write_to_packet_str(";Bss=", ctx);
        gdb_write_to_packet_hex((uintptr_t)_bss_start, sizeof(uintptr_t), ctx);
        gdb_write_to_packet_str(";.rdata=", ctx);
        gdb_write_to_packet_hex((uintptr_t)_rdata_start, sizeof(uintptr_t),
                                ctx);
    } else if (!strncmp("qRcmd,", ctx->in_buf, 6)) {
        int i;
        char cmd[129];
        if (ctx->in_bytes < 8 || ctx->in_bytes > (6 + 256)) {
            gdb_send_reply("E03", ctx);
            return;
        }
        if (ctx->in_bytes & 1) {
            gdb_send_reply("E04", ctx);
            return;
        }
        for (i = 6; i < ctx->in_bytes; i += 2)
            cmd[(i - 6) / 2] = str2hex(&ctx->in_buf[i]);
        cmd[(ctx->in_bytes - 6) / 2] = 0;
        printk("monitor command: %s\n", cmd);
        if (!strcmp(cmd, "current")) {
            snprintf(cmd, sizeof(cmd), "current: %p\n", current);
            gdb_write_to_packet_char('O', ctx);
            for (i = 0; cmd[i]; i++)
                gdb_write_to_packet_hex(cmd[i], sizeof(cmd[i]), ctx);
        } else if (!strcmp(cmd, "vmcs")) {
            snprintf(cmd, sizeof(cmd), "vmcs: %p\n",
                     current->arch.hvm_vmx.vmcs);
            gdb_start_packet(ctx);
            gdb_write_to_packet_char('O', ctx);
            for (i = 0; cmd[i]; i++)
                gdb_write_to_packet_hex(cmd[i], sizeof(cmd[i]), ctx);
            gdb_send_packet(ctx);
            vmcs_dump_vcpu(current);
        }
        gdb_write_to_packet_str("OK", ctx);
    } else
        gdb_write_to_packet_str("", ctx);

    gdb_send_packet(ctx);
}

/* command dispatcher */
static int 
process_command(struct cpu_user_regs *regs, struct gdb_context *ctx)
{
    const char *ptr;
    unsigned long addr, length, val;
    int resume = 0;
    unsigned long type = GDB_CONTINUE;

    /* XXX check ctx->in_bytes >= 2 or similar. */

    gdb_start_packet(ctx);
    switch ( ctx->in_buf[0] )
    {
    case '?':    /* query signal number */
        gdb_cmd_signum(ctx);
        break;
    case 'H':    /* thread operations */
        if (ctx->in_buf[1] == 'g') {
            unsigned long cpu = simple_strtoul(ctx->in_buf + 2, &ptr, 16);
            if (ptr == ctx->in_buf + 2) {
                gdb_send_reply("E03", ctx);
                return 0;
            }
            if (cpu) {
                cpu--;
                if (!cpumask_test_cpu(cpu, &cpu_online_map)) {
                    gdb_send_reply("E04", ctx);
                    return 0;
                }
                set_gdb_regs(cpu);
            }
        }
        gdb_send_reply("OK", ctx);
        break;
    case 'T': {
        unsigned long cpu = simple_strtoul(ctx->in_buf + 1, &ptr, 16);
        if (ptr == ctx->in_buf + 1) {
            gdb_send_reply("E03", ctx);
            return 0;
        }
        if (cpu) {
            cpu--;
            if (!cpumask_test_cpu(cpu, &cpu_online_map)) {
                gdb_send_reply("E04", ctx);
                return 0;
            }
        }
        gdb_send_reply("OK", ctx);
        break;
    }
    case 'g': /* Read registers */
        gdb_arch_read_reg_array(regs, ctx);
        break;
    case 'G': /* Write registers */
        gdb_arch_write_reg_array(regs, ctx->in_buf + 1, ctx);
        break;
    case 'm': /* Read memory */
        addr = simple_strtoul(ctx->in_buf + 1, &ptr, 16);
        if ( (ptr == (ctx->in_buf + 1)) || (ptr[0] != ',') )
        {
            gdb_send_reply("E03", ctx);
            return 0;
        }
        length = simple_strtoul(ptr + 1, &ptr, 16);
        if ( ptr[0] != 0 )
        {
            gdb_send_reply("E04", ctx);
            return 0;
        }
        gdb_cmd_read_mem(addr, length, ctx);
        break;
    case 'M': /* Write memory */
        addr = simple_strtoul(ctx->in_buf + 1, &ptr, 16);
        if ( (ptr == (ctx->in_buf + 1)) || (ptr[0] != ',') )
        {
            gdb_send_reply("E03", ctx);
            return 0;
        }
        length = simple_strtoul(ptr + 1, &ptr, 16);
        if ( ptr[0] != ':')
        {
            gdb_send_reply("E04", ctx);
            return 0;
        }
        gdb_cmd_write_mem(addr, length, ptr + 1, ctx);
        break;
    case 'p': /* read register */
        addr = simple_strtoul(ctx->in_buf + 1, &ptr, 16);
        if ( ptr == (ctx->in_buf + 1) )
        {
            gdb_send_reply("E03", ctx);
            return 0;
        }
        if ( ptr[0] != 0 )
        {
            gdb_send_reply("E04", ctx);
            return 0;
        }
        gdb_arch_read_reg(addr, regs, ctx);
        break;
    case 'P': /* write register */
        addr = simple_strtoul(ctx->in_buf + 1, &ptr, 16);
        if ( ptr == (ctx->in_buf + 1) )
        {
            gdb_send_reply("E03", ctx);
            return 0;
        }
        if ( ptr[0] != '=' )
        {
            gdb_send_reply("E04", ctx);
            return 0;
        }
        ptr++;
        val = str_to_native_ulong(ptr);
        gdb_arch_write_reg(addr, val, regs, ctx);
        break;
    case 'D':
    case 'k':
        gdbstub_detach(ctx);
        gdb_send_reply("OK", ctx);
        ctx->connected = 0;
        resume = 1;
        break;
    case 's': /* Single step */
        type = GDB_STEP;
    case 'c': /* Resume at current address */
        addr = ~((unsigned long)0);

        if ( ctx->in_buf[1] )
            addr = str2ulong(&ctx->in_buf[1], sizeof(unsigned long));
        gdbstub_attach(ctx);
        resume = 1;
        gdb_arch_resume(regs, addr, type, ctx);
        break;
    case 'q':
        gdbstub_handle_query(ctx);
        break;
    default:
        gdb_send_reply("", ctx);
        break;
    }
    return resume;
}

static struct gdb_context
__gdb_ctx = {
    .serhnd  = -1,
    .running = ATOMIC_INIT(1),
    .signum  = 1
};
static struct gdb_context *gdb_ctx = &__gdb_ctx;

static void
gdbstub_console_puts(const char *str)
{
    const char *p;

    gdb_start_packet(gdb_ctx);
    gdb_write_to_packet_char('O', gdb_ctx);

    for ( p = str; *p != '\0'; p++ )
    {
        gdb_write_to_packet_char(hex2char((*p>>4) & 0x0f), gdb_ctx );
        gdb_write_to_packet_char(hex2char((*p) & 0x0f), gdb_ctx );
    }

    gdb_send_packet(gdb_ctx);
}

/* trap handler: main entry point */
int 
__trap_to_gdb(struct cpu_user_regs *regs, unsigned long cookie)
{
    unsigned int cpu;
    unsigned long flags;
    int rc = 0;

    if ( gdb_ctx->serhnd < 0 )
    {
        printk("Debugging connection not set up.\n");
        return -EBUSY;
    }

    /* We rely on our caller to ensure we're only on one processor
     * at a time... We should probably panic here, but given that
     * we're a debugger we should probably be a little tolerant of
     * things going wrong. */
    /* We don't want to use a spin lock here, because we're doing
       two distinct things:

       1 -- we don't want to run on more than one processor at a time,
            and
       2 -- we want to do something sensible if we re-enter ourselves.

       Spin locks are good for 1, but useless for 2. */
    if ( !atomic_dec_and_test(&gdb_ctx->running) )
    {
        printk("WARNING WARNING WARNING: Avoiding recursive gdb.\n");
        atomic_inc(&gdb_ctx->running);
        return -EBUSY;
    }

    if ( !gdb_ctx->connected )
    {
        printk("GDB connection activated. (cpu %d)\n", smp_processor_id());
        gdb_arch_print_state(regs);
        gdb_ctx->connected = 1;
    }

    for_each_online_cpu(cpu)
        per_cpu(gdb_regs, cpu) = NULL;

    cpu_irq_save(flags);

    gdb_smp_pause();

    this_cpu(gdb_regs) = regs;
    gdb_regs = this_cpu(gdb_regs);

    watchdog_disable();
    console_start_sync();

    gdb_arch_enter(gdb_regs);
    gdb_ctx->signum = gdb_arch_signal_num(gdb_regs, cookie);

    for_each_online_cpu(cpu)
        printk("cpu %d regs %p\n", cpu, per_cpu(gdb_regs, cpu));

    /* If gdb is already attached, tell it we've stopped again. */
    if ( gdb_ctx->currently_attached )
    {
        gdb_start_packet(gdb_ctx);
        gdb_cmd_signum(gdb_ctx);
    }

    do {
        if ( receive_command(gdb_ctx) < 0 )
        {
            dbg_printk("Error in GDB session...\n");
            rc = -EIO;
            break;
        }
    } while ( process_command(gdb_regs, gdb_ctx) == 0 );

    gdb_smp_resume();

    gdb_arch_exit(regs);
    console_end_sync();
    watchdog_enable();
    atomic_inc(&gdb_ctx->running);

    cpu_irq_restore(flags);

    return rc;
}

static int __init initialise_gdb(void)
{
    if ( *opt_gdb == '\0' )
        return 0;

    gdb_ctx->serhnd = serial_parse_handle(opt_gdb);
    if ( gdb_ctx->serhnd == -1 )
    {
        printk("Bad gdb= option '%s'\n", opt_gdb);
        return 0;
    }

    serial_start_sync(gdb_ctx->serhnd);

    printk("GDB stub initialised.\n");

    return 0;
}
presmp_initcall(initialise_gdb);

void gdb_pause_this_cpu(void *_regs)
{
    struct cpu_user_regs null_regs = { };
    unsigned long flags;

    cpu_irq_save(flags);

    this_cpu(gdb_regs) = (struct cpu_user_regs *)_regs;
    if (!this_cpu(gdb_regs)) {
#ifdef __x86_64__
        asm("mov %%rsp, %0" : "=g" (null_regs.rsp) : : "memory");
#else
        asm("mov %%esp, %0" : "=g" (null_regs.esp) : : "memory");
#endif
        null_regs.eip = (uintptr_t)current_text_addr();
        this_cpu(gdb_regs) = &null_regs;
    }

    atomic_set(&gdb_cpu[smp_processor_id()].ack, 1);
    atomic_inc(&gdb_smp_paused_count);

    while ( atomic_read(&gdb_cpu[smp_processor_id()].paused) )
        mdelay(1);

    atomic_dec(&gdb_smp_paused_count);
    atomic_set(&gdb_cpu[smp_processor_id()].ack, 0);

    /* Restore interrupts */
    cpu_irq_restore(flags);
}

static void gdb_smp_pause(void)
{
    int cpu;
    cpumask_t m;

    for_each_online_cpu(cpu)
    {
        atomic_set(&gdb_cpu[cpu].ack, 0);
        atomic_set(&gdb_cpu[cpu].paused, 1);
    }

    atomic_set(&gdb_smp_paused_count, 0);

    cpumask_andnot(&m, &cpu_online_map, cpumask_of(smp_processor_id()));
    send_IPI_mask(&m, GDB_STOP_VECTOR);

    /* Wait 10ms for other CPUs to enter pause loop */
    mdelay(10);

    if ( atomic_read(&gdb_smp_paused_count) < (num_online_cpus() - 1) )
    {
        printk("GDB: Not all CPUs have paused, missing CPUs ");
        for_each_online_cpu(cpu)
        {
            if ( (cpu != smp_processor_id()) &&
                 !atomic_read(&gdb_cpu[cpu].ack) )
                printk("%d ", cpu);
        }
        printk("\n");
    }
}

static void gdb_smp_resume(void)
{
    int cpu;
    int timeout = 100;

    for_each_online_cpu(cpu)
        atomic_set(&gdb_cpu[cpu].paused, 0);

    /* Make sure all CPUs resume */
    while ( (atomic_read(&gdb_smp_paused_count) > 0)
            && (timeout-- > 0) )
        mdelay(1);

    if ( atomic_read(&gdb_smp_paused_count) > 0 )
    {
        printk("GDB: Not all CPUs have resumed execution, missing CPUs ");
        for_each_online_cpu(cpu)
        {
            if ( (cpu != smp_processor_id()) &&
                 atomic_read(&gdb_cpu[cpu].ack) )
                printk("%d ", cpu);
        }
        printk("\n");
    }
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * End:
 */
