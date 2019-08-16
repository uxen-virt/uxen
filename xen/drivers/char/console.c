/******************************************************************************
 * console.c
 * 
 * Emergency console I/O for Xen and the domain-0 guest OS.
 * 
 * Copyright (c) 2002-2004, K A Fraser.
 *
 * Added printf_ratelimit
 *     Taken from Linux - Author: Andi Kleen (net_ratelimit)
 *     Ported to Xen - Steven Rostedt - Red Hat
 */
/*
 * uXen changes:
 *
 * Copyright 2011-2019, Bromium, Inc.
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

#include <xen/version.h>
#include <xen/lib.h>
#include <xen/event.h>
#include <xen/console.h>
#include <xen/serial.h>
#include <xen/softirq.h>
#include <xen/keyhandler.h>
#include <xen/delay.h>
#include <xen/guest_access.h>
#include <xen/shutdown.h>
#include <xen/vga.h>
#include <xen/kexec.h>
#include <asm/debugger.h>
#include <asm/div64.h>
#include <xen/hypercall.h> /* for do_console_io */

/* console: comma-separated list of console outputs. */
static char __initdata opt_console[30] = OPT_CONSOLE_STR;
string_param("console", opt_console);

/* sync_console: force synchronous console output (useful for debugging). */
static bool_t __initdata opt_sync_console = 1;
boolean_param("sync_console", opt_sync_console);

/* console_timestamps: include a timestamp prefix on every Xen console line. */
static bool_t __read_mostly opt_console_timestamps;
boolean_param("console_timestamps", opt_console_timestamps);

static int __read_mostly sercon_handle = -1;

static DEFINE_SPINLOCK(console_lock);

static int printk_ratelimit(int);

/*
 * To control the amount of printing, thresholds are added.
 * These thresholds correspond to the XENLOG logging levels.
 * There's an upper and lower threshold for non-guest messages and for
 * guest-provoked messages.  This works as follows, for a given log level L:
 *
 * L < lower_threshold                     : always logged
 * lower_threshold <= L < upper_threshold  : rate-limited logging
 * upper_threshold <= L                    : never logged
 *
 * Note, in the above algorithm, to disable rate limiting simply make
 * the lower threshold equal to the upper.
 */
#ifdef NDEBUG
#define XENLOG_UPPER_THRESHOLD       2 /* Do not print INFO and DEBUG  */
#define XENLOG_LOWER_THRESHOLD       2 /* Always print ERR and WARNING */
#define XENLOG_GUEST_UPPER_THRESHOLD 3 /* Do not print DEBUG           */
#define XENLOG_GUEST_LOWER_THRESHOLD 0 /* Rate-limit ERR / WARNING / INFO */
#else
#define XENLOG_UPPER_THRESHOLD       3 /* Do not print DEBUG           */
#define XENLOG_LOWER_THRESHOLD       3 /* Always print ERR / WARNING / INFO */
#define XENLOG_GUEST_UPPER_THRESHOLD 3 /* Do not print DEBUG           */
#define XENLOG_GUEST_LOWER_THRESHOLD 3 /* Always print ERR / WARNING / INFO */
#endif
/*
 * The XENLOG_DEFAULT is the default given to printks that
 * do not have any print level associated with them.
 */
#define XENLOG_DEFAULT       1 /* XENLOG_WARNING */
#define XENLOG_GUEST_DEFAULT 1 /* XENLOG_WARNING */

static int __read_mostly xenlog_upper_thresh = XENLOG_UPPER_THRESHOLD;
static int __read_mostly xenlog_lower_thresh = XENLOG_LOWER_THRESHOLD;
static int __read_mostly xenlog_guest_upper_thresh = XENLOG_GUEST_UPPER_THRESHOLD;
static int __read_mostly xenlog_guest_lower_thresh = XENLOG_GUEST_LOWER_THRESHOLD;

static atomic_t print_everything = ATOMIC_INIT(0);

#ifdef __UXEN_console__
static char * __init loglvl_str(int lvl)
{
    switch ( lvl )
    {
    case 0: return "Nothing";
    case 1: return "Errors";
    case 2: return "Errors and warnings";
    case 3: return "Errors, warnings and info";
    case 4: return "All";
    }
    return "???";
}
#endif  /* __UXEN_console__ */


/*
 * *******************************************************
 * *************** ACCESS TO SERIAL LINE *****************
 * *******************************************************
 */

static void (*serial_steal_fn)(const char *);

int console_steal(int handle, void (*fn)(const char *))
{
    if ( (handle == -1) || (handle != sercon_handle) )
        return 0;

    if ( serial_steal_fn != NULL )
        return -EBUSY;

    serial_steal_fn = fn;
    return 1;
}

void console_giveback(int id)
{
    if ( id == 1 )
        serial_steal_fn = NULL;
}

int uxen_printk_enabled = 1;

#define UXEN_DMSG_MAXLINE 255
static DEFINE_PER_CPU(char [UXEN_DMSG_MAXLINE + 1], dmsgbuf);

static void
uxen_puts(const char *s)
{
    struct vm_info_shared *vmi =
        current ? current->domain->vm_info_shared : NULL;
    char *dmsgbuf = this_cpu(dmsgbuf);
    int used, new, copy;
    const char *p;

    used = strlen(dmsgbuf);
    while ((new = strlen(s))) {
        p = strchr(s, '\n');
        if (p)
            copy = (int)(p + 1 - s);
        else
            copy = new;
        if (used + copy > UXEN_DMSG_MAXLINE)
            copy = UXEN_DMSG_MAXLINE - used;
        memcpy(dmsgbuf + used, s, copy);
        s += copy;
        used += copy;
        dmsgbuf[used] = 0;
        if (dmsgbuf[used - 1] == '\n' || used == UXEN_DMSG_MAXLINE) {
            UI_HOST_CALL(ui_printf, vmi, "%s", dmsgbuf);
            used = 0;
            dmsgbuf[used] = 0;
        }
    }
}

static void sercon_puts(const char *s)
{
    if ( serial_steal_fn != NULL )
        (*serial_steal_fn)(s);
    else {
        if (sercon_handle != -1)
            serial_puts(sercon_handle, s);
        if (uxen_printk_enabled)
            uxen_puts(s);
    }
}

static void __serial_rx(char c, struct cpu_user_regs *regs)
{
    return handle_keypress(c, regs);
}

static void serial_rx(char c, struct cpu_user_regs *regs)
{

    /* Finally process the just-received character. */
    __serial_rx(c, regs);
}


/*
 * *****************************************************
 * *************** GENERIC CONSOLE I/O *****************
 * *****************************************************
 */

static void __putstr(const char *str)
{

    ASSERT(spin_is_locked(&console_lock));

    sercon_puts(str);
}

static int printk_prefix_check(char *p, char **pp)
{
    int loglvl = -1;
    int upper_thresh = xenlog_upper_thresh;
    int lower_thresh = xenlog_lower_thresh;
    int per_guest = 0;

    while ( (p[0] == '<') && (p[1] != '\0') && (p[2] == '>') )
    {
        switch ( p[1] )
        {
        case 'G':
            upper_thresh = xenlog_guest_upper_thresh;
            lower_thresh = xenlog_guest_lower_thresh;
            if ( loglvl == -1 )
                loglvl = XENLOG_GUEST_DEFAULT;
            per_guest = 1;
            break;
        case '0' ... '3':
            loglvl = p[1] - '0';
            break;
        }
        p += 3;
    }

    if ( loglvl == -1 )
        loglvl = XENLOG_DEFAULT;

    *pp = p;

    return ((atomic_read(&print_everything) != 0) ||
            (loglvl < lower_thresh) ||
            ((loglvl < upper_thresh) && printk_ratelimit(per_guest)));
} 

static void printk_start_of_line(void)
{
    struct tm tm;
    char tstr[32];

    __putstr("(uXEN) ");

    if ( !opt_console_timestamps )
        return;

    tm = wallclock_time();
    if ( tm.tm_mday == 0 )
        return;

    snprintf(tstr, sizeof(tstr), "[%04u-%02u-%02u %02u:%02u:%02u] ",
             1900 + tm.tm_year, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
    __putstr(tstr);
}

void vprintk(const char *fmt, va_list args)
{
    static char   buf[1024];
    static int    start_of_line = 1, do_print;

    char         *p, *q;
    unsigned long flags;

    /* console_lock can be acquired recursively from __printk_ratelimit(). */
    local_irq_save(flags);
    spin_lock_recursive(&console_lock);

    (void)vsnprintf(buf, sizeof(buf), fmt, args);

    p = buf;

    while ( (q = strchr(p, '\n')) != NULL )
    {
        *q = '\0';
        if ( start_of_line )
            do_print = printk_prefix_check(p, &p);
        if ( do_print )
        {
            if ( start_of_line )
                printk_start_of_line();
            __putstr(p);
            __putstr("\n");
        }
        start_of_line = 1;
        p = q + 1;
    }

    if ( *p != '\0' )
    {
        if ( start_of_line )
            do_print = printk_prefix_check(p, &p);
        if ( do_print )
        {
            if ( start_of_line )
                printk_start_of_line();
            __putstr(p);
        }
        start_of_line = 0;
    }

    spin_unlock_recursive(&console_lock);
    local_irq_restore(flags);
}

void printk(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vprintk(fmt, args);
    va_end(args);
}

void __init console_init_preirq(void)
{
    char *p;

    serial_init_preirq();

    /* Where should console output go? */
    for ( p = opt_console; p != NULL; p = strchr(p, ',') )
    {
        if ( *p == ',' )
            p++;
        if ( strncmp(p, "com", 3) ||
             (sercon_handle = serial_parse_handle(p)) == -1 )
        {
            char *q = strchr(p, ',');
            if ( q != NULL )
                *q = '\0';
            printk("Bad console= option '%s'\n", p);
            if ( q != NULL )
                *q = ',';
        }
    }

    serial_set_rx_handler(sercon_handle, serial_rx);

    /* HELLO WORLD --- start-of-day banner text. */
    spin_lock_recursive(&console_lock);
    printk("%.*s by christian limpach\n", (int)strlen(xen_banner()) - 23,
           xen_banner());
    spin_unlock_recursive(&console_lock);
    printk("uXen version %d.%d%s (%s@%s) (%s) %s\n",
           xen_major_version(), xen_minor_version(), xen_extra_version(),
           xen_compile_by(), xen_compile_domain(),
           xen_compiler(), xen_compile_date());
    printk("Latest ChangeSet: %s\n", xen_changeset());

    if ( opt_sync_console )
    {
        serial_start_sync(sercon_handle);
        add_taint(TAINT_SYNC_CONSOLE);
        printk("Console output is synchronous.\n");
    }
}

void __init console_init_postirq(void)
{

    serial_init_postirq();

}

#ifdef __UXEN_console__
void __init console_endboot(void)
{
    int i, j;

    printk("Std. Loglevel: %s", loglvl_str(xenlog_lower_thresh));
    if ( xenlog_upper_thresh != xenlog_lower_thresh )
        printk(" (Rate-limited: %s)", loglvl_str(xenlog_upper_thresh));
    printk("\nGuest Loglevel: %s", loglvl_str(xenlog_guest_lower_thresh));
    if ( xenlog_guest_upper_thresh != xenlog_guest_lower_thresh )
        printk(" (Rate-limited: %s)", loglvl_str(xenlog_guest_upper_thresh));
    printk("\n");

    if ( opt_sync_console )
    {
        printk("**********************************************\n");
        printk("******* WARNING: CONSOLE OUTPUT IS SYNCHRONOUS\n");
        printk("******* This option is intended to aid debugging "
               "of Xen by ensuring\n");
        printk("******* that all output is synchronously delivered "
               "on the serial line.\n");
        printk("******* However it can introduce SIGNIFICANT latencies "
               "and affect\n");
        printk("******* timekeeping. It is NOT recommended for "
               "production use!\n");
        printk("**********************************************\n");
        for ( i = 0; i < 3; i++ )
        {
            printk("%d... ", 3-i);
            for ( j = 0; j < 100; j++ )
            {
                process_pending_softirqs();
                mdelay(10);
            }
        }
        printk("\n");
    }

    vga_endboot();

    /*
     * If user specifies so, we fool the switch routine to redirect input
     * straight back to Xen. I use this convoluted method so we still print
     * a useful 'how to switch' message.
     */
    if ( opt_conswitch[1] == 'x' )
        xen_rx = !xen_rx;

    /* Serial input is directed to DOM0 by default. */
    switch_serial_input();
}
#endif  /* __UXEN_console__ */

int __init console_has(const char *device)
{
    char *p;

    for ( p = opt_console; p != NULL; p = strchr(p, ',') )
    {
        if ( *p == ',' )
            p++;
        if ( strncmp(p, device, strlen(device)) == 0 )
            return 1;
    }

    return 0;
}

void console_start_log_everything(void)
{
#ifdef __UXEN_console__
    serial_start_log_everything(sercon_handle);
#endif  /* __UXEN_console__ */
    atomic_inc(&print_everything);
}

void console_end_log_everything(void)
{
#ifdef __UXEN_console__
    serial_end_log_everything(sercon_handle);
#endif  /* __UXEN_console__ */
    atomic_dec(&print_everything);
}

void console_force_unlock(void)
{
    spin_lock_init(&console_lock);
    serial_force_unlock(sercon_handle);
    console_start_sync();
}

void console_start_sync(void)
{
    atomic_inc(&print_everything);
    serial_start_sync(sercon_handle);
}

void console_end_sync(void)
{
#ifdef __UXEN_console__
    serial_end_sync(sercon_handle);
#endif  /* __UXEN_console__ */
    atomic_dec(&print_everything);
}

/*
 * printk rate limiting, lifted from Linux.
 *
 * This enforces a rate limit: not more than one kernel message
 * every printk_ratelimit_ms (millisecs).
 */
static int __printk_ratelimit(int ratelimit_ms, int ratelimit_burst,
                              long *toks, unsigned long *last_msg,
                              int *missed)
{
    static DEFINE_SPINLOCK(ratelimit_lock);
    unsigned long flags;
    unsigned long long now = NOW(); /* ns */
    unsigned long ms;

    do_div(now, 1000000);
    ms = (unsigned long)now;

    spin_lock_irqsave(&ratelimit_lock, flags);
    if (*toks > ms - *last_msg)
        *toks -= ms - *last_msg;
    else
        *toks = 0;
    *last_msg = ms;
    if ( *toks < (ratelimit_burst * ratelimit_ms) )
    {
        int lost = *missed;
        *missed = 0;
        *toks += ratelimit_ms;
        spin_unlock(&ratelimit_lock);
        if ( lost )
        {
            char lost_str[8];
            snprintf(lost_str, sizeof(lost_str), "%d", lost);
            /* console_lock may already be acquired by printk(). */
            spin_lock_recursive(&console_lock);
            printk_start_of_line();
            __putstr("printk: ");
            __putstr(lost_str);
            __putstr(" messages suppressed.\n");
            spin_unlock_recursive(&console_lock);
        }
        local_irq_restore(flags);
        return 1;
    }
    *missed += 1;
    spin_unlock_irqrestore(&ratelimit_lock, flags);
    return 0;
}

/* minimum time in ms between messages */
static int __read_mostly printk_ratelimit_ms = 1000;

/* number of messages we send before ratelimiting */
static int __read_mostly printk_ratelimit_burst = 100;

void change_log_limits(uint64_t ratelimit_ms, uint64_t ratelimit_burst)
{
    if (ratelimit_ms)
        printk_ratelimit_ms = (int)ratelimit_ms;
    if (ratelimit_burst)
        printk_ratelimit_burst = (int)ratelimit_burst;
}

static int printk_ratelimit(int per_guest)
{
    static long toks = 0;
    static unsigned long last_msg = 0;
    static int missed = 0;
    uint64_t *params = NULL;
    int guest_printk_ratelimit_ms = 1000;
    int guest_printk_ratelimit_burst = 1000;

    if (!current || !current->domain) {
        per_guest = 0;
    } else if (is_hvm_domain(current->domain)) {
        params = current->domain->arch.hvm_domain.params;
        if (params[HVM_PARAM_LOG_RATELIMIT_GUEST_MS])
            guest_printk_ratelimit_ms =
                (int)params[HVM_PARAM_LOG_RATELIMIT_GUEST_MS];
        if (params[HVM_PARAM_LOG_RATELIMIT_GUEST_BURST])
            guest_printk_ratelimit_burst =
                (int)params[HVM_PARAM_LOG_RATELIMIT_GUEST_BURST];
    }

    if (per_guest)
        return  __printk_ratelimit(
            guest_printk_ratelimit_ms, guest_printk_ratelimit_burst,
            &current->domain->printk_ratelimit_toks,
            &current->domain->printk_ratelimit_last_msg,
            &current->domain->printk_ratelimit_missed);
    else
        return __printk_ratelimit(printk_ratelimit_ms, printk_ratelimit_burst,
                                  &toks, &last_msg, &missed);
}

/*
 * **************************************************************
 * *************** Serial console ring buffer *******************
 * **************************************************************
 */

#ifdef DEBUG_TRACE_DUMP

/* Send output direct to console, or buffer it? */
static volatile int debugtrace_send_to_console = 1;

static char        *debugtrace_buf; /* Debug-trace buffer */
static unsigned int debugtrace_prd; /* Producer index     */
static unsigned int debugtrace_kilobytes = 128, debugtrace_bytes;
static unsigned int debugtrace_used;
static DEFINE_SPINLOCK(debugtrace_lock);
integer_param("debugtrace", debugtrace_kilobytes);

static void debugtrace_dump_worker(void)
{
    if ( (debugtrace_bytes == 0) || !debugtrace_used )
        return;

    printk("debugtrace_dump() starting\n");

    /* Print oldest portion of the ring. */
    ASSERT(debugtrace_buf[debugtrace_bytes - 1] == 0);
    sercon_puts(&debugtrace_buf[debugtrace_prd]);

    /* Print youngest portion of the ring. */
    debugtrace_buf[debugtrace_prd] = '\0';
    sercon_puts(&debugtrace_buf[0]);

    memset(debugtrace_buf, '\0', debugtrace_bytes);

    printk("debugtrace_dump() finished\n");
}

static void debugtrace_toggle(void)
{
    unsigned long flags;

    watchdog_disable();
    spin_lock_irqsave(&debugtrace_lock, flags);

    /*
     * Dump the buffer *before* toggling, in case the act of dumping the
     * buffer itself causes more printk() invocations.
     */
    printk("debugtrace_printk now writing to %s.\n",
           !debugtrace_send_to_console ? "console": "buffer");
    if ( !debugtrace_send_to_console )
        debugtrace_dump_worker();

    debugtrace_send_to_console = !debugtrace_send_to_console;

    spin_unlock_irqrestore(&debugtrace_lock, flags);
    watchdog_enable();

}

void debugtrace_dump(void)
{
    unsigned long flags;

    watchdog_disable();
    spin_lock_irqsave(&debugtrace_lock, flags);

    debugtrace_dump_worker();

    spin_unlock_irqrestore(&debugtrace_lock, flags);
    watchdog_enable();
}

void debugtrace_printk(const char *fmt, ...)
{
    static char    buf[1024];
    static u32 count;

    va_list       args;
    char         *p;
    unsigned long flags;

    if ( debugtrace_bytes == 0 )
        return;

    debugtrace_used = 1;

    spin_lock_irqsave(&debugtrace_lock, flags);

    ASSERT(debugtrace_buf[debugtrace_bytes - 1] == 0);

    snprintf(buf, sizeof(buf), "%u ", ++count);

    va_start(args, fmt);
    (void)vsnprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), fmt, args);
    va_end(args);

    if ( debugtrace_send_to_console )
    {
        sercon_puts(buf);
    }
    else
    {
        for ( p = buf; *p != '\0'; p++ )
        {
            debugtrace_buf[debugtrace_prd++] = *p;            
            /* Always leave a nul byte at the end of the buffer. */
            if ( debugtrace_prd == (debugtrace_bytes - 1) )
                debugtrace_prd = 0;
        }
    }

    spin_unlock_irqrestore(&debugtrace_lock, flags);
}

static void debugtrace_key(unsigned char key)
{
    debugtrace_toggle();
}

static struct keyhandler debugtrace_keyhandler = {
    .u.fn = debugtrace_key,
    .desc = "toggle debugtrace to console/buffer"
};

static int __init debugtrace_init(void)
{
    int order;
    unsigned int kbytes, bytes;

    /* Round size down to next power of two. */
    while ( (kbytes = (debugtrace_kilobytes & (debugtrace_kilobytes-1))) != 0 )
        debugtrace_kilobytes = kbytes;

    bytes = debugtrace_kilobytes << 10;
    if ( bytes == 0 )
        return 0;

    order = get_order_from_bytes(bytes);
    debugtrace_buf = alloc_xenheap_pages(order, 0);
    ASSERT(debugtrace_buf != NULL);

    memset(debugtrace_buf, '\0', bytes);

    debugtrace_bytes = bytes;

    register_keyhandler('T', &debugtrace_keyhandler);

    return 0;
}
__initcall(debugtrace_init);

#endif /* !NDEBUG */


/*
 * **************************************************************
 * *************** Debugging/tracing/error-report ***************
 * **************************************************************
 */

void panic(const char *fmt, ...)
{
    va_list args;
    unsigned long flags;
    static DEFINE_SPINLOCK(lock);
    static char buf[128];
    
    debugtrace_dump();

    /* Protects buf[] and ensure multi-line message prints atomically. */
    spin_lock_irqsave(&lock, flags);

    va_start(args, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    console_start_sync();
    printk("\n****************************************\n");
    printk("Panic on CPU %d:\n", smp_processor_id());
    printk("%s", buf);
    printk("****************************************\n\n");

    spin_unlock_irqrestore(&lock, flags);

    debugger_trap_immediate();

    BUG();
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

