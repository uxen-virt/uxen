/*
 * Copyright 2017, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/irq.h>
#include <xen/cpu.h>
#include <asm/msr.h>
#include <asm/apic.h>
#include <asm/poke.h>
#include <uxen/mapcache.h>

#ifdef UXEN_HOST_WINDOWS
  #ifdef __x86_64__
    #define POKE_INT_VECTOR 0x2f /* ISR: nt!KiDpcInterrupt */
  #else
    #define POKE_INT_VECTOR 0x1f /* ISR: hal!HalpApicSpuriousService */
  #endif
#else
  #error system not supported
#endif

#define MSR_IA32_LAPIC_BASE   0x1b
#define MSR_IA32_LAPIC_BASE_EXTD	0x400

#define MSR_IA32_X2APIC_BASE   0x800

typedef union
{
  uint64_t icr;
  struct
  {
    uint64_t vector:8,
      delivery_mode:3,
      destination_mode:1,
      delivery_status:1,
      res1:1,
      level:1,
             trigger_mode:1,
             res2:2,
             destination_shorthand:2,
             res3:36,
             destination:8;
  };
} xapic_icr_t;

typedef union
{
  uint64_t icr;
  struct
  {
    uint64_t vector:8,
      delivery_mode:3,
      destination_mode:1,
      delivery_status:1,
      res1:1,
      level:1,
             trigger_mode:1,
             res2:2,
             destination_shorthand:2,
             res3:12,
             destination:32;
  };
} x2apic_icr_t;

#define   POKE_APIC_ID         0x20
#define   POKE_APIC_LVR        0x30
#define   POKE_APIC_TPR        0x80
#define   POKE_APIC_SPIV       0xF0
#define   POKE_APIC_ISR        0x100
#define   POKE_APIC_TMR        0x180
#define   POKE_APIC_IRR        0x200
#define   POKE_APIC_ESR        0x280
#define   POKE_APIC_ICR        0x300
#define   POKE_APIC_ICR_LOW    0x300
#define   POKE_APIC_ICR_HIGH   0x310

#define POKE_APIC_DM_FIXED	0
#define POKE_APIC_DM_LOWEST_PRI	1
#define POKE_APIC_DM_SMI	2
#define POKE_APIC_DM_NMI	4
#define POKE_APIC_DM_INIT	5
#define POKE_APIC_DM_SIPI	6

#define POKE_APIC_DEST_PHYSICAL	0
#define POKE_APIC_DEST_LOGICAL	1

#define POKE_APIC_STATUS_IDLE		0
#define POKE_APIC_STATUS_PENDING	1

#define POKE_APIC_LEVEL_DEASSERT	0
#define POKE_APIC_LEVEL_ASSERT		1

#define POKE_APIC_MODE_EDGE	0
#define POKE_APIC_MODE_LEVEL	1

#define POKE_APIC_DS_NONE		0
#define POKE_APIC_DS_SELF		1
#define POKE_APIC_DS_ALL		2
#define POKE_APIC_DS_ALL_EXCLUDING_SELF	3

DECLARE_PER_CPU (int, poke_is_x2apic);
DECLARE_PER_CPU (uint32_t, poke_lapic_id);

DEFINE_PER_CPU_READ_MOSTLY (int, poke_ready);
DEFINE_PER_CPU_READ_MOSTLY (int, poke_is_x2apic);
DEFINE_PER_CPU_READ_MOSTLY (uint32_t, poke_lapic_id);

static inline uint32_t
poke_read_32 (const volatile void __iomem *addr)
{
  uint32_t ret;
  asm volatile ("mov" "l" " %1,%0":"=r" (ret):"m" (* (volatile uint32_t __force *) addr):"memory");
  return ret;
}

static inline void
poke_write_32 (volatile void __iomem *addr, uint32_t val)
{
  asm volatile ("mov" "l" " %0,%1"::"r" (val), "m" (* (volatile uint32_t __force *) addr):"memory");
}

static int poke_x2apic_enabled(void) 
{
  uint64_t base;
  rdmsrl (MSR_IA32_LAPIC_BASE, base);
return !!(base & MSR_IA32_LAPIC_BASE_EXTD);
}

static void *
poke_xapic_map (void)
{
  uint64_t base;
  rdmsrl (MSR_IA32_LAPIC_BASE, base);
  return mapcache_map_page(base >> PAGE_SHIFT);
}

static void 
poke_xapic_unmap(void *base)
{
  mapcache_unmap_page_va(base);
}

static uint32_t
poke_xapic_read (void *base, unsigned reg)
{
  return poke_read_32 (base + reg);
}
static void
poke_xapic_write (void *base, unsigned reg, uint32_t v)
{
#if 0
  uint32_t *a = (base + reg);
  __asm__ __volatile__ ("xchgl %0,%1":"+r" (v), "+m" (*a)::"memory");
#else
  return poke_write_32 (base + reg, v);
#endif
}

static uint64_t
poke_x2apic_read (unsigned reg)
{
  uint64_t val;
  rdmsrl(MSR_IA32_X2APIC_BASE + reg, val);
  return val;
}

static void poke_x2apic_write(unsigned reg,uint64_t val)
{
  wrmsrl(MSR_IA32_X2APIC_BASE+reg,val);
}

static void
poke_xapic_write_icr (void *base, xapic_icr_t icr)
{
  poke_xapic_write (base, POKE_APIC_ICR_HIGH, icr.icr >> 32);
  poke_xapic_write (base, POKE_APIC_ICR_LOW, icr.icr & 0xffffffff);
}

static xapic_icr_t
poke_xapic_read_icr (void *base)
{
  xapic_icr_t icr;
  icr.icr = ((uint64_t) poke_xapic_read (base, POKE_APIC_ICR_HIGH)) << 32;
  icr.icr |= poke_xapic_read (base, POKE_APIC_ICR_LOW);
  return icr;
}

static void
poke_xapic_busy_wait (void *base)
{
  xapic_icr_t icr;

  do {
      icr = poke_xapic_read_icr (base);
  } while (icr.delivery_status == POKE_APIC_STATUS_PENDING);
    }

static void
poke_x2apic_write_icr (x2apic_icr_t icr)
{
  poke_x2apic_write (POKE_APIC_ICR>>4, icr.icr);
}

#if 0
static x2apic_icr_t
poke_x2apic_read_icr (void)
{
  x2apic_icr_t icr;
  icr.icr=poke_x2apic_read(POKE_APIC_ICR_LOW >> 4);
  return icr;
}

static void
poke_x2apic_busy_wait (void)
{
  x2apic_icr_t icr;

  do {
      icr = poke_x2apic_read_icr ();
  } while (icr.delivery_status == POKE_APIC_STATUS_PENDING);
}
#endif

static void
poke_xapic_send_int (uint32_t dest)
{
  void *base = poke_xapic_map ();
  xapic_icr_t icr;
  uint32_t old_icr_high;
  unsigned long flags;

  if (!base)
    return;

  cpu_irq_save (flags);
  old_icr_high = poke_xapic_read (base, POKE_APIC_ICR_HIGH);

  icr.icr = 0;
  icr.trigger_mode = POKE_APIC_MODE_EDGE;
  icr.delivery_mode = POKE_APIC_DM_FIXED;
  icr.vector = POKE_INT_VECTOR;
  icr.destination_mode = POKE_APIC_DEST_PHYSICAL;

  if (dest == -1)
    icr.destination_shorthand = POKE_APIC_DS_ALL_EXCLUDING_SELF;
  else {
      icr.destination_shorthand = POKE_APIC_DS_NONE;
      icr.destination = dest;
    }

  poke_xapic_busy_wait (base);
  poke_xapic_write_icr (base, icr);
  poke_xapic_busy_wait (base);

  poke_xapic_write (base, POKE_APIC_ICR_HIGH, old_icr_high);
  cpu_irq_restore (flags);

  poke_xapic_unmap (base);
}

static void
poke_x2apic_send_int (uint32_t dest)
{
  x2apic_icr_t icr;
  unsigned long flags;

  cpu_irq_save (flags);

  icr.icr = 0;
  icr.trigger_mode = POKE_APIC_MODE_EDGE;
  icr.delivery_mode = POKE_APIC_DM_FIXED;
  icr.vector = POKE_INT_VECTOR;
  icr.destination_mode = POKE_APIC_DEST_PHYSICAL;

  if (dest == (uint32_t) ~0)
    icr.destination_shorthand = POKE_APIC_DS_ALL_EXCLUDING_SELF;
  else {
      icr.destination_shorthand = POKE_APIC_DS_NONE;
      icr.destination = dest;
    }

  // poke_x2apic_busy_wait ();
  poke_x2apic_write_icr (icr);
  // poke_x2apic_busy_wait ();

  cpu_irq_restore (flags);
}

void
_poke_setup_cpu (void)
{
  this_cpu(poke_is_x2apic)=poke_x2apic_enabled();

  if (this_cpu(poke_is_x2apic)) {
    this_cpu (poke_lapic_id) = poke_x2apic_read (POKE_APIC_ID >> 4);
  } else {
    void *base = poke_xapic_map ();
    if (!base)
      return;

    this_cpu (poke_lapic_id) = poke_xapic_read ((void *) base, POKE_APIC_ID) >> 24;
    poke_xapic_unmap(base);
  }

  mb ();
  this_cpu (poke_ready) = 1;
  UI_HOST_CALL(ui_printf, NULL, "poke: cpu%d lapic id %p\n",
               (int) smp_processor_id(),
               (void *) (size_t) this_cpu (poke_lapic_id));
}

void
poke_cpu (unsigned cpu)
{
  poke_setup_cpu();

  if (!per_cpu (poke_ready, cpu))
    return;

  if (this_cpu(poke_is_x2apic))  
    poke_x2apic_send_int (per_cpu (poke_lapic_id, cpu));
  else 
    poke_xapic_send_int (per_cpu (poke_lapic_id, cpu));
}
