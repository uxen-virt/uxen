/*
 * include/asm-i386/xstate.h
 *
 * x86 extended state (xsave/xrstor) related definitions
 * 
 */

#ifndef __ASM_XSTATE_H
#define __ASM_XSTATE_H

#include <xen/types.h>
#include <xen/percpu.h>

#define FCW_DEFAULT               0x037f
#define MXCSR_DEFAULT             0x1f80

#define XSTATE_CPUID              0x0000000d
#define XSTATE_FEATURE_XSAVEOPT   (1 << 0)    /* sub-leaf 1, eax[bit 0] */

#define XCR_XFEATURE_ENABLED_MASK 0x00000000  /* index of XCR0 */

#define XSTATE_YMM_SIZE           256
#define XSTATE_YMM_OFFSET         XSAVE_AREA_MIN_SIZE
#define XSTATE_AREA_MIN_SIZE      (512 + 64)  /* FP/SSE + XSAVE.HEADER */

#define XSTATE_FP      (1ULL << 0)
#define XSTATE_SSE     (1ULL << 1)
#define XSTATE_YMM     (1ULL << 2)
#define XSTATE_LWP     (1ULL << 62) /* AMD lightweight profiling */
#define XSTATE_FP_SSE  (XSTATE_FP | XSTATE_SSE)
#define XCNTXT_MASK    (XSTATE_FP | XSTATE_SSE | XSTATE_YMM | XSTATE_LWP)

#define XSTATE_ALL     (~0)
#define XSTATE_NONLAZY (XSTATE_LWP)
#define XSTATE_LAZY    (XSTATE_ALL & ~XSTATE_NONLAZY)

#ifdef CONFIG_X86_64
#define REX_PREFIX     "0x48, "
#else
#define REX_PREFIX
#endif

/* extended state variables */
DECLARE_PER_CPU(uint64_t, xcr0);

extern unsigned int xsave_cntxt_size;
extern u64 xfeature_mask;

/* extended state save area */
struct xsave_struct
{
    union {                                  /* FPU/MMX, SSE */
        char x[512];
        struct {
            uint16_t fcw;
            uint16_t fsw;
            uint8_t ftw;
            uint8_t rsvd1;
            uint16_t fop;
            union {
#ifdef __x86_64__
                uint64_t addr;
#endif
                struct {
                    uint32_t offs;
                    uint16_t sel;
                    uint16_t rsvd;
                };
            } fip, fdp;
            uint32_t mxcsr;
            uint32_t mxcsr_mask;
            /* data registers follow here */
        };
    } fpu_sse;

    struct {
        u64 xstate_bv;
        u64 reserved[7];
    } xsave_hdr;                             /* The 64-byte header */

    struct { char x[XSTATE_YMM_SIZE]; } ymm; /* YMM */
    char   data[];                           /* Future new states */
} __attribute__ ((packed, aligned (64)));

/* extended state operations */
u64 xgetbv(uint32_t index);
void sync_xcr0(void);
void _set_xcr0(u64 xfeatures);
uint64_t get_xcr0(void);
void xsave(struct vcpu *v, uint64_t mask);
void xrstor(struct vcpu *v, uint64_t mask);
bool_t xsave_enabled(const struct vcpu *v);

#ifndef NDEBUG
#define XCR0_STATE_DEBUG 1
#endif  /* NDEBUG */

#ifdef XCR0_STATE_DEBUG
/* tag the set_xcr0 calls indicating which xcr0 value is being set,
 * assert that the host value is used when returning to the host and
 * the VM value is used when executing the VM */
enum xcr0_state {
    XCR0_STATE_HOST = 0,        /* start with host state */
    XCR0_STATE_HOSTALL,
    XCR0_STATE_VM,
    XCR0_STATE_VMALL,
    XCR0_STATE_UNDEF,
};

DECLARE_PER_CPU(int, xcr0_state);
#define set_xcr0(xfeatures, state) do { \
    _set_xcr0(xfeatures);               \
    this_cpu(xcr0_state) = (state);     \
    } while (0)
#define assert_xcr0_state(state)                                \
    ASSERT(!cpu_has_xsave || this_cpu(xcr0_state) == (state))
#else  /* XCR0_STATE_DEBUG */
#define set_xcr0(xfeatures, state) _set_xcr0(xfeatures)
#define assert_xcr0_state(state) do { /* nothing */ } while (0)
#endif /* XCR0_STATE_DEBUG */

/* extended state init and cleanup functions */
void xstate_free_save_area(struct vcpu *v);
int xstate_alloc_save_area(struct vcpu *v);
void xstate_init(void);

#define XCR0_STATE_HOST 0
#define XCR0_STATE_VM 1
#define XCR0_STATE_VMALL 2
#define XCR0_STATE_HOSTALL 3
#define XCR0_STATE_UNDEF 4

#endif /* __ASM_XSTATE_H */
