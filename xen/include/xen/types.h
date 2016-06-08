#ifndef __TYPES_H__
#define __TYPES_H__

#include <xen/config.h>
#include <asm/types.h>

#define BITS_TO_LONGS(bits) \
    (((bits)+BITS_PER_LONG-1)/BITS_PER_LONG)
#define DECLARE_BITMAP(name,bits) \
    unsigned long name[BITS_TO_LONGS(bits)]

#ifndef NULL
#define NULL ((void*)0)
#endif

#if !defined(__UXEN_SYS__)
#define INT_MAX         ((int)(~0U>>1))
#define INT_MIN         (-INT_MAX - 1)
#define UINT_MAX        (~0U)
#define LONG_MAX        ((long)(~0UL>>1))
#define LONG_MIN        (-LONG_MAX - 1)
#define ULONG_MAX       (~0UL)
#endif	/* __UXEN_SYS__ */

#if (!defined(__UXEN_SYS__) && !defined(XENV4V_DRIVER)) || !defined(UXEN_HOST_OSX)
/* bsd */
typedef unsigned char           u_char;
typedef unsigned short          u_short;
typedef unsigned int            u_int;
typedef unsigned long           u_long;

/* sysv */
typedef unsigned char           unchar;
typedef unsigned short          ushort;
typedef unsigned int            uint;
typedef unsigned long           ulong;

typedef         __u8            uint8_t;
typedef         __u8            u_int8_t;
typedef         __s8            int8_t;

typedef         __u16           uint16_t;
typedef         __u16           u_int16_t;
typedef         __s16           int16_t;

typedef         __u32           uint32_t;
typedef         __u32           u_int32_t;
typedef         __s32           int32_t;

typedef         __u64           uint64_t;
typedef         __u64           u_int64_t;
typedef         __s64           int64_t;
#endif  /* __UXEN_SYS__ */

struct domain;
struct vcpu;

typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u32 __be32;
typedef __u64 __le64;
typedef __u64 __be64;

#endif /* __TYPES_H__ */
