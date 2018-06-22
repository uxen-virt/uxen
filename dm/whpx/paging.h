/*
 * Copyright 2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef PAGING_H_
#define PAGING_H_

#define IA32_MTRR_FIX64K_00000    0x250
#define IA32_MTRR_FIX16K_80000    0x258
#define IA32_MTRR_FIX16K_A0000    0x259
#define IA32_MTRR_FIX4K_C0000   0x268
#define IA32_MTRR_FIX4K_C8000   0x269
#define IA32_MTRR_FIX4K_D0000   0x26A
#define IA32_MTRR_FIX4K_D8000   0x26B
#define IA32_MTRR_FIX4K_E0000   0x26C
#define IA32_MTRR_FIX4K_E8000   0x26D
#define IA32_MTRR_FIX4K_F0000   0x26E
#define IA32_MTRR_FIX4K_F8000   0x26F


#define IA32_MTRR_PHYSBASE(a) (0x200+((a)<<1))
#define IA32_MTRR_PHYSMASK(a) (0x201+((a)<<1))
#define IA32_MTRR_DEF_TYPE 0x2ff





#define MTRR_TYPE_MASK  0xff
#define MTRR_FIXED_ENABLED  0x400
#define MTRR_ENABLED  0x800

#define EPT_MT_UC       0
#define EPT_MT_WC       1
#define EPT_MT_WT       4
#define EPT_MT_WB       6

#define NPT_MT_WB       6

typedef union {
  struct {
    uint64_t        p: 1,
                    rw: 1,
                    us: 1,
                    pwt: 1,
                    pcd: 1,
                    a: 1,
                    d: 1,
                    ps: 1,
                    g: 1,
                    ign1: 3,
                    mfn: 40,
                    ign2: 11,
                    xd: 1;
  };
  uint64_t pte;
} pte64_t;

typedef union {
  struct {
    uint64_t        r: 1,
                    w: 1,
                    x: 1,
                    mt: 3,
                    pat: 1,
                    ps: 1,
                    a: 1,
                    d: 1,
                    ign1: 2,
                    mfn: 40,
                    ign2: 12;
  };
  struct {
    uint64_t  rwx: 3;
  };
  struct {
    uint64_t  ctrl: 10;
  };
  uint64_t pte;
} epte_t;


typedef union {
  struct {
    uint64_t          p: 1,
                      rw: 1,
                      us: 1,
                      pwt: 1,
                      pcd: 1,
                      a: 1,
                      d: 1,
                      pat: 1,
                      g: 1,
                      : 54,
                      xd: 1;
  };
  struct {
    uint64_t prw: 2;
  };
  uint64_t pte;
} npte_t;



typedef union {
  epte_t ept;
  npte_t npt;
  struct {
    uint64_t        : 1,
                    w: 1,
                    : 5,
                    ps: 1, /*Really that looks like d above*/
                    : 4,
                    mfn: 40,
                    : 12;
  };
  uint64_t pte;
} hap_t;


#define EPT_ACCESS_NONE (0ULL)
#define EPT_ACCESS_R  (1ULL << 0)
#define EPT_ACCESS_W  (1ULL << 1)
#define EPT_ACCESS_X  (1ULL << 2)

#define EPT_ACCESS_RW (EPT_ACCESS_R|EPT_ACCESS_W)
#define EPT_ACCESS_RWX  (EPT_ACCESS_R|EPT_ACCESS_W|EPT_ACCESS_X)

#define NPT_ACCESS_NONE  (0ULL)
#define NPT_ACCESS_P   (1ULL << 0)
#define NPT_ACCESS_R  NPT_ACCESS_P
#define NPT_ACCESS_W  ((1ULL << 1)|NPT_ACCESS_P)
#define NPT_ACCESS_NX  (1ULL << 63)
#define NPT_ACCESS_MASK (NPT_ACCESS_R|NPT_ACCESS_W|NPT_ACCESS_NX)
#define NPT_CTRL_MASK (NPT_ACCESS_NX | 0x1ff)

#define NPT_ACCESS_RW (NPT_ACCESS_R|NPT_ACCESS_W)
#define NPT_ACCESS_RWX  ((NPT_ACCESS_R|NPT_ACCESS_W) & (~NPT_ACCESS_NX))

#define PAGE_OFFSET_FN(fn,l) (((fn) >> ((l)*9)) & 0x1ff)
#define PAGE_OFFSET_A(a,l) PAGE_OFFSET_FN((a) >> PAGE_SHIFT,l)
#define PAGE_OFFSET_O(a,l) (PAGE_OFFSET_FN((a) >> PAGE_SHIFT,l) << 3)
#define LEAF_SIZE(l) (1UL << ((l)*9 + PAGE_SHIFT))
#define LEAF_MASK(l) (LEAF_SIZE(l)-1)

#define PAGE_ALIGNED(a,l) (!((a) & (LEAF_SIZE(l) -1 )))


#define N_PTES  512

#endif
