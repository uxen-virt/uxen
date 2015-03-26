/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENAUDIO_UXENAUD_HW_H_
#define _UXENAUDIO_UXENAUD_HW_H_



#define UXAU_SIGNATURE	0x0
#define UXAU_SIGNATURE_VALUE 0xb38a5012
#define UXAU_VERSION	0x4
#define UXAU_NVOICE	0x100

#define UXAU_V_BASE(n)  (((ULONG) (n)+1)<<16ULL)


#define UXAU_V_SIGNATURE 0x0
#define UXAU_V_SIGNATURE_VALUE 0x9104ac2f
#define UXAU_V_MMIOBASE	0x4
#define UXAU_V_BUFLEN	0x8
#define UXAU_V_AVFEAT	0x10
#define UXAU_V_AVFEAT_INTERRUPTS	(1UL << 0)
#define UXAU_V_AVFMT	0x18
#define UXAU_V_AVFMT_44100_16_2		(1UL << 0)
#define UXAU_V_AVFMT_48000_16_2		(1UL << 1)
#define UXAU_V_CTL	0x20
#define UXAU_V_CTL_RUN_NSTOP		(1UL << 0)
#define UXAU_V_FMT	0x28
#define UXAU_V_POSITION	0x40
#define UXAU_V_POSITION_STEP 0x44
#define UXAU_V_TARGETLAG 0x48
#define UXAU_V_LWM	0x4c
#define UXAU_V_GAIN0	0x100
#define UXAU_V_GAIN1	0x104


#define UXAU_VM_SIGNATURE	0x0
#define UXAU_VM_SIGNATURE_VALUE	0x37a3932f
#define UXAU_VM_WPTR		0x4
#define UXAU_VM_RPTR		0x8
#define UXAU_VM_STS		0xc
#define UXAU_VM_SILENCE		0x10

#define UXAU_VM_BUF		0x80

#endif //_UXENAUDIO_UXENAUD_HW_H_
