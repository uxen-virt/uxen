/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <uxenaudio.h>
#include "common.h"
#include "voice.h"
#include "uxaud_hw.h"


ULONG CVoice::ReadMMIO32
(
	IN ULONG ulOffset
)
{
	ULONG ulValue = ULONG(-1);

	ulValue = READ_REGISTER_ULONG((PULONG) (m_pMMIOBase + ulOffset));

#if 0
        DOUT (DBG_REGS, ("VReadMMIO32(0x%p)=0x%8x", ulOffset,ulValue));
#endif

	return ulValue;
}

VOID CVoice::WriteMMIO32
(
	IN ULONG ulOffset,
	IN ULONG ulValue
)
{

	WRITE_REGISTER_ULONG((PULONG) (m_pMMIOBase + ulOffset), ulValue);

#if 0
        DOUT (DBG_REGS, ("VWriteMMIO32(0x%p,0x%8x)", ulOffset,ulValue));
#endif
}

ULONG CVoice::ReadRMMIO32
(
	IN ULONG ulOffset
)
{
	ULONG ulValue = ULONG(-1);

	ulValue = READ_REGISTER_ULONG((PULONG) (m_pRMMIOBase + ulOffset));

#if 0
        DOUT (DBG_REGS, ("VReadRMMIO32(0x%p)=0x%8x (bar offset=%lx, absolute=%p)", ulOffset,ulValue,(unsigned long) (m_pRMMIOBase-m_pRamBase),m_pRMMIOBase + ulOffset ));
#endif

	return ulValue;
}

VOID CVoice::WriteRMMIO32
(
	IN ULONG ulOffset,
	IN ULONG ulValue
)
{

	WRITE_REGISTER_ULONG((PULONG) (m_pRMMIOBase + ulOffset), ulValue);

#if 0
        DOUT (DBG_REGS, ("VWriteRMMIO32(0x%p,0x%8x)", ulOffset,ulValue));
#endif
}

VOID CVoice::CopyToBuffer(IN PUCHAR Data,OUT PUCHAR Dest,UINT Len)
{
	ULONG v, max;
	PULONG dp;
	UINT l;

        RtlCopyMemory(Dest, Data, Len);

	dp = (PULONG) Dest;
	max = 0;

	/* Magic bitops - approximate an absolute value*/
	/* xor everything with the bit to the left of it */
	/* and drop the two edge bits. This way consecutive */
	/* bits that are 1 or 0 are turned into a run of 0s */
	/* thus the resultant value is bounded above by */
	/* 1.5 * abs(v). Thus the or is bounded above by */
	/* 3 * abs(v) */

	for (l = Len; l >= 4; l -= 4)
        {
		v = *(dp++);
		v &= 0xfffefffe;
		v ^= v >> 1;
		v &= 0x7fff7fff;
		max |= v;
        }

	max |= max >> 16;
	max &= 0xffff;

	if (max > 0x80) 
		m_nSilence = 0;
	else 
		m_nSilence += Len >> 2;

}

NTSTATUS CVoice::CheckSig(VOID)
{
    if (ReadMMIO32(UXAU_V_SIGNATURE) != UXAU_V_SIGNATURE_VALUE )
	return STATUS_INVALID_PARAMETER;

    return STATUS_SUCCESS;
}

NTSTATUS CVoice::CheckRMMIOSig(VOID)
{
    if (ReadRMMIO32(UXAU_VM_SIGNATURE) != UXAU_VM_SIGNATURE_VALUE )
	return STATUS_INVALID_PARAMETER;

    return STATUS_SUCCESS;
}

NTSTATUS CVoice::Probe(IN PUCHAR MMIOBase, IN PUCHAR RAMBase)
{
	NTSTATUS ntStatus;

//        DOUT (DBG_REGS, ("CVoice::Probe(%p,%p)",MMIOBase,RAMBase));

	m_pMMIOBase=MMIOBase;
	m_pRamBase=RAMBase;
	m_pRMMIOBase=0;
	m_pBufStart=0;
	m_pBufEnd=0;
	m_nTicks=0;

	ntStatus=CheckSig();
        if (!NT_SUCCESS(ntStatus)) return ntStatus;
	
	//XXX: FIXME way for host to be evil - check buffer lies within bar - fix for 1.5

	m_pRMMIOBase=m_pRamBase+ReadMMIO32(UXAU_V_MMIOBASE);
	m_pBufStart=m_pRMMIOBase+UXAU_VM_BUF;
	m_nBufLen=ReadMMIO32(UXAU_V_BUFLEN);
	m_pBufEnd=m_pBufStart+m_nBufLen;
	
	m_nBytesBeforeStart=m_nBufLen/8;

	ntStatus=CheckRMMIOSig();
        if (!NT_SUCCESS(ntStatus)) return ntStatus;
	
	//XXX: for the moment we'll just stick with one fixed format
		
	if (!(ReadMMIO32(UXAU_V_AVFMT) & UXAU_V_AVFMT_44100_16_2)) {
		DOUT(DBG_PRINT,("44.1k 16bits 2 channels not supported"));
		return STATUS_INVALID_PARAMETER;
	}

	WriteMMIO32(UXAU_V_FMT,UXAU_V_AVFMT_44100_16_2);

	WriteMMIO32(UXAU_V_GAIN0,0x10000);
	WriteMMIO32(UXAU_V_GAIN1,0x10000);

	m_nTargetLag=ReadMMIO32(UXAU_V_TARGETLAG);
	m_nPositionStep=ReadMMIO32(UXAU_V_POSITION_STEP);

	return STATUS_SUCCESS;
}

NTSTATUS CVoice::Start(VOID)
{
	WriteMMIO32(UXAU_V_CTL,0);
	m_bHWRunning=FALSE;

//        DOUT (DBG_REGS, ("CVoice::Start"));

	WriteMMIO32(UXAU_V_CTL,UXAU_V_CTL_RUN_NSTOP);
	m_bHWRunning=TRUE;
	m_bRunning=TRUE;

	m_nTicks=0;
        m_nSilence=0;

	return STATUS_SUCCESS;
}

NTSTATUS CVoice::Stop(VOID)
{
//        DOUT (DBG_REGS, ("CVoice::Stop"));

	WriteMMIO32(UXAU_V_CTL,0);

	m_nWPTR=ReadRMMIO32(UXAU_VM_RPTR);
	WriteRMMIO32(UXAU_VM_WPTR,m_nWPTR);

	m_nBytesWritten=0;

	m_bRunning=FALSE;
	m_bHWRunning=FALSE;


	return STATUS_SUCCESS;
}


ULONG CVoice::Stats(IN ULONG playback_ptr, IN INT)
{
	ULONG lag;
	ULONG reported_lag;
	ULONG read_position;

	// n contains the number of bytes that the host
	// audio driver has consumed thus far (allegedly accurate to
	// the dac but not)
	
	if (playback_ptr>m_nBytesWritten) {
		lag=0;
	} else {
		lag=m_nBytesWritten-playback_ptr;
	}

	// This is the number of bytes in the host qemu's buffers
	// we aim to keep that at about 176400 (1 second)


	if (lag>m_nTargetLag) {
		reported_lag=lag-m_nTargetLag;
	} else {
		reported_lag=0;
	}


	if (reported_lag<=m_nBufLen) {
		read_position=m_nWPTR + m_nBufLen - reported_lag;
		read_position %= m_nBufLen;
	} else {
		read_position=m_nWPTR+4;
		read_position %= m_nBufLen;
	}

        /* rounding to winwave buffer length avoids playback startup glitches */
        if (m_nPositionStep) {
            read_position /= m_nPositionStep;
            read_position *= m_nPositionStep;
        }

//	if (Print || !reported_lag) {
//		DOUT(DBG_PRINT,("[CVoice::ReadOffset] playpack_ptr=%d m_nBytesWritten=%d lag=%d reported_lag=%d m_nWPTR=%d read_position=%d\n",
//			(int) playback_ptr,(int) m_nBytesWritten,(int) lag,(int) reported_lag,(int) m_nWPTR,(int) read_position));
//	}

	return read_position;
}


NTSTATUS CVoice::Notify(VOID)
{
	ULONG playback_ptr;

	m_nTicks++;

	if (m_nTicks % 100) return STATUS_SUCCESS;

	playback_ptr=ReadMMIO32(UXAU_V_POSITION);

	Stats(playback_ptr,1);

	return STATUS_SUCCESS;
}

NTSTATUS CVoice::ReadOffset(OUT PULONG  Position)
{
	ULONG playback_ptr=ReadMMIO32(UXAU_V_POSITION);

	*Position=Stats(playback_ptr,0);

	return STATUS_SUCCESS;
}

NTSTATUS CVoice::RingSize(OUT PULONG  RingSize)
{
	*RingSize=(ULONG) m_nBufLen;
	return STATUS_SUCCESS;
}


NTSTATUS CVoice::CopyTo(ULONG Offset,IN PUCHAR Data,IN UINT Len)
{
	//XXX: FIXME check for stalls
	UINT rptr;

	if (Offset>= m_nBufLen) 
		return STATUS_INVALID_PARAMETER;

	if ((Offset+Len)> m_nBufLen) 
		return STATUS_INVALID_PARAMETER;

	CVoice::CopyToBuffer(Data,m_pBufStart+Offset,Len);

	rptr=ReadRMMIO32(UXAU_VM_RPTR);
	m_nWPTR=Offset+Len;
	m_nWPTR%=m_nBufLen;

	m_nBytesWritten+=Len;

#if 0
       	DOUT(DBG_PRINT,("[CVoice::CopyTo] Wrote [%d-%d] m_nWPTR=%d\n",(int) Offset, (int) (Offset+Len-1),(int) m_nWPTR));

	{
		PSHORT sd=(PSHORT) Data;
		SHORT min=sd[0],max=sd[0];	
		UINT ns=Len/2;

		while (ns--) {
			if (min>sd[0]) min=sd[0];
			if (max<sd[0]) max=sd[0];
			sd++;
		}
		sd=(PSHORT) Data;


        	DOUT(DBG_PRINT,("xenaudio: transfer in: Offet=%d Len=%d rptr=%d, wptr=%d, %d in [0x%04x 0x%04x ...] [%d,%d]\n",(int) Offset,(int) Len, (int)rptr,(int)m_nWPTR, (int)Len,(unsigned int)sd[0],(unsigned int) sd[1],min,max));

	}
#endif
	
	WriteRMMIO32(UXAU_VM_WPTR,m_nWPTR);
	WriteRMMIO32(UXAU_VM_SILENCE,m_nSilence);
	

	return STATUS_SUCCESS;
}

CVoice::CVoice(VOID)
{
}

CVoice::~CVoice(VOID)
{
if (m_bHWRunning) Stop();
}


	

