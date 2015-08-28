/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENAUDIO_VOICE_H_
#define _UXENAUDIO_VOICE_H_

#define HW_MAX_VOICE 2
#define HW_MIN_VOICE 1

class CVoice 
{
    private:
        int                     m_nIndex;
	PUCHAR			m_pRamBase; // Of adapter

	PUCHAR			m_pMMIOBase; // Of Voice
	PUCHAR			m_pRMMIOBase;
	PUCHAR			m_pBufStart;
	PUCHAR			m_pBufEnd;
	ULONG			m_nBufLen;

	ULONG			m_nBytesBeforeStart;
	
	ULONG			m_nWPTR;
        ULONG                   m_nRPTR;

	BOOL			m_bRunning;
	BOOL			m_bHWRunning;
        BOOL                    m_bCapture;
	ULONG			m_nBytesWritten;

	ULONG			m_nTicks;
	ULONG			m_nTargetLag;
	ULONG			m_nPositionStep;
	ULONG			m_nSilence;


        STDMETHODIMP_(VOID)     CopyToBuffer
	(
		IN PUCHAR Data,
		OUT PUCHAR Dest, 
		UINT Len
	);


        STDMETHODIMP_(ULONG)     ReadMMIO32
	(
		IN ULONG ulOffset
	);

        STDMETHODIMP_(VOID)     WriteMMIO32
	(
		IN ULONG ulOffset,
		IN ULONG ulValue
	);

        STDMETHODIMP_(ULONG)     ReadRMMIO32
	(
		IN ULONG ulOffset
	);

        STDMETHODIMP_(VOID)     WriteRMMIO32
	(
		IN ULONG ulOffset,
		IN ULONG ulValue
	);

        STDMETHODIMP_(NTSTATUS)     CheckSig
	(	
		VOID
	);

        STDMETHODIMP_(NTSTATUS)     CheckRMMIOSig
	(	
		VOID
	);

    public:
	CVoice(int index);
	~CVoice();

        STDMETHODIMP_(NTSTATUS)     Probe
        ( 

		IN PUCHAR		IOBase,
		IN PUCHAR		RAMBase
        );

        STDMETHODIMP_(NTSTATUS)     Start
        ( 
		IN BOOL capture
	);


        STDMETHODIMP_(NTSTATUS)     Stop
        ( 
		VOID
	);

        STDMETHODIMP_(NTSTATUS)     Notify
        ( 
		VOID
	);

        STDMETHODIMP_(NTSTATUS)     CopyTo
        ( 
		IN ULONG	Offset,
		IN PUCHAR	Data,
		IN UINT		Len
	);

        STDMETHODIMP_(NTSTATUS)     CopyFrom
        (
		IN ULONG	Offset,
		IN PUCHAR	Data,
		IN UINT		Len
	);

        STDMETHODIMP_(ULONG)     Stats
	(
		IN ULONG	playback_ptr,
		IN INT		Print
	);

        STDMETHODIMP_(NTSTATUS)     ReadOffset
        ( 
		OUT PULONG	Position
	);

        STDMETHODIMP_(NTSTATUS)     RingSize
        ( 
		OUT PULONG	RingSize
	);

};

typedef class CVoice *PVOICE;
	
#endif // _UXENAUDIO_VOICE_H_

