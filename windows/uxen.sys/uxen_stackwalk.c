/*
 * Copyright 2011-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <windef.h>

#include "uxen_debug.h"

#define UXEN_DEFINE_SYMBOLS_PROTO
#include <uxen/uxen_link.h>

#define UNW_FLAG_NHANDLER 0x0
extern VOID DbgBreakPoint(VOID);

__declspec(noinline)
void
uxen_stacktrace(PCONTEXT _Context)
{
    CONTEXT                       Context;
    KNONVOLATILE_CONTEXT_POINTERS NvContext;
    PRUNTIME_FUNCTION             RuntimeFunction;
    PVOID                         HandlerData;
    ULONG64                       EstablisherFrame;
    ULONG64                       ImageBase;
    ULONG frame;
    ULONG i;
    static const CHAR* RegNames[ 16 ] =
	{ "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9",
	  "r10", "r11", "r12", "r13", "r14", "r15" };
    char symbol_buffer[200];
    intptr_t ret;

    if (_Context)
	Context = *_Context;
    else
	RtlCaptureContext(&Context);

    //
    // If we reach an RIP of zero, this means that we've walked off the end
    // of the call stack and are done.
    //
    for (frame = 0; Context.Rip; frame++) {
	//
	// Display the context.  Note that we don't bother showing the XMM
	// context, although we have the nonvolatile portion of it.
	//
	ret = uxen_do_lookup_symbol(Context.Rip, symbol_buffer,
				    sizeof(symbol_buffer));
        if (ret)
            break;

        printk("================ %02x: rip=%p %s\n", frame, Context.Rip,
               symbol_buffer);
        printk("r12=%p r13=%p r14=%p\n"
               "rdi=%p rsi=%p rbx=%p\n"
               "rbp=%p rsp=%p\n",
               Context.R12, Context.R13, Context.R14,
               Context.Rdi, Context.Rsi, Context.Rbx,
               Context.Rbp, Context.Rsp);

#if 0
        //
        // If we have stack-based register stores, then display them here.
        //
        for (i = 0; i < 16; i++) {
            if (NvContext.IntegerContext[i]) {
                printk(" -> Saved register '%s' on stack at %p (=> %p)\n",
                       RegNames[i], NvContext.IntegerContext[i],
                       *NvContext.IntegerContext[i]);
            }
        }
        printk("\n");
#endif

	//
	// Try to look up unwind metadata for the current function.
	//
	RuntimeFunction = RtlLookupFunctionEntry(Context.Rip, &ImageBase,
						 NULL);

	RtlZeroMemory(&NvContext, sizeof(KNONVOLATILE_CONTEXT_POINTERS));

	if (!RuntimeFunction) {
	    //
	    // If we don't have a RUNTIME_FUNCTION, then we've encountered
	    // a leaf function.  Adjust the stack approprately.
	    //

	    Context.Rip  = (ULONG64)(*(PULONG64)Context.Rsp);
	    Context.Rsp += 8;
	} else {
	    //
	    // Otherwise, call upon RtlVirtualUnwind to execute the unwind for
	    // us.
	    //

	    RtlVirtualUnwind(UNW_FLAG_NHANDLER, ImageBase, Context.Rip,
			     RuntimeFunction, &Context, &HandlerData,
			     &EstablisherFrame, &NvContext);
	}
    }
}
