/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _PE_H_
#define _PE_H_

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE,
    UWOP_ALLOC_SMALL,
    UWOP_SET_FPREG,
    UWOP_SAVE_NONVOL,
    UWOP_SAVE_NONVOL_FAR,
    UWOP_SAVE_XMM,
    UWOP_SAVE_XMM_FAR,
    UWOP_SAVE_XMM128,
    UWOP_SAVE_XMM128_FAR,
    UWOP_PUSH_MACHFRAME
} UNWIND_CODE_OPS;

#define UBYTE uint8_t
#ifndef USHORT
#define USHORT uint16_t
#endif

typedef union _UNWIND_CODE {
    struct {
        UBYTE CodeOffset;
        UBYTE UnwindOp:4;
        UBYTE OpInfo:4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

enum {
    UNW_FLAG_EHANDLER = 0x01,
    UNW_FLAG_UHANDLER = 0x02,
    UNW_FLAG_CHAININFO = 0x03,
};

typedef struct _UNWIND_INFO {
    UBYTE Version:3;
    UBYTE Flags:5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister:4;
    UBYTE FrameOffset:4;
    UNWIND_CODE UnwindCode[];
    /* union { */
    /*     OPTIONAL ULONG ExceptionHandler; */
    /*     OPTIONAL ULONG FunctionEntry; */
    /* }; */
    /* OPTIONAL ULONG ExceptionData[]; */
} UNWIND_INFO, *PUNWIND_INFO;

#ifndef RUNTIME_FUNCTION_INDIRECT
#ifndef DWORD
#define DWORD uint32_t
#endif
typedef struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
} RUNTIME_FUNCTION,*PRUNTIME_FUNCTION;
#endif

#endif  /* _PE_H_ */
