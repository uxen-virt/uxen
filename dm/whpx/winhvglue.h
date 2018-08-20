/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef WINHVGLUE_H_
#define WINHVGLUE_H_

#include <windows.h>

#define _In_
#define _In_reads_(x)
#define _In_reads_bytes_(x)
#define _Out_
#define _Out_writes_(x)
#define _Out_writes_bytes_(x)
#define _Out_writes_bytes_to_(x,y)
#define _Out_writes_bytes_to_opt_(x,y)
#define _Out_opt_

#define _Inout_

#define WINAPI_FAMILY_PARTITION(x) 1

#define WHP_API(name, ...) \
    typedef HRESULT WINAPI (*WhpPtr ## name) ( __VA_ARGS__ ); \
    extern WhpPtr##name name;

#endif
