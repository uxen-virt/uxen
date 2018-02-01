/*
 * Copyright 2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef DBGHELP_H_
#define DBGHELP_H_

#include "../../common/debug.h"

#define verify_on_stack(p) { \
  char *p8 = (char*)p; \
  char *rsp_est = _AddressOfReturnAddress(); \
  if (!((p8 >= rsp_est - 4096*4) && (p8 <= rsp_est + 4096*4))) {        \
    uxen_err("Unexpectedly, not on stack: %p, rsp_est=%p", p8, rsp_est); \
  } \
}

#endif
