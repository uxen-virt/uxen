/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UNWIND_PE_H_
#define _UNWIND_PE_H_

int unwind_pe(uintptr_t *_eip, uintptr_t *_esp, struct cpu_user_regs *regs,
              int check_epilog);

#endif  /* _UNWIND_PE_H_ */
