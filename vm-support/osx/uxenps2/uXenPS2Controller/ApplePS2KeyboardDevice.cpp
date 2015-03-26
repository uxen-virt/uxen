/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * uXen changes:
 *
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <IOKit/assert.h>
#include "ApplePS2KeyboardDevice.h"
#include "uXenPS2Controller.h"

// =============================================================================
// ApplePS2KeyboardDevice Class Implementation
//

#define super IOService
OSDefineMetaClassAndStructors(ApplePS2KeyboardDevice, IOService);

bool ApplePS2KeyboardDevice::attach( IOService * provider )
{
  if( !super::attach(provider) )  return false;

  assert(_controller == 0);
  _controller = (ApplePS2Controller *)provider;
  _controller->retain();

  return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void ApplePS2KeyboardDevice::detach( IOService * provider )
{
  assert(_controller == provider);
  _controller->release();
  _controller = 0;

  super::detach(provider);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void ApplePS2KeyboardDevice::installInterruptAction(OSObject *         target,
                                                    PS2InterruptAction action)
{
  _controller->installInterruptAction(kDT_Keyboard, target, action);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void ApplePS2KeyboardDevice::uninstallInterruptAction()
{
  _controller->uninstallInterruptAction(kDT_Keyboard);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void ApplePS2KeyboardDevice::installPowerControlAction(
                                                OSObject *            target,
                                                PS2PowerControlAction action)
{
  _controller->installPowerControlAction(kDT_Keyboard, target, action);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void ApplePS2KeyboardDevice::uninstallPowerControlAction()
{
  _controller->uninstallPowerControlAction(kDT_Keyboard);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

PS2Request * ApplePS2KeyboardDevice::allocateRequest()
{
  return _controller->allocateRequest();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void ApplePS2KeyboardDevice::freeRequest(PS2Request * request)
{
  _controller->freeRequest(request);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool ApplePS2KeyboardDevice::submitRequest(PS2Request * request)
{
  return _controller->submitRequest(request);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void ApplePS2KeyboardDevice::submitRequestAndBlock(PS2Request * request)
{
  _controller->submitRequestAndBlock(request);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void ApplePS2KeyboardDevice::installMessageAction(OSObject* target, PS2MessageAction action)
{
  _controller->installMessageAction(kDT_Keyboard, target, action);
}

void ApplePS2KeyboardDevice::uninstallMessageAction()
{
  _controller->uninstallMessageAction(kDT_Keyboard);
}

void ApplePS2KeyboardDevice::dispatchMouseMessage(int message, void *data)
{
  _controller->dispatchMessage(kDT_Mouse, message, data);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(ApplePS2KeyboardDevice, 0);
OSMetaClassDefineReservedUnused(ApplePS2KeyboardDevice, 1);
OSMetaClassDefineReservedUnused(ApplePS2KeyboardDevice, 2);
OSMetaClassDefineReservedUnused(ApplePS2KeyboardDevice, 3);
OSMetaClassDefineReservedUnused(ApplePS2KeyboardDevice, 4);
OSMetaClassDefineReservedUnused(ApplePS2KeyboardDevice, 5);
OSMetaClassDefineReservedUnused(ApplePS2KeyboardDevice, 6);
OSMetaClassDefineReservedUnused(ApplePS2KeyboardDevice, 7);
