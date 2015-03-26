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

#ifndef _APPLEPS2KEYBOARDDEVICE_H
#define _APPLEPS2KEYBOARDDEVICE_H

#include "ApplePS2Device.h"

class ApplePS2Controller;

class ApplePS2KeyboardDevice : public IOService
{
  OSDeclareDefaultStructors(ApplePS2KeyboardDevice);

private:
  ApplePS2Controller * _controller;

protected:
  struct ExpansionData { /* */ };
  ExpansionData * _expansionData;

public:
  virtual bool attach(IOService * provider);
  virtual void detach(IOService * provider);

  // Interrupt Handling Routines

  virtual void installInterruptAction(OSObject *, PS2InterruptAction);
  virtual void uninstallInterruptAction();

  // Request Submission Routines

  virtual PS2Request * allocateRequest();
  virtual void         freeRequest(PS2Request * request);
  virtual bool         submitRequest(PS2Request * request);
  virtual void         submitRequestAndBlock(PS2Request * request);

  // Power Control Handling Routines

  virtual void installPowerControlAction(OSObject *, PS2PowerControlAction);
  virtual void uninstallPowerControlAction();
    
  // Messaging
  virtual void installMessageAction(OSObject*, PS2MessageAction);
  virtual void uninstallMessageAction();
    
  // Mouse/Keyboard interaction
    
  virtual void dispatchMouseMessage(int message, void* data);

  OSMetaClassDeclareReservedUnused(ApplePS2KeyboardDevice, 0);
  OSMetaClassDeclareReservedUnused(ApplePS2KeyboardDevice, 1);
  OSMetaClassDeclareReservedUnused(ApplePS2KeyboardDevice, 2);
  OSMetaClassDeclareReservedUnused(ApplePS2KeyboardDevice, 3);
  OSMetaClassDeclareReservedUnused(ApplePS2KeyboardDevice, 4);
  OSMetaClassDeclareReservedUnused(ApplePS2KeyboardDevice, 5);
  OSMetaClassDeclareReservedUnused(ApplePS2KeyboardDevice, 6);
  OSMetaClassDeclareReservedUnused(ApplePS2KeyboardDevice, 7);
};

#endif /* !_APPLEPS2KEYBOARDDEVICE_H */
