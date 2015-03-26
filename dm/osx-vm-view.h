/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Michael Dales <michael@digitalflapjack.com>
 * SPDX-License-Identifier: ISC
 */

#import <AppKit/AppKit.h>

// import this so we can use the same debug_printf as the rest of the code
#include "config.h"

#include "qemu_glue.h"
#include "timer.h"

@interface UXENVirtualMachineView : NSView
{
    CGDataProviderRef dataProviderRef;

    uint8_t *rawbitmap;
    int bitmap_width;
    int bitmap_height;

    int lastx, lasty;
    NSUInteger lastflags;

    QEMUTimer *capslock_timer;

    NSTrackingArea *trackingArea;
    NSCursor *cursor;
    BOOL cursor_in_vm;
}

- (void)setBackingStoreBitmap: (void *)bitmap
                        width: (int)width
                       height: (int)height;

- (void *)getBackingStoreBitmap;

- (void)setCursor: (NSCursor *)new_cursor;

@end
