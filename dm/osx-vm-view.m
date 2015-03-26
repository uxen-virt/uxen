/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Michael Dales <michael@digitalflapjack.com>
 * SPDX-License-Identifier: ISC
 */

#import "osx-vm-view.h"

#include "bh.h"
#include "input.h"

#include "osx-keymap.h"

#define cgrect(nsrect) (*(CGRect *)&(nsrect))

static void capslock_timer_cb(void *);

@implementation UXENVirtualMachineView

- (id)initWithFrame: (NSRect)frame
{
    if ((self = [super initWithFrame: frame]) != nil) {
        dataProviderRef = nil;

        lastx = 0;
        lasty = 0;
        lastflags = 0;

        capslock_timer = qemu_new_timer_ms(vm_clock, capslock_timer_cb, self);

        cursor = [NSCursor arrowCursor];
        cursor_in_vm = YES;
        trackingArea =
            [[NSTrackingArea alloc] initWithRect: [self bounds]
                                    options: (NSTrackingMouseEnteredAndExited |
                                    NSTrackingMouseMoved |
                                    NSTrackingCursorUpdate |
                                    NSTrackingActiveAlways)
                                    owner: self
                                    userInfo: nil];
        [self addTrackingArea: trackingArea];
    }

    return self;
}

- (void)updateTrackingAreas
{
    [self removeTrackingArea: trackingArea];
    [trackingArea release];

    trackingArea =
        [[NSTrackingArea alloc] initWithRect: [self bounds]
                                options: (NSTrackingMouseEnteredAndExited |
                                NSTrackingMouseMoved |
                                NSTrackingCursorUpdate |
                                NSTrackingActiveAlways)
                                owner: self
                                userInfo: nil];
    [self addTrackingArea: trackingArea];
}

- (void)setBackingStoreBitmap: (void *)bitmap
                        width: (int)width
                       height: (int)height
{

    if (dataProviderRef != NULL) {
        CGDataProviderRef oldDataProviderRef = dataProviderRef;
        dataProviderRef = NULL;
        CFRelease(oldDataProviderRef);
    }

    rawbitmap = (uint8_t *)bitmap;
    bitmap_width = width;
    bitmap_height = height;

    if (rawbitmap != NULL) {
        dataProviderRef = CGDataProviderCreateWithData(
            NULL, rawbitmap, bitmap_width * 4 * bitmap_height, NULL);
    }

    [self setNeedsDisplay: YES];
}

- (void *)getBackingStoreBitmap
{

    return (void *)rawbitmap;
}

- (void)drawRect: (NSRect)damageArea
{
    // get CoreGraphic context
    CGContextRef viewContextRef =
        [[NSGraphicsContext currentContext] graphicsPort];
    CGContextSetInterpolationQuality (viewContextRef, kCGInterpolationNone);
    CGContextSetShouldAntialias (viewContextRef, NO);

    // draw screen bitmap directly to Core Graphics context
    if (dataProviderRef) {
        CGImageRef imageRef = CGImageCreate(
            bitmap_width,       // width
            bitmap_height,      // height
            8,                  // bitsPerComponent
            32,                 // bitsPerPixel
            (bitmap_width * 4), // bytesPerRow
            CGColorSpaceCreateWithName(kCGColorSpaceGenericRGB), // colorspace
            kCGBitmapByteOrder32Little | kCGImageAlphaNoneSkipFirst,
                                // bitmapInfo
            dataProviderRef,    // provider
            NULL,               // decode
            0,                  // interpolate
            kCGRenderingIntentDefault // intent
            );

        const NSRect *rectList;
        NSInteger rectCount;
        int i;
        CGImageRef clipImageRef;
        CGRect clipRect;

        [self getRectsBeingDrawn:&rectList count:&rectCount];
        for (i = 0; i < rectCount; i++) {
            clipRect.origin.x = rectList[i].origin.x;
            clipRect.origin.y = (float)bitmap_height -
                (rectList[i].origin.y + rectList[i].size.height);
            clipRect.size.width = rectList[i].size.width;
            clipRect.size.height = rectList[i].size.height;
            clipImageRef = CGImageCreateWithImageInRect(
                imageRef, clipRect);
            CGContextDrawImage (viewContextRef, cgrect(rectList[i]),
                                clipImageRef);
            CGImageRelease (clipImageRef);
        }

        CGImageRelease (imageRef);
    }
}

- (BOOL)isOpaque
{
    return YES;
}

- (BOOL)acceptsFirstResponder
{
    return YES;
}

static void
inject_key(int keycode, int up)
{
    struct input_event *input_event;
    BH *bh;
    int scancode;

    if (keycode >= osx_keymap_len)
        return;

    scancode = osx_keymap[keycode].scancode;
    if (!scancode)
        return;

    bh = bh_new_with_data(input_event_cb, sizeof(struct input_event),
                          (void **)&input_event);
    if (!bh)
        return;
    input_event->type = KEYBOARD_INPUT_EVENT;
    input_event->keycode = scancode;
    if (up)
        input_event->keycode |= 0x80;
    input_event->extended = osx_keymap[keycode].extended;

    bh_schedule_one_shot(bh);
}

- (void)keyUp: (NSEvent*)event
{
    //dprintf("keyUp %x\n", [event keyCode]);
    inject_key([event keyCode], 1);
}

- (void)keyDown: (NSEvent*)event
{
    //dprintf("keyDown %x\n", [event keyCode]);
    inject_key([event keyCode], 0);
}

static void capslock_timer_cb(void *opaque)
{
    inject_key(KEY_CAPSLOCK, 1);
}

- (void)update_key_modifiers: (NSUInteger)modifier
{
    NSUInteger flags = lastflags ^ modifier;

    lastflags = modifier;

    if (flags & MODKEY_LSHIFT)
        inject_key(KEY_LSHIFT, !(lastflags & MODKEY_LSHIFT));
    if (flags & MODKEY_RSHIFT)
        inject_key(KEY_RSHIFT, !(lastflags & MODKEY_RSHIFT));

    if (flags & MODKEY_LCTRL)
        inject_key(KEY_LCTRL, !(lastflags & MODKEY_LCTRL));
    if (flags & MODKEY_RCTRL)
        inject_key(KEY_RCTRL, !(lastflags & MODKEY_RCTRL));

    if (flags & MODKEY_LALT)
        inject_key(KEY_LALT, !(lastflags & MODKEY_LALT));
    if (flags & MODKEY_RALT)
        inject_key(KEY_RALT, !(lastflags & MODKEY_RALT));

    if (flags & MODKEY_LCMD)
        inject_key(KEY_LCMD, !(lastflags & MODKEY_LCMD));
    if (flags & MODKEY_RCMD)
        inject_key(KEY_RCMD, !(lastflags & MODKEY_RCMD));

    if (flags & MODKEY_CAPSLOCK) {
        inject_key(KEY_CAPSLOCK, 0);
        /* Delay release by 100ms otherwise the HID system in OSX locks up */
        qemu_mod_timer(capslock_timer, os_get_clock_ms() + 100);
    }
}

- (void)flagsChanged: (NSEvent*)event
{
    //dprintf("%s: flags change %lx -> %lx\n", __FUNCTION__,
    //        lastflags, [event modifierFlags]);

    [self update_key_modifiers:[event modifierFlags]];
}

- (void)becomeKeyWindow
{
    //dprintf("%s: gain focus\n", __FUNCTION__);

    [self update_key_modifiers:[NSEvent modifierFlags]];
}

- (void)resignKeyWindow
{
    //dprintf("%s: loose focus\n", __FUNCTION__);
}

- (void)commonMouseEvent: (NSEvent*)event
{
    struct input_event *input_event;
    int x, y;
    int dz;
    int buttons;
    BH *bh;

    NSPoint p = [event locationInWindow];

    p.y = bitmap_height - p.y;

    if (p.x < 0 || p.x >= bitmap_width ||
        p.y < 0 || p.y >= bitmap_height)
        return;

    if (input_mouse_is_absolute()) {
        lastx = p.x;
        lasty = p.y;
        x = (int)p.x * 0x7fff / (bitmap_width - 1);
        y = (int)p.y * 0x7fff / (bitmap_height - 1);
    } else {
        x = p.x - lastx;
        y = p.y - lasty;
        lastx = p.x;
        lasty = p.y;
    }

    dz = (event.type == NSScrollWheel) ? -[event deltaY] : 0;

    // happens that uxendm and OS X agree on this one...
    buttons = [NSEvent pressedMouseButtons];

    bh = bh_new_with_data(input_event_cb, sizeof(struct input_event),
                          (void **)&input_event);
    if (!bh)
        return;
    input_event->type = MOUSE_INPUT_EVENT;
    input_event->x = x;
    input_event->y = y;
    input_event->dz = dz;
    input_event->button_state = buttons;
    bh_schedule_one_shot(bh);
}

- (void)mouseMoved: (NSEvent*)event
{
    [self commonMouseEvent: event];
}

- (void)mouseDown: (NSEvent*)event
{
    [self commonMouseEvent: event];
}

- (void)mouseUp: (NSEvent*)event
{
    [self commonMouseEvent: event];
}

- (void)mouseDragged: (NSEvent*)event
{
    [self commonMouseEvent: event];
}

- (void)rightMouseDown: (NSEvent*)event
{
    [self commonMouseEvent: event];
}

- (void)rightMouseUp: (NSEvent*)event
{
    [self commonMouseEvent: event];
}

- (void)rightMouseDragged: (NSEvent*)event
{
    [self commonMouseEvent: event];
}

- (void)otherMouseDown: (NSEvent*)event
{
    [self commonMouseEvent: event];
}

- (void)otherMouseUp: (NSEvent*)event
{
    [self commonMouseEvent: event];
}

- (void)otherMouseDragged: (NSEvent*)event
{
    [self commonMouseEvent: event];
}

- (void)scrollWheel: (NSEvent*)event
{
    [self commonMouseEvent: event];
}

- (void)mouseEntered: (NSEvent*)event
{
    cursor_in_vm = YES;

    if (cursor)
        [cursor set];
    else
        [NSCursor hide];
}

- (void)mouseExited: (NSEvent*)event
{
    cursor_in_vm = NO;

    [[NSCursor arrowCursor] set];
    if (!cursor)
        [NSCursor unhide];
}

-(void)setCursor: (NSCursor *)new_cursor
{
    if (!new_cursor) {
        if (cursor && cursor_in_vm)
            [NSCursor hide];
        cursor = nil;
    } else {
        if (cursor_in_vm) {
            if (!cursor)
                [NSCursor unhide];
            [new_cursor set];
        }
        cursor = new_cursor;
    }
}

-(void)cursorUpdate: (NSEvent *)event
{
    if (cursor)
        [cursor set];
}

@end
