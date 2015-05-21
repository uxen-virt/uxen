/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#import <AppKit/AppKit.h>
#import <Carbon/Carbon.h>
#import <Foundation/Foundation.h>

#include <pthread.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <stdlib.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <assert.h>

#include "osx-keymap.h"
#include "uxenconsolelib.h"

@class UXENConsole;

extern NSString *const UXENConsoleErrorDomain;
extern NSString *const UXENConsoleErrorDescription;

enum {
    UXENConsoleErrorDispatchSourceCreateFailed = 1,
    UXENConsoleErrorCursorCreateFailed = 2,
    UXENConsoleErrorInvalidCursorDimensions = 3,
    UXENConsoleErrorInvalidOperation = 4,
};

typedef void (^UXENConsoleSurfaceBlock)(void *bytes,
                                        size_t length,
                                        int width,
                                        int height,
                                        int lineSize,
                                        int bitsPerPixel,
                                        int offset);

@protocol UXENConsoleDelegate <NSObject>

- (void)console:(UXENConsole *)console didResizeSurfaceWithError:(NSError *)error;
- (void)console:(UXENConsole *)console invalidateRect:(NSRect)rect error:(NSError *)error;
- (void)console:(UXENConsole *)console setCursor:(NSCursor *)cursor error:(NSError *)error;
- (void)console:(UXENConsole *)console didDisconnectWithError:(NSError *)error;

@end

@interface UXENConsole : NSObject

@property (nonatomic, weak) id<UXENConsoleDelegate> delegate;

+ (instancetype)consoleWithPath:(NSString *)path;
- (instancetype)initWithPath:(NSString *)path;
- (BOOL)connect:(NSError **)error;
- (BOOL)disconnectWithError:(NSError **)error;
- (void)readSurface:(UXENConsoleSurfaceBlock)surfaceBlock;
- (void)keyboardEventWithKeycode:(int)keycode
                              up:(BOOL)up;
- (void)mouseEventWithPoint:(NSPoint)point
                     scroll:(NSPoint)scroll
                    buttons:(unsigned int)buttons;

@end

@interface UXENConsole ()

@property (nonatomic, strong) NSString *path;
@property (nonatomic, strong) dispatch_source_t source;

@property (nonatomic, assign) uxenconsole_context_t ctx;
@property (nonatomic, assign) int channel_fd;

@property (nonatomic, assign) int shm_fd;
@property (nonatomic, assign) size_t shm_len;
@property (nonatomic, assign) void *shm_view;

@property (nonatomic, assign) int linesize;
@property (nonatomic, assign) int bpp;
@property (nonatomic, assign) int width;
@property (nonatomic, assign) int height;
@property (nonatomic, assign) int offset;

@property (nonatomic, assign) void *cursor_data;

@property (nonatomic, assign) BOOL connected;

@end

NSString *const UXENConsoleErrorDomain = @"UXENConsoleErrorDomain";
NSString *const UXENConsoleErrorDescription = @"UXENConsoleErrorDescription";

@implementation UXENConsole

#pragma mark - Utility functions

static NSCursor *
osx_create_cursor(uint8_t *data, int w, int h, int hot_x, int hot_y)
{
    CGColorSpaceRef colorspace;
    CGBitmapInfo info;
    CGDataProviderRef provider;
    CGImageRef image_ref;
    NSCursor *ret = nil;
    NSSize cursor_size;
    NSPoint cursor_hotspot;
    NSImage *cursor_image;
    
    info = kCGBitmapByteOrder32Little | kCGImageAlphaFirst;
    colorspace = CGColorSpaceCreateWithName(kCGColorSpaceGenericRGB);
    if (!colorspace)
        goto err_colorspace;
    
    provider = CGDataProviderCreateWithData(NULL, data, w * 4 * h, NULL);
    if (!provider)
        goto err_provider;
    
    image_ref = CGImageCreate(w, h, 8, 32, w * 4,
                              colorspace, info, provider,
                              NULL, 0,
                              kCGRenderingIntentDefault);
    if (!image_ref)
        goto err_image_ref;
    
    cursor_size = NSMakeSize(w, h);
    cursor_hotspot = NSMakePoint(hot_x, hot_y);
    
    cursor_image = [[NSImage alloc] initWithCGImage: image_ref
                                               size: cursor_size];
    ret = [[NSCursor alloc] initWithImage: cursor_image
                                  hotSpot: cursor_hotspot];
    
    
    CGImageRelease(image_ref);
err_image_ref:
    CGDataProviderRelease(provider);
err_provider:
    CGColorSpaceRelease(colorspace);
err_colorspace:
    return ret;
}

#pragma mark - Callback functions

static void
console_resize_surface(void *priv,
                       unsigned int width,
                       unsigned int height,
                       unsigned int linesize,
                       unsigned int length,
                       unsigned int bpp,
                       unsigned int offset,
                       int shm_handle)
{
    @autoreleasepool {
        UXENConsole *console = (__bridge UXENConsole *)priv;
        @synchronized(console) {
            
            void *v;
            
            v = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED,
                     shm_handle, 0);
            if (v == MAP_FAILED) {
                int code = errno;
                close(shm_handle);
                NSError *error = [NSError errorWithDomain:NSPOSIXErrorDomain
                                                     code:code
                                                 userInfo:@{UXENConsoleErrorDescription: @"mmap failed"}];
                [console.delegate console:console didResizeSurfaceWithError:error];
                return;
            }

            /* Check we're in a valid state */
            assert((console.shm_view != NULL && console.shm_len > 0 && console.shm_fd >= 0) ||
                   (console.shm_view == NULL && console.shm_len == 0 && console.shm_fd == -1));

            /* Unmap the previous shared memory */
            if (console.shm_view != NULL && console.shm_len > 0) {
                munmap(console.shm_view, console.shm_len);
                close(console.shm_fd);
                console.shm_view = NULL;
                console.shm_len = 0;
                console.shm_fd = -1;
            }
            
            /* Map the new shared memory */
            console.shm_fd = shm_handle;
            console.shm_view = v;
            console.shm_len = length;
            
            /* Store the dimensions */
            console.linesize = linesize;
            console.bpp = bpp;
            console.width = width;
            console.height = height;
            console.offset = offset;
            
            [console.delegate console:console didResizeSurfaceWithError:nil];
            
        }
    }
}

static void
console_invalidate_rect(void *priv,
                        int x,
                        int y,
                        int w,
                        int h)
{
    @autoreleasepool {
        UXENConsole *console = (__bridge UXENConsole *)priv;
        @synchronized(console) {
            
            NSRect rect = NSMakeRect(x, console.height - y - h, w, h);
            [console.delegate console:console
                       invalidateRect:rect
                                error:nil];
            
        }
    }
}

static void
console_update_cursor(void *priv,
                      unsigned int width,
                      unsigned int height,
                      unsigned int hot_x,
                      unsigned int hot_y,
                      unsigned int mask_offset,
                      unsigned int flags,
                      int shm_handle)
{
    @autoreleasepool {
        UXENConsole *console = (__bridge UXENConsole *)priv;
        @synchronized(console) {
            
            NSCursor *cursor = nil;
            void *v, *cursor_data;
            size_t len;
            
            /* Clear the cursor if none is set or it is hidden */
            if (width == 0 || height == 0 ||
                flags & CURSOR_UPDATE_FLAG_HIDE) {
                [console.delegate console:console
                                setCursor:nil
                                    error:nil];
                return;
            }

            /* Sanity check */
            if (width > 128 || height > 128 ||
                hot_x >= width || hot_y >= height) {
                NSError *error = [NSError errorWithDomain:UXENConsoleErrorDomain
                                                     code:UXENConsoleErrorInvalidCursorDimensions
                                                 userInfo:@{UXENConsoleErrorDescription: @"invalid cursor dimensions"}];
                [console.delegate console:console
                                setCursor:nil
                                    error:error];
                return;
            }

            /* Calculate the correct length accounting for the mask */
            if (mask_offset) {
                len = mask_offset;
                len += ((width + 7) / 8) * height;
                if (flags & CURSOR_UPDATE_FLAG_MONOCHROME)
                    len += ((width + 7) / 8) * height;
            } else
                len = height * width * 4;

            v = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED,
                     shm_handle, 0);
            if (v == MAP_FAILED) {
                int code = errno;
                close(shm_handle);
                NSError *error =
                [NSError errorWithDomain:NSPOSIXErrorDomain
                                    code:code
                                userInfo:@{UXENConsoleErrorDescription: @"cursor mmap failed"}];
                [console.delegate console:console
                                setCursor:nil
                                    error:error];
                return;
            }
            cursor_data = malloc(len);
            if (!cursor_data) {
                int code = errno;
                munmap(v, len);
                close(shm_handle);
                NSError *error =
                [NSError errorWithDomain:NSPOSIXErrorDomain
                                    code:code
                                userInfo:@{UXENConsoleErrorDescription: @"cusor malloc failed"}];
                [console.delegate console:console
                                setCursor:nil
                                    error:error];
                return;
            }

            if (flags & CURSOR_UPDATE_FLAG_MONOCHROME) {
                uint8_t *and = v;
                uint8_t *xor;
                uint32_t *pixel = cursor_data;
                int x, y;
                int p;

                and += mask_offset;
                xor = and + ((width + 7) / 8) * height;

                for (y = 0; y < height; y++) {
                    for (x = 0; x < width; x++) {
                        p = ((xor[x / 8] << (x % 8)) & 0x80) ? 0x1 : 0x0 ;
                        p |= ((and[x / 8] << (x % 8)) & 0x80) ? 0x2 : 0x0;

                        switch (p) {
                        case 0x0:
                            pixel[x] = 0xFF000000;
                            break;
                        case 0x1:
                            pixel[x] = 0xFFFFFFFF;
                            break;
                        case 0x2:
                            pixel[x] = 0x00FFFFFF;
                            break;
                        case 0x3:
                            pixel[x] = 0xFF000000;
                            break;
                        }
                    }
                    and += (width + 7) / 8;
                    xor += (width + 7) / 8;
                    pixel += width;
                }
            } else {
                memcpy(cursor_data, v, width * height * 4);

                if (mask_offset) {
                    uint8_t *mask = v;
                    uint32_t *pixel = cursor_data;
                    int x, y;
                    int p;

                    mask += mask_offset;

                    for (y = 0; y < height; y++) {
                        for (x = 0; x < width; x++) {
                            p = ((mask[x / 8] << (x % 8)) & 0x80) ? 0x1 : 0x0;

                            if (((pixel[x] & 0x00FFFFFF) == 0x00FFFFFF) && p)
                                pixel[x] = 0xFF000000;
                            else if (!p)
                                pixel[x] |= 0xFF000000;
                        }
                        mask += (width + 7) / 8;
                        pixel += width;
                    }
                }
            }

            munmap(v, len);
            close(shm_handle);

            cursor = osx_create_cursor(cursor_data, width, height, hot_x, hot_y);
            
            if (cursor)
                [console.delegate console:console
                                setCursor:cursor
                                    error:nil];
            else {
                NSError *error = [NSError errorWithDomain:UXENConsoleErrorDomain
                                                     code:UXENConsoleErrorCursorCreateFailed
                                                 userInfo:@{UXENConsoleErrorDescription: @"cursor create failed"}];
                [console.delegate console:console
                                setCursor:nil
                                    error:error];
            }
        
            if (console.cursor_data)
                free(console.cursor_data);
            console.cursor_data = cursor_data;
            
        }
    }
}

static void
console_disconnected(void *priv)
{
    @autoreleasepool {
        UXENConsole *console = (__bridge UXENConsole *)priv;
        @synchronized(console) {
            
            [console.delegate console:console didDisconnectWithError:nil];
            [console cleanup];
            
        }
    }
}

static ConsoleOps console_ops = {
    .resize_surface = console_resize_surface,
    .invalidate_rect = console_invalidate_rect,
    .update_cursor = console_update_cursor,
    .disconnected = console_disconnected,
};

#pragma mark - Public API

+ (instancetype)consoleWithPath:(NSString *)path
{
    return [[self alloc] initWithPath:path];
}

- (instancetype)initWithPath:(NSString *)path
{
    self = [super init];
    if (self) {
        _path = path;
        _shm_fd = -1;
    }
    return self;
}

- (void)dealloc
{
    [self cleanup];
}

- (BOOL)connect:(NSError **)error
{
    @synchronized(self) {
        
        /* Only support one connection */
        if (self.connected) {
            if (error) {
                *error = [NSError errorWithDomain:UXENConsoleErrorDomain
                                             code:UXENConsoleErrorInvalidOperation
                                         userInfo:@{UXENConsoleErrorDescription: @"Attempt to connect when already connected."}];
            }
            return NO;
        }
        
        self.ctx = uxenconsole_init(&console_ops,
                                    (__bridge void *)(self),
                                    (char *)[self.path fileSystemRepresentation]);
        if (self.ctx == NULL) {
            if (error) {
                int code = errno;
                *error = [NSError errorWithDomain:NSPOSIXErrorDomain
                                             code:code
                                         userInfo:@{UXENConsoleErrorDescription: @"uxenconsole_init failed"}];
            }
            return NO;
        }
        
        self.channel_fd = uxenconsole_connect(self.ctx);
        if (self.channel_fd < 0) {
            if (error) {
                int code = errno;
                *error = [NSError errorWithDomain:NSPOSIXErrorDomain
                                             code:code
                                         userInfo:@{UXENConsoleErrorDescription: @"uxenconsole_connect failed"}];
            }
            return NO;
        }
        
        self.source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,
                                             self.channel_fd,
                                             0,
                                             dispatch_get_main_queue());
        if (!self.source) {
            uxenconsole_cleanup(self.ctx);
            self.ctx = 0;
            self.channel_fd = -1;
            if (error)
                *error = [NSError errorWithDomain:UXENConsoleErrorDomain
                                             code:UXENConsoleErrorDispatchSourceCreateFailed
                                         userInfo:@{UXENConsoleErrorDescription: @"dispatch_source_create failed"}];
            return NO;
        }
        
        __weak UXENConsole *weakSelf = self;
        dispatch_source_set_event_handler(self.source, ^{
            UXENConsole *strongSelf = weakSelf;
            if (strongSelf)
                uxenconsole_channel_event(strongSelf.ctx,
                                          strongSelf.channel_fd,
                                          0);
        });
        
        dispatch_resume(self.source);
        
        self.connected = YES;
        
        return YES;
    }
}

- (BOOL)disconnectWithError:(NSError **)error
{
    @synchronized(self) {
        
        if (!self.connected) {
            if (error) {
                *error = [NSError errorWithDomain:UXENConsoleErrorDomain
                                             code:UXENConsoleErrorInvalidOperation
                                         userInfo:@{UXENConsoleErrorDescription: @"Attempt to disconnect when not connected."}];
            }
            return NO;
        }
        
        [self cleanup];
        return YES;
        
    }
}

- (void)readSurface:(UXENConsoleSurfaceBlock)surfaceBlock
{
    @synchronized(self) {
        surfaceBlock(self.shm_view,
                     self.shm_len,
                     self.width,
                     self.height,
                     self.linesize,
                     self.bpp,
                     self.offset);
        
    }
}

- (void)cleanup
{
    @synchronized(self) {
        
        if (self.connected) {
            
            /* Releases and stops the source */
            self.source = nil;
            
            uxenconsole_cleanup(self.ctx);
            self.ctx = 0;
            self.channel_fd = -1;
            
            if (self.shm_view) {
                munmap(self.shm_view, self.shm_len);
                self.shm_view = NULL;
                self.shm_len = 0;
            }
            
            if (self.cursor_data) {
                free(self.cursor_data);
                self.cursor_data = NULL;
            }
            
            if (self.shm_fd >= 0) {
                close(self.shm_fd);
                self.shm_fd = -1;
            }
            
            self.width = 0;
            self.height = 0;
            
            self.connected = NO;
        }
        
    }
}

- (void)keyboardEventWithKeycode:(int)keycode
                              up:(BOOL)up
{
    @synchronized(self) {
        
        unsigned int scancode = osx_keymap[keycode].scancode |
        (up ? 0x80 : 0);
        unsigned int flags = 0;
        
        if (osx_keymap[keycode].extended)
            flags |= KEYBOARD_EVENT_FLAG_EXTENDED;
        
        uxenconsole_keyboard_event(self.ctx, keycode, 1, scancode, flags, NULL, 0);
        
    }
}

- (void)mouseEventWithPoint:(NSPoint)point
                     scroll:(NSPoint)scroll
                    buttons:(unsigned int)buttons
{
    @synchronized(self) {
        
        uxenconsole_mouse_event(self.ctx, point.x, point.y, scroll.x, scroll.y, buttons);
        
    }
}

@end

@interface VirtualMachineView : NSView

@property (nonatomic, assign) int lastx;
@property (nonatomic, assign) int lasty;
@property (nonatomic, assign) NSUInteger lastflags;

@property (nonatomic, strong) NSTrackingArea *trackingArea;
@property (nonatomic, strong) NSCursor *cursor;
@property (nonatomic, assign) BOOL cursor_in_vm;

@property (nonatomic, strong) UXENConsole *console;

@end

#define cgrect(nsrect) (*(CGRect *)&(nsrect))

@implementation VirtualMachineView

- (id)initWithFrame:(NSRect)frame
{
    @throw @"Don't call this";
}

- (id)initWithFrame:(NSRect)frame console:(UXENConsole *)console
{
    self = [super initWithFrame:frame];
    if (self) {

        _console = console;

        _cursor = [NSCursor arrowCursor];
        _cursor_in_vm = YES;
        _trackingArea =
            [[NSTrackingArea alloc] initWithRect:[self bounds]
                                         options:NSTrackingMouseEnteredAndExited |
                                                 NSTrackingMouseMoved |
                                                 NSTrackingCursorUpdate |
                                                 NSTrackingActiveAlways
                                           owner:self
                                        userInfo:nil];
        [self addTrackingArea:_trackingArea];
    }

    return self;
}

- (void)updateTrackingAreas
{
    [self removeTrackingArea:self.trackingArea];

    self.trackingArea =
        [[NSTrackingArea alloc] initWithRect:[self bounds]
                                     options:NSTrackingMouseEnteredAndExited |
                                             NSTrackingMouseMoved |
                                             NSTrackingCursorUpdate |
                                             NSTrackingActiveAlways
                                       owner:self
                                    userInfo:nil];
    [self addTrackingArea:self.trackingArea];
}

- (void)drawRect:(NSRect)damageArea
{
    [self.console readSurface:^(void *bytes,
                                size_t length,
                                int width,
                                int height,
                                int lineSize,
                                int bitsPerPixel,
                                int offset) {
        
        if (bytes == NULL)
            return;
        
        CGDataProviderRef dataProviderRef = CGDataProviderCreateWithData(NULL, bytes, width * 4 * height, NULL);
        if (dataProviderRef == NULL) {
            NSLog(@"Unable to create data provider.");
            return;
        }
        
        // get CoreGraphic context
        CGContextRef viewContextRef =
        [[NSGraphicsContext currentContext] graphicsPort];
        CGContextSetInterpolationQuality(viewContextRef, kCGInterpolationNone);
        CGContextSetShouldAntialias(viewContextRef, NO);

        // draw screen bitmap directly to Core Graphics context
        CGImageRef imageRef = CGImageCreate(
                                            width,            // width
                                            height,          // height
                                            8,               // bitsPerComponent
                                            32,              // bitsPerPixel
                                            (width * 4),     // bytesPerRow
                                            CGColorSpaceCreateWithName(kCGColorSpaceGenericRGB), // colorspace
                                            kCGBitmapByteOrder32Little | kCGImageAlphaNoneSkipFirst,
                                            // bitmapInfo
                                            dataProviderRef, // provider
                                            NULL,            // decode
                                            0,                         // interpolate
                                            kCGRenderingIntentDefault  // intent
                                            );
        
        const NSRect *rectList;
        NSInteger rectCount;
        int i;
        CGImageRef clipImageRef;
        CGRect clipRect;

        [self getRectsBeingDrawn:&rectList count:&rectCount];
        for (i = 0; i < rectCount; i++) {
            clipRect.origin.x = rectList[i].origin.x;
            clipRect.origin.y = (float)height -
            (rectList[i].origin.y + rectList[i].size.height);
            clipRect.size.width = rectList[i].size.width;
            clipRect.size.height = rectList[i].size.height;
            clipImageRef = CGImageCreateWithImageInRect(
                                                        imageRef, clipRect);
            CGContextDrawImage(viewContextRef, cgrect(rectList[i]),
                               clipImageRef);
            CGImageRelease(clipImageRef);
        }
        
        CGImageRelease(imageRef);
        CGDataProviderRelease(dataProviderRef);
        
    }];
}

- (BOOL)isOpaque
{
    return YES;
}

- (BOOL)acceptsFirstResponder
{
    return YES;
}

- (void)keyUp:(NSEvent*)event
{
    [self.console keyboardEventWithKeycode:[event keyCode]
                                        up:YES];
}

- (void)keyDown:(NSEvent*)event
{
    [self.console keyboardEventWithKeycode:[event keyCode]
                                        up:NO];
}

- (void)update_key_modifiers: (NSUInteger)modifier
{
    NSUInteger flags = self.lastflags ^ modifier;

    self.lastflags = modifier;

    if (flags & MODKEY_LSHIFT)
        [self.console keyboardEventWithKeycode:KEY_LSHIFT
                                            up:!(self.lastflags & MODKEY_LSHIFT)];
    if (flags & MODKEY_RSHIFT)
        [self.console keyboardEventWithKeycode:KEY_RSHIFT
                                            up:!(self.lastflags & MODKEY_RSHIFT)];
    
    if (flags & MODKEY_LCTRL)
        [self.console keyboardEventWithKeycode:KEY_LCTRL
                                            up:!(self.lastflags & MODKEY_LCTRL)];
    if (flags & MODKEY_RCTRL)
        [self.console keyboardEventWithKeycode:KEY_RCTRL
                                            up:!(self.lastflags & MODKEY_RCTRL)];

    if (flags & MODKEY_LALT)
        [self.console keyboardEventWithKeycode:KEY_LALT
                                            up:!(self.lastflags & MODKEY_LALT)];
    if (flags & MODKEY_RALT)
        [self.console keyboardEventWithKeycode:KEY_RALT
                                            up:!(self.lastflags & MODKEY_RALT)];

    if (flags & MODKEY_LCMD)
        [self.console keyboardEventWithKeycode:KEY_LCMD
                                            up:!(self.lastflags & MODKEY_LCMD)];
    if (flags & MODKEY_RCMD)
        [self.console keyboardEventWithKeycode:KEY_RCMD
                                            up:!(self.lastflags & MODKEY_RCMD)];

    if (flags & MODKEY_CAPSLOCK) {
        [self.console keyboardEventWithKeycode:KEY_CAPSLOCK
                                            up:NO];
        /* Delay release by 100ms otherwise the HID system in OSX locks up */
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(100 * NSEC_PER_MSEC)),
                       dispatch_get_main_queue(), ^(void){
                           [self.console keyboardEventWithKeycode:KEY_CAPSLOCK
                                                               up:YES];
                       });
    }
}

- (void)flagsChanged:(NSEvent*)event
{
    [self update_key_modifiers:[event modifierFlags]];
}

- (void)becomeKeyWindow
{
    [self update_key_modifiers:[NSEvent modifierFlags]];
}

- (void)resignKeyWindow
{
}

- (void)commonMouseEvent:(NSEvent*)event
{
    int dz;
    int buttons;

    NSPoint p = [event locationInWindow];

    p.y = self.frame.size.height - p.y;

    if (p.x < 0 || p.x >= self.frame.size.width ||
        p.y < 0 || p.y >= self.frame.size.height)
        return;

    dz = (event.type == NSScrollWheel) ? -[event deltaY] : 0;

    buttons = (int)[NSEvent pressedMouseButtons];

    [self.console mouseEventWithPoint:p
                               scroll:NSMakePoint(dz, 0)
                              buttons:buttons];
}

- (void)mouseMoved:(NSEvent*)event
{
    [self commonMouseEvent:event];
}

- (void)mouseDown:(NSEvent*)event
{
    [self commonMouseEvent:event];
}

- (void)mouseUp:(NSEvent*)event
{
    [self commonMouseEvent:event];
}

- (void)mouseDragged:(NSEvent*)event
{
    [self commonMouseEvent:event];
}

- (void)rightMouseDown:(NSEvent*)event
{
    [self commonMouseEvent:event];
}

- (void)rightMouseUp:(NSEvent*)event
{
    [self commonMouseEvent:event];
}

- (void)rightMouseDragged:(NSEvent*)event
{
    [self commonMouseEvent:event];
}

- (void)otherMouseDown:(NSEvent*)event
{
    [self commonMouseEvent:event];
}

- (void)otherMouseUp:(NSEvent*)event
{
    [self commonMouseEvent:event];
}

- (void)otherMouseDragged:(NSEvent*)event
{
    [self commonMouseEvent:event];
}

- (void)scrollWheel:(NSEvent*)event
{
    [self commonMouseEvent:event];
}

- (void)mouseEntered:(NSEvent*)event
{
    self.cursor_in_vm = YES;

    if (self.cursor)
        [self.cursor set];
    else
        [NSCursor hide];
}

- (void)mouseExited:(NSEvent*)event
{
    self.cursor_in_vm = NO;

    [[NSCursor arrowCursor] set];
    if (!self.cursor)
        [NSCursor unhide];
}

-(void)setCursor:(NSCursor *)new_cursor
{
    if (!new_cursor) {
        if (self.cursor && self.cursor_in_vm)
            [NSCursor hide];
        _cursor = nil;
    } else {
        if (self.cursor_in_vm) {
            if (!self.cursor)
                [NSCursor unhide];
            [new_cursor set];
        }
        _cursor = new_cursor;
    }
}

-(void)cursorUpdate:(NSEvent *)event
{
    if (self.cursor)
        [self.cursor set];
}

@end

@interface ConsoleAppDelegate : NSObject
<NSApplicationDelegate
,NSWindowDelegate
,UXENConsoleDelegate>

@property (nonatomic, strong) NSString *path;
@property (nonatomic, strong) VirtualMachineView *vmView;
@property (nonatomic, strong) NSWindow *window;
@property (nonatomic, strong) UXENConsole *console;

@end

@implementation ConsoleAppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification
{
    self.path = [[NSProcessInfo processInfo] arguments][1];
    self.console = [UXENConsole consoleWithPath:self.path];
    self.console.delegate = self;
    NSError *error = nil;
    BOOL success = [self.console connect:&error];
    if (NO == success) {
        NSLog(@"Failed to connect with error %@", error);
        self.console = nil;
        exit(1);
    }
}

- (void)applicationWillTerminate:(NSNotification *)notification
{
    NSError *error = nil;
    BOOL success = [self.console disconnectWithError:&error];
    if (NO == success) {
        NSLog(@"Failed to disconnect with error %@", error);
        exit(1);
    }
    self.window = nil;
    self.vmView = nil;
    self.console = nil;
}

- (void)createWindow:(NSRect)frame
{
    self.vmView = [[VirtualMachineView alloc] initWithFrame:frame
                                                    console:self.console];
    if (self.vmView == nil)
        return;

    self.window = [[NSWindow alloc]
                  initWithContentRect:self.vmView.frame
                            styleMask:NSTitledWindowMask |
                                      NSMiniaturizableWindowMask |
                                      NSClosableWindowMask
                              backing:NSBackingStoreBuffered
                                defer:NO];
    if(self.window == nil)
        return;

    [self.window setDelegate:self];
    [self.window setReleasedWhenClosed:NO];
    [self.window setAcceptsMouseMovedEvents:YES];
    [self.window setTitle:[NSString stringWithFormat:@"VM"]];
    [self.window setContentView:self.vmView];
    [self.window makeKeyAndOrderFront:self];
    [self.window makeMainWindow];
    [self.window center];
}

#pragma mark - NSWindow delegate methods

- (void)windowWillClose:(NSNotification *)notification
{
    [[NSApplication sharedApplication] terminate:self];
}

#pragma mark - UXENConsoleDelegate

- (void)console:(UXENConsole *)console didResizeSurfaceWithError:(NSError *)error
{
    if (error) {
        NSLog(@"Resize surface failed with error %@", error);
        return;
    }
    
    [console readSurface:^(void *bytes,
                           size_t length,
                           int width,
                           int height,
                           int lineSize,
                           int bitsPerPixel,
                           int offset) {
        if (self.window) {
            [self.window setContentSize:CGSizeMake(width, height)];
        } else {
            [self createWindow:NSMakeRect(0.0, 0.0, width, height)];
        }

        // Force a redraw.
        [self.vmView setNeedsDisplay:YES];
    }];
}

- (void)console:(UXENConsole *)console invalidateRect:(NSRect)rect error:(NSError *)error
{
    if (error) {
        NSLog(@"Invalidate rect failed with error %@", error);
        return;
    }
    
    NSApplication *application = [NSApplication sharedApplication];
    ConsoleAppDelegate *delegate = (ConsoleAppDelegate*)[application delegate];
    VirtualMachineView *view = delegate.vmView;
    [view setNeedsDisplayInRect:rect];
}

- (void)console:(UXENConsole *)console setCursor:(NSCursor *)cursor error:(NSError *)error
{
    if (error) {
        NSLog(@"Set cursor failed with error %@", error);
        return;
    }
    
    [self.vmView setCursor:cursor];
}

- (void)console:(UXENConsole *)console didDisconnectWithError:(NSError *)error
{
    if (error)
        NSLog(@"Disconnected with error %@", error);

    [self.window performClose:nil];
    [NSApp terminate:nil];
}

@end

int
main(int argc, char **argv)
{
    ProcessSerialNumber psn = { 0, kCurrentProcess };
    TransformProcessType(&psn, kProcessTransformToForegroundApplication);
    @autoreleasepool {
        [NSApplication sharedApplication];
        ConsoleAppDelegate *delegate = [[ConsoleAppDelegate alloc] init];
        NSApplication *application = [NSApplication sharedApplication];
        [application setDelegate:delegate];
        [NSApp run];
    }
}
