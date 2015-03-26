/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Michael Dales <michael@digitalflapjack.com>
 * SPDX-License-Identifier: ISC
 */

#import "osx-app-delegate.h"
#import "osx-vm-view.h"

// import this so we can use the same debug_printf as the rest of the code
#include "config.h"
#include "vm.h"

@implementation UXENAppDelegate

- (id)init
{
    if ((self = [super init]) != nil) {
        _window = nil;
        _vmView = nil;
    }

    return self;
}

- (void)createVMWindowWithFrame: (NSRect)frame
{
    _vmView = [[UXENVirtualMachineView alloc] initWithFrame: frame];
    if (_vmView == nil)	{
        debug_printf("UXENAppDelegate::createVMWindowWithFrame: "
                     "failed to create view\n");

        // XXX: now to return this error?
        return;
    }

    _window = [[NSWindow alloc]
                  initWithContentRect: _vmView.frame
                            styleMask: NSTitledWindowMask |
                  NSMiniaturizableWindowMask | NSClosableWindowMask
                              backing: NSBackingStoreBuffered
                                defer: NO];
    if(_window == nil) {
        debug_printf("UXENAppDelegate::createVMWindowWithFrame: "
                     "can't create window\n");

        // XXX: how to return this error?
        return;
    }

    [_window setDelegate: self];
    [_window setReleasedWhenClosed:NO];
    [_window setAcceptsMouseMovedEvents: YES];
    [_window setTitle: [NSString stringWithFormat: @"VM"]];
    [_window setContentView: _vmView];
    [_window useOptimizedDrawing: YES];
    [_window makeKeyAndOrderFront: self];
    [_window makeMainWindow];
    [_window center];
}

#pragma mark - NSWindow delegate methods

- (void)windowWillClose: (NSNotification *)notification
{
    // thread safe call to kill everything
    vm_set_run_mode(DESTROY_VM);
}

@end
