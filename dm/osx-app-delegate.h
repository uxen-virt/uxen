/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Michael Dales <michael@digitalflapjack.com>
 * SPDX-License-Identifier: ISC
 */

#import <AppKit/AppKit.h>

@class UXENVirtualMachineView;

@interface UXENAppDelegate : NSObject <NSApplicationDelegate, NSWindowDelegate>

@property (nonatomic, retain) UXENVirtualMachineView *vmView;
@property (nonatomic, retain) NSWindow *window;


- (void)createVMWindowWithFrame: (NSRect)frame;

@end