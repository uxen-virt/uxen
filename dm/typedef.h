/*
 * Copyright 2012-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _TYPEDEF_H_
#define _TYPEDEF_H_

typedef struct AIOPool AIOPool;
typedef struct BlockDriver BlockDriver;
typedef struct BlockDriverState BlockDriverState;
typedef struct BusInfo BusInfo;
typedef struct BusState BusState;
typedef struct CharDriverState CharDriverState;
typedef struct DeviceInfo DeviceInfo;
typedef struct DeviceState DeviceState;
typedef struct DisplayAllocator DisplayAllocator;
typedef struct DisplayChangeListener DisplayChangeListener;
typedef struct DisplayState DisplayState;
typedef struct DriveInfo DriveInfo;
typedef struct ISABus ISABus;
typedef struct ISADevice ISADevice;
typedef struct ISADeviceInfo ISADeviceInfo;
typedef struct MACAddr MACAddr;
typedef struct MemoryRegion MemoryRegion;
typedef struct MemoryRegionOps MemoryRegionOps;
typedef struct Monitor Monitor;
typedef struct NetQueue NetQueue;
typedef struct NICInfo NICInfo;
typedef struct PCIBridge PCIBridge;
typedef struct PCIBus PCIBus;
typedef struct PCIDevice PCIDevice;
typedef struct PCIHostState PCIHostState;
typedef struct PCII440FXState PCII440FXState;
typedef struct Property Property;
typedef struct PropertyInfo PropertyInfo;
typedef struct QEMUFile QEMUFile;
typedef struct RTCState RTCState;
typedef struct SerialSetParams SerialSetParams;
typedef struct SerialState SerialState;
typedef struct Timer Timer;
typedef TAILQ_HEAD( , Timer) TimerQueue;
typedef struct VLANState VLANState;
typedef struct VLANClientState VLANClientState;
typedef struct VMStateField VMStateField;
typedef struct VMStateInfo VMStateInfo;
typedef struct VMStateDescription VMStateDescription;
typedef struct VMStateSubsection VMStateSubsection;
typedef struct WaitObjects WaitObjects;
typedef struct WaitObjectsDesc WaitObjectsDesc;
typedef void WaitObjectFunc(void *opaque);
typedef void WaitObjectFunc2(void *opaque, int revents);
typedef struct i2c_bus i2c_bus;

#endif	/* _TYPEDEF_H_ */
