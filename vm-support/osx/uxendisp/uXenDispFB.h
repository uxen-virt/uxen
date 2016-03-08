/*
 * Copyright 2013-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENDISP_FB_H_
#define _UXENDISP_FB_H_

#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/graphics/IOFramebuffer.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

#include "../../../dm/hw/uxdisp_hw.h" /* XXX */

#if DEBUG
#define dprintk(fmt, ...) IOLog("uxendisp: " fmt, ## __VA_ARGS__)
#else
#define dprintk(fmt, ...) do {} while (0);
#endif

struct mode_info {
    IODisplayModeID id;
    IODisplayModeInformation mode;
    IOPixelInformation pix;
};

typedef struct interrupt_info {
    IOFBInterruptProc proc;
    OSObject *target;
    void *ref;
    bool set;
    bool enabled;
} interrupt_info;

class uXenDispFB : public IOFramebuffer
{
    OSDeclareDefaultStructors(uXenDispFB);

public:
    /* IOService */
    virtual bool init(OSDictionary *dict = NULL);
    virtual void free(void);
    virtual IOService *probe(IOService *provider, SInt32 *score);

    virtual bool start(IOService *provider);
    virtual void stop(IOService *provider);

    /* IOFramebuffer */
    virtual IODeviceMemory *getApertureRange(IOPixelAperture);
    virtual IODeviceMemory *getVRAMRange();
    virtual IOReturn getCurrentDisplayMode(IODisplayModeID *, IOIndex *);
    virtual IOItemCount getDisplayModeCount(void);
    virtual IOReturn getDisplayModes(IODisplayModeID *);
    virtual IOReturn getInformationForDisplayMode(IODisplayModeID,
                                                  IODisplayModeInformation *);
    virtual const char *getPixelFormats(void);
    virtual UInt64 getPixelFormatsForDisplayMode(IODisplayModeID, IOIndex);
    virtual IOReturn getPixelInformation(IODisplayModeID, IOIndex,
                                         IOPixelAperture,
                                         IOPixelInformation *);
    virtual IOReturn setDisplayMode(IODisplayModeID, IOIndex);
    virtual IOReturn getAttribute(IOSelect, uintptr_t *);
    virtual void flushCursor(void);
    virtual IOReturn setCursorImage(void *);
    virtual IOReturn setCursorState(SInt32, SInt32, bool);
    virtual IOReturn registerForInterruptType(IOSelect,
                                              IOFBInterruptProc,
                                              OSObject *,
                                              void *,
                                              void **);
    virtual IOReturn setGammaTable(UInt32 channelCount,
                                   UInt32 dataCount,
                                   UInt32 dataWidth,
                                   void *data);
    virtual IOReturn getTimingInfoForDisplayMode(IODisplayModeID displayMode,
                                                 IOTimingInformation *info);
    virtual IOReturn newUserClient(task_t,
                                   void *,
                                   UInt32,
                                   IOUserClient **);
    virtual IOReturn unregisterInterrupt(void *interruptRef);
    virtual IOReturn setInterruptState(void *interruptRef,
                                       UInt32 state);

    IOReturn setCustomMode(unsigned long, unsigned long);

private:
    IOPCIDevice *pcidev;
    IODeviceMemory *vram;
    size_t vram_size;

    struct mode_info *modes, *current_mode;
    unsigned int custom_mode;
    unsigned int n_modes;

    bool cursor_visible;

    /* vblank timer */
    IOWorkLoop *vblank_workloop;
    IOTimerEventSource *vblank_timer;
  
    /* interrupts */
    interrupt_info vblank_interrupt;
    interrupt_info connect_interrupt;
  
    int init_modes(void);
    size_t get_fb_size(void);
    size_t get_vram_size(void) const;

    void configureInterrupt(interrupt_info *interrupt,
                            IOFBInterruptProc proc,
                            OSObject *target,
                            void *ref,
                            void **interrupt_ref);
    void sendInterrupt(interrupt_info *interrupt);
  
    static void timerCallback(OSObject *owner,
                              IOTimerEventSource *sender);
    void scheduleVBLTimer();
    void enableVBL(bool enable);
  
    void cleanup();

    int set_mode(unsigned int width, unsigned int height,
                 unsigned int bpp, unsigned int stride);
    int get_current_mode(unsigned int *width, unsigned int *height,
                         unsigned int *bpp /*, unsigned int *stride */);

    IOMemoryMap *mmio;

    uint32_t uxdisp_read(uint32_t reg) const
    {
        return *(uint32_t *)((uint8_t *)mmio->getVirtualAddress() + reg);
    }
    void uxdisp_write(uint32_t reg, uint32_t val)
    {
        *(uint32_t *)((uint8_t *)mmio->getVirtualAddress() + reg) = val;
    }
    uint32_t uxdisp_alloc_read(uint32_t alloc, uint32_t reg) const
    {
        return uxdisp_read(UXDISP_REG_ALLOC(alloc) + reg);
    }
    void uxdisp_alloc_write(uint32_t alloc, uint32_t reg, uint32_t val)
    {
        return uxdisp_write(UXDISP_REG_ALLOC(alloc) + reg, val);
    }
    uint32_t uxdisp_crtc_read(uint32_t crtc, uint32_t reg) const
    {
        return uxdisp_read(UXDISP_REG_CRTC(crtc) + reg);
    }
    void uxdisp_crtc_write(uint32_t crtc, uint32_t reg, uint32_t val)
    {
        return uxdisp_write(UXDISP_REG_CRTC(crtc) + reg, val);
    }
};

#endif /* _UXENDISP_FB_H_ */
