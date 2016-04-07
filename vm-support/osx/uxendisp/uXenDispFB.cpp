/*
 * Copyright 2013-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <IOKit/IOLib.h>
#include <IOKit/IOTimerEventSource.h>

#include "uXenDispFB.h"
#include "uXenDispCtl.h"

#define super IOFramebuffer

OSDefineMetaClassAndStructors(uXenDispFB, IOFramebuffer);

#define FREQUENCY_TIMER_US 16667 /* 60Hz */

/*
 * Note:
 *  Documentation can be found there: http://bit.ly/ZfX0fm (IOFramebuffer),
 *  and there: http://bit.ly/WRTCwt (IOGraphicsTypes.h User-Space Reference)
 */

/* HW */
struct hw_mode {
    int id;
    unsigned int xres;
    unsigned int yres;
    unsigned int bpp;
};

static struct hw_mode hw_modes[] = {
    { 0x143,  800,  600, 32 },
    { 0x148, 1024,  768, 32 },
    { 0x14d, 1024,  700, 32 },
    { 0x145, 1280, 1024, 32 },
    { 0x147, 1600, 1200, 32 },
    { 0x186, 1680, 1050, 32 },
    { 0x189, 1920, 1200, 32 },
    { 0x17a, 1280,  800, 32 }, // 13" MacBook Pro
    { 0x17e, 1440,  900, 32 }, // 15" MacBook Pro/13" MacBook Air

    { 0x190, 1366,  768, 32 }, // not in bochs - 11" MacBook Air
    { 0x191, 2560, 1440, 32 }, // not in bochs - 27" iMac/Apple Thunderbolt Display
    { 0x192, 1920, 1080, 32 }, // not in bochs - 21.5" iMac
    { 0x193, 2560, 1600, 32 }, // not in bochs - 13" MacBook Pro Retina
    { 0x194, 2560, 1600, 32 }, // not in bochs - 13" MacBook Pro Retina scaled
    { 0x194, 2560, 1600, 32 }, // not in bochs - 13" MacBook Pro Retina scaled
    { 0x195, 1680 * 2, 1050 * 2, 32 }, // not in bochs - 13" MacBook Pro Retina scaled
    { 0x197, 1440 * 2,  900 * 2, 32 }, // not in bochs - 15" MacBook Pro Retina 
    { 0x198, 1024 * 2,  640 * 2, 32 }, // not in bochs - 13"/15" MacBook Pro Retina scaled
    { 0x199, 1280 * 2,  800 * 2, 32 }, // not in bochs - 15" MacBook Pro Retina scaled
    { 0x200, 1680 * 2, 1050 * 2, 32 }, // not in bochs - 13"/15" MacBook Pro Retina scaled
    { 0x201, 1920 * 2, 1200 * 2, 32 }, // not in bochs - 15" MacBook Pro Retina scaled
};

#define hw_mode_count (sizeof (hw_modes) / sizeof (hw_modes[0]))

#define Mode16bpp  "RRRRRGGGGGGRRRRR"
#define Mode24bpp  "RRRRRRRRGGGGGGGGBBBBBBBB"
#define Mode32bpp  IO32BitDirectPixels

static int get_mode_info(int index, struct mode_info *info)
{
    struct hw_mode *mode = &hw_modes[index];

    if (!info || index > hw_mode_count)
        return -1;

    info->id = mode->id;

    info->mode.nominalWidth = mode->xres;
    info->mode.nominalHeight = mode->yres;
    info->mode.refreshRate = 60U << 16;
    info->mode.flags = 0;
    info->mode.imageWidth = 0;
    info->mode.imageHeight = 0;
    info->mode.maxDepthIndex = 0;

    info->pix.bytesPerRow = mode->xres * ((mode->bpp + 7) / 8);
    info->pix.bytesPerPlane = 0;
    info->pix.bitsPerPixel = mode->bpp;
    info->pix.pixelType = kIORGBDirectPixels;
    info->pix.componentCount = 3;
    info->pix.flags = 0;
    info->pix.activeWidth = mode->xres;
    info->pix.activeHeight = mode->yres;

    switch (mode->bpp) {
    case 16:
        info->pix.bitsPerComponent = 6; /* 5-6-5 in theory */
        info->pix.componentMasks[0] = 0x0000F800; /* R */
        info->pix.componentMasks[1] = 0x000007E0; /* G */
        info->pix.componentMasks[2] = 0x0000001F; /* B */
        snprintf(info->pix.pixelFormat, sizeof (IOPixelEncoding), Mode16bpp);
        break;
    case 24:
    case 32:
        info->pix.bitsPerComponent = 8;
        info->pix.componentMasks[0] = 0x00FF0000; /* R */
        info->pix.componentMasks[1] = 0x0000FF00; /* G */
        info->pix.componentMasks[2] = 0x000000FF; /* B */
        snprintf(info->pix.pixelFormat, sizeof (IOPixelEncoding),
                 (mode->bpp == 32) ? Mode32bpp : Mode24bpp);
        break;
    default:
        return -1;
    }

    return 0;
}

int uXenDispFB::set_mode(unsigned int width, unsigned int height,
                         unsigned int bpp, unsigned int stride)
{
    uint32_t fmt;

    dprintk("%s: Setting mode %dx%d/%d, %dbpp\n", __func__,
            width, height, stride, bpp);

    switch (bpp) {
    case 32:
        fmt = UXDISP_CRTC_FORMAT_BGRX_8888;
        break;
    case 24:
        fmt = UXDISP_CRTC_FORMAT_BGR_888;
        break;
    case 16:
        fmt = UXDISP_CRTC_FORMAT_BGR_565;
        break;
    case 15:
        fmt = UXDISP_CRTC_FORMAT_BGR_555;
        break;
    default:
        return -1;
    }

    uxdisp_alloc_write(0, UXDISP_REG_ALLOC_PAGE_START, 0);
    uxdisp_alloc_write(0, UXDISP_REG_ALLOC_PAGE_COUNT,
                       ((height * stride + 64 /* shared memory header */ + 4095) >> 12) * 2);
    uxdisp_crtc_write(0, UXDISP_REG_CRTC_ENABLE, 1);
    uxdisp_crtc_write(0, UXDISP_REG_CRTC_XRES, width);
    uxdisp_crtc_write(0, UXDISP_REG_CRTC_YRES, height);
    uxdisp_crtc_write(0, UXDISP_REG_CRTC_STRIDE, stride);
    uxdisp_crtc_write(0, UXDISP_REG_CRTC_FORMAT, fmt);
    /* Flush */
    uxdisp_write(UXDISP_REG_MODE, UXDISP_MODE_VGA_DISABLED |
                                  UXDISP_MODE_PAGE_TRACKING_DISABLED);
    uxdisp_crtc_write(0, UXDISP_REG_CRTC_OFFSET, 0);

    return 0;
}

int uXenDispFB::get_current_mode(unsigned int *width, unsigned int *height,
                                 unsigned int *bpp /*, unsigned int *stride */)
{
    if (width)
        *width = uxdisp_crtc_read(0, UXDISP_REG_CRTC_XRES);
    if (height)
        *height = uxdisp_crtc_read(0, UXDISP_REG_CRTC_YRES);
    if (bpp) {
        uint32_t fmt = uxdisp_crtc_read(0, UXDISP_REG_CRTC_FORMAT);

        *bpp = uxdisp_fmt_to_bpp(fmt);
    }

    return 0;
}

int
uXenDispFB::init_modes()
{
    int i;
    int ret = 0;
    unsigned int cur_width, cur_height, cur_bpp;

    get_current_mode(&cur_width, &cur_height, &cur_bpp);
    dprintk("%s: Detected current mode %dx%d\n", __func__,
            cur_width, cur_height);

    current_mode = NULL;

    modes = (struct mode_info *)IOMalloc((hw_mode_count + 2) *
                                         sizeof (*modes));
    if (!modes)
        return -1;

    n_modes = 0;
    for (i = 0; i < hw_mode_count; i++) {
        struct mode_info *m = &modes[n_modes];

        ret = get_mode_info(i, m);
        if (ret) {
            IOFree(modes, (hw_mode_count + 2) * sizeof (*modes));
            return ret;
        }
        /* Check if enough video mem is available */
        if (m->pix.bytesPerRow * m->pix.activeHeight > vram_size) {
            dprintk("%s: Not enough vram for mode %x\n", __func__, m->id);
            continue;
        }
        if (m->pix.activeWidth == cur_width &&
            m->pix.activeHeight == cur_height &&
            m->pix.bitsPerPixel == cur_bpp &&
            !current_mode) {
            dprintk("%s: default mode = %x\n", __func__, m->id);
            m->mode.flags |= kDisplayModeDefaultFlag;
            m->pix.flags |= kDisplayModeDefaultFlag;
            current_mode = m;
        }

        n_modes++;
    }
    custom_mode = n_modes;
    for (i = 0; i < 2; i++) {
        struct mode_info *m = &modes[n_modes];

        memcpy(m, &modes[0], sizeof (struct mode_info));
        m->id = 0x400 + i;
        n_modes++;
    }

    dprintk("%s: Found %d modes\n", __func__, n_modes);

    return 0;
}

IOReturn
uXenDispFB::setCustomMode(unsigned long width, unsigned long height)
{
    struct mode_info *m;

    if (custom_mode == (n_modes - 1))
        custom_mode = n_modes - 2;
    else
        custom_mode = n_modes - 1;

    m = &modes[custom_mode];

    m->mode.nominalWidth = (UInt32)width;
    m->mode.nominalHeight = (UInt32)height;
    m->pix.bytesPerRow = (UInt32)(width * 4);
    m->pix.bitsPerPixel = 32;
    m->pix.activeWidth = (UInt32)width;
    m->pix.activeHeight = (UInt32)height;

    m->pix.bitsPerComponent = 8;
    m->pix.componentMasks[0] = 0x00FF0000; /* R */
    m->pix.componentMasks[1] = 0x0000FF00; /* G */
    m->pix.componentMasks[2] = 0x000000FF; /* B */
    snprintf(m->pix.pixelFormat, sizeof (IOPixelEncoding),
             IO32BitDirectPixels);

    /* Fake hotplug interrupt */
    sendInterrupt(&connect_interrupt);

    return kIOReturnSuccess;
}

size_t
uXenDispFB::get_fb_size()
{
    size_t len;

    if (!current_mode)
        return 0;

    len = current_mode->pix.activeHeight * current_mode->pix.bytesPerRow;

    /* align to next page boundary */
    return (len + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
}

size_t
uXenDispFB::get_vram_size() const
{
    size_t len;

    len = uxdisp_read(UXDISP_REG_VRAM_SIZE);

    return len;
}

/* IOFramebuffer */

IOReturn
uXenDispFB::setDisplayMode(IODisplayModeID id, IOIndex depth)
{
    unsigned int i;
    struct mode_info *info = NULL;
    int rc;

    dprintk("%s(id=%x)\n", __func__, id);

    for (i = 0; i < n_modes; i++) {
        if (id == modes[i].id) {
            info = &modes[i];
            break;
        }
    }

    if (!info)
        return kIOReturnNotFound;

    rc = set_mode(info->pix.activeWidth,
                  info->pix.activeHeight,
                  info->pix.bitsPerPixel,
                  info->pix.bytesPerRow);
    if (rc)
        return kIOReturnError;

    current_mode = info;

    return kIOReturnSuccess;
}

IODeviceMemory *
uXenDispFB::getApertureRange(IOPixelAperture aperture)
{
    UInt32 screen_bytes;

    if (aperture != kIOFBSystemAperture) {
        dprintk("%s: %d != kIOFBSystemAperture\n", __func__, aperture);
        return NULL;
    }

    dprintk("%s\n", __func__);

    /* Determine how much vram is required for the screen. */
    if (current_mode)
      screen_bytes = current_mode->pix.bytesPerRow * current_mode->pix.activeHeight;
    else
      screen_bytes = 0;

    if (screen_bytes > vram_size)
        return NULL;

    return IODeviceMemory::withSubRange(vram, 0, screen_bytes);
}

IODeviceMemory *
uXenDispFB::getVRAMRange()
{
    return IODeviceMemory::withSubRange(vram, 0, vram_size);
}

UInt64
uXenDispFB::getPixelFormatsForDisplayMode(IODisplayModeID displayMode,
                                          IOIndex depth)
{
    /* Documentation says this should return 0 */
    return 0ULL;
}

const char *
uXenDispFB::getPixelFormats()
{
    dprintk("%s\n", __func__);

    return Mode16bpp "\0" Mode24bpp "\0" Mode32bpp "\0\0";
}

IOReturn
uXenDispFB::getCurrentDisplayMode(IODisplayModeID *id, IOIndex *depth)
{
    dprintk("%s\n", __func__);

    if (!current_mode)
        return kIOReturnError;

    *id = current_mode->id;
    *depth = 0;

    return kIOReturnSuccess;
}

IOItemCount
uXenDispFB::getDisplayModeCount()
{
    dprintk("%s\n", __func__);
    return n_modes;
}

IOReturn
uXenDispFB::getDisplayModes(IODisplayModeID *display_modes)
{
    unsigned int i;

    dprintk("%s\n", __func__);

    for (i = 0; i < n_modes; i++) {
        display_modes[i] = modes[i].id;
    }

    return kIOReturnSuccess;
}

IOReturn
uXenDispFB::getInformationForDisplayMode(IODisplayModeID id,
                                         IODisplayModeInformation *modeinfo)
{
    unsigned int i;

    dprintk("%s(id=%x)\n", __func__, id);

    for (i = 0; i < n_modes; i++) {
        if (id == modes[i].id) {
            *modeinfo = modes[i].mode;
            return kIOReturnSuccess;
        }
    }

    return kIOReturnNotFound;
}

IOReturn
uXenDispFB::getPixelInformation(IODisplayModeID id, IOIndex depth,
                                IOPixelAperture aperture,
                                IOPixelInformation *pixinfo)
{
    unsigned int i;

    dprintk("%s(id=%x,depth=%d,aperture=%d)\n", __func__,
            id, depth, aperture);

    if (aperture != kIOFBSystemAperture) {
        dprintk("%s: %d != kIOFBSystemAperture\n", __func__, aperture);
        return kIOReturnError;
    }

    for (i = 0; i < n_modes; i++) {
        if (id == modes[i].id) {
            *pixinfo = modes[i].pix;
            return kIOReturnSuccess;
        }
    }

    return kIOReturnNotFound;
}

/* cursor */

void
uXenDispFB::flushCursor(void)
{
    uxdisp_write(UXDISP_REG_CURSOR_ENABLE,
                 cursor_visible ? UXDISP_CURSOR_SHOW : 0);
}

IOReturn
uXenDispFB::setCursorImage(void *image)
{
    bool convert;
    IOHardwareCursorDescriptor c_desc;
    IOHardwareCursorInfo c_info;

    c_desc.majorVersion = kHardwareCursorDescriptorMajorVersion;
    c_desc.minorVersion = kHardwareCursorDescriptorMinorVersion;
    c_desc.height = 128;
    c_desc.width = 128;
    c_desc.bitDepth = 32;
    c_desc.maskBitDepth = 0; /* Unused */
    c_desc.numColors = 0; /* For indexed pixel types */
    c_desc.colorEncodings = NULL;
    c_desc.flags = 0;
    //c_desc.supportedSpecialEncodings = kInvertingEncodedPixel;
    //c_desc.specialEncodings[kInvertingEncoding] = 0xFF000000;

    c_info.majorVersion = kHardwareCursorInfoMajorVersion;
    c_info.minorVersion = kHardwareCursorInfoMinorVersion;
    c_info.hardwareCursorData = ((uint8_t *)mmio->getVirtualAddress() +
                                 UXDISP_REG_CURSOR_DATA);

    convert = convertCursorImage(image, &c_desc, &c_info);
    if (!convert) {
        dprintk("%s: Failed to convert cursor image\n", __func__);
        return kIOReturnError;
    }

    uxdisp_write(UXDISP_REG_CURSOR_WIDTH, c_info.cursorWidth);
    uxdisp_write(UXDISP_REG_CURSOR_HEIGHT, c_info.cursorHeight);
    uxdisp_write(UXDISP_REG_CURSOR_HOT_X, c_info.cursorHotSpotX);
    uxdisp_write(UXDISP_REG_CURSOR_HOT_Y, c_info.cursorHotSpotY);
    uxdisp_write(UXDISP_REG_CURSOR_CRTC, 0);
    uxdisp_write(UXDISP_REG_CURSOR_FLAGS, 0);

    flushCursor();

    return kIOReturnSuccess;
}

IOReturn
uXenDispFB::setCursorState(SInt32 x, SInt32 y, bool visible)
{
    uxdisp_write(UXDISP_REG_CURSOR_POS_X, x);
    uxdisp_write(UXDISP_REG_CURSOR_POS_Y, y);

    if (visible != cursor_visible) {
        cursor_visible = visible;
        flushCursor();
    }

    return kIOReturnSuccess;
}

IOReturn
uXenDispFB::setGammaTable(UInt32 channelCount,
                          UInt32 dataCount,
                          UInt32 dataWidth,
                          void *data)
{
    /*
     * There's nothing we can do with the gamma table but we
     * return success to reduce the number of errors encountered
     * by the WindowServer and prevent the window server from
     * attempting to apply gamma.
     */
    return kIOReturnSuccess;
}

IOReturn
uXenDispFB::getTimingInfoForDisplayMode(IODisplayModeID displayMode,
                                        IOTimingInformation *info)
{
    dprintk("%s(id=%d)\n", __func__, displayMode);

    unsigned int i;
    int mode;

    /* Find the display mode. */
    mode = -1;
    for (i = 0; i < n_modes; i++) {
        if (modes[i].id == displayMode) {
            mode = i;
            break;
        }
    }

    /* Unable to find mode. */
    if (mode == -1)
        return kIOReturnUnsupportedMode;

    /* Populate the timing info. */
    dprintk("%s found at index %d\n", __func__, mode);
    info->appleTimingID = kIOTimingIDApple_FixedRateLCD;
    info->detailedInfo.v2.horizontalActive = modes[mode].pix.activeWidth;
    info->detailedInfo.v2.verticalActive = modes[mode].pix.activeHeight;
    return kIOReturnSuccess;
}

/* IOService */

bool
uXenDispFB::init(OSDictionary *dict)
{
    bool rc = super::init(dict);

    dprintk("%s\n", __func__);

    return rc;
}

void
uXenDispFB::free(void)
{
    dprintk("%s\n", __func__);
    super::free();
}

IOService *
uXenDispFB::probe(IOService *provider, SInt32 *score)
{
    IOService *ret;

    ret = super::probe(provider, score);
    dprintk("%s: probe=%p score=%d\n", __func__, ret, *score);

    return ret;
}

void
uXenDispFB::sendInterrupt(interrupt_info *interrupt)
{
  if (interrupt->set && interrupt->enabled) {
    interrupt->proc(interrupt->target,
                    interrupt->ref);
  }
}

void
uXenDispFB::scheduleVBLTimer()
{
    /* Check that the timer is enabled before re-scheduling. */
    if (vblank_interrupt.enabled) {
        vblank_timer->setTimeoutUS(FREQUENCY_TIMER_US);
    }
}

void
uXenDispFB::timerCallback(OSObject *owner,
                          IOTimerEventSource *sender)
{
  uXenDispFB *fb = static_cast<uXenDispFB *>(owner);
  fb->sendInterrupt(&fb->vblank_interrupt);
  fb->scheduleVBLTimer();
}

void
uXenDispFB::enableVBL(bool enable)
{
    vblank_interrupt.enabled = enable;
    vblank_timer->cancelTimeout();
    scheduleVBLTimer();
}

bool
uXenDispFB::start(IOService *provider)
{
    bool rc;
    int ret;

    dprintk("%s\n", __func__);

    rc = super::start(provider);
    if (!rc)
        return false;

    pcidev = OSDynamicCast(IOPCIDevice, provider);
    if (!pcidev)
        return false;

    pcidev->setMemoryEnable(true);
    vram = pcidev->getDeviceMemoryWithRegister(kIOPCIConfigBaseAddress0);
    if (!vram) {
        cleanup();
        return false;
    }
    mmio = pcidev->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress1);
    if (!mmio) {
        cleanup();
        return false;
    }
    vram_size = get_vram_size();
    if (vram_size > vram->getLength())
        vram_size = vram->getLength();

    dprintk("%s: VRAM size = %ldM\n", __func__, vram_size / (1024 * 1024));

    /* Initialize the display modes. */
    ret = init_modes();
    if (ret != 0) {
        cleanup();
        return false;
    }

    /* Create an IOWorkLoop and IOTimerEventSource to fake-up
       vblank events in the hope that they will keep the driver
       on the straight and narrow. */

    vblank_workloop = IOWorkLoop::workLoop();
    if (vblank_workloop == NULL) {
        cleanup();
        return false;
    }

    vblank_timer = IOTimerEventSource::timerEventSource(this, &timerCallback);
    if (vblank_timer == NULL) {
        cleanup();
        return false;
    }

    ret = vblank_workloop->addEventSource(vblank_timer);
    if (ret != kIOReturnSuccess) {
        cleanup();
        return false;
    }

    connect_interrupt.set = false;

    cursor_visible = true;

    return true;
}

void
uXenDispFB::stop(IOService *provider)
{
    cleanup();
    super::stop(provider);
}

void
uXenDispFB::cleanup()
{
    current_mode = NULL;
    if (modes)
        IOFree(modes, n_modes * sizeof (*modes));

    if (vblank_timer) {
        vblank_timer->release();
        vblank_timer = NULL;
    }

    if (vblank_workloop) {
        vblank_workloop->release();
        vblank_workloop = NULL;
    }
}

IOReturn
uXenDispFB::getAttribute(IOSelect attr, uintptr_t *value)
{
    IOReturn ret;

    switch(attr) {
    case kIOHardwareCursorAttribute:
        dprintk("%s(attr=kIOHardwareCursorAttribute)\n", __func__);
        *value = 1;
        ret = kIOReturnSuccess;
        break;
    default:
        dprintk("%s(attr=%x)\n", __func__, attr);
        ret = super::getAttribute(attr, value);
        break;
    }

    return ret;
}

void
uXenDispFB::configureInterrupt(interrupt_info *interrupt,
                               IOFBInterruptProc proc,
                               OSObject *target,
                               void *ref,
                               void **interrupt_ref)
{
    interrupt->proc = proc;
    interrupt->target = target;
    interrupt->ref = ref;
    interrupt->set = true;
    if (interrupt_ref)
        *interrupt_ref = interrupt;
    interrupt->enabled = true;
}

IOReturn
uXenDispFB::registerForInterruptType(IOSelect type,
                                     IOFBInterruptProc proc,
                                     OSObject *target,
                                     void *ref,
                                     void **interrupt_ref)
{
    IOReturn ret;

    switch(type) {
    case kIOFBMCCSInterruptType:
        ret = super::registerForInterruptType(type, proc, target, ref,
                                              interrupt_ref);
        break;
    case kIOFBConnectInterruptType:
        configureInterrupt(&connect_interrupt,
                           proc,
                           target,
                           ref,
                           interrupt_ref);
        ret = kIOReturnSuccess;
        break;
    case kIOFBVBLInterruptType:
        configureInterrupt(&vblank_interrupt,
                           proc,
                           target,
                           ref,
                           interrupt_ref);
        enableVBL(true);
        ret = kIOReturnSuccess;
        break;
    default:
        dprintk("%s(type=%x)\n", __func__, type);
        ret = kIOReturnUnsupported;
        break;
    }

    return ret;
}

/* UserClient */

IOReturn
uXenDispFB::newUserClient(task_t owningTask,
                          void *security_id,
                          UInt32 type,
                          IOUserClient **handler)
{
    IOReturn ret;
    IOUserClient *client;

    switch (type) {
    case kIOFBServerConnectType:
    case kIOFBSharedConnectType:
        ret = super::newUserClient(owningTask, security_id, type, handler);
        break;
    case kIOuXenDispCtlConnectType:
        client = new uXenDispCtl;
        if (!client)
            return kIOReturnNoMemory;
        if (!client->initWithTask(owningTask, security_id, type, NULL)) {
            client->release();
            return kIOReturnBadArgument;
        }
        if (!client->attach(this)) {
            client->release();
            return kIOReturnUnsupported;
        }
        if (!client->start(this)) {
            client->detach(this);
            client->release();
            return kIOReturnUnsupported;
        }
        ret = kIOReturnSuccess;
        *handler = client;
        break;
    default:
        ret = kIOReturnBadArgument;
        break;
    }

    return ret;
}

IOReturn
uXenDispFB::unregisterInterrupt(void *interruptRef)
{
    if (interruptRef == &connect_interrupt ||
        interruptRef == &vblank_interrupt) {
        memset(interruptRef, 0, sizeof(interrupt_info));
        return kIOReturnSuccess;
    } else {
        return super::unregisterInterrupt(interruptRef);
    }
}

IOReturn
uXenDispFB::setInterruptState(void *interruptRef, UInt32 state)
{
    /* It seems that 'state == 0' means that the interrupt should be enabled. */
    bool enable = (state == 0);
    if (interruptRef == &connect_interrupt) {
        dprintk("setInterruptState - connect interrupt - enable %d\n", enable);
        connect_interrupt.enabled = enable;
        return kIOReturnSuccess;
    } else if (interruptRef == &vblank_interrupt) {
        dprintk("setInterruptState - vblank interrupt - enabled %d\n", enable);
        enableVBL(enable);
        return kIOReturnSuccess;
    } else {
      return super::setInterruptState(interruptRef, state);
    }
}

