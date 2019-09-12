/*
 * Authors:  Alan Hourihane, <alanh@fairlite.demon.co.uk>
 *	     Michel Dänzer, <michel@tungstengraphics.com>
 */
/*
 * uXen changes:
 *
 * Copyright 2016-2019, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <execinfo.h>
#include <string.h>

/* all driver need this */
#include "xf86.h"
#include "xf86_OSproc.h"

#include "mipointer.h"
#include "micmap.h"
#include "colormapst.h"
#include "xf86cmap.h"
#include "shadow.h"

/* for visuals */
#include "fb.h"

#if GET_ABI_MAJOR(ABI_VIDEODRV_VERSION) < 6
#include "xf86Resources.h"
#include "xf86RAC.h"
#endif

#include "fbdevhw.h"

#include "xf86xv.h"

#include "compat-api.h"

# define _HAVE_STRING_ARCH_strsep /* bits/string2.h, __strsep_1c. */
# include "xf86Crtc.h"
# include "xf86Modes.h"
/* For xf86RandR12GetOriginalVirtualSize(). */
# include "xf86RandR12.h"


#define UXENFB_MAX_WIDTH    4096
#define UXENFB_MAX_HEIGHT   2160
#define UXENFB_BPP          32
#define UXENFB_RAM_SIZE     0x2000000
#define UXEN_OUTPUT           "uxen"


/* for xf86{Depth,FbBpp}. i am a terrible person, and i am sorry. */
#include "xf86Priv.h"

//#define DEBUG 1
static Bool debug = TRUE;
static int paulian = 1;
static xf86CrtcPtr uxen_crtc = NULL;
static xf86OutputPtr uxen_output = NULL;
static DisplayModePtr uxen_modes = NULL;

#ifdef DEBUG
#define DBG(fmt, ...) do { fprintf(stderr, "(uxenfb) %s: " fmt "\n", __FUNCTION__, ## __VA_ARGS__);  } while (1 == 0)
#else
#define DBG(fmt, ...) do { } while (1 == 0)
#endif

#define TRACE_ENTER(str) \
    do { if (debug) ErrorF("fbdev: " str " %d\n",pScrn->scrnIndex); } while (0)
#define TRACE_EXIT(str) \
    do { if (debug) ErrorF("fbdev: " str " done\n"); } while (0)
#define TRACE(str) \
    do { if (debug) ErrorF("fbdev trace: " str "\n"); } while (0)


/* -------------------------------------------------------------------- */
/* prototypes                                                           */

static const OptionInfoRec * FBDevAvailableOptions(int chipid, int busid);
static void	FBDevIdentify(int flags);
static Bool	FBDevProbe(DriverPtr drv, int flags);
static Bool	FBDevPreInit(ScrnInfoPtr pScrn, int flags);
static Bool	FBDevScreenInit(SCREEN_INIT_ARGS_DECL);
static Bool	FBDevCloseScreen(CLOSE_SCREEN_ARGS_DECL);
static void *	FBDevWindowLinear(ScreenPtr pScreen, CARD32 row, CARD32 offset, int mode,
				  CARD32 *size, void *closure);
static void	FBDevPointerMoved(SCRN_ARG_TYPE arg, int x, int y);
static Bool	FBDevDriverFunc(ScrnInfoPtr pScrn, xorgDriverFuncOp op,
				pointer ptr);


enum { FBDEV_ROTATE_NONE=0, FBDEV_ROTATE_CW=270, FBDEV_ROTATE_UD=180, FBDEV_ROTATE_CCW=90 };


/* -------------------------------------------------------------------- */

/*
 * This is intentionally screen-independent.  It indicates the binding
 * choice made in the first PreInit.
 */
static int pix24bpp = 0;

#define FBDEV_VERSION		4000
#define FBDEV_NAME		"FBDEV"
#define FBDEV_DRIVER_NAME	"fbdev"


_X_EXPORT DriverRec FBDEV = {
	FBDEV_VERSION,
	FBDEV_DRIVER_NAME,
#if 0
	"driver for linux framebuffer devices",
#endif
	FBDevIdentify,
	FBDevProbe,
	FBDevAvailableOptions,
	NULL,
	0,
	FBDevDriverFunc,

};

/* Supported "chipsets" */
static SymTabRec FBDevChipsets[] = {
    { 0, "fbdev" },
    {-1, NULL }
};

/* Supported options */
typedef enum {
	OPTION_SHADOW_FB,
	OPTION_ROTATE,
	OPTION_FBDEV,
	OPTION_DEBUG
} FBDevOpts;

static const OptionInfoRec FBDevOptions[] = {
	{ OPTION_SHADOW_FB,	"ShadowFB",	OPTV_BOOLEAN,	{0},	FALSE },
	{ OPTION_ROTATE,	"Rotate",	OPTV_STRING,	{0},	FALSE },
	{ OPTION_FBDEV,		"fbdev",	OPTV_STRING,	{0},	FALSE },
	{ OPTION_DEBUG,		"debug",	OPTV_BOOLEAN,	{0},	FALSE },
	{ -1,			NULL,		OPTV_NONE,	{0},	FALSE }
};

/* -------------------------------------------------------------------- */

#ifdef XFree86LOADER

MODULESETUPPROTO(FBDevSetup);

static XF86ModuleVersionInfo FBDevVersRec =
{
	"fbdev",
	MODULEVENDORSTRING,
	MODINFOSTRING1,
	MODINFOSTRING2,
	XORG_VERSION_CURRENT,
	PACKAGE_VERSION_MAJOR, PACKAGE_VERSION_MINOR, PACKAGE_VERSION_PATCHLEVEL,
	ABI_CLASS_VIDEODRV,
	ABI_VIDEODRV_VERSION,
	MOD_CLASS_VIDEODRV,
	{0,0,0,0}
};

_X_EXPORT XF86ModuleData fbdevModuleData = { &FBDevVersRec, FBDevSetup, NULL };

pointer
FBDevSetup(pointer module, pointer opts, int *errmaj, int *errmin)
{
	static Bool setupDone = FALSE;

	if (!setupDone) {
		setupDone = TRUE;
		xf86AddDriver(&FBDEV, module, HaveDriverFuncs);
		return (pointer)1;
	} else {
		if (errmaj) *errmaj = LDR_ONCEONLY;
		return NULL;
	}
}

#endif /* XFree86LOADER */

/* -------------------------------------------------------------------- */
/* our private data, and two functions to allocate/free this            */

typedef struct {
	unsigned char*			fbstart;
	unsigned char*			fbmem;
	int				fboff;
	int				lineLength;
	int				rotate;
	Bool				shadowFB;
	void				*shadow;
	CloseScreenProcPtr		CloseScreen;
	CreateScreenResourcesProcPtr	CreateScreenResources;
	void				(*PointerMoved)(SCRN_ARG_TYPE arg, int x, int y);
	EntityInfoPtr			pEnt;
	OptionInfoPtr			Options;
} FBDevRec, *FBDevPtr;

#define FBDEVPTR(p) ((FBDevPtr)((p)->driverPrivate))

static void uxen_fb_change_mode(ScrnInfoPtr pScrn, int width, int height)
{

}

static void uxen_crtc_dpms(xf86CrtcPtr crtc, int mode)
{
    ScrnInfoPtr pScrn = crtc->scrn;
}

static Bool uxen_crtc_lock (xf86CrtcPtr crtc)
{
    (void) crtc;
    return FALSE;
}

static Bool
uxen_crtc_mode_fixup (xf86CrtcPtr crtc, DisplayModePtr mode,
                      DisplayModePtr adjusted_mode)
{
  (void) crtc;
  (void) mode;
  (void) adjusted_mode;

  return TRUE;
}

static void uxen_crtc_stub (xf86CrtcPtr crtc)
{
    (void) crtc;
}

static void uxen_crtc_mode_set (xf86CrtcPtr crtc, DisplayModePtr mode,
                    DisplayModePtr adjusted_mode, int x, int y)
{

    ScrnInfoPtr pScrn = crtc->scrn;

    fbdevHWSwitchMode(pScrn, adjusted_mode);
}

static void
vbox_crtc_gamma_set (xf86CrtcPtr crtc, CARD16 *red,
                     CARD16 *green, CARD16 *blue, int size)
{
    (void) crtc;
    (void) red;
    (void) green;
    (void) blue;
    (void) size;
}

static void *
uxen_crtc_shadow_allocate (xf86CrtcPtr crtc, int width, int height)
{
    void *ret;
    ScreenPtr pScreen = crtc->scrn->pScreen;
    PixmapPtr rootpix = pScreen->GetScreenPixmap(pScreen);

    DBG("(call) pScreen->CreatePixmap width %d height %d rootdepth %d", width, height,
        (int)  rootpix->drawable.depth);
    ret = pScreen->CreatePixmap(pScreen, width, height,
                                 rootpix->drawable.depth, 0);

    DBG("(end)  pScreen->CreatePixmap");
    return ret;
}

static PixmapPtr
uxen_crtc_shadow_create(xf86CrtcPtr crtc, void *data, int width, int height)
{
    DBG("");
    return (PixmapPtr) data;
}

static void
uxen_crtc_shadow_destroy(xf86CrtcPtr crtc, PixmapPtr rotate_pixmap, void *data)
{
    ScreenPtr pScreen;

    DBG("");
    if (rotate_pixmap == NULL)
        return;

    pScreen = rotate_pixmap->drawable.pScreen;
    pScreen->DestroyPixmap(rotate_pixmap);
}


static void
uxen_crtc_gamma_set (xf86CrtcPtr crtc, CARD16 *red,
                     CARD16 *green, CARD16 *blue, int size)
{
    (void) crtc;
    (void) red;
    (void) green;
    (void) blue;
    (void) size;
}

static const xf86CrtcFuncsRec uxen_crtc_funcs = {
    .dpms = uxen_crtc_dpms,
    .save = NULL, /* These two are never called by the server. */
    .restore = NULL,
    .lock = uxen_crtc_lock,
    .unlock = NULL, /* This will not be invoked if lock returns FALSE. */
    .mode_fixup = uxen_crtc_mode_fixup,
    .prepare = uxen_crtc_stub,
    .mode_set = uxen_crtc_mode_set,
    .commit = uxen_crtc_stub,
    .gamma_set = uxen_crtc_gamma_set,
    .shadow_allocate = uxen_crtc_shadow_allocate,
    .shadow_create = uxen_crtc_shadow_create,
    .shadow_destroy = uxen_crtc_shadow_destroy,
    .set_cursor_colors = NULL, /* We are still using the old cursor API. */
    .set_cursor_position = NULL,
    .show_cursor = NULL,
    .hide_cursor = NULL,
    .load_cursor_argb = NULL,
    .destroy = uxen_crtc_stub
};

static void uxen_output_stub(xf86OutputPtr output)
{
    (void) output;
}

static void uxen_output_dpms(xf86OutputPtr output, int mode)
{
    (void)output;
    (void)mode;
}

static int uxen_output_mode_valid(xf86OutputPtr output, DisplayModePtr mode)
{
    //return mode->type & M_T_BUILTIN ? MODE_BAD : MODE_OK;
    return MODE_OK;
}

static Bool
uxen_output_mode_fixup (xf86OutputPtr output, DisplayModePtr mode,
                        DisplayModePtr adjusted_mode)
{
    (void) output;
    (void) mode;
    (void) adjusted_mode;

    return TRUE;
}

static void
uxen_output_mode_set (xf86OutputPtr output, DisplayModePtr mode,
                        DisplayModePtr adjusted_mode)
{
    (void) output;
    (void) mode;
    (void) adjusted_mode;
}

/* A virtual monitor is always connected. */
static xf86OutputStatus uxen_output_detect(xf86OutputPtr output)
{
   return XF86OutputStatusConnected;
}

static DisplayModePtr
uxen_add_mode(DisplayModePtr modes, const char *name, int x, int y,int is_prefered, int is_userdef)
{
    DisplayModePtr pMode = xnfcalloc(1, sizeof(DisplayModeRec));
    int cRefresh = 60;

    pMode->status        = MODE_OK;
    pMode->type          = is_userdef ? M_T_USERDEF : M_T_BUILTIN;
    if (is_prefered)
        pMode->type     |= M_T_PREFERRED;
    pMode->HDisplay  = x;
    pMode->HSyncStart    = pMode->HDisplay + 2;
    pMode->HSyncEnd      = pMode->HDisplay + 4;
    pMode->HTotal        = pMode->HDisplay + 6;
    pMode->VDisplay      = y;
    pMode->VSyncStart    = pMode->VDisplay + 2;
    pMode->VSyncEnd      = pMode->VDisplay + 4;
    pMode->VTotal        = pMode->VDisplay + 6;
    pMode->Clock         = pMode->HTotal * pMode->VTotal * cRefresh / 1000; /* kHz */
    if (!name)
        xf86SetModeDefaultName(pMode);
    else
        pMode->name = xnfstrdup(name);
    modes = xf86ModesAdd(modes, pMode);
    return modes;
}

static DisplayModePtr uxen_output_get_modes(xf86OutputPtr output)
{
    DisplayModePtr modes = NULL;

    modes = uxen_add_mode(modes, NULL, 1, 1, 0, 1);
    modes = uxen_add_mode(modes, NULL, 800, 600, 0, 1);
    modes = uxen_add_mode(modes, NULL, 1024, 769, 0, 1);
    modes = uxen_add_mode(modes, NULL, 1100, 900, 1, 1);
    return modes;
}

static const xf86OutputFuncsRec uxen_output_funcs = {
    .create_resources = uxen_output_stub,
    .dpms = uxen_output_dpms,
    .save = NULL, /* These two are never called by the server. */
    .restore = NULL,
    .mode_valid = uxen_output_mode_valid,
    .mode_fixup = uxen_output_mode_fixup,
    .prepare = uxen_output_stub,
    .commit = uxen_output_stub,
    .mode_set = uxen_output_mode_set,
    .detect = uxen_output_detect,
    .get_modes = uxen_output_get_modes,
     .set_property = NULL,
    .destroy = uxen_output_stub
};

Bool uxen_config_resize(ScrnInfoPtr pScrn, int cw, int ch)
{
    Bool rc = TRUE;
    FBDevPtr fPtr = FBDEVPTR(pScrn);
    PixmapPtr ppix;
    ScreenPtr screen = xf86ScrnToScreen(pScrn);
    int pitch;

    pScrn->virtualX = cw;
    pScrn->virtualY = ch;
    pScrn->displayWidth = cw;

    pitch = pScrn->displayWidth * (pScrn->bitsPerPixel / 8);
    DBG("cwxch %dx%d pitch %d depth %d bbp %d", cw, ch, pitch, pScrn->depth,
         pScrn->bitsPerPixel);

    ppix = screen->GetScreenPixmap(screen);
    if (ppix)
        rc = screen->ModifyPixmapHeader(ppix, cw, ch, pScrn->depth, pScrn->bitsPerPixel,
                                        pitch, fPtr->fbstart);

    return rc;
}

static const xf86CrtcConfigFuncsRec crtc_funcs = {
    uxen_config_resize
};

static Bool
FBDevGetRec(ScrnInfoPtr pScrn)
{
	if (pScrn->driverPrivate != NULL)
		return TRUE;
	
	pScrn->driverPrivate = xnfcalloc(sizeof(FBDevRec), 1);
	return TRUE;
}

static void
FBDevFreeRec(ScrnInfoPtr pScrn)
{
	if (pScrn->driverPrivate == NULL)
		return;
	free(pScrn->driverPrivate);
	pScrn->driverPrivate = NULL;
}

/* -------------------------------------------------------------------- */

static const OptionInfoRec *
FBDevAvailableOptions(int chipid, int busid)
{
	return FBDevOptions;
}

static void
FBDevIdentify(int flags)
{
	xf86PrintChipsets(FBDEV_NAME, "driver for framebuffer", FBDevChipsets);
}

static Bool
fbdevSwitchMode(ScrnInfoPtr pScrn, DisplayModePtr mode)
{
    return fbdevHWSwitchMode(pScrn, mode);
}

static void
fbdevAdjustFrame(ScrnInfoPtr pScrn, int x, int y)
{
    fbdevHWAdjustFrame(pScrn, x, y);
}

static Bool
fbdevEnterVT(ScrnInfoPtr pScrn)
{
    DBG("EnterVT");
    return fbdevHWEnterVT(pScrn);
}

static void
fbdevLeaveVT(ScrnInfoPtr pScrn)
{
    DBG("LeaveVT");
    fbdevHWLeaveVT(pScrn);
}

static ModeStatus
fbdevValidMode(ScrnInfoPtr pScrn, DisplayModePtr mode, Bool verbose, int flags)
{
    return fbdevHWValidMode(pScrn, mode, verbose, flags);
}



static Bool
FBDevProbe(DriverPtr drv, int flags)
{
	int i;
	ScrnInfoPtr pScrn;
       	GDevPtr *devSections;
	int numDevSections;
	char *dev;
	Bool foundScreen = FALSE;

	TRACE("probe start");

	/* For now, just bail out for PROBE_DETECT. */
	if (flags & PROBE_DETECT)
		return FALSE;

	if ((numDevSections = xf86MatchDevice(FBDEV_DRIVER_NAME, &devSections)) <= 0) 
	    return FALSE;
	
	if (!xf86LoadDrvSubModule(drv, "fbdevhw"))
	    return FALSE;
	    
        DBG("numDevSections %d", numDevSections);
	for (i = 0; i < numDevSections; i++) {
	    Bool isIsa = FALSE;
	    Bool isPci = FALSE;

	    dev = xf86FindOptionValue(devSections[i]->options,"fbdev");
	    if (fbdevHWProbe(NULL,dev,NULL)) {
		pScrn = NULL;
                {
		   int entity;

		    entity = xf86ClaimFbSlot(drv, 0,
					      devSections[i], TRUE);
		    pScrn = xf86ConfigFbEntity(pScrn,0,entity,
					       NULL,NULL,NULL,NULL);
		   
		}
		if (pScrn) {
		    foundScreen = TRUE;
		    
		    pScrn->driverVersion = FBDEV_VERSION;
		    pScrn->driverName    = FBDEV_DRIVER_NAME;
		    pScrn->name          = FBDEV_NAME;
		    pScrn->Probe         = FBDevProbe;
		    pScrn->PreInit       = FBDevPreInit;
		    pScrn->ScreenInit    = FBDevScreenInit;
		    pScrn->SwitchMode    = fbdevSwitchMode;
		    pScrn->AdjustFrame   = fbdevAdjustFrame;
		    pScrn->EnterVT       = fbdevEnterVT;
		    pScrn->LeaveVT       = fbdevLeaveVT;
		    pScrn->ValidMode     = fbdevValidMode;
		    
		    xf86DrvMsg(pScrn->scrnIndex, X_INFO,
			       "using %s\n", dev ? dev : "default device");
		}
	    }
	}
	free(devSections);
	TRACE("probe done");
	return foundScreen;
}

static Bool
FBDevPreInit(ScrnInfoPtr pScrn, int flags)
{
	FBDevPtr fPtr;
	int default_depth, fbbpp;
	const char *s;
	int type;
	void *pci_dev = NULL;
        Gamma gzeros = {0.0, 0.0, 0.0};

	if (flags & PROBE_DETECT) return FALSE;

	TRACE_ENTER("PreInit");

	/* Check the number of entities, and fail if it isn't one. */
	if (pScrn->numEntities != 1)
		return FALSE;

	pScrn->monitor = pScrn->confScreen->monitor;

	FBDevGetRec(pScrn);
	fPtr = FBDEVPTR(pScrn);

	fPtr->pEnt = xf86GetEntityInfo(pScrn->entityList[0]);

	/* open device */
	if (!fbdevHWInit(pScrn, pci_dev,
			 xf86FindOptionValue(fPtr->pEnt->device->options,
					     "fbdev")))
		return FALSE;
	default_depth = fbdevHWGetDepth(pScrn,&fbbpp);
        DBG("default_depth %d", default_depth);

        if (default_depth != 24) {
            xf86DrvMsg(pScrn->scrnIndex, X_ERROR,
                       "Only 24 depth mode supported\n");
            return FALSE;
        }

	if (!xf86SetDepthBpp(pScrn, default_depth, default_depth, fbbpp,
	     Support24bppFb | Support32bppFb | SupportConvert32to24 | SupportConvert24to32)) {

		return FALSE;
        }
	xf86PrintDepthBpp(pScrn);

	/* Get the depth24 pixmap format */
	if (pScrn->depth == 24 && pix24bpp == 0)
		pix24bpp = xf86GetBppFromDepth(pScrn, 24);

	/* color weight */
	if (pScrn->depth > 8) {
		rgb zeros = { 0, 0, 0 };
		if (!xf86SetWeight(pScrn, zeros, zeros))
			return FALSE;
	}

	/* visual init */
	if (!xf86SetDefaultVisual(pScrn, -1))
		return FALSE;

	/* We don't currently support DirectColor at > 8bpp */
	if (pScrn->depth > 8 && pScrn->defaultVisual != TrueColor) {
		xf86DrvMsg(pScrn->scrnIndex, X_ERROR, "requested default visual"
			   " (%s) is not supported at depth %d\n",
			   xf86GetVisualName(pScrn->defaultVisual), pScrn->depth);
		return FALSE;
	}

	{
		Gamma zeros = {0.0, 0.0, 0.0};

		if (!xf86SetGamma(pScrn,zeros)) {
			return FALSE;
		}
	}

	pScrn->progClock = TRUE;
	pScrn->rgbBits   = 8;
	pScrn->chipset   = "fbdev";
	pScrn->videoRam  = fbdevHWGetVidmem(pScrn);

	xf86DrvMsg(pScrn->scrnIndex, X_INFO, "hardware: %s (video memory:"
		   " %dkB)\n", fbdevHWGetName(pScrn), pScrn->videoRam/1024);

	/* handle options */
	xf86CollectOptions(pScrn, NULL);
	if (!(fPtr->Options = malloc(sizeof(FBDevOptions))))
		return FALSE;
	memcpy(fPtr->Options, FBDevOptions, sizeof(FBDevOptions));
	xf86ProcessOptions(pScrn->scrnIndex, fPtr->pEnt->device->options, fPtr->Options);

	/* use shadow framebuffer by default */
	fPtr->shadowFB = xf86ReturnOptValBool(fPtr->Options, OPTION_SHADOW_FB, TRUE);

	debug = xf86ReturnOptValBool(fPtr->Options, OPTION_DEBUG, FALSE);

	/* rotation */
	fPtr->rotate = FBDEV_ROTATE_NONE;

	/* select video modes */
        while (paulian) {
            ClockRange* clockRanges;

            // virtual monitor
            pScrn->monitor = pScrn->confScreen->monitor;
            if (pScrn->monitor) {
                pScrn->monitor->DDC = NULL;
                pScrn->monitor->nHsync = 1;
                pScrn->monitor->hsync[0].lo = 1;
                pScrn->monitor->hsync[0].hi = 10000;
                pScrn->monitor->nVrefresh = 1;
                pScrn->monitor->vrefresh[0].lo = 1;
                pScrn->monitor->vrefresh[0].hi = 100;

                DBG("monitor configured");
            }

            // clock ranges
            clockRanges = xnfcalloc(sizeof(ClockRange), 1);
            if (!clockRanges)
                break;
            clockRanges->next = NULL;
            clockRanges->minClock = 1;
            clockRanges->maxClock = 400000000;
            clockRanges->clockIndex = -1;
            clockRanges->interlaceAllowed = FALSE;
            clockRanges->doubleScanAllowed = FALSE;
            clockRanges->ClockMulFactor = 1;
            clockRanges->ClockDivFactor = 1;

            pScrn->progClock = TRUE;
            pScrn->clockRanges = clockRanges;

            uxen_modes = uxen_add_mode(uxen_modes, "default", 1, 1, 0, 0);
            pScrn->modes = uxen_modes;

            DBG("default modes added modes %p", pScrn->modes);

            break;
        }

        pScrn->currentMode = pScrn->modes;
        if (pScrn->currentMode) {
            pScrn->virtualX = pScrn->currentMode->HDisplay;
            pScrn->virtualY = pScrn->currentMode->VDisplay;
        }
        pScrn->displayWidth = pScrn->virtualX;

        xf86PrintModes(pScrn);

        xf86RandR12PreInit(pScrn);
        /* Set gamma */
        xf86SetGamma(pScrn, gzeros);

	/* Set DPI */
	xf86SetDpi(pScrn, 0, 0);

	/* Load bpp-specific modules */
	if (xf86LoadSubModule(pScrn, "fb") == NULL) {
		FBDevFreeRec(pScrn);
		return FALSE;
	}

	/* Load shadow if needed */
	if (fPtr->shadowFB) {
		xf86DrvMsg(pScrn->scrnIndex, X_CONFIG, "using shadow"
			   " framebuffer\n");
		if (!xf86LoadSubModule(pScrn, "shadow")) {
			FBDevFreeRec(pScrn);
			return FALSE;
		}
	}

	TRACE_EXIT("PreInit");
        DBG("return TRUE");
	return TRUE;
}

static void
fbdevUpdateRotatePacked(ScreenPtr pScreen, shadowBufPtr pBuf)
{
    shadowUpdateRotatePacked(pScreen, pBuf);
}

static void
fbdevUpdatePacked(ScreenPtr pScreen, shadowBufPtr pBuf)
{
    shadowUpdatePacked(pScreen, pBuf);
}

static Bool
FBDevCreateScreenResources(ScreenPtr pScreen)
{
    PixmapPtr pPixmap;
    ScrnInfoPtr pScrn = xf86ScreenToScrn(pScreen);
    FBDevPtr fPtr = FBDEVPTR(pScrn);
    Bool ret;

    pScreen->CreateScreenResources = fPtr->CreateScreenResources;
    ret = pScreen->CreateScreenResources(pScreen);
    pScreen->CreateScreenResources = FBDevCreateScreenResources;

    if (!ret)
	return FALSE;

    pPixmap = pScreen->GetScreenPixmap(pScreen);

    if (!shadowAdd(pScreen, pPixmap, fPtr->rotate ?
		   fbdevUpdateRotatePacked : fbdevUpdatePacked,
		   FBDevWindowLinear, fPtr->rotate, NULL)) {
	return FALSE;
    }

    return TRUE;
}

static Bool
FBDevShadowInit(ScreenPtr pScreen)
{
    ScrnInfoPtr pScrn = xf86ScreenToScrn(pScreen);
    FBDevPtr fPtr = FBDEVPTR(pScrn);
    
    if (!shadowSetup(pScreen)) {
	return FALSE;
    }

    fPtr->CreateScreenResources = pScreen->CreateScreenResources;
    pScreen->CreateScreenResources = FBDevCreateScreenResources;

    return TRUE;
}

static void
fbdevLoadPalette(ScrnInfoPtr pScrn, int num, int *i, LOCO *col, VisualPtr pVis)
{
    fbdevHWLoadPalette(pScrn, num, i, col, pVis);
}

static void
fbdevDPMSSet(ScrnInfoPtr pScrn, int mode, int flags)
{
    fbdevHWDPMSSet(pScrn, mode, flags);
}

static Bool
fbdevSaveScreen(ScreenPtr pScreen, int mode)
{
    DBG("FB SAVE SCREEN");
    return fbdevHWSaveScreen(pScreen, mode);
}

static Bool
FBDevScreenInit(SCREEN_INIT_ARGS_DECL)
{
	ScrnInfoPtr pScrn = xf86ScreenToScrn(pScreen);
	FBDevPtr fPtr = FBDEVPTR(pScrn);
	VisualPtr visual;
	int init_picture = 0;
	int ret, flags;
	int type;

	TRACE_ENTER("FBDevScreenInit");

#if DEBUG
	ErrorF("\tbitsPerPixel=%d, depth=%d, defaultVisual=%s\n"
	       "\tmask: %x,%x,%x, offset: %d,%d,%d\n",
	       pScrn->bitsPerPixel,
	       pScrn->depth,
	       xf86GetVisualName(pScrn->defaultVisual),
	       pScrn->mask.red,pScrn->mask.green,pScrn->mask.blue,
	       pScrn->offset.red,pScrn->offset.green,pScrn->offset.blue);
#endif

	if (NULL == (fPtr->fbmem = fbdevHWMapVidmem(pScrn))) {
	        xf86DrvMsg(pScrn->scrnIndex,X_ERROR,"mapping of video memory"
			   " failed\n");
		return FALSE;
	}
	fPtr->fboff = fbdevHWLinearOffset(pScrn);

	fbdevHWSave(pScrn);

	if (!fbdevHWModeInit(pScrn, pScrn->currentMode)) {
		xf86DrvMsg(pScrn->scrnIndex,X_ERROR,"mode initialization failed\n");
		return FALSE;
	}
	fbdevHWSaveScreen(pScreen, SCREEN_SAVER_ON);
	fbdevHWAdjustFrame(ADJUST_FRAME_ARGS(pScrn, 0, 0));

	/* mi layer */
	miClearVisualTypes();
	if (pScrn->bitsPerPixel > 8) {
		if (!miSetVisualTypes(pScrn->depth, TrueColorMask, pScrn->rgbBits, TrueColor)) {
			xf86DrvMsg(pScrn->scrnIndex,X_ERROR,"visual type setup failed"
				   " for %d bits per pixel [1]\n",
				   pScrn->bitsPerPixel);
			return FALSE;
		}
	} else {
		if (!miSetVisualTypes(pScrn->depth,
				      miGetDefaultVisualMask(pScrn->depth),
				      pScrn->rgbBits, pScrn->defaultVisual)) {
			xf86DrvMsg(pScrn->scrnIndex,X_ERROR,"visual type setup failed"
				   " for %d bits per pixel [2]\n",
				   pScrn->bitsPerPixel);
			return FALSE;
		}
	}
	if (!miSetPixmapDepths()) {
	  xf86DrvMsg(pScrn->scrnIndex,X_ERROR,"pixmap depth setup failed\n");
	  return FALSE;
	}

	if(fPtr->rotate==FBDEV_ROTATE_CW || fPtr->rotate==FBDEV_ROTATE_CCW)
	{
	  int tmp = pScrn->virtualX;
	  pScrn->virtualX = pScrn->displayWidth = pScrn->virtualY;
	  pScrn->virtualY = tmp;
	} else if (!fPtr->shadowFB) {
		/* FIXME: this doesn't work for all cases, e.g. when each scanline
			has a padding which is independent from the depth (controlfb) */
		pScrn->displayWidth = fbdevHWGetLineLength(pScrn) /
				      (pScrn->bitsPerPixel / 8);

		if (pScrn->displayWidth != pScrn->virtualX) {
			xf86DrvMsg(pScrn->scrnIndex, X_INFO,
				   "Pitch updated to %d after ModeInit\n",
				   pScrn->displayWidth);
		}
	}

	if(fPtr->rotate && !fPtr->PointerMoved) {
		fPtr->PointerMoved = pScrn->PointerMoved;
		pScrn->PointerMoved = FBDevPointerMoved;
	}

	fPtr->fbstart = fPtr->fbmem + fPtr->fboff;

	if (fPtr->shadowFB) {
	    fPtr->shadow = calloc(1, pScrn->virtualX * pScrn->virtualY *
				  pScrn->bitsPerPixel);

	    if (!fPtr->shadow) {
		xf86DrvMsg(pScrn->scrnIndex, X_ERROR,
			   "Failed to allocate shadow framebuffer\n");
		return FALSE;
	    }
	}

	switch ((type = fbdevHWGetType(pScrn)))
	{
	case FBDEVHW_PACKED_PIXELS:
		switch (pScrn->bitsPerPixel) {
		case 8:
		case 16:
		case 24:
		case 32:
			ret = fbScreenInit(pScreen, fPtr->shadowFB ? fPtr->shadow
					   : fPtr->fbstart, pScrn->virtualX,
					   pScrn->virtualY, pScrn->xDpi,
					   pScrn->yDpi, pScrn->displayWidth,
					   pScrn->bitsPerPixel);
			init_picture = 1;
			break;
	 	default:
			xf86DrvMsg(pScrn->scrnIndex, X_ERROR,
				   "internal error: invalid number of bits per"
				   " pixel (%d) encountered in"
				   " FBDevScreenInit()\n", pScrn->bitsPerPixel);
			ret = FALSE;
			break;
		}
		break;
	case FBDEVHW_INTERLEAVED_PLANES:
		/* This should never happen ...
		* we should check for this much much earlier ... */
		xf86DrvMsg(pScrn->scrnIndex, X_ERROR,
		           "internal error: interleaved planes are not yet "
			   "supported by the fbdev driver\n");
		ret = FALSE;
		break;
	case FBDEVHW_TEXT:
		/* This should never happen ...
		* we should check for this much much earlier ... */
		xf86DrvMsg(pScrn->scrnIndex, X_ERROR,
		           "internal error: text mode is not supported by the "
			   "fbdev driver\n");
		ret = FALSE;
		break;
	case FBDEVHW_VGA_PLANES:
		/* Not supported yet */
		xf86DrvMsg(pScrn->scrnIndex, X_ERROR,
		           "internal error: EGA/VGA Planes are not yet "
			   "supported by the fbdev driver\n");
		ret = FALSE;
		break;
	default:
		xf86DrvMsg(pScrn->scrnIndex, X_ERROR,
		           "internal error: unrecognised hardware type (%d) "
			   "encountered in FBDevScreenInit()\n", type);
		ret = FALSE;
		break;
	}
	if (!ret)
		return FALSE;

	if (pScrn->bitsPerPixel > 8) {
		/* Fixup RGB ordering */
		visual = pScreen->visuals + pScreen->numVisuals;
		while (--visual >= pScreen->visuals) {
			if ((visual->class | DynamicClass) == DirectColor) {
				visual->offsetRed   = pScrn->offset.red;
				visual->offsetGreen = pScrn->offset.green;
				visual->offsetBlue  = pScrn->offset.blue;
				visual->redMask     = pScrn->mask.red;
				visual->greenMask   = pScrn->mask.green;
				visual->blueMask    = pScrn->mask.blue;
			}
		}
	}

	/* must be after RGB ordering fixed */
	if (init_picture && !fbPictureInit(pScreen, NULL, 0))
		xf86DrvMsg(pScrn->scrnIndex, X_WARNING,
			   "Render extension initialisation failed\n");

	if (fPtr->shadowFB && !FBDevShadowInit(pScreen)) {
	    xf86DrvMsg(pScrn->scrnIndex, X_ERROR,
		       "shadow framebuffer initialization failed\n");
	    return FALSE;
	}

	xf86SetBlackWhitePixels(pScreen);
	xf86SetBackingStore(pScreen);

        xf86CrtcConfigInit(pScrn, &crtc_funcs);

       uxen_crtc = xf86CrtcCreate(pScrn, &uxen_crtc_funcs);
       if (!uxen_crtc)
           return FALSE;
       uxen_output = xf86OutputCreate(pScrn, &uxen_output_funcs, UXEN_OUTPUT);
       if (!uxen_output)
           return FALSE;
       xf86OutputUseScreenMonitor(uxen_output, FALSE);
       uxen_output->possible_crtcs = 1;
       xf86CrtcSetSizeRange(pScrn, 1, 1, UXENFB_MAX_WIDTH, UXENFB_MAX_HEIGHT);

        if (!xf86InitialConfiguration(pScrn, TRUE)) {
            xf86DrvMsg(pScrn->scrnIndex, X_ERROR, "Initial CRTC configuration failed!\n");
            return FALSE;
        }
        if (!xf86CrtcScreenInit(pScreen)) {
            return FALSE;
        }

        /* set first video mode */
        if (!xf86SetDesiredModes(pScrn)) {
            return FALSE;
        }

	/* software cursor */
	miDCInitialize(pScreen, xf86GetPointerScreenFuncs());

	/* colormap */
	switch ((type = fbdevHWGetType(pScrn)))
	{
	/* XXX It would be simpler to use miCreateDefColormap() in all cases. */
	case FBDEVHW_PACKED_PIXELS:
		if (!miCreateDefColormap(pScreen)) {
			xf86DrvMsg(pScrn->scrnIndex, X_ERROR,
                                   "internal error: miCreateDefColormap failed "
				   "in FBDevScreenInit()\n");
			return FALSE;
		}
		break;
	case FBDEVHW_INTERLEAVED_PLANES:
		xf86DrvMsg(pScrn->scrnIndex, X_ERROR,
		           "internal error: interleaved planes are not yet "
			   "supported by the fbdev driver\n");
		return FALSE;
	case FBDEVHW_TEXT:
		xf86DrvMsg(pScrn->scrnIndex, X_ERROR,
		           "internal error: text mode is not supported by "
			   "the fbdev driver\n");
		return FALSE;
	case FBDEVHW_VGA_PLANES:
		xf86DrvMsg(pScrn->scrnIndex, X_ERROR,
		           "internal error: EGA/VGA planes are not yet "
			   "supported by the fbdev driver\n");
		return FALSE;
	default:
		xf86DrvMsg(pScrn->scrnIndex, X_ERROR,
		           "internal error: unrecognised fbdev hardware type "
			   "(%d) encountered in FBDevScreenInit()\n", type);
		return FALSE;
	}
	flags = CMAP_PALETTED_TRUECOLOR;
	if(!xf86HandleColormaps(pScreen, 256, 8, fbdevLoadPalette, NULL, flags))
		return FALSE;

	xf86DPMSInit(pScreen, fbdevDPMSSet, 0);

	pScreen->SaveScreen = fbdevSaveScreen;

	/* Wrap the current CloseScreen function */
	fPtr->CloseScreen = pScreen->CloseScreen;
	pScreen->CloseScreen = FBDevCloseScreen;

#if XV
	{
	    XF86VideoAdaptorPtr *ptr;

	    int n = xf86XVListGenericAdaptors(pScrn,&ptr);
	    if (n) {
		xf86XVScreenInit(pScreen,ptr,n);
	    }
	}
#endif

	TRACE_EXIT("FBDevScreenInit");

	return TRUE;
}

static Bool
FBDevCloseScreen(CLOSE_SCREEN_ARGS_DECL)
{
	ScrnInfoPtr pScrn = xf86ScreenToScrn(pScreen);
	FBDevPtr fPtr = FBDEVPTR(pScrn);
	
        DBG("FB CLOSE SCREEN");
	fbdevHWRestore(pScrn);
	fbdevHWUnmapVidmem(pScrn);
	if (fPtr->shadow) {
	    shadowRemove(pScreen, pScreen->GetScreenPixmap(pScreen));
	    free(fPtr->shadow);
	    fPtr->shadow = NULL;
	}
	pScrn->vtSema = FALSE;

	pScreen->CreateScreenResources = fPtr->CreateScreenResources;
	pScreen->CloseScreen = fPtr->CloseScreen;
	return (*pScreen->CloseScreen)(CLOSE_SCREEN_ARGS);
}



/***********************************************************************
 * Shadow stuff
 ***********************************************************************/

static void *
FBDevWindowLinear(ScreenPtr pScreen, CARD32 row, CARD32 offset, int mode,
		 CARD32 *size, void *closure)
{
    ScrnInfoPtr pScrn = xf86ScreenToScrn(pScreen);
    FBDevPtr fPtr = FBDEVPTR(pScrn);

    if (!pScrn->vtSema)
      return NULL;

    if (fPtr->lineLength)
      *size = fPtr->lineLength;
    else
      *size = fPtr->lineLength = fbdevHWGetLineLength(pScrn);

    return ((CARD8 *)fPtr->fbstart + row * fPtr->lineLength + offset);
}

static void
FBDevPointerMoved(SCRN_ARG_TYPE arg, int x, int y)
{
    SCRN_INFO_PTR(arg);
    FBDevPtr fPtr = FBDEVPTR(pScrn);
    int newX, newY;

    switch (fPtr->rotate)
    {
    case FBDEV_ROTATE_CW:
	/* 90 degrees CW rotation. */
	newX = pScrn->pScreen->height - y - 1;
	newY = x;
	break;

    case FBDEV_ROTATE_CCW:
	/* 90 degrees CCW rotation. */
	newX = y;
	newY = pScrn->pScreen->width - x - 1;
	break;

    case FBDEV_ROTATE_UD:
	/* 180 degrees UD rotation. */
	newX = pScrn->pScreen->width - x - 1;
	newY = pScrn->pScreen->height - y - 1;
	break;

    default:
	/* No rotation. */
	newX = x;
	newY = y;
	break;
    }

    /* Pass adjusted pointer coordinates to wrapped PointerMoved function. */
    (*fPtr->PointerMoved)(arg, newX, newY);
}

static Bool
FBDevDriverFunc(ScrnInfoPtr pScrn, xorgDriverFuncOp op, pointer ptr)
{
    xorgHWFlags *flag;
    
    switch (op) {
	case GET_REQUIRED_HW_INTERFACES:
	    flag = (CARD32*)ptr;
	    (*flag) = 0;
	    return TRUE;
	default:
	    return FALSE;
    }
}
