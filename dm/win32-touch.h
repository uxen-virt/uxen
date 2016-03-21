/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _WIN32_TOUCH_H_
#define _WIN32_TOUCH_H_

#define WM_PARENTNOTIFY               0x0210
#define WM_POINTERDEVICECHANGE        0x0238
#define WM_POINTERDEVICEINRANGE       0x0239
#define WM_POINTERDEVICEOUTOFRANGE    0x023A
#define WM_NCPOINTERUPDATE            0x0241
#define WM_NCPOINTERDOWN              0x0242
#define WM_NCPOINTERUP                0x0243
#define WM_POINTERUPDATE              0x0245
#define WM_POINTERDOWN                0x0246
#define WM_POINTERUP                  0x0247
#define WM_POINTERENTER               0x0249
#define WM_POINTERLEAVE               0x024A
#define WM_POINTERACTIVATE            0x024B
#define WM_POINTERCAPTURECHANGED      0x024C
#define WM_TOUCHHITTESTING            0x024D
#define WM_POINTERWHEEL               0x024E
#define WM_POINTERHWHEEL              0x024F

#define TOUCH_HIT_TESTING_PROXIMITY_CLOSEST  0x0
#define TOUCH_HIT_TESTING_PROXIMITY_FARTHEST 0x0fff

#define TOUCH_HIT_TESTING_DEFAULT 0x0
#define TOUCH_HIT_TESTING_CLIENT  0x1
#define TOUCH_HIT_TESTING_NONE    0x2

#define PDC_ARRIVAL                   0x0001
#define PDC_REMOVAL                   0x0002
#define PDC_ORIENTATION_0             0x0004
#define PDC_ORIENTATION_90            0x0008
#define PDC_ORIENTATION_180           0x0010
#define PDC_ORIENTATION_270           0x0020
#define PDC_MODE_DEFAULT              0x0040
#define PDC_MODE_CENTERED             0x0080
#define PDC_MODE_CENTERED             0x0080
#define PDC_MAPPING_CHANGE            0x0100
#define PDC_RESOLUTION                0x0200
#define PDC_ORIGIN                    0x0400
#define PDC_MODE_ASPECTRATIOPRESERVED 0x0900

#define POINTER_MESSAGE_FLAG_NEW          0x00000001
#define POINTER_MESSAGE_FLAG_INRANGE      0x00000002
#define POINTER_MESSAGE_FLAG_INCONTAC T   0x00000004
#define POINTER_MESSAGE_FLAG_FIRSTBUTTON  0x00000010
#define OINTER_MESSAGE_FLAG_SECONDBUTTON  0x00000020
#define POINTER_MESSAGE_FLAG_THIRDBUTTON  0x00000040
#define POINTER_MESSAGE_FLAG_FOURTHBUTTON 0x00000080
#define POINTER_MESSAGE_FLAG_FIFTHBUTTON  0x00000100
#define POINTER_MESSAGE_FLAG_PRIMARY      0x00000200
#define POINTER_MESSAGE_FLAG_CONFIDENCE   0x00000400
#define POINTER_MESSAGE_FLAG_CANCELED     0x00000800

#define MAX_TOUCH_COUNT 256
#define TOUCH_FEEDBACK_DEFAULT 0x1
#define TOUCH_FEEDBACK_INDIRECT 0x2
#define TOUCH_FEEDBACK_NONE 0x3

typedef enum tagPOINTER_FLAGS {
    POINTER_FLAG_NONE           = 0x00000000,
    POINTER_FLAG_NEW            = 0x00000001,
    POINTER_FLAG_INRANGE        = 0x00000002,
    POINTER_FLAG_INCONTACT      = 0x00000004,
    POINTER_FLAG_FIRSTBUTTON    = 0x00000010,
    POINTER_FLAG_SECONDBUTTON   = 0x00000020,
    POINTER_FLAG_THIRDBUTTON    = 0x00000040,
    POINTER_FLAG_OTHERBUTTON    = 0x00000080,
    POINTER_FLAG_PRIMARY        = 0x00000100,
    POINTER_FLAG_CONFIDENCE     = 0x00000200,
    POINTER_FLAG_CANCELLED      = 0x00000400,
    POINTER_FLAG_DOWN           = 0x00010000,
    POINTER_FLAG_UPDATE         = 0x00020000,
    POINTER_FLAG_UP             = 0x00040000,
    POINTER_FLAG_WHEEL          = 0x00080000,
    POINTER_FLAG_HWHEEL         = 0x00100000
} POINTER_FLAGS;

typedef enum tagPEN_FLAGS {
    PEN_FLAG_NONE             = 0x00000000,
    PEN_FLAG_BARREL           = 0x00000001,
    PEN_FLAG_INVERTED         = 0x00000002,
    PEN_FLAG_ERASER           = 0x00000004
} PEN_FLAGS;

typedef enum tagPEN_MASK {
    PEN_MASK_NONE      = 0x00000000,
    PEN_MASK_PRESSURE  = 0x00000001,
    PEN_MASK_ROTATION  = 0x00000002,
    PEN_MASK_TILT_X    = 0x00000004,
    PEN_MASK_TILT_Y    = 0x00000008
} PEN_MASK;

typedef enum tagTOUCH_FLAGS {
    TOUCH_FLAG_NONE  = 0x00000000
} TOUCH_FLAGS;

typedef enum tagTOUCH_MASK {
    TOUCH_MASK_NONE         = 0x00000000,
    TOUCH_MASK_CONTACTAREA  = 0x00000001,
    TOUCH_MASK_ORIENTATION  = 0x00000002,
    TOUCH_MASK_PRESSURE     = 0x00000004
} TOUCH_MASK;


typedef enum tagPOINTER_INPUT_TYPE {
    PT_POINTER  = 0x00000001,
    PT_TOUCH    = 0x00000002,
    PT_PEN      = 0x00000003,
    PT_MOUSE    = 0x00000004,
    PT_TOUCHPAD = 0x00000005
} POINTER_INPUT_TYPE;

/* FIXME: values missing on MSDN! */
typedef enum _POINTER_BUTTON_CHANGE_TYPE {
    POINTER_CHANGE_NONE               ,
    POINTER_CHANGE_FIRSTBUTTON_DOWN   ,
    POINTER_CHANGE_FIRSTBUTTON_UP     ,
    POINTER_CHANGE_SECONDBUTTON_DOWN  ,
    POINTER_CHANGE_SECONDBUTTON_UP    ,
    POINTER_CHANGE_THIRDBUTTON_DOWN   ,
    POINTER_CHANGE_THIRDBUTTON_UP     ,
    POINTER_CHANGE_FOURTHBUTTON_DOWN  ,
    POINTER_CHANGE_FOURTHBUTTON_UP    ,
    POINTER_CHANGE_FIFTHBUTTON_DOWN   ,
    POINTER_CHANGE_FIFTHBUTTON_UP
} POINTER_BUTTON_CHANGE_TYPE;

typedef struct tagTOUCH_HIT_TESTING_PROXIMITY_EVALUATION {
    UINT16 score;
    POINT  adjustedPoint;
} TOUCH_HIT_TESTING_PROXIMITY_EVALUATION, *PTOUCH_HIT_TESTING_PROXIMITY_EVALUATION;

typedef struct tagINPUT_TRANSFORM {
    union NAMELESS_UNION {
        struct NAMELESS_STRUCT {
            float _11;
            float _12;
            float _13;
            float _14;
            float _21;
            float _22;
            float _23;
            float _24;
            float _31;
            float _32;
            float _33;
            float _34;
            float _41;
            float _42;
            float _43;
            float _44;
        };
        float m[4][4];
    };
} INPUT_TRANSFORM;

typedef struct tagPOINTER_INFO {
    POINTER_INPUT_TYPE         pointerType;
    UINT32                     pointerId;
    UINT32                     frameId;
    POINTER_FLAGS              pointerFlags;
    HANDLE                     sourceDevice;
    HWND                       hwndTarget;
    POINT                      ptPixelLocation;
    POINT                      ptHimetricLocation;
    POINT                      ptPixelLocationRaw;
    POINT                      ptHimetricLocationRaw;
    DWORD                      dwTime;
    UINT32                     historyCount;
    INT32                      inputData;
    DWORD                      dwKeyStates;
    UINT64                     PerformanceCount;
    POINTER_BUTTON_CHANGE_TYPE ButtonChangeType;
} POINTER_INFO;

typedef struct tagPOINTER_PEN_INFO {
    POINTER_INFO pointerInfo;
    PEN_FLAGS    penFlags;
    PEN_MASK     penMask;
    UINT32       pressure;
    UINT32       rotation;
    INT32        tiltX;
    INT32        tiltY;
} POINTER_PEN_INFO;

typedef struct tagPOINTER_TOUCH_INFO {
    POINTER_INFO pointerInfo;
    TOUCH_FLAGS  touchFlags;
    TOUCH_MASK   touchMask;
    RECT         rcContact;
    RECT         rcContactRaw;
    UINT32       orientation;
    UINT32       pressure;
} POINTER_TOUCH_INFO;

typedef struct tagTOUCH_HIT_TESTING_INPUT {
    UINT32 pointerId;
    POINT  point;
    RECT   boundingBox;
    RECT   nonOccludedBoundingBox;
    UINT32 orientation;
} TOUCH_HIT_TESTING_INPUT, *PTOUCH_HIT_TESTING_INPUT;

typedef struct tagTouchPredictionParameters {
    UINT cbSize;
    UINT dwLatency;
    UINT dwSampleTime;
    UINT bUseHWTimeStamp;
} TouchPredictionParameters, *PTouchPredictionParameters;

#define WM_TOUCH 0x0240

#define TOUCHEVENTF_MOVE    0x0001
#define TOUCHEVENTF_DOWN    0x0002
#define TOUCHEVENTF_UP  0x0004
#define TOUCHEVENTF_INRANGE 0x0008
#define TOUCHEVENTF_PRIMARY 0x0010
#define TOUCHEVENTF_NOCOALESCE  0x0020
#define TOUCHEVENTF_PALM    0x0080

#define TOUCHINPUTMASKF_CONTACTAREA 0x0004
#define TOUCHINPUTMASKF_EXTRAINFO   0x0002
#define TOUCHINPUTMASKF_TIMEFROMSYSTEM  0x0001

static inline
BOOL FN_RegisterTouchWindow(HWND hWnd, ULONG ulFlags)
{
    typedef BOOL (CALLBACK *PFN_RegisterTouchWindow)(HWND, ULONG);
    static PFN_RegisterTouchWindow fn = NULL;

    if (!fn) {
        fn = (PFN_RegisterTouchWindow) GetProcAddress(GetModuleHandleA("user32.dll"),
                                        "RegisterTouchWindow");
        if (!fn)
            return FALSE;
    }

    return fn(hWnd, ulFlags);
}

static inline
BOOL FN_UnregisterTouchWindow(HWND hWnd)
{
    typedef BOOL (CALLBACK *PFN_UnregisterTouchWindow)(HWND);
    static PFN_UnregisterTouchWindow fn = NULL;

    if (!fn) {
        fn = (PFN_UnregisterTouchWindow)GetProcAddress(GetModuleHandleA("user32.dll"),
                                            "UnregisterTouchWindow");
        if (!fn)
            return FALSE;
    }

    return fn(hWnd);
}

static inline
BOOL FN_GetTouchInputInfo(HTOUCHINPUT hTouchInput, UINT cInputs,
                       PTOUCHINPUT pInputs, int cbSize)
{
    typedef BOOL (CALLBACK *PFN_GetTouchInputInfo)(HTOUCHINPUT, UINT, PTOUCHINPUT, int);
    static PFN_GetTouchInputInfo fn = NULL;

    if (!fn) {
        fn = (PFN_GetTouchInputInfo)GetProcAddress(GetModuleHandleA("user32.dll"),
                                        "GetTouchInputInfo");
        if (!fn)
            return FALSE;
    }

    return fn(hTouchInput, cInputs, pInputs, cbSize);
}

static inline
BOOL FN_CloseTouchInputHandle(HTOUCHINPUT hTouchInput)
{
    typedef BOOL (CALLBACK *PFN_CloseTouchInputHandle)(HTOUCHINPUT);
    static PFN_CloseTouchInputHandle fn = NULL;

    if (!fn) {
        fn = (PFN_CloseTouchInputHandle)GetProcAddress(GetModuleHandleA("user32.dll"),
                                            "CloseTouchInputHandle");
        if (!fn)
            return FALSE;
    }

    return fn(hTouchInput);
}

static inline
BOOL FN_GetPointerInfo(UINT32 pointerId, POINTER_INFO *pointerInfo)
{
    typedef BOOL (CALLBACK *PFN_GetPointerInfo)(UINT32, POINTER_INFO *);
    static PFN_GetPointerInfo fn = NULL;

    if (!fn) {
        fn = (PFN_GetPointerInfo)GetProcAddress(GetModuleHandleA("user32.dll"),
                                    "GetPointerInfo");
        if (!fn)
            return FALSE;
    }

    return fn(pointerId, pointerInfo);
}

static inline
BOOL FN_GetPointerTouchInfo(UINT32 pointerId, POINTER_TOUCH_INFO *touchInfo)
{
    typedef BOOL (CALLBACK *PFN_GetPointerTouchInfo)(UINT32, POINTER_TOUCH_INFO *);
    static PFN_GetPointerTouchInfo fn = NULL;

    if (!fn) {
        fn = (PFN_GetPointerTouchInfo)GetProcAddress(GetModuleHandleA("user32.dll"),
                                    "GetPointerTouchInfo");
        if (!fn)
            return FALSE;
    }

    return fn(pointerId, touchInfo);
}

static inline
BOOL FN_GetPointerFrameTouchInfo(UINT32 pointerId, UINT32 *pointerCount,
                                 POINTER_TOUCH_INFO *touchInfo)
{
    typedef BOOL (CALLBACK *PFN_GetPointerFrameTouchInfo)(UINT32, UINT32 *, POINTER_TOUCH_INFO *);
    static PFN_GetPointerFrameTouchInfo fn = NULL;

    if (!fn) {
        fn = (PFN_GetPointerFrameTouchInfo)GetProcAddress(GetModuleHandleA("user32.dll"),
                                                         "GetPointerFrameTouchInfo");
        if (!fn)
            return FALSE;
    }

    return fn(pointerId, pointerCount, touchInfo);
}

static inline
BOOL FN_GetPointerFramePenInfo(UINT32 pointerId, UINT32 *pointerCount,
                               POINTER_PEN_INFO *penInfo)
{
    typedef BOOL (CALLBACK *PFN_GetPointerFramePenInfo)(UINT32, UINT32 *, POINTER_PEN_INFO *);
    static PFN_GetPointerFramePenInfo fn = NULL;

    if (!fn) {
        fn = (PFN_GetPointerFramePenInfo)GetProcAddress(GetModuleHandleA("user32.dll"),
                                        "GetPointerFramePenInfo");
        if (!fn)
            return FALSE;
    }

    return fn(pointerId, pointerCount, penInfo);
}

static inline
BOOL FN_SkipPointerFrameMessages(UINT32 pointerId)
{
    typedef BOOL (CALLBACK *PFN_SkipPointerFrameMessages)(UINT32);
    static PFN_SkipPointerFrameMessages fn = NULL;

    if (!fn) {
        fn = (PFN_SkipPointerFrameMessages)GetProcAddress(GetModuleHandleA("user32.dll"),
                                          "SkipPointerFrameMessages");
        if (!fn)
            return FALSE;
    }

    return fn(pointerId);
}

#define GET_POINTERID_WPARAM(wParam) (LOWORD (wParam))
#define IS_POINTER_FLAG_SET_WPARAM(wParam, flag) (((DWORD)HIWORD (wParam) &(flag)) == (flag))
#define IS_POINTER_NEW_WPARAM(wParam) IS_POINTER_FLAG_SET_WPARAM (wParam, POINTER_MESSAGE_FLAG_NEW)
#define IS_POINTER_INRANGE_WPARAM(wParam) IS_POINTER_FLAG_SET_WPARAM (wParam, POINTER_MESSAGE_FLAG_INRANGE)
#define IS_POINTER_INCONTACT_WPARAM(wParam) IS_POINTER_FLAG_SET_WPARAM (wParam, POINTER_MESSAGE_FLAG_INCONTACT)
#define IS_POINTER_FIRSTBUTTON_WPARAM(wParam) IS_POINTER_FLAG_SET_WPARAM (wParam, POINTER_MESSAGE_FLAG_FIRSTBUTTON)
#define IS_POINTER_SECONDBUTTON_WPARAM(wParam) IS_POINTER_FLAG_SET_WPARAM (wParam, POINTER_MESSAGE_FLAG_SECONDBUTTON)
#define IS_POINTER_THIRDBUTTON_WPARAM(wParam) IS_POINTER_FLAG_SET_WPARAM (wParam, POINTER_MESSAGE_FLAG_THIRDBUTTON)
#define IS_POINTER_FOURTHBUTTON_WPARAM(wParam) IS_POINTER_FLAG_SET_WPARAM (wParam, POINTER_MESSAGE_FLAG_FOURTHBUTTON)
#define IS_POINTER_FIFTHBUTTON_WPARAM(wParam) IS_POINTER_FLAG_SET_WPARAM (wParam, POINTER_MESSAGE_FLAG_FIFTHBUTTON)
#define IS_POINTER_PRIMARY_WPARAM(wParam) IS_POINTER_FLAG_SET_WPARAM (wParam, POINTER_MESSAGE_FLAG_PRIMARY)
#define HAS_POINTER_CONFIDENCE_WPARAM(wParam) IS_POINTER_FLAG_SET_WPARAM (wParam, POINTER_MESSAGE_FLAG_CONFIDENCE)
#define IS_POINTER_CANCELED_WPARAM(wParam) IS_POINTER_FLAG_SET_WPARAM (wParam, POINTER_MESSAGE_FLAG_CANCELED)


#endif /* _WIN32_TOUCH_H_ */
