/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _TOUCH_DEFS_H_
#define _TOUCH_DEFS_H_

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

/* Values not on MSDN
#define POINTER_MOD_SHIFT
#define POINTER_MOD_CTRL
*/

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
  PEN_FLAG_PEN_FLAG_ERASER  = 0x00000004
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
  __C89_NAMELESS union {
    __C89_NAMELESS struct {
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
    float  m[4][4];
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

WINUSERAPI WINBOOL WINAPI EnableMouseInPointer(
  WINBOOL fEnable
);

WINUSERAPI WINBOOL WINAPI GetPointerCursorId (
  UINT32 pointerId,
  UINT32 *cursorId
);

WINUSERAPI WINBOOL WINAPI GetPointerFrameInfo(
  UINT32 pointerId,
  UINT32 *pointerCount,
  POINTER_INFO *pointerInfo
);

WINUSERAPI WINBOOL WINAPI GetPointerInfoHistory(
  UINT32 pointerId,
  UINT32 *entriesCount,
  POINTER_INFO *pointerInfo
);

WINUSERAPI WINBOOL WINAPI GetPointerFramePenInfo(
  UINT32 pointerId,
  UINT32 *pointerCount,
  POINTER_PEN_INFO *penInfo
);

WINUSERAPI WINBOOL WINAPI GetPointerFramePenInfoHistory(
  UINT32 pointerId,
  UINT32 *entriesCount,
  UINT32 *pointerCount,
  POINTER_PEN_INFO *penInfo
);

WINUSERAPI WINBOOL WINAPI GetPointerFrameTouchInfo(
  UINT32 pointerId,
  UINT32 *pointerCount,
  POINTER_TOUCH_INFO *touchInfo
);

WINUSERAPI WINBOOL WINAPI GetPointerFrameTouchInfoHistory(
  UINT32 pointerId,
  UINT32 *entriesCount,
  UINT32 *pointerCount,
  POINTER_TOUCH_INFO *touchInfo
);

WINUSERAPI WINBOOL WINAPI GetPointerInfo(
  UINT32 pointerId,
  POINTER_INFO *pointerInfo
);

WINUSERAPI WINBOOL WINAPI GetPointerInfoHistory(
  UINT32 pointerId,
  UINT32 *entriesCount,
  POINTER_INFO *pointerInfo
);

WINUSERAPI WINBOOL WINAPI GetPointerInputTransform(
  UINT32 pointerId,
  UINT32 historyCount,
  UINT32 *inputTransform
);

WINUSERAPI WINBOOL WINAPI GetPointerPenInfo(
  UINT32 pointerId,
  POINTER_PEN_INFO *penInfo
);

WINUSERAPI WINBOOL WINAPI GetPointerPenInfoHistory(
  UINT32 pointerId,
  UINT32 *entriesCount,
  POINTER_PEN_INFO  *penInfo
);

WINUSERAPI WINBOOL WINAPI GetPointerTouchInfo(
  UINT32 pointerId,
  POINTER_TOUCH_INFO *touchInfo
);

 WINUSERAPI WINBOOL WINAPI GetPointerTouchInfoHistory(
  UINT32 pointerId,
  UINT32 *entriesCount,
  POINTER_TOUCH_INFO *touchInfo
);

WINUSERAPI WINBOOL WINAPI GetPointerType (
  UINT32 pointerId,
  POINTER_INPUT_TYPE *pointerType
);

WINUSERAPI DWORD WINAPI GetUnpredictedMessagePos(void);

WINUSERAPI WINBOOL WINAPI IsMousePointerEnabled(void);

WINUSERAPI WINBOOL WINAPI SkipPointerFrameMessages(
  UINT32 pointerId
);

WINUSERAPI WINBOOL WINAPI GetPointerInfo(
  UINT32 pointerId,
  POINTER_INFO *pointerInfo
);

WINUSERAPI WINBOOL WINAPI SkipPointerFrameMessages(
  UINT32 pointerId
);

WINUSERAPI WINBOOL WINAPI EvaluateProximityToRect(
  const RECT *controlBoundingBox,
  const TOUCH_HIT_TESTING_INPUT *pHitTestingInput,
  TOUCH_HIT_TESTING_PROXIMITY_EVALUATION *pProximityEval
);

WINUSERAPI WINBOOL WINAPI EvaluateProximityToPolygon(
  UINT32 numVertices,
  const POINT *controlPolygon,
  const TOUCH_HIT_TESTING_INPUT *pHitTestingInput,
  TOUCH_HIT_TESTING_PROXIMITY_EVALUATION *pProximityEval
);

WINUSERAPI LRESULT WINAPI PackTouchHitTestingProximityEvaluation(
  const TOUCH_HIT_TESTING_INPUT *pHitTestingInput,
  const TOUCH_HIT_TESTING_PROXIMITY_EVALUATION *pProximityEval
);

WINUSERAPI WINBOOL WINAPI RegisterTouchHitTestingWindow(
  HWND hwnd,
  ULONG value
);

static inline
BOOL InjectTouchInput(UINT32 count, const POINTER_TOUCH_INFO *contacts)
{
    static BOOL WINAPI (*fn)(UINT32, const POINTER_TOUCH_INFO *) = NULL;

    if (!fn) {
        fn = (void *)GetProcAddress(GetModuleHandle("user32.dll"),
                                    "InjectTouchInput");
        if (!fn)
            return FALSE;
    }

    return fn(count, contacts);
}

static inline
BOOL InitializeTouchInjection(UINT32 maxCount, DWORD dwMode)
{
    static BOOL WINAPI (*fn)(UINT32, DWORD) = NULL;

    if (!fn) {
        fn = (void *)GetProcAddress(GetModuleHandle("user32.dll"),
                                    "InitializeTouchInjection");
        if (!fn)
            return FALSE;
    }

    return fn(maxCount, dwMode);
}

#endif /* _TOUCH_DEFS_H_ */
