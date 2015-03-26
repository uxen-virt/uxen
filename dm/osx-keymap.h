/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _OSX_KEYMAP_
#define _OSX_KEYMAP_

#define MODKEY_LCTRL        (1 << 0)
#define MODKEY_LSHIFT       (1 << 1)
#define MODKEY_RSHIFT       (1 << 2)
#define MODKEY_LCMD         (1 << 3)
#define MODKEY_RCMD         (1 << 4)
#define MODKEY_LALT         (1 << 5)
#define MODKEY_RALT         (1 << 6)
#define MODKEY_RCTRL        (1 << 13)
#define MODKEY_CAPSLOCK     (1 << 16)
#define MODKEY_FN           (1 << 23)

enum {
    KEY_LSHIFT              = 56,
    KEY_LCTRL               = 59,
    KEY_LALT                = 58,
    KEY_RSHIFT              = 60,
    KEY_RCTRL               = 62,
    KEY_RALT                = 61,
    KEY_LCMD                = 55,
    KEY_RCMD                = 54,
    KEY_CAPSLOCK            = 57,
};

// keymap conversion
static const struct {
    int scancode;
    int extended;
} osx_keymap[] =
{                //  SdlI    macI    macH    SdlH    104xtH  104xtC  sdl
    { 0x1e, 0 }, //  0       0x00    0x1e            A       QZ_a
    { 0x1f, 0 }, //  1       0x01    0x1f            S       QZ_s
    { 0x20, 0 }, //  2       0x02    0x20            D       QZ_d
    { 0x21, 0 }, //  3       0x03    0x21            F       QZ_f
    { 0x23, 0 }, //  4       0x04    0x23            H       QZ_h
    { 0x22, 0 }, //  5       0x05    0x22            G       QZ_g
    { 0x2c, 0 }, //  6       0x06    0x2c            Z       QZ_z
    { 0x2d, 0 }, //  7       0x07    0x2d            X       QZ_x
    { 0x2e, 0 }, //  8       0x08    0x2e            C       QZ_c
    { 0x2f, 0 }, //  9       0x09    0x2f            V       QZ_v
    {    0, 0 }, //  10      0x0A    Undefined
    { 0x30, 0 }, //  11      0x0B    0x30            B       QZ_b
    { 0x10, 0 }, //  12      0x0C    0x10            Q       QZ_q
    { 0x11, 0 }, //  13      0x0D    0x11            W       QZ_w
    { 0x12, 0 }, //  14      0x0E    0x12            E       QZ_e
    { 0x13, 0 }, //  15      0x0F    0x13            R       QZ_r
    { 0x15, 0 }, //  16      0x10    0x15            Y       QZ_y
    { 0x14, 0 }, //  17      0x11    0x14            T       QZ_t
    { 0x02, 0 }, //  18      0x12    0x02            1       QZ_1
    { 0x03, 0 }, //  19      0x13    0x03            2       QZ_2
    { 0x04, 0 }, //  20      0x14    0x04            3       QZ_3
    { 0x05, 0 }, //  21      0x15    0x05            4       QZ_4
    { 0x07, 0 }, //  22      0x16    0x07            6       QZ_6
    { 0x06, 0 }, //  23      0x17    0x06            5       QZ_5
    { 0x0d, 0 }, //  24      0x18    0x0d            =       QZ_EQUALS
    { 0x0a, 0 }, //  25      0x19    0x0a            9       QZ_9
    { 0x08, 0 }, //  26      0x1A    0x08            7       QZ_7
    { 0x0c, 0 }, //  27      0x1B    0x0c            -       QZ_MINUS
    { 0x09, 0 }, //  28      0x1C    0x09            8       QZ_8
    { 0x0b, 0 }, //  29      0x1D    0x0b            0       QZ_0
    { 0x1b, 0 }, //  30      0x1E    0x1b            ]       QZ_RIGHTBRACKET
    { 0x18, 0 }, //  31      0x1F    0x18            O       QZ_o
    { 0x16, 0 }, //  32      0x20    0x16            U       QZ_u
    { 0x1a, 0 }, //  33      0x21    0x1a            [       QZ_LEFTBRACKET
    { 0x17, 0 }, //  34      0x22    0x17            I       QZ_i
    { 0x19, 0 }, //  35      0x23    0x19            P       QZ_p
    { 0x1c, 0 }, //  36      0x24    0x1c            ENTER   QZ_RETURN
    { 0x26, 0 }, //  37      0x25    0x26            L       QZ_l
    { 0x24, 0 }, //  38      0x26    0x24            J       QZ_j
    { 0x28, 0 }, //  39      0x27    0x28            '       QZ_QUOTE
    { 0x25, 0 }, //  40      0x28    0x25            K       QZ_k
    { 0x27, 0 }, //  41      0x29    0x27            ;       QZ_SEMICOLON
    { 0x2b, 0 }, //  42      0x2A    0x2b            \       QZ_BACKSLASH
    { 0x33, 0 }, //  43      0x2B    0x33            ,       QZ_COMMA
    { 0x35, 0 }, //  44      0x2C    0x35            /       QZ_SLASH
    { 0x31, 0 }, //  45      0x2D    0x31            N       QZ_n
    { 0x32, 0 }, //  46      0x2E    0x32            M       QZ_m
    { 0x34, 0 }, //  47      0x2F    0x34            .       QZ_PERIOD
    { 0x0f, 0 }, //  48      0x30    0x0f            TAB     QZ_TAB
    { 0x39, 0 }, //  49      0x31    0x39            SPACE   QZ_SPACE
    { 0x29, 0 }, //  50      0x32    0x29            `       QZ_BACKQUOTE
    { 0x0e, 0 }, //  51      0x33    0x0e            BKSP    QZ_BACKSPACE
    {    0, 0 }, //  52      0x34    Undefined
    { 0x01, 0 }, //  53      0x35    0x01            ESC     QZ_ESCAPE
    { 0x5c, 1 }, //  54      0x36            E0,5C           QZ_RMETA
    { 0x5b, 1 }, //  55      0x37            E0,5B           QZ_LMETA
    { 0x2a, 0 }, //  56      0x38    0x2a            L SHFT  QZ_LSHIFT
    { 0x3a, 0 }, //  57      0x39    0x3a            CAPS    QZ_CAPSLOCK
    { 0x38, 0 }, //  58      0x3A    0x38            L ALT   QZ_LALT
    { 0x1d, 0 }, //  59      0x3B    0x1d            L CTRL  QZ_LCTRL
    { 0x36, 0 }, //  60      0x3C    0x36            R SHFT  QZ_RSHIFT
    { 0x38, 1 }, //  61      0x3D    0xb8    E0,38   R ALT   QZ_RALT
    { 0x1d, 1 }, //  62      0x3E    0x9d    E0,1D   R CTRL  QZ_RCTRL
    {    0, 0 }, //  63      0x3F    Undefined
    {    0, 0 }, //  64      0x40    Undefined
    {    0, 0 }, //  65      0x41    Undefined
    {    0, 0 }, //  66      0x42    Undefined
    { 0x37, 0 }, //  67      0x43    0x37            KP *    QZ_KP_MULTIPLY
    {    0, 0 }, //  68      0x44    Undefined
    { 0x4e, 0 }, //  69      0x45    0x4e            KP +    QZ_KP_PLUS
    {    0, 0 }, //  70      0x46    Undefined
    { 0x45, 0 }, //  71      0x47    0x45            NUM     QZ_NUMLOCK
    {    0, 0 }, //  72      0x48    Undefined
    {    0, 0 }, //  73      0x49    Undefined
    {    0, 0 }, //  74      0x4A    Undefined
    { 0x35, 1 }, //  75      0x4B    0xb5    E0,35   KP /    QZ_KP_DIVIDE
    { 0x1c, 1 }, //  76      0x4C    0x9c    E0,1C   KP EN   QZ_KP_ENTER
    {    0, 0 }, //  77      0x4D    undefined
    { 0x4a, 0 }, //  78      0x4E    0x4a            KP -    QZ_KP_MINUS
    {    0, 0 }, //  79      0x4F    Undefined
    {    0, 0 }, //  80      0x50    Undefined
    {    0, 0 }, //  81      0x51                            QZ_KP_EQUALS
    { 0x52, 0 }, //  82      0x52    0x52            KP 0    QZ_KP0
    { 0x4f, 0 }, //  83      0x53    0x4f            KP 1    QZ_KP1
    { 0x50, 0 }, //  84      0x54    0x50            KP 2    QZ_KP2
    { 0x51, 0 }, //  85      0x55    0x51            KP 3    QZ_KP3
    { 0x4b, 0 }, //  86      0x56    0x4b            KP 4    QZ_KP4
    { 0x4c, 0 }, //  87      0x57    0x4c            KP 5    QZ_KP5
    { 0x4d, 0 }, //  88      0x58    0x4d            KP 6    QZ_KP6
    { 0x47, 0 }, //  89      0x59    0x47            KP 7    QZ_KP7
    {    0, 0 }, //  90      0x5A    Undefined
    { 0x48, 0 }, //  91      0x5B    0x48            KP 8    QZ_KP8
    { 0x49, 0 }, //  92      0x5C    0x49            KP 9    QZ_KP9
    {    0, 0 }, //  93      0x5D    Undefined
    {    0, 0 }, //  94      0x5E    Undefined
    {    0, 0 }, //  95      0x5F    Undefined
    { 0x3f, 0 }, //  96      0x60    0x3f            F5      QZ_F5
    { 0x40, 0 }, //  97      0x61    0x40            F6      QZ_F6
    { 0x41, 0 }, //  98      0x62    0x41            F7      QZ_F7
    { 0x3d, 0 }, //  99      0x63    0x3d            F3      QZ_F3
    { 0x42, 0 }, //  100     0x64    0x42            F8      QZ_F8
    { 0x43, 0 }, //  101     0x65    0x43            F9      QZ_F9
    {    0, 0 }, //  102     0x66    Undefined
    { 0x57, 0 }, //  103     0x67    0x57            F11     QZ_F11
    {    0, 0 }, //  104     0x68    Undefined
    { 0xb7, 0 }, //  105     0x69    0xb7                    QZ_PRINT
    {    0, 0 }, //  106     0x6A    Undefined
    { 0x46, 0 }, //  107     0x6B    0x46            SCROLL  QZ_SCROLLOCK
    {    0, 0 }, //  108     0x6C    Undefined
    { 0x44, 0 }, //  109     0x6D    0x44            F10     QZ_F10
    {    0, 0 }, //  110     0x6E    Undefined
    { 0x58, 0 }, //  111     0x6F    0x58            F12     QZ_F12
    {    0, 0 }, //  112     0x70    Undefined
    { 0x00, 0 }, //  113     0x71    0x0 ???                 QZ_PAUSE
    { 0x52, 1 }, //  114     0x72    0xd2    E0,52   INSERT  QZ_INSERT
    { 0x47, 1 }, //  115     0x73    0xc7    E0,47   HOME    QZ_HOME
    { 0x49, 1 }, //  116     0x74    0xc9    E0,49   PG UP   QZ_PAGEUP
    { 0x53, 1 }, //  117     0x75    0xd3    E0,53   DELETE  QZ_DELETE
    { 0x3e, 0 }, //  118     0x76    0x3e            F4      QZ_F4
    { 0x4f, 1 }, //  119     0x77    0xcf    E0,4f   END     QZ_END
    { 0x3c, 0 }, //  120     0x78    0x3c            F2      QZ_F2
    { 0x51, 1 }, //  121     0x79    0xd1    E0,51   PG DN   QZ_PAGEDOWN
    { 0x3b, 0 }, //  122     0x7A    0x3b            F1      QZ_F1
    { 0x4b, 1 }, //  123     0x7B    0xcb    e0,4B   L ARROW QZ_LEFT
    { 0x4d, 1 }, //  124     0x7C    0xcd    e0,4D   R ARROW QZ_RIGHT
    { 0x50, 1 }, //  125     0x7D    0xd0    E0,50   D ARROW QZ_DOWN
    { 0x48, 1 }, //  126     0x7E    0xc8    E0,48   U ARROW QZ_UP
/* completed according to http://www.libsdl.org/cgi/cvsweb.cgi/SDL12/src/video/quartz/SDL_QuartzKeys.h?rev=1.6&content-type=text/x-cvsweb-markup */

/* Aditional 104 Key XP-Keyboard Scancodes from http://www.computer-engineering.org/ps2keyboard/scancodes1.html */
/*
    219 //          0xdb            e0,5b   L GUI
    220 //          0xdc            e0,5c   R GUI
    221 //          0xdd            e0,5d   APPS
        //              E0,2A,E0,37         PRNT SCRN
        //              E1,1D,45,E1,9D,C5   PAUSE
    83  //          0x53    0x53            KP .
// ACPI Scan Codes
    222 //          0xde            E0, 5E  Power
    223 //          0xdf            E0, 5F  Sleep
    227 //          0xe3            E0, 63  Wake
// Windows Multimedia Scan Codes
    153 //          0x99            E0, 19  Next Track
    144 //          0x90            E0, 10  Previous Track
    164 //          0xa4            E0, 24  Stop
    162 //          0xa2            E0, 22  Play/Pause
    160 //          0xa0            E0, 20  Mute
    176 //          0xb0            E0, 30  Volume Up
    174 //          0xae            E0, 2E  Volume Down
    237 //          0xed            E0, 6D  Media Select
    236 //          0xec            E0, 6C  E-Mail
    161 //          0xa1            E0, 21  Calculator
    235 //          0xeb            E0, 6B  My Computer
    229 //          0xe5            E0, 65  WWW Search
    178 //          0xb2            E0, 32  WWW Home
    234 //          0xea            E0, 6A  WWW Back
    233 //          0xe9            E0, 69  WWW Forward
    232 //          0xe8            E0, 68  WWW Stop
    231 //          0xe7            E0, 67  WWW Refresh
    230 //          0xe6            E0, 66  WWW Favorites
*/
};
static const size_t osx_keymap_len =
    (sizeof (osx_keymap) / sizeof (osx_keymap[0]));

#endif /* _OSX_KEYMAP_ */
