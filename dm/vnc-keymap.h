/*
 * Copyright 2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _VNC_KEYMAP_
#define _VNC_KEYMAP_

enum {
    MODKEY_LSHIFT = 1,
    MODKEY_LCTRL,
    MODKEY_LALT,
    MODKEY_RSHIFT,
    MODKEY_RCTRL,
    MODKEY_RALT,
    MODKEY_LCMD,
    MODKEY_RCMD,

    MODKEY_last = MODKEY_RCMD,

    MODKEY_CAPSLOCK,
    MODKEY_FN,

    MODKEY_extra = MODKEY_FN + 1,
};

#define MODKEY_flags(key) (1 << (key))

#define MODKEY_shift_on (1 << MODKEY_extra)
#define MODKEY_shift_off (1 << (MODKEY_extra + 1))
#define MODKEY_shift_mask (MODKEY_shift_on | MODKEY_shift_off)

static const struct {
    int scancode;
    int extended;
} modifier_map[] =
{
    { 0x00, 0 },                /* dummy for modkey == 0 value */
    { 0x2a, 0 },                /* KEY_LSHIFT = 56, */
    { 0x1d, 0 },                /* KEY_LCTRL = 59, */
    { 0x38, 0 },                /* KEY_LALT = 58, */
    { 0x36, 0 },                /* KEY_RSHIFT = 60, */
    { 0x1d, 1 },                /* KEY_RCTRL = 62, */
    { 0x38, 1 },                /* KEY_RALT = 61, */
    { 0x5b, 1 },                /* KEY_LCMD = 55, */
    { 0x5c, 1 },                /* KEY_RCMD = 54, */
    { 0x3a, 0 },                /* KEY_CAPSLOCK = 57, */
};
static const size_t modifier_map_len =
    (sizeof(modifier_map) / sizeof(modifier_map[0]));

// keymap conversion
static const struct {
    int scancode;
    int extended;
    int modifier;
} vnc_keymap00[] =
{
    { 0x00, 0 },                /* 0x000 */
    { 0x00, 0 },                /* 0x001 */
    { 0x00, 0 },                /* 0x002 */
    { 0x00, 0 },                /* 0x003 */
    { 0x00, 0 },                /* 0x004 */
    { 0x00, 0 },                /* 0x005 */
    { 0x00, 0 },                /* 0x006 */
    { 0x00, 0 },                /* 0x007 */
    { 0x00, 0 },                /* 0x008 */
    { 0x00, 0 },                /* 0x009 */
    { 0x00, 0 },                /* 0x00a */
    { 0x00, 0 },                /* 0x00b */
    { 0x00, 0 },                /* 0x00c */
    { 0x00, 0 },                /* 0x00d */
    { 0x00, 0 },                /* 0x00e */
    { 0x00, 0 },                /* 0x00f */
    { 0x00, 0 },                /* 0x010 */
    { 0x00, 0 },                /* 0x011 */
    { 0x00, 0 },                /* 0x012 */
    { 0x00, 0 },                /* 0x013 */
    { 0x00, 0 },                /* 0x014 */
    { 0x00, 0 },                /* 0x015 */
    { 0x00, 0 },                /* 0x016 */
    { 0x00, 0 },                /* 0x017 */
    { 0x00, 0 },                /* 0x018 */
    { 0x00, 0 },                /* 0x019 */
    { 0x00, 0 },                /* 0x01a */
    { 0x00, 0 },                /* 0x01b */
    { 0x00, 0 },                /* 0x01c */
    { 0x00, 0 },                /* 0x01d */
    { 0x00, 0 },                /* 0x01e */
    { 0x00, 0 },                /* 0x01f */
    { 0x39, 0 },                /* XK_space               0x020 */
    { 0x02, 0, MODKEY_shift_on }, /* XK_exclam              0x021 */
    { 0x28, 0, MODKEY_shift_on }, /* XK_quotedbl            0x022 */
    { 0x04, 0, MODKEY_shift_on }, /* XK_numbersign          0x023 */
    { 0x05, 0, MODKEY_shift_on }, /* XK_dollar              0x024 */
    { 0x06, 0, MODKEY_shift_on }, /* XK_percent             0x025 */
    { 0x08, 0, MODKEY_shift_on }, /* XK_ampersand           0x026 */
    { 0x28, 0, MODKEY_shift_off }, /* XK_apostrophe / XK_quoteright 0x027 */
    { 0x0a, 0, MODKEY_shift_on },  /* XK_parenleft           0x028 */
    { 0x0b, 0, MODKEY_shift_on },  /* XK_parenright          0x029 */
    { 0x09, 0, MODKEY_shift_on },  /* XK_asterisk            0x02a */
    { 0x0d, 0, MODKEY_shift_on },  /* XK_plus                0x02b */
    { 0x33, 0, MODKEY_shift_off }, /* XK_comma               0x02c */
    { 0x0c, 0, MODKEY_shift_off }, /* XK_minus               0x02d */
    { 0x34, 0, MODKEY_shift_off }, /* XK_period              0x02e */
    { 0x35, 0, MODKEY_shift_off }, /* XK_slash               0x02f */
    { 0x0b, 0, MODKEY_shift_off }, /* XK_0                   0x030 */
    { 0x02, 0, MODKEY_shift_off }, /* XK_1                   0x031 */
    { 0x03, 0, MODKEY_shift_off }, /* XK_2                   0x032 */
    { 0x04, 0, MODKEY_shift_off }, /* XK_3                   0x033 */
    { 0x05, 0, MODKEY_shift_off }, /* XK_4                   0x034 */
    { 0x06, 0, MODKEY_shift_off }, /* XK_5                   0x035 */
    { 0x07, 0, MODKEY_shift_off }, /* XK_6                   0x036 */
    { 0x08, 0, MODKEY_shift_off }, /* XK_7                   0x037 */
    { 0x09, 0, MODKEY_shift_off }, /* XK_8                   0x038 */
    { 0x0a, 0, MODKEY_shift_off }, /* XK_9                   0x039 */
    { 0x27, 0, MODKEY_shift_on },  /* XK_colon               0x03a */
    { 0x27, 0, MODKEY_shift_off }, /* XK_semicolon           0x03b */
    { 0x33, 0, MODKEY_shift_on },  /* XK_less                0x03c */
    { 0x0d, 0, MODKEY_shift_off }, /* XK_equal               0x03d */
    { 0x34, 0, MODKEY_shift_on },  /* XK_greater             0x03e */
    { 0x35, 0, MODKEY_shift_on },  /* XK_question            0x03f */
    { 0x03, 0, MODKEY_shift_on },  /* XK_at                  0x040 */
    { 0x1e, 0, MODKEY_shift_on },  /* XK_A                   0x041 */
    { 0x30, 0, MODKEY_shift_on },  /* XK_B                   0x042 */
    { 0x2e, 0, MODKEY_shift_on },  /* XK_C                   0x043 */
    { 0x20, 0, MODKEY_shift_on },  /* XK_D                   0x044 */
    { 0x12, 0, MODKEY_shift_on },  /* XK_E                   0x045 */
    { 0x21, 0, MODKEY_shift_on },  /* XK_F                   0x046 */
    { 0x22, 0, MODKEY_shift_on },  /* XK_G                   0x047 */
    { 0x23, 0, MODKEY_shift_on },  /* XK_H                   0x048 */
    { 0x17, 0, MODKEY_shift_on },  /* XK_I                   0x049 */
    { 0x24, 0, MODKEY_shift_on },  /* XK_J                   0x04a */
    { 0x25, 0, MODKEY_shift_on },  /* XK_K                   0x04b */
    { 0x26, 0, MODKEY_shift_on },  /* XK_L                   0x04c */
    { 0x32, 0, MODKEY_shift_on },  /* XK_M                   0x04d */
    { 0x31, 0, MODKEY_shift_on },  /* XK_N                   0x04e */
    { 0x18, 0, MODKEY_shift_on },  /* XK_O                   0x04f */
    { 0x19, 0, MODKEY_shift_on },  /* XK_P                   0x050 */
    { 0x10, 0, MODKEY_shift_on },  /* XK_Q                   0x051 */
    { 0x13, 0, MODKEY_shift_on },  /* XK_R                   0x052 */
    { 0x1f, 0, MODKEY_shift_on },  /* XK_S                   0x053 */
    { 0x14, 0, MODKEY_shift_on },  /* XK_T                   0x054 */
    { 0x16, 0, MODKEY_shift_on },  /* XK_U                   0x055 */
    { 0x2f, 0, MODKEY_shift_on },  /* XK_V                   0x056 */
    { 0x11, 0, MODKEY_shift_on },  /* XK_W                   0x057 */
    { 0x2d, 0, MODKEY_shift_on },  /* XK_X                   0x058 */
    { 0x15, 0, MODKEY_shift_on },  /* XK_Y                   0x059 */
    { 0x2c, 0, MODKEY_shift_on },  /* XK_Z                   0x05a */
    { 0x1a, 0, MODKEY_shift_off }, /* XK_bracketleft         0x05b */
    { 0x2b, 0, MODKEY_shift_off }, /* XK_backslash           0x05c */
    { 0x1b, 0, MODKEY_shift_off }, /* XK_bracketright        0x05d */
    { 0x07, 0, MODKEY_shift_on },  /* XK_asciicircum         0x05e */
    { 0x0c, 0, MODKEY_shift_on },  /* XK_underscore          0x05f */
    { 0x29, 0, MODKEY_shift_off }, /* XK_grave / XK_quoteleft 0x060 */
    { 0x1e, 0, MODKEY_shift_off }, /* XK_a                   0x061 */
    { 0x30, 0, MODKEY_shift_off }, /* XK_b                   0x062 */
    { 0x2e, 0, MODKEY_shift_off }, /* XK_c                   0x063 */
    { 0x20, 0, MODKEY_shift_off }, /* XK_d                   0x064 */
    { 0x12, 0, MODKEY_shift_off }, /* XK_e                   0x065 */
    { 0x21, 0, MODKEY_shift_off }, /* XK_f                   0x066 */
    { 0x22, 0, MODKEY_shift_off }, /* XK_g                   0x067 */
    { 0x23, 0, MODKEY_shift_off }, /* XK_h                   0x068 */
    { 0x17, 0, MODKEY_shift_off }, /* XK_i                   0x069 */
    { 0x24, 0, MODKEY_shift_off }, /* XK_j                   0x06a */
    { 0x25, 0, MODKEY_shift_off }, /* XK_k                   0x06b */
    { 0x26, 0, MODKEY_shift_off }, /* XK_l                   0x06c */
    { 0x32, 0, MODKEY_shift_off }, /* XK_m                   0x06d */
    { 0x31, 0, MODKEY_shift_off }, /* XK_n                   0x06e */
    { 0x18, 0, MODKEY_shift_off }, /* XK_o                   0x06f */
    { 0x19, 0, MODKEY_shift_off }, /* XK_p                   0x070 */
    { 0x10, 0, MODKEY_shift_off }, /* XK_q                   0x071 */
    { 0x13, 0, MODKEY_shift_off }, /* XK_r                   0x072 */
    { 0x1f, 0, MODKEY_shift_off }, /* XK_s                   0x073 */
    { 0x14, 0, MODKEY_shift_off }, /* XK_t                   0x074 */
    { 0x16, 0, MODKEY_shift_off }, /* XK_u                   0x075 */
    { 0x2f, 0, MODKEY_shift_off }, /* XK_v                   0x076 */
    { 0x11, 0, MODKEY_shift_off }, /* XK_w                   0x077 */
    { 0x2d, 0, MODKEY_shift_off }, /* XK_x                   0x078 */
    { 0x15, 0, MODKEY_shift_off }, /* XK_y                   0x079 */
    { 0x2c, 0, MODKEY_shift_off }, /* XK_z                   0x07a */
    { 0x1a, 0, MODKEY_shift_on },  /* XK_braceleft           0x07b */
    { 0x2b, 0, MODKEY_shift_on },  /* XK_bar                 0x07c */
    { 0x1b, 0, MODKEY_shift_on },  /* XK_braceright          0x07d */
    { 0x29, 0, MODKEY_shift_on },  /* XK_asciitilde          0x07e */
};
static const size_t vnc_keymap00_len =
    (sizeof(vnc_keymap00) / sizeof(vnc_keymap00[0]));

static const struct {
    int scancode;
    int extended;
    int modifier;
} vnc_keymapFF[] =
{
    { 0x00, 0 }, /* 0xFF00 */
    { 0x00, 0 }, /* 0xFF01 */
    { 0x00, 0 }, /* 0xFF02 */
    { 0x00, 0 }, /* 0xFF03 */
    { 0x00, 0 }, /* 0xFF04 */
    { 0x00, 0 }, /* 0xFF05 */
    { 0x00, 0 }, /* 0xFF06 */
    { 0x00, 0 }, /* 0xFF07 */
    { 0x0e, 0 }, /* 0xFF08 */  /* XK_BackSpace 0xFF08 back space, back char */
    { 0x0f, 0 }, /* 0xFF09 */  /* XK_Tab 0xFF09 */
    { 0x00, 0 }, /* 0xFF0a */  /* XK_Linefeed 0xFF0A Linefeed, LF */
    { 0x00, 0 }, /* 0xFF0b */  /* XK_Clear 0xFF0B */
    { 0x00, 0 }, /* 0xFF0c */
    { 0x1c, 0 }, /* 0xFF0d */  /* XK_Return 0xFF0D Return, enter */
    { 0x00, 0 }, /* 0xFF0e */
    { 0x00, 0 }, /* 0xFF0f */
    { 0x00, 0 }, /* 0xFF10 */
    { 0x00, 0 }, /* 0xFF11 */
    { 0x00, 0 }, /* 0xFF12 */
    { 0x00, 0 }, /* 0xFF13 */  /* XK_Pause 0xFF13 Pause, hold */
    { 0x46, 0 }, /* 0xFF14 */  /* XK_Scroll_Lock 0xFF14 */
    { 0x00, 0 }, /* 0xFF15 */  /* XK_Sys_Req 0xFF15 */
    { 0x00, 0 }, /* 0xFF16 */
    { 0x00, 0 }, /* 0xFF17 */
    { 0x00, 0 }, /* 0xFF18 */
    { 0x00, 0 }, /* 0xFF19 */
    { 0x00, 0 }, /* 0xFF1a */
    { 0x01, 0 }, /* 0xFF1b */  /* XK_Escape 0xFF1B */
    { 0x00, 0 }, /* 0xFF1c */
    { 0x00, 0 }, /* 0xFF1d */
    { 0x00, 0 }, /* 0xFF1e */
    { 0x00, 0 }, /* 0xFF1f */
    { 0x00, 0 }, /* 0xFF20 */  /* XK_Multi_key 0xFF20 Multi-key character compose */
    { 0x00, 0 }, /* 0xFF21 */
    { 0x00, 0 }, /* 0xFF22 */
    { 0x00, 0 }, /* 0xFF23 */
    { 0x00, 0 }, /* 0xFF24 */
    { 0x00, 0 }, /* 0xFF25 */
    { 0x00, 0 }, /* 0xFF26 */
    { 0x00, 0 }, /* 0xFF27 */
    { 0x00, 0 }, /* 0xFF28 */
    { 0x00, 0 }, /* 0xFF29 */
    { 0x00, 0 }, /* 0xFF2a */
    { 0x00, 0 }, /* 0xFF2b */
    { 0x00, 0 }, /* 0xFF2c */
    { 0x00, 0 }, /* 0xFF2d */
    { 0x00, 0 }, /* 0xFF2e */
    { 0x00, 0 }, /* 0xFF2f */
    { 0x00, 0 }, /* 0xFF30 */
    { 0x00, 0 }, /* 0xFF31 */
    { 0x00, 0 }, /* 0xFF32 */
    { 0x00, 0 }, /* 0xFF33 */
    { 0x00, 0 }, /* 0xFF34 */
    { 0x00, 0 }, /* 0xFF35 */
    { 0x00, 0 }, /* 0xFF36 */
    { 0x00, 0 }, /* 0xFF37 */
    { 0x00, 0 }, /* 0xFF38 */
    { 0x00, 0 }, /* 0xFF39 */
    { 0x00, 0 }, /* 0xFF3a */
    { 0x00, 0 }, /* 0xFF3b */
    { 0x00, 0 }, /* 0xFF3c */  /* XK_SingleCandidate	0xFF3C */
    { 0x00, 0 }, /* 0xFF3d */  /* XK_MultipleCandidate	0xFF3D */
    { 0x00, 0 }, /* 0xFF3e */  /* XK_PreviousCandidate	0xFF3E */
    { 0x00, 0 }, /* 0xFF3f */
    { 0x00, 0 }, /* 0xFF40 */
    { 0x00, 0 }, /* 0xFF41 */
    { 0x00, 0 }, /* 0xFF42 */
    { 0x00, 0 }, /* 0xFF43 */
    { 0x00, 0 }, /* 0xFF44 */
    { 0x00, 0 }, /* 0xFF45 */
    { 0x00, 0 }, /* 0xFF46 */
    { 0x00, 0 }, /* 0xFF47 */
    { 0x00, 0 }, /* 0xFF48 */
    { 0x00, 0 }, /* 0xFF49 */
    { 0x00, 0 }, /* 0xFF4a */
    { 0x00, 0 }, /* 0xFF4b */
    { 0x00, 0 }, /* 0xFF4c */
    { 0x00, 0 }, /* 0xFF4d */
    { 0x00, 0 }, /* 0xFF4e */
    { 0x00, 0 }, /* 0xFF4f */
    { 0x47, 1 }, /* 0xFF50 */  /* XK_Home 0xFF50 */
    { 0x4b, 1 }, /* 0xFF51 */  /* XK_Left 0xFF51 Move left, left arrow */
    { 0x48, 1 }, /* 0xFF52 */  /* XK_Up 0xFF52 Move up, up arrow */
    { 0x4d, 1 }, /* 0xFF53 */  /* XK_Right 0xFF53 Move right, right arrow */
    { 0x50, 1 }, /* 0xFF54 */  /* XK_Down 0xFF54 Move down, down arrow */
    { 0x49, 1 }, /* 0xFF55 */  /* XK_Prior / XK_Page_Up 0xFF55 Prior, previous */
    { 0x51, 1 }, /* 0xFF56 */  /* XK_Next / XK_Page_Down 0xFF56 Next */
    { 0x4f, 1 }, /* 0xFF57 */  /* XK_End 0xFF57 EOL */
    { 0x00, 0 }, /* 0xFF58 */  /* XK_Begin 0xFF58 BOL */
    { 0x00, 0 }, /* 0xFF59 */
    { 0x00, 0 }, /* 0xFF5a */
    { 0x00, 0 }, /* 0xFF5b */
    { 0x00, 0 }, /* 0xFF5c */
    { 0x00, 0 }, /* 0xFF5d */
    { 0x00, 0 }, /* 0xFF5e */
    { 0x00, 0 }, /* 0xFF5f */
    { 0x00, 0 }, /* 0xFF60 */  /* XK_Select 0xFF60 Select, mark */
    { 0xb7, 0 }, /* 0xFF61 */  /* XK_Print 0xFF61 */
    { 0x00, 0 }, /* 0xFF62 */  /* XK_Execute 0xFF62 Execute, run, do */
    { 0x52, 1 }, /* 0xFF63 */  /* XK_Insert 0xFF63 Insert, insert here */
    { 0x00, 0 }, /* 0xFF64 */
    { 0x00, 0 }, /* 0xFF65 */  /* XK_Undo 0xFF65 Undo, oops */
    { 0x00, 0 }, /* 0xFF66 */  /* XK_Redo 0xFF66 redo, again */
    { 0x00, 0 }, /* 0xFF67 */  /* XK_Menu 0xFF67 */
    { 0x00, 0 }, /* 0xFF68 */  /* XK_Find 0xFF68 Find, search */
    { 0x00, 0 }, /* 0xFF69 */  /* XK_Cancel 0xFF69 Cancel, stop, abort, exit */
    { 0x00, 0 }, /* 0xFF6a */  /* XK_Help 0xFF6A Help */
    { 0x00, 0 }, /* 0xFF6b */  /* XK_Break 0xFF6B */
    { 0x00, 0 }, /* 0xFF6c */
    { 0x00, 0 }, /* 0xFF6d */
    { 0x00, 0 }, /* 0xFF6e */
    { 0x00, 0 }, /* 0xFF6f */
    { 0x00, 0 }, /* 0xFF70 */
    { 0x00, 0 }, /* 0xFF71 */
    { 0x00, 0 }, /* 0xFF72 */
    { 0x00, 0 }, /* 0xFF73 */
    { 0x00, 0 }, /* 0xFF74 */
    { 0x00, 0 }, /* 0xFF75 */
    { 0x00, 0 }, /* 0xFF76 */
    { 0x00, 0 }, /* 0xFF77 */
    { 0x00, 0 }, /* 0xFF78 */
    { 0x00, 0 }, /* 0xFF79 */
    { 0x00, 0 }, /* 0xFF7a */
    { 0x00, 0 }, /* 0xFF7b */
    { 0x00, 0 }, /* 0xFF7c */
    { 0x00, 0 }, /* 0xFF7d */
    { 0x00, 0 }, /* 0xFF7e */  /* XK_Mode_switch / XK_script_switch 0xFF7E Character set switch */
    { 0x45, 0 }, /* 0xFF7f */  /* XK_Num_Lock 0xFF7F */
    { 0x00, 0 }, /* 0xFF80 */  /* XK_KP_Space 0xFF80 space */
    { 0x00, 0 }, /* 0xFF81 */
    { 0x00, 0 }, /* 0xFF82 */
    { 0x00, 0 }, /* 0xFF83 */
    { 0x00, 0 }, /* 0xFF84 */
    { 0x00, 0 }, /* 0xFF85 */
    { 0x00, 0 }, /* 0xFF86 */
    { 0x00, 0 }, /* 0xFF87 */
    { 0x00, 0 }, /* 0xFF88 */
    { 0x00, 0 }, /* 0xFF89 */  /* XK_KP_Tab 0xFF89 */
    { 0x00, 0 }, /* 0xFF8a */
    { 0x00, 0 }, /* 0xFF8b */
    { 0x00, 0 }, /* 0xFF8c */
    { 0x1c, 1 }, /* 0xFF8d */  /* XK_KP_Enter 0xFF8D enter */
    { 0x00, 0 }, /* 0xFF8e */
    { 0x00, 0 }, /* 0xFF8f */
    { 0x00, 0 }, /* 0xFF90 */
    { 0x00, 0 }, /* 0xFF91 */  /* XK_KP_F1 0xFF91 PF1, KP_A, ... */
    { 0x00, 0 }, /* 0xFF92 */  /* XK_KP_F2 0xFF92 */
    { 0x00, 0 }, /* 0xFF93 */  /* XK_KP_F3 0xFF93 */
    { 0x00, 0 }, /* 0xFF94 */  /* XK_KP_F4 0xFF94 */
    { 0x00, 0 }, /* 0xFF95 */  /* XK_KP_Home 0xFF95 */
    { 0x00, 0 }, /* 0xFF96 */  /* XK_KP_Left 0xFF96 */
    { 0x00, 0 }, /* 0xFF97 */  /* XK_KP_Up 0xFF97 */
    { 0x00, 0 }, /* 0xFF98 */  /* XK_KP_Right 0xFF98 */
    { 0x00, 0 }, /* 0xFF99 */  /* XK_KP_Down 0xFF99 */
    { 0x00, 0 }, /* 0xFF9a */  /* XK_KP_Prior / XK_KP_Page_Up 0xFF9A */
    { 0x00, 0 }, /* 0xFF9b */  /* XK_KP_Next / XK_KP_Page_Down 0xFF9B */
    { 0x00, 0 }, /* 0xFF9c */  /* XK_KP_End 0xFF9C */
    { 0x00, 0 }, /* 0xFF9d */  /* XK_KP_Begin 0xFF9D */
    { 0x00, 0 }, /* 0xFF9e */  /* XK_KP_Insert 0xFF9E */
    { 0x00, 0 }, /* 0xFF9f */  /* XK_KP_Delete 0xFF9F */
    { 0x00, 0 }, /* 0xFFa0 */
    { 0x00, 0 }, /* 0xFFa1 */
    { 0x00, 0 }, /* 0xFFa2 */
    { 0x00, 0 }, /* 0xFFa3 */
    { 0x00, 0 }, /* 0xFFa4 */
    { 0x00, 0 }, /* 0xFFa5 */
    { 0x00, 0 }, /* 0xFFa6 */
    { 0x00, 0 }, /* 0xFFa7 */
    { 0x00, 0 }, /* 0xFFa8 */
    { 0x00, 0 }, /* 0xFFa9 */
    { 0x37, 0 }, /* 0xFFaa */  /* XK_KP_Multiply 0xFFAA */
    { 0x4e, 0 }, /* 0xFFab */  /* XK_KP_Add 0xFFAB */
    { 0x00, 0 }, /* 0xFFac */  /* XK_KP_Separator 0xFFAC separator, often comma */
    { 0x4a, 0 }, /* 0xFFad */  /* XK_KP_Subtract 0xFFAD */
    { 0x00, 0 }, /* 0xFFae */  /* XK_KP_Decimal 0xFFAE */
    { 0x35, 1 }, /* 0xFFaf */  /* XK_KP_Divide 0xFFAF */
    { 0x52, 0 }, /* 0xFFb0 */  /* XK_KP_0 0xFFB0 */
    { 0x4f, 0 }, /* 0xFFb1 */  /* XK_KP_1 0xFFB1 */
    { 0x50, 0 }, /* 0xFFb2 */  /* XK_KP_2 0xFFB2 */
    { 0x51, 0 }, /* 0xFFb3 */  /* XK_KP_3 0xFFB3 */
    { 0x4b, 0 }, /* 0xFFb4 */  /* XK_KP_4 0xFFB4 */
    { 0x4c, 0 }, /* 0xFFb5 */  /* XK_KP_5 0xFFB5 */
    { 0x4d, 0 }, /* 0xFFb6 */  /* XK_KP_6 0xFFB6 */
    { 0x47, 0 }, /* 0xFFb7 */  /* XK_KP_7 0xFFB7 */
    { 0x48, 0 }, /* 0xFFb8 */  /* XK_KP_8 0xFFB8 */
    { 0x49, 0 }, /* 0xFFb9 */  /* XK_KP_9 0xFFB9 */
    { 0x00, 0 }, /* 0xFFba */
    { 0x00, 0 }, /* 0xFFbb */
    { 0x00, 0 }, /* 0xFFbc */
    { 0x00, 0 }, /* 0xFFbd */  /* XK_KP_Equal 0xFFBD equals */
    { 0x3b, 0 }, /* 0xFFbe */  /* XK_F1 0xFFBE */
    { 0x3c, 0 }, /* 0xFFbf */  /* XK_F2 0xFFBF */
    { 0x3d, 0 }, /* 0xFFc0 */  /* XK_F3 0xFFC0 */
    { 0x3e, 0 }, /* 0xFFc1 */  /* XK_F4 0xFFC1 */
    { 0x3f, 0 }, /* 0xFFc2 */  /* XK_F5 0xFFC2 */
    { 0x40, 0 }, /* 0xFFc3 */  /* XK_F6 0xFFC3 */
    { 0x41, 0 }, /* 0xFFc4 */  /* XK_F7 0xFFC4 */
    { 0x42, 0 }, /* 0xFFc5 */  /* XK_F8 0xFFC5 */
    { 0x43, 0 }, /* 0xFFc6 */  /* XK_F9 0xFFC6 */
    { 0x44, 0 }, /* 0xFFc7 */  /* XK_F10 0xFFC7 */
    { 0x57, 0 }, /* 0xFFc8 */  /* XK_F11 / XK_L1 0xFFC8 */
    { 0x58, 0 }, /* 0xFFc9 */  /* XK_F12 / XK_L2 0xFFC9 */
    { 0x00, 0 }, /* 0xFFca */  /* XK_F13 / XK_L3 0xFFCA */
    { 0x00, 0 }, /* 0xFFcb */  /* XK_F14 / XK_L4 0xFFCB */
    { 0x00, 0 }, /* 0xFFcc */  /* XK_F15 / XK_L5 0xFFCC */
    { 0x00, 0 }, /* 0xFFcd */  /* XK_F16 / XK_L6 0xFFCD */
    { 0x00, 0 }, /* 0xFFce */  /* XK_F17 / XK_L7 0xFFCE */
    { 0x00, 0 }, /* 0xFFcf */  /* XK_F18 / XK_L8 0xFFCF */
    { 0x00, 0 }, /* 0xFFd0 */  /* XK_F19 / XK_L9 0xFFD0 */
    { 0x00, 0 }, /* 0xFFd1 */  /* XK_F20 / XK_L10 0xFFD1 */
    { 0x00, 0 }, /* 0xFFd2 */  /* XK_F21 / XK_R1 0xFFD2 */
    { 0x00, 0 }, /* 0xFFd3 */  /* XK_F22 / XK_R2 0xFFD3 */
    { 0x00, 0 }, /* 0xFFd4 */  /* XK_F23 / XK_R3 0xFFD4 */
    { 0x00, 0 }, /* 0xFFd5 */  /* XK_F24 / XK_R4 0xFFD5 */
    { 0x00, 0 }, /* 0xFFd6 */  /* XK_F25 / XK_R5 0xFFD6 */
    { 0x00, 0 }, /* 0xFFd7 */  /* XK_F26 / XK_R6 0xFFD7 */
    { 0x00, 0 }, /* 0xFFd8 */  /* XK_F27 / XK_R7 0xFFD8 */
    { 0x00, 0 }, /* 0xFFd9 */  /* XK_F28 / XK_R8 0xFFD9 */
    { 0x00, 0 }, /* 0xFFda */  /* XK_F29 / XK_R9 0xFFDA */
    { 0x00, 0 }, /* 0xFFdb */  /* XK_F30 / XK_R10 0xFFDB */
    { 0x00, 0 }, /* 0xFFdc */  /* XK_F31 / XK_R11 0xFFDC */
    { 0x00, 0 }, /* 0xFFdd */  /* XK_F32 / XK_R12 0xFFDD */
    { 0x00, 0 }, /* 0xFFde */  /* XK_F33 / XK_R13 0xFFDE */
    { 0x00, 0 }, /* 0xFFdf */  /* XK_F34 / XK_R14 0xFFDF */
    { 0x00, 0 }, /* 0xFFe0 */  /* XK_F35 / XK_R15 0xFFE0 */
    { /* 0x2a, 0, */ 0x00, 0, MODKEY_LSHIFT }, /* 0xFFe1 */  /* XK_Shift_L 0xFFE1 Left shift */
    { /* 0x36, 0, */ 0x00, 0, MODKEY_RSHIFT }, /* 0xFFe2 */  /* XK_Shift_R 0xFFE2 Right shift */
    { /* 0x1d, 0, */ 0x00, 0, MODKEY_LCTRL }, /* 0xFFe3 */  /* XK_Control_L 0xFFE3 Left control */
    { /* 0x1d, 1, */ 0x00, 0, MODKEY_RCTRL }, /* 0xFFe4 */  /* XK_Control_R 0xFFE4 Right control */
    { /* 0x3a, 0, */ 0x00, 0, MODKEY_CAPSLOCK }, /* 0xFFe5 */  /* XK_Caps_Lock 0xFFE5 Caps lock */
    { 0x00, 0 }, /* 0xFFe6 */  /* XK_Shift_Lock 0xFFE6 Shift lock */
    { /* 0x5b, 1, */ 0x00, 0, MODKEY_LALT }, /* 0xFFe7 */  /* XK_Meta_L 0xFFE7 Left meta */
    { /* 0x5c, 1, */ 0x00, 0, MODKEY_RALT }, /* 0xFFe8 */  /* XK_Meta_R 0xFFE8 Right meta */
    { /* 0x38, 0, */ 0x00, 0, MODKEY_LCMD }, /* 0xFFe9 */  /* XK_Alt_L 0xFFE9 Left alt */
    { /* 0x38, 1, */ 0x00, 0, MODKEY_RCMD }, /* 0xFFea */  /* XK_Alt_R 0xFFEA Right alt */
    { 0x00, 0 }, /* 0xFFeb */  /* XK_Super_L 0xFFEB Left super */
    { 0x00, 0 }, /* 0xFFec */  /* XK_Super_R 0xFFEC Right super */
    { 0x00, 0 }, /* 0xFFed */  /* XK_Hyper_L 0xFFED Left hyper */
    { 0x00, 0 }, /* 0xFFee */  /* XK_Hyper_R 0xFFEE Right hyper */
    { 0x00, 0 }, /* 0xFFef */
    { 0x00, 0 }, /* 0xFFf0 */
    { 0x00, 0 }, /* 0xFFf1 */
    { 0x00, 0 }, /* 0xFFf2 */
    { 0x00, 0 }, /* 0xFFf3 */
    { 0x00, 0 }, /* 0xFFf4 */
    { 0x00, 0 }, /* 0xFFf5 */
    { 0x00, 0 }, /* 0xFFf6 */
    { 0x00, 0 }, /* 0xFFf7 */
    { 0x00, 0 }, /* 0xFFf8 */
    { 0x00, 0 }, /* 0xFFf9 */
    { 0x00, 0 }, /* 0xFFfa */
    { 0x00, 0 }, /* 0xFFfb */
    { 0x00, 0 }, /* 0xFFfc */
    { 0x00, 0 }, /* 0xFFfd */
    { 0x00, 0 }, /* 0xFFfe */
    { 0x53, 1 }, /* 0xFFff */  /* XK_Delete 0xFFFF Delete, rubout */
};
static const size_t vnc_keymapFF_len =
    (sizeof(vnc_keymapFF) / sizeof(vnc_keymapFF[0]));

#endif  /* _VNC_KEYMAP_ */
