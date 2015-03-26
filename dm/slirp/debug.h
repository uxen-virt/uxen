/*
 * Copyright (c) 1995 Danny Gasparovski.
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

//#define SLIRP_DEBUG 1

#ifdef SLIRP_DEBUG

#define DBG_CALL 0x1
#define DBG_MISC 0x2
#define DBG_ERROR 0x4
#define DBG_XTRA 0x8
#define DBG_MBUF 0x10
#define DBG_ARP 0x20
#define DBG_VERBOSE 0x40

extern int slirp_debug;

#define _DEBUG_PRINT(fmt, ...) debug_printf(fmt, ## __VA_ARGS__)

#ifdef _WIN32
#define _DEBUG_RESTORE_ERRNO(old_errno) WSASetLastError(old_errno)
#else
#define _DEBUG_RESTORE_ERRNO(old_errno) errno = old_errno
#endif

#define DEBUG_PRINT(fmt, ...) do {		\
    int old_errno = errno;			\
    _DEBUG_PRINT(fmt "\n", ## __VA_ARGS__);	\
    _DEBUG_RESTORE_ERRNO(old_errno);		\
  } while (0)

#define DEBUG_CALL(fmt, ...) if (slirp_debug & DBG_CALL) DEBUG_PRINT(fmt, ## __VA_ARGS__)
#define DEBUG_CALL_MORE(fmt, ...) if (slirp_debug & DBG_CALL) DEBUG_PRINT(fmt, ## __VA_ARGS__)
#define DEBUG_MISC(fmt, ...) if (slirp_debug & DBG_MISC) DEBUG_PRINT(fmt, ## __VA_ARGS__)
#define DEBUG_ERROR(fmt, ...) if (slirp_debug & DBG_ERROR) DEBUG_PRINT(fmt, ## __VA_ARGS__)
#define DEBUG_XTRA(fmt, ...) if (slirp_debug & DBG_XTRA) DEBUG_PRINT(fmt, ## __VA_ARGS__)
#define DEBUG_MBUF(fmt, ...) if (slirp_debug & DBG_MBUF) DEBUG_PRINT(fmt, ## __VA_ARGS__)
#define DEBUG_ARP(fmt, ...) if (slirp_debug & DBG_ARP) DEBUG_PRINT(fmt, ## __VA_ARGS__)
#define DEBUG_VERBOSE(fmt, ...) if (slirp_debug & DBG_VERBOSE) DEBUG_PRINT(fmt, ## __VA_ARGS__)

#define DEBUG_BREAK() asm("int $3\n")

#else

#define DEBUG_PRINT(fmt, ...) do { /**/ } while (0)

#define DEBUG_CALL(fmt, ...)
#define DEBUG_CALL_MORE(fmt, ...)
#define DEBUG_MISC(fmt, ...)
#define DEBUG_ERROR(fmt, ...)
#define DEBUG_XTRA(fmt, ...)
#define DEBUG_MBUF(fmt, ...)
#define DEBUG_ARP(fmt, ...)
#define DEBUG_VERBOSE(fmt, ...)

#define DEBUG_BREAK() do { /**/ } while (0)

#endif

#define DPRINTF(fmt, ...) DEBUG_PRINT(fmt, ## __VA_ARGS__)
