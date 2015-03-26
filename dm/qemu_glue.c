
#include "qemu_glue.h"
#include <string.h>

void pstrcpy(char *buf, int buf_size, const char *str)
{
    int c;
    char *q = buf;

    if (buf_size <= 0)
        return;

    for(;;) {
        c = *str++;
        if (c == 0 || q >= buf + buf_size - 1)
            break;
        *q++ = c;
    }
    *q = '\0';
}

/* strcat and truncate. */
char *pstrcat(char *buf, int buf_size, const char *s)
{
    int len;
    len = strlen(buf);
    if (len < buf_size)
        pstrcpy(buf + len, buf_size - len, s);
    return buf;
}

#if defined(__APPLE__)
#include <sys/socket.h>
int qemu_socket(int domain, int type, int protocol)
{
    int s = socket(domain, type, protocol);
    if (s >= 0) {
        int set = 1;
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
    }

    return s;
}
#endif
