/*
 * Copyright 2015-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#define _WIN32_WINNT 0x0600
#define WINVER 0x0600

#include <windows.h>

#include <stdio.h>

#include <ctype.h>
#include <errno.h>
#include <stdint.h>

#include <inttypes.h>

#include <winioctl.h>
#define V4V_USE_INLINE_API
#include <windows/uxenv4vlib/gh_v4vapi.h>

#define PORT 0x10001

#define RING_SIZE 262144
#define PACKET_SIZE 4

static char buf[PACKET_SIZE + sizeof (v4v_datagram_t)];

#undef MAP

#if 0
static int
have_v4v (void)
{
    v4v_channel_t c = { 0 };

    if (v4v_open (&c, 4096, V4V_FLAG_NONE)) {
        v4v_close (&c);
        return 1;
    }

    return 0;
}
#endif


struct foo {
    uint64_t reqs;
    uint64_t start;
};

static LARGE_INTEGER freq;

static inline void
start_foo (struct foo *foo)
{
    LARGE_INTEGER t;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t);
    foo->start = t.QuadPart;
}

static inline void
do_foo (struct foo *foo)
{
    LARGE_INTEGER t1;
    uint64_t dt;

    QueryPerformanceCounter(&t1);
    dt = (t1.QuadPart - foo->start) * 1000 / freq.QuadPart;
    if (dt < 2000)
        return;

    printf("%d round trips/s\n", (int)(foo->reqs * 1000 / dt));
    foo->start = t1.QuadPart;
    foo->reqs = 0;
}


static void
rr (v4v_channel_t *c, v4v_ring_t *ring, int domid, int rx)
{
#ifdef MAP
#error no map, you will not go to space today
#else
    struct foo foo = { 0 };
    v4v_datagram_t to = { };
    DWORD red = 0, writ = 0;

    memset (&to, 0, sizeof (to));

    to.addr.port = PORT;
    to.addr.domain = domid;

    memcpy (buf, &to, sizeof (to));

    if (rx) {
        printf("receiving\n");
        ReadFile (c->v4v_handle, buf, sizeof (buf), &red, NULL);
    } else {
        printf("sending\n");
        memcpy (buf, &to, sizeof (to));
    }

    for (;;) {
        ((v4v_datagram_t *) (char *) buf)->flags = V4V_DATAGRAM_FLAG_IGNORE_DLO;
        red = writ = 0;
        WriteFile (c->v4v_handle, buf, PACKET_SIZE + sizeof (to), &writ, NULL);
        ReadFile (c->v4v_handle, buf, sizeof (buf), &red, NULL);

        if ((writ == (PACKET_SIZE + sizeof (to))) && (red == writ))
            ++foo.reqs;
        else {
            printf("error\n");
            exit(1);
        }
        if (!foo.start)
            start_foo(&foo);
        do_foo (&foo);
    }
#endif
}

int
main (int argc, char *argv[])
{
    v4v_channel_t c = { 0 };
    v4v_ring_id_t r;
#ifdef MAP
    v4v_mapring_values_t mr;
#endif
    v4v_ring_t *ring;

    int rx;
    int domid;


    rx = (argc > 1) ? !strcmp (argv[1], "rx") : 1;
    domid = (argc == 3) ? atoi (argv[2]) : 0;

    r.addr.port = rx ? PORT : 0;
    r.addr.domain = V4V_DOMID_ANY;
    r.partner = V4V_DOMID_ANY;

    if (!v4v_open (&c, RING_SIZE, V4V_FLAG_NONE)) {
        printf ("v4v_open failed\n");
        return -1;
    }

    if (!v4v_bind (&c, &r)) {
        printf ("v4v_bind failed\n");
        return -1;
    }


#ifdef MAP
    mr.ring = NULL;
    if (!v4v_map (&c, &mr)) {
        printf ("v4v_map failed\n");
        return -1;
    }

    ring = mr.ring;


    printf ("Bound to %x.%x\n", ring->id.addr.domain, ring->id.addr.port);
#else
    ring = 0;
#endif


    rr (&c, ring, domid, rx);

    return 0;
}
