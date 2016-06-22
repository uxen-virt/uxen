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

#define PORT 10000

#define RING_SIZE 262144
#define PACKET_SIZE 16384

static char buf[PACKET_SIZE + sizeof (v4v_datagram_t)];

#undef MAP

#if 0
static int
have_v4v (void)
{
    v4v_chanel_t c = { 0 };

    if (v4v_open (&c, 4096, V4V_FLAG_NONE)) {
        v4v_close (&c);
        return 1;
    }

    return 0;
}
#endif


struct foo {
    uint64_t bytes;
    uint64_t start;
    uint64_t last;
};


static inline void
start_foo (struct foo *foo)
{
    foo->last = foo->start = GetTickCount64 ();
}

static inline void
do_foo (struct foo *foo)
{
    uint64_t now = GetTickCount64 ();
    char unit = 'k';
    float f;

    if ((now - foo->last) < 5000)
        return;
    foo->last = now;

    now -= foo->start;

    if (!now)
        return;

    f = (float) foo->bytes;
    f *= 8000.;
    f = f / (float) now;


    if (f > 1E9) {
        f = f / 1.E9;
        unit = 'G';
    }


    if (f > 1E6) {
        f = f / 1.E9;
        unit = 'M';
    }

    if (f > 1E3) {
        f = f / 1.E3;
        unit = 'k';
    }

    printf ("%.3f %cbits/s\n", f, unit);

}


static void
write_thread (v4v_channel_t *c, int domid)
{
    struct foo foo = { 0 };
    v4v_datagram_t to = { };
    DWORD writ;

    memset(&to, 0, sizeof(to));

    printf ("send data\n");

    to.addr.port = PORT;
    to.addr.domain = domid;
    to.flags = V4V_DATAGRAM_FLAG_IGNORE_DLO;

    memcpy (buf, &to, sizeof (to));


    start_foo (&foo);

    for (;;) {
        writ = 0;
        WriteFile (c->v4v_handle, buf, PACKET_SIZE + sizeof (to), &writ, NULL);

        if (writ > 0) {
            foo.bytes += writ - sizeof (to);

            do_foo (&foo);
        }



    }

}


#ifdef MAP
static void
read_thread (v4v_channel_t *c, v4v_ring_t *ring)
{
    ssize_t len;
    v4v_datagram_t from;
    uint32_t protocol;
    struct foo foo = { 0 };
    int red = 0;


    printf ("listening for data\n");


    for (;;) {
        switch (WaitForSingleObject (c->recv_event, INFINITE)) {

            case WAIT_OBJECT_0: {

                    do {
                        len =
                            v4v_copy_out (ring, &from, &protocol, buf, PACKET_SIZE, 1);


                        if (!foo.start)
                            start_foo (&foo);
                        if (len < 0)
                            break;

                        if (len > PACKET_SIZE)
                            len = PACKET_SIZE;

                        foo.bytes += len;
                        do_foo (&foo);

                        red++;
                    } while (1);

                    h_v4v_notify (c, NULL);

                }

                break;

            default:
                printf ("Wait error (%d)\n", (int) GetLastError ());
                return;
        }
    }
}
#else
static void
read_thread (v4v_channel_t *c, v4v_ring_t *ring)
{
    struct foo foo = { 0 };
    DWORD red;
    v4v_datagram_t from;

    (void) ring;


    printf ("listening for data\n");


    for (;;) {
        red = 0;
        ReadFile (c->v4v_handle, buf, PACKET_SIZE + sizeof (from), &red, NULL);

        if (!foo.start)
            start_foo (&foo);

        if (red > 0) {
            foo.bytes += red - sizeof (from);

            do_foo (&foo);
        }


    }
}

#endif


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

    if (rx) {
        read_thread (&c, ring);
    } else {
        write_thread (&c, domid);
    }

    return 0;
}
