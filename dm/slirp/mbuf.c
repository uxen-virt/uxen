/*
 * Copyright (c) 1995 Danny Gasparovski
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

/*
 * mbuf's in SLiRP are much simpler than the real mbufs in
 * FreeBSD.  They are fixed size, determined by the MTU,
 * so that one whole packet can fit.  Mbuf's cannot be
 * chained together.  If there's more data than the mbuf
 * could hold, an external malloced buffer is pointed to
 * by m_ext (and the data pointers) and M_EXT is set in
 * the flags
 */

#include <slirp.h>

#define MBUF_THRESH 30

/*
 * Find a nice value for msize
 */
#define SLIRP_MSIZE (IF_MAX_MTU + IF_MAXLINKHDR + offsetof(struct mbuf, m_dat))

void
m_init(Slirp *slirp)
{
}

struct mbuf *
m_get(Slirp *slirp)
{
    struct mbuf *m;

    m = (struct mbuf *)calloc(1, SLIRP_MSIZE);
    if (m == NULL)
        goto end_error;

    m->slirp = slirp;
    m->m_flags = 0;

    /* Initialise it */
    m->m_size = SLIRP_MSIZE - offsetof(struct mbuf, m_dat);
    m->m_data = m->m_dat;
    m->m_len = 0;
    m->arp_requested = false;
    m->expiration_date = (uint64_t)-1;
  end_error:
    DEBUG_MBUF("m = %p", m);
    return m;
}

void
m_free(struct mbuf *m)
{
    DEBUG_MBUF("m_free(m = %p)", m);

    if (m == NULL)
        return;

    /* If it's M_EXT, free() it */
    if (m->m_flags & M_EXT)
        free(m->m_ext);

    free(m);
}

/*
 * Copy data from one mbuf to the end of
 * the other.. if result is too big for one mbuf, malloc()
 * an M_EXT data segment
 */
void
m_cat(struct mbuf *m, struct mbuf *n)
{
    /*
     * If there's no room, realloc
     */
    if (M_FREEROOM(m) < n->m_len) {
        int data_off;   /* offset from buffer starting address */
        int new_size;

        if (m->m_flags & M_EXT) {
            data_off = m->m_data - m->m_ext;
        } else {
            data_off = m->m_data - m->m_dat;
        }

        new_size = data_off + m->m_len + n->m_len;
        new_size = max(new_size, m->m_size + MINCSIZE);

        m_inc(m, new_size);
    }

    memcpy(m->m_data + m->m_len, n->m_data, n->m_len);
    m->m_len += n->m_len;
}


/* make m size bytes large */
void
m_inc(struct mbuf *m, int size)
{
    int data_off;   /* offset from buffer starting address */

    /* some compiles throw up on gotos.  This one we can fake. */
    if (m->m_size >= size)
        return;

    if (m->m_flags & M_EXT) {
        data_off = m->m_data - m->m_ext;
        m->m_ext = (char *)realloc(m->m_ext, size);
    } else {
        data_off = m->m_data - m->m_dat;
        m->m_ext = (char *)malloc(size);
        memcpy(m->m_ext, m->m_dat, m->m_size);

        m->m_flags |= M_EXT;
    }

    m->m_data = m->m_ext + data_off;
    m->m_size = size;
}

void
m_adj(struct mbuf *m, int len)
{
    if (m == NULL)
        return;

    if (len >= 0) {
        /* Trim from head */
        m->m_data += len;
    } else {
        /* Trim from tail */
        len = -len;
    }

    m->m_len -= len;
}


/*
 * Copy len bytes from m, starting off bytes into n
 */
int
m_copy(struct mbuf *n, struct mbuf *m, int off, int len)
{
    if (len > M_FREEROOM(n))
        return -1;

    if ((off + len) > m->m_len)
        return -1;

    memcpy((n->m_data + n->m_len), (m->m_data + off), len);
    n->m_len += len;
    return 0;
}
