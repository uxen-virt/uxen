/*
 * ARP table
 *
 * Copyright (c) 2011 AdaCore
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "slirp.h"

#include <dm/file.h>

void
arp_table_add(Slirp *slirp, uint32_t ip_addr, uint8_t ethaddr[ETH_ALEN])
{
    const uint32_t broadcast_addr =
        ~slirp->vnetwork_mask.s_addr | slirp->vnetwork_addr.s_addr;
    ArpTable *arptbl = &slirp->arp_table;
    int i;

    DEBUG_ARP("arp_table_add(ip = 0x%x, "
	      "hw addr = %02x:%02x:%02x:%02x:%02x:%02x)",
	      ip_addr, ethaddr[0], ethaddr[1], ethaddr[2],
	      ethaddr[3], ethaddr[4], ethaddr[5]);

    /* Check 0.0.0.0/8 invalid source-only addresses */
    if ((ip_addr & htonl(~(0xf << 28))) == 0)
        return;

    if (ip_addr == 0xffffffff || ip_addr == broadcast_addr)
        /* Do not register broadcast addresses */
        return;

    /* Search for an entry */
    for (i = 0; i < ARP_TABLE_SIZE; i++)
        if (arptbl->table[i].ar_sip == ip_addr) {
            /* Update the entry */
            memcpy(arptbl->table[i].ar_sha, ethaddr, ETH_ALEN);
            return;
        }

    /* No entry found, create a new one */
    arptbl->table[arptbl->next_victim].ar_sip = ip_addr;
    memcpy(arptbl->table[arptbl->next_victim].ar_sha,  ethaddr, ETH_ALEN);
    arptbl->next_victim = (arptbl->next_victim + 1) % ARP_TABLE_SIZE;
}

bool
arp_table_search(Slirp *slirp, uint32_t ip_addr, uint8_t out_ethaddr[ETH_ALEN])
{
    const uint32_t broadcast_addr =
        ~slirp->vnetwork_mask.s_addr | slirp->vnetwork_addr.s_addr;
    ArpTable *arptbl = &slirp->arp_table;
    int i;

    DEBUG_ARP("arp_table_search(ip = 0x%x)", ip_addr);

    /* Check 0.0.0.0/8 invalid source-only addresses */
    assert((ip_addr & htonl(~(0xf << 28))) != 0);

    /* If broadcast address */
    if (ip_addr == 0xffffffff || ip_addr == broadcast_addr) {
        /* return Ethernet broadcast address */
        memset(out_ethaddr, 0xff, ETH_ALEN);
	return 1;
    }

    for (i = 0; i < ARP_TABLE_SIZE; i++)
	if (arptbl->table[i].ar_sip == ip_addr) {
            memcpy(out_ethaddr, arptbl->table[i].ar_sha,  ETH_ALEN);
            DEBUG_ARP("-> found hw addr = %02x:%02x:%02x:%02x:%02x:%02x",
		      out_ethaddr[0], out_ethaddr[1], out_ethaddr[2],
		      out_ethaddr[3], out_ethaddr[4], out_ethaddr[5]);
            return 1;
        }

    return 0;
}

void
arp_table_save(QEMUFile *f, Slirp *slirp)
{
    ArpTable *arptbl = &slirp->arp_table;
    struct arphdr *t;
    int i;

    qemu_put_byte(f, ARP_TABLE_SIZE);
    qemu_put_be32(f, arptbl->next_victim);

    for (i = 0; i < ARP_TABLE_SIZE; i++) {
	t = &arptbl->table[i];

	qemu_put_be16(f, t->ar_hrd);
	qemu_put_be16(f, t->ar_pro);
	qemu_put_byte(f, t->ar_hln);
	qemu_put_byte(f, t->ar_pln);
	qemu_put_be16(f, t->ar_op);
	qemu_put_buffer(f, t->ar_sha, sizeof(t->ar_sha));
	qemu_put_be32(f, t->ar_sip);
	qemu_put_buffer(f, t->ar_tha, sizeof(t->ar_tha));
	qemu_put_be32(f, t->ar_tip);
    }
}

void
arp_table_load(QEMUFile *f, Slirp *slirp)
{
    ArpTable *arptbl = &slirp->arp_table;
    struct arphdr *t;
    int i, n;

    n = qemu_get_byte(f);
    arptbl->next_victim = qemu_get_be32(f) % ARP_TABLE_SIZE;

    for (i = 0; i < n; i++) {
	t = &arptbl->table[i % ARP_TABLE_SIZE];

	t->ar_hrd = qemu_get_be16(f);
	t->ar_pro = qemu_get_be16(f);
	t->ar_hln = qemu_get_byte(f);
	t->ar_pln = qemu_get_byte(f);
	t->ar_op = qemu_get_be16(f);
	qemu_get_buffer(f, t->ar_sha, sizeof(t->ar_sha));
	t->ar_sip = qemu_get_be32(f);
	qemu_get_buffer(f, t->ar_tha, sizeof(t->ar_tha));
	t->ar_tip = qemu_get_be32(f);
    }
}
