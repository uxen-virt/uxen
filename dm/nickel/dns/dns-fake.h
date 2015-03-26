/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _DNS_FAKE_H_
#define _DNS_FAKE_H_

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

/*
This is a deliberately reserved address range for allocating fake IPs.
See the wikipedia article here:
    http://en.wikipedia.org/wiki/Reserved_IP_addresses
*/

#define FAKE_ADDRESS_RANGE "198.18.0.0"
#define FAKE_SUBNET_MASK "255.254.0.0"

struct net_addr;
struct nickel;

void fakedns_init(struct nickel *ni);
void fakedns_exit(struct nickel *ni);
struct in_addr * fakedns_create_ip(const char *cname, const struct net_addr *a);
struct in_addr * fakedns_get_ip(const char *cname);
const char * fakedns_get_name(struct in_addr ip_address);
struct net_addr * fakedns_get_ips(struct in_addr addr);
void fakedns_save_state(QEMUFile *f);
int fakedns_load_state(QEMUFile *f, int version_id);
bool fakedns_is_fake(const struct in_addr *addr_to_check);
bool fakedns_is_denied(const struct in_addr *addr_to_check);
void fakedns_update_ips(struct in_addr ip_address, const struct net_addr *a);
void fakedns_deny_ip(struct in_addr ip_address);
void fakedns_register_callbacks(void (*updated) (struct in_addr fkaddr, struct net_addr *a),
        void (*blocked) (struct in_addr fkaddr));

#endif /*_DNS_FAKE_H_*/
