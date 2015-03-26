/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/os.h>
#include <dm/qemu_glue.h>
#include <buff.h>
#include <ctype.h>
#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include "dns.h"
#include "dns-fake.h"

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

#define IPADDR_EQUAL(addr1, addr2) ((addr1).s_addr == (addr2).s_addr)
#define NL_ADD(a,b) htonl(ntohl(a) + ntohl(b))
#define NL_CMP(a,b) (ntohl(a) < ntohl(b))

struct dns_hostip {
    struct dns_hostip *next;
    struct in_addr ip_address;
    struct net_addr *a;
    char *hostname;
    int denied;
};

static int num_entries = 0;
static uint32_t subnet = 0;
static uint32_t subnet_mask = 0;
static struct in_addr current_address = {.s_addr = 0};
static struct in_addr current_address_step = {.s_addr = 0};
static struct dns_hostip *first_record = NULL;

static uint32_t *denied_ips = NULL;
static size_t number_denied_ips = 0, cap_denied_ips = 0;

static void (*updated_cb) (struct in_addr fkaddr, struct net_addr *a) = NULL;
static void (*blocked_cb) (struct in_addr fkaddr) = NULL;

static void fakedns_record_free(struct dns_hostip *record);
static struct dns_hostip * fakedns_lastrecord();

static void init_fake_address();
static struct in_addr generate_fake_address();
static uint32_t add_fake_address(uint32_t ip);
static struct dns_hostip * fakedns_get_rec(const char *cname);

#define GRAN_CAP_DENIED_IPS     64
static int add_denied_ip(uint32_t ip_addr)
{
    if (number_denied_ips + 1 >= cap_denied_ips) {
        uint32_t *tmp;

        tmp = realloc(denied_ips, (cap_denied_ips + GRAN_CAP_DENIED_IPS) * sizeof(uint32_t));
        if (!tmp) {
            warnx("%s: memory error", __FUNCTION__);
            return -1;
        }
        denied_ips = tmp;
        cap_denied_ips += GRAN_CAP_DENIED_IPS;
    }

    denied_ips[number_denied_ips++] = ip_addr;
    return 0;
}

/* Checks if the address is in the specified subnet. */
bool fakedns_is_fake(const struct in_addr *addr_to_check)
{
    if (!addr_to_check)
        return false;

    if ((addr_to_check->s_addr & subnet_mask) != subnet)
        return false;

    return NL_CMP(addr_to_check->s_addr, current_address.s_addr);
}

bool fakedns_is_denied(const struct in_addr *addr_to_check)
{
    size_t i;

    for (i = 0; i < number_denied_ips; i++)
        if (denied_ips[i] == addr_to_check->s_addr)
            return true;

    return false;
}

/* Initialise the fake address structures. */
static void init_fake_address()
{
    struct in_addr subnet_mask_addr = {.s_addr = 0};

    num_entries = 0;
    inet_aton(FAKE_ADDRESS_RANGE, &current_address);
    inet_aton("0.0.0.1", &current_address_step);

    subnet = current_address.s_addr;
    inet_aton(FAKE_SUBNET_MASK, &subnet_mask_addr);
    subnet_mask = subnet_mask_addr.s_addr;
}

/* Generate a unique fake address */
static struct in_addr generate_fake_address()
{
    struct in_addr result = {.s_addr = 0};

    if ((current_address.s_addr & subnet_mask) == subnet) {
        result = current_address;
        current_address.s_addr = NL_ADD(current_address.s_addr, current_address_step.s_addr);
        num_entries += 1;
    }
    return result;
}

/* Add a fake address to the list - used for streaming in state */
static uint32_t add_fake_address(uint32_t ip)
{
    if (NL_CMP(current_address.s_addr, NL_ADD(ip, current_address_step.s_addr)))
        current_address.s_addr = NL_ADD(ip, current_address_step.s_addr);
    num_entries += 1;
    return ip;
}

static int update_ips(struct dns_hostip *rec, const struct net_addr *a)
{
    int ret = -1;

    free(rec->a);
    rec->a = NULL;
    if (a && a[0].family) {
        size_t len = 0;

        while (a[len].family)
            len++;
        rec->a = calloc(1, (len + 1) * sizeof(*a));
        if (!rec->a)
            goto mem_err;
        memcpy(rec->a, a, len * sizeof(*a));
    }
    ret = 0;
out:
    return ret;
mem_err:
    warnx("%s: memory error", __FUNCTION__);
    ret = -1;
    goto out;
}

static void fakedns_record_free(struct dns_hostip *record)
{
    free(record->a);
    record->a = NULL;
    free(record->hostname);
}

void fakedns_init(struct nickel *ni)
{
    static bool hostip_init_ok = false;

    if (hostip_init_ok)
        return;

    first_record = NULL;
    init_fake_address();

    hostip_init_ok = true;
}

void fakedns_exit(struct nickel *ni)
{
    struct dns_hostip *current_record = NULL;
    struct dns_hostip *store_record = NULL;

    current_record = first_record;
    while (current_record) {
        fakedns_record_free(current_record);
        store_record = current_record;
        current_record = current_record->next;
        free(store_record);
    }
}

static int fakedns_num_records()
{
    struct dns_hostip *current_record = NULL;
    int num_records = 0;

    current_record = first_record;
    while (current_record) {
        num_records++;
        current_record = current_record->next;
    }

    return num_records;
}

static void fakedns_save_record(QEMUFile *f, struct dns_hostip *record)
{
    uint32_t sz = 0, i;

    qemu_put_be32(f, record->ip_address.s_addr);
    while (record->a && record->a[sz].family)
        sz++;

    /* reset hyb timestamps */
    for (i = 0; i < sz; i++)
        record->a[i].ts_hyb = 0;

    qemu_put_be32(f, sz);
    if (sz)
        qemu_put_buffer(f, (uint8_t *) record->a, sz * sizeof(*(record->a)));

    sz = strlen(record->hostname);
    qemu_put_be32(f, sz);
    qemu_put_buffer(f, (unsigned char*)record->hostname, sz);
    qemu_put_be32(f, (uint32_t) record->denied);
}

void fakedns_save_state(QEMUFile *f)
{
    int num_records = 0;
    struct dns_hostip *current_record = NULL;

    num_records = fakedns_num_records();
    qemu_put_be32(f, num_records);

    current_record = first_record;
    while (current_record) {
        fakedns_save_record(f, current_record);
        current_record = current_record->next;
    }

    debug_printf("vm saved %u fake dns records\n", num_records);
}

static struct dns_hostip* fakedns_load_record(QEMUFile *f, int version_id)
{
    struct dns_hostip *new_dns_hostip = NULL;
    uint32_t ip = 0;
    uint32_t len;
    char *hostname = NULL;
    uint32_t hostname_len = 0;
    int denied = 0;
    struct net_addr *a = NULL;

    // load network IP address
    ip = qemu_get_be32(f);
    len = qemu_get_be32(f);
    if (len > 0) {
        a = calloc(1, (len + 1) * sizeof(*a));
        if (!a)
            goto mem_error;
        qemu_get_buffer(f, (uint8_t *)a, len * sizeof(*a));
    }
    hostname_len = qemu_get_be32(f);
    hostname = calloc(1, hostname_len + 2);
    if (!hostname)
        goto mem_error;

    qemu_get_buffer(f, (unsigned char *)hostname, hostname_len);
    if (version_id >= 12)
        denied = (int) qemu_get_be32(f);
    new_dns_hostip = calloc(1, sizeof(struct dns_hostip));
    if (!new_dns_hostip)
        goto mem_error;

    new_dns_hostip->hostname = hostname;
    new_dns_hostip->denied = denied;
    if (denied)
        add_denied_ip(ip);
    new_dns_hostip->next = NULL;
    new_dns_hostip->a = a;
    new_dns_hostip->ip_address.s_addr = add_fake_address(ip);

out:
    return new_dns_hostip;

mem_error:
   warnx("%s: failed to allocate memory!", __FUNCTION__);
   free(hostname);
   new_dns_hostip = NULL;
   goto out;
}

int fakedns_load_state(QEMUFile *f, int version_id)
{
    int record = 0;
    uint32_t num_records;
    struct dns_hostip *current_record = NULL;

    num_records = qemu_get_be32(f);

    current_record = first_record;
    for (record = 0; record < num_records; record++) {
        struct dns_hostip *new_dns_hostip = fakedns_load_record(f, version_id);

        if (!new_dns_hostip) {
           debug_printf("%s: Failed to restore proxy fake IP list", __FUNCTION__);
           return -1;
        }

        if (current_record) {
            current_record->next = new_dns_hostip;
            current_record = current_record->next;
        } else {
            first_record = new_dns_hostip;
            current_record = first_record;
        }

    }

    debug_printf("vm restored %u fake dns records\n", num_records);
    if (number_denied_ips)
        debug_printf("... of which %"PRIuSIZE" are DENIED\n",
                     number_denied_ips);
    return 0;
}

/* Get the last record in the fake DNS list */
static struct dns_hostip* fakedns_lastrecord()
{
    struct dns_hostip *current_record = NULL;

    current_record = first_record;
    while (current_record != NULL) {
        if (current_record->next == NULL)
            return current_record;
        current_record = current_record->next;
    }

    return NULL;
}

/* Create a new fake Ip for the specified hostname */
struct in_addr *
fakedns_create_ip(const char *cname, const struct net_addr *a)
{
    struct dns_hostip *new_dns_hostip = NULL;
    struct dns_hostip *last_record = NULL;
    struct dns_hostip *search_rec = NULL;
    struct in_addr fake_ip_addr = {.s_addr = 0};
    size_t hostname_len = 0;

    if (!cname) {
        debug_printf("%s: hostname is NULL\n", __FUNCTION__);
        return NULL;
    }

    search_rec = fakedns_get_rec(cname);
    if (search_rec) {
        if (update_ips(search_rec, a) < 0)
            return NULL;
        return &search_rec->ip_address;
    }

    fake_ip_addr = generate_fake_address();
    if (fake_ip_addr.s_addr == 0) {
        debug_printf("%s: have used up addresses in fake ip pool\n", __FUNCTION__);
        return NULL;
    }

    new_dns_hostip = calloc(1, sizeof(struct dns_hostip));
    if (new_dns_hostip == NULL)
        goto mem_err;

    hostname_len = strlen(cname);
    new_dns_hostip->hostname = calloc(1, hostname_len + 1);
    if (!new_dns_hostip->hostname)
        goto mem_err;
    strncpy(new_dns_hostip->hostname, cname, hostname_len);
    buff_strtolower(new_dns_hostip->hostname);
    new_dns_hostip->next = NULL;
    new_dns_hostip->ip_address = fake_ip_addr;
    if (update_ips(new_dns_hostip, a) < 0)
        return NULL;
    last_record = fakedns_lastrecord();
    if (last_record)
        last_record->next = new_dns_hostip;
    else
        first_record = new_dns_hostip;

    return &(new_dns_hostip->ip_address);

mem_err:
    free(new_dns_hostip);
    return NULL;
}

static struct dns_hostip * fakedns_get_rec(const char *cname)
{
    struct dns_hostip *current_record = NULL;

    current_record = first_record;
    while (current_record) {
        if (strcasecmp(current_record->hostname, cname) == 0)
            return current_record;
        current_record = current_record->next;
    }

    return NULL;
}

struct net_addr * fakedns_get_ips(struct in_addr addr)
{

    struct dns_hostip *current_record = NULL;

    current_record = first_record;
    while (current_record) {
        if (IPADDR_EQUAL(current_record->ip_address, addr))
            return current_record->a;
        current_record = current_record->next;
    }

    return NULL;
}

const char *
fakedns_get_name(struct in_addr ip_address)
{
    struct dns_hostip *current_record = NULL;
    const char *result = NULL;

    current_record = first_record;
    while (current_record) {
        if (IPADDR_EQUAL(current_record->ip_address, ip_address)) {
            result = current_record->hostname;
            break;
        }
        current_record = current_record->next;
    }

    return result;
}

void fakedns_update_ips(struct in_addr ip_address, const struct net_addr *a)
{
    struct dns_hostip *current_record = NULL;

    current_record = first_record;
    while (current_record) {
        if (IPADDR_EQUAL(current_record->ip_address, ip_address)) {
            update_ips(current_record, a);
            break;
        }
        current_record = current_record->next;
    }

    if (current_record && updated_cb)
        updated_cb(ip_address, current_record->a);
}

void fakedns_deny_ip(struct in_addr ip_address)
{
    struct dns_hostip *current_record = NULL;

    current_record = first_record;
    while (current_record) {
        if (IPADDR_EQUAL(current_record->ip_address, ip_address)) {
            if (!current_record->denied)
                add_denied_ip(ip_address.s_addr);
            current_record->denied = 1;
            break;
        }
        current_record = current_record->next;
    }

    if (current_record && blocked_cb)
        blocked_cb(ip_address);
}

void fakedns_register_callbacks(void (*updated) (struct in_addr fkaddr, struct net_addr *a),
        void (*blocked) (struct in_addr fkaddr))
{
    updated_cb = updated;
    blocked_cb = blocked;
}
