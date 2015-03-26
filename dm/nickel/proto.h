/*
 * Copyright 2014-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _NICKEL_PROTO_H_
#define _NICKEL_PROTO_H_

#define LITTLE_ENDIAN_BITFIELD 1

#define NI_NTOHS(a)    ntohs(a)
#define NI_NTOHL(a)    ntohl(a)
#define NI_HTONS(a)    htons(a)
#define NI_HTONL(a)    htonl(a)

#if 0
#define NILOG(fmt, ...) do { debug_printf("(ni): %s:%d " fmt "\n", __FUNCTION__, \
        __LINE__, ## __VA_ARGS__); } while(1 == 0)
#else
#define NILOG(fmt, ...) do { ; } while(1 == 0)
#endif

#define USO(fmt, ...) do { if (NLOG_LEVEL < 5) break; \
        NETLOG("ni: %s:%d s:%lx " fmt "\n", \
        __FUNCTION__, __LINE__, so, ## __VA_ARGS__); } while(1 == 0)

#define ETH_ALEN 6
#define ETH_HLEN 14
#define ARPOP_REQUEST 1         /* ARP request */
#define ARPOP_REPLY   2         /* ARP reply   */
#define ETH_P_ARP 0x0806
#define ETH_P_IP  0x0800
#define IP_V4    4

#define MIN_MTU 1500

#define BOOTP_SERVER      67

struct ethhdr {
    unsigned char  h_dest[ETH_ALEN];   /* destination eth addr */
    unsigned char  h_source[ETH_ALEN]; /* source ether addr    */
    unsigned short h_proto;            /* packet type ID field */
};

struct arphdr {
    unsigned short ar_hrd;      /* format of hardware address */
    unsigned short ar_pro;      /* format of protocol address */
    unsigned char  ar_hln;      /* length of hardware address */
    unsigned char  ar_pln;      /* length of protocol address */
    unsigned short ar_op;       /* ARP opcode (command)       */

    /*
     *  Ethernet looks like this : This bit is variable sized however...
     */
    unsigned char ar_sha[ETH_ALEN]; /* sender hardware address */
    uint32_t      ar_sip;           /* sender IP address       */
    unsigned char ar_tha[ETH_ALEN]; /* target hardware address */
    uint32_t      ar_tip;           /* target IP address       */
} __attribute__((packed));

struct ip {
#ifdef LITTLE_ENDIAN_BITFIELD
    uint8_t             ip_hl:4,        /* header length */
                        ip_v:4;         /* version */
#else
    uint8_t             ip_v:4,         /* version */
                        ip_hl:4;        /* header length */
#endif
    uint8_t             ip_tos;         /* type of service */
    uint16_t            ip_len;         /* total length */
    uint16_t            ip_id;          /* identification */
    uint16_t            ip_off;         /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* don't fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
    uint8_t             ip_ttl;         /* time to live */
    uint8_t             ip_p;           /* protocol */
    uint16_t            ip_sum;         /* checksum */
    uint32_t            ip_src, ip_dst; /* source and dest address */
} __attribute__((packed));

struct tcp {
  uint16_t th_sport;            /* source port */
  uint16_t th_dport;            /* destination port */
  uint32_t th_seq;              /* sequence number */
  uint32_t th_ack;              /* acknowledgement number */
#ifdef LITTLE_ENDIAN_BITFIELD
  uint8_t th_x2:4,              /* (unused) */
    th_off:4;                   /* data offset */
#else
  uint8_t th_off:4,             /* data offset */
    th_x2:4;                    /* (unused) */
#endif
  uint8_t th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
  uint16_t th_win;              /* window */
  uint16_t th_sum;              /* checksum */
  uint16_t th_urp;              /* urgent pointer */
} __attribute__((packed));

struct udp {
    uint16_t uh_sport;          /* source port */
    uint16_t uh_dport;          /* destination port */
    int16_t  uh_ulen;           /* udp length */
    uint16_t uh_sum;            /* udp checksum */
} __attribute__((packed));

struct icmp {
    uint8_t type;
    uint8_t code;
    uint16_t cksum;
};

#define	ICMP_ECHOREPLY  0   /* echo reply */
#define	ICMP_ECHO       8   /* echo service */

#endif
