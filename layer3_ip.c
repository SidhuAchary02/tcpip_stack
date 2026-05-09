/* layer3_ip.c
 *
 * LAYER 3 — NETWORK LAYER (IPv4 + ICMP)
 * ======================================
 * IPv4 gives every host a logical 32-bit address.
 * It breaks data into "packets" and routes them across networks.
 *
 * IP Header (minimum 20 bytes):
 *   ver | IHL | DSCP | Total Len | ID | Flags | TTL | Proto | Cksum
 *   Src IP (4B) | Dst IP (4B) | Payload ...
 *
 * TTL (Time-To-Live): each router decrements it by 1.
 * When TTL hits 0 the packet is dropped — prevents infinite loops.
 *
 * ICMP is a control protocol that rides inside IP.
 * We implement Echo Request/Reply ("ping").
 */

#include "tcpip.h"

/* ============================================================
 *  IPv4 SEND
 * ============================================================ */

void ip_send(stack_t *s, uint32_t dst_ip, uint8_t proto,
             const uint8_t *payload, size_t plen) {

    uint8_t   buf[MAX_PACKET_SIZE];
    ip_header_t *iph = (ip_header_t *)buf;

    iph->ver_ihl       = (4 << 4) | 5;  /* IPv4, 20-byte header */
    iph->dscp_ecn      = 0;
    iph->total_len     = hton16((uint16_t)(20 + plen));
    iph->identification= hton16(s->ip_id_counter++);
    iph->flags_frag    = 0;
    iph->ttl           = 64;
    iph->protocol      = proto;
    iph->checksum      = 0;             /* zero before computing */
    iph->src_ip        = hton32(s->nic.ip);
    iph->dst_ip        = hton32(dst_ip);

    iph->checksum      = checksum(iph, 20);

    memcpy(buf + 20, payload, plen);

    printf("[IP]  TX  src="); print_ip(s->nic.ip);
    printf("  dst="); print_ip(dst_ip);
    printf("  proto=%d  len=%zu\n", proto, 20 + plen);

    /* Find the next-hop MAC via ARP */
    uint32_t nexthop = dst_ip;
    /* If destination is outside our subnet, use gateway */
    if ((dst_ip & s->nic.netmask) != (s->nic.ip & s->nic.netmask))
        nexthop = s->nic.gateway;

    uint8_t *dst_mac = arp_lookup(s, nexthop);
    if (!dst_mac) {
        printf("[IP]  No ARP entry for "); print_ip(nexthop);
        printf(" — sending ARP request\n");
        arp_send_request(s, nexthop);
        /* In a real stack we'd queue the packet and retry after ARP reply.
         * Here we just drop it for simplicity. */
        return;
    }

    eth_send(s, dst_mac, ETH_TYPE_IP, buf, 20 + plen);
}

/* ============================================================
 *  IPv4 RECEIVE
 * ============================================================ */

void ip_recv(stack_t *s, const uint8_t *src_mac,
             const uint8_t *pkt, size_t len) {
    if (len < 20) return;

    const ip_header_t *iph = (const ip_header_t *)pkt;
    uint8_t  ihl        = (iph->ver_ihl & 0x0F) * 4;
    uint32_t dst_ip     = ntoh32(iph->dst_ip);
    uint32_t src_ip     = ntoh32(iph->src_ip);
    uint16_t total      = ntoh16(iph->total_len);

    /* Validate checksum */
    uint16_t saved_cksum = iph->checksum;
    /* (skip full validation for clarity — just log it) */
    (void)saved_cksum;

    printf("[IP]  RX  src="); print_ip(src_ip);
    printf("  dst="); print_ip(dst_ip);
    printf("  proto=%d  TTL=%d\n", iph->protocol, iph->ttl);

    /* Accept only packets addressed to us */
    if (dst_ip != s->nic.ip && dst_ip != 0xFFFFFFFF) {
        printf("[IP]  Not our address — dropped\n");
        return;
    }

    const uint8_t *payload = pkt + ihl;
    size_t         plen    = total - ihl;

    switch (iph->protocol) {
    case IP_PROTO_ICMP: icmp_recv(s, src_ip, payload, plen); break;
    case IP_PROTO_TCP:  tcp_recv (s, src_ip, payload, plen); break;
    case IP_PROTO_UDP:  udp_recv (s, src_ip, payload, plen); break;
    default:
        printf("[IP]  Unknown protocol %d — dropped\n", iph->protocol);
    }
    (void)src_mac;
}

/* ============================================================
 *  ICMP — PING (Echo Request / Reply)
 * ============================================================ */

void icmp_recv(stack_t *s, uint32_t src_ip,
               const uint8_t *pkt, size_t len) {
    if (len < sizeof(icmp_header_t)) return;

    const icmp_header_t *icmp = (const icmp_header_t *)pkt;
    printf("[ICMP] RX type=%d id=%d seq=%d\n",
           icmp->type, ntoh16(icmp->id), ntoh16(icmp->seq));

    if (icmp->type == ICMP_ECHO_REQUEST) {
        printf("[ICMP] → Sending Echo Reply\n");
        icmp_send_reply(s, src_ip,
                        ntoh16(icmp->id), ntoh16(icmp->seq),
                        pkt + sizeof(icmp_header_t),
                        len - sizeof(icmp_header_t));
    }
}

void icmp_send_reply(stack_t *s, uint32_t dst_ip,
                     uint16_t id, uint16_t seq,
                     const uint8_t *data, size_t dlen) {
    uint8_t buf[MAX_PACKET_SIZE];
    icmp_header_t *icmp = (icmp_header_t *)buf;

    icmp->type     = ICMP_ECHO_REPLY;
    icmp->code     = 0;
    icmp->checksum = 0;
    icmp->id       = hton16(id);
    icmp->seq      = hton16(seq);
    memcpy(buf + sizeof(icmp_header_t), data, dlen);

    size_t total = sizeof(icmp_header_t) + dlen;
    icmp->checksum = checksum(buf, total);

    printf("[ICMP] TX reply → "); print_ip(dst_ip);
    printf("  id=%d seq=%d\n", id, seq);
    ip_send(s, dst_ip, IP_PROTO_ICMP, buf, total);
}
