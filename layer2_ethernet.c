/* layer2_ethernet.c
 *
 * LAYER 2 — DATA LINK LAYER (Ethernet + ARP)
 * ===========================================
 * Ethernet gives each device a 48-bit MAC address.
 * It wraps an IP packet (or ARP packet) in a "frame":
 *
 *   [ dst MAC 6B ][ src MAC 6B ][ EtherType 2B ][ payload ... ]
 *
 * ARP (Address Resolution Protocol) answers the question:
 *   "I know an IP address — what MAC address goes with it?"
 * We need the MAC to build the Ethernet frame.
 *
 * ARP Table: a small cache of IP→MAC mappings we've learned.
 */

#include "tcpip.h"

static const uint8_t BROADCAST_MAC[ETH_ALEN] =
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* ============================================================
 *  ETHERNET
 * ============================================================ */

/* eth_send — wrap payload in Ethernet frame and hand to PHY */
void eth_send(stack_t *s, const uint8_t *dst_mac,
              uint16_t ethertype,
              const uint8_t *payload, size_t plen) {

    uint8_t frame[MAX_PACKET_SIZE];
    eth_frame_t *eth = (eth_frame_t *)frame;

    memcpy(eth->dst_mac, dst_mac,      ETH_ALEN);
    memcpy(eth->src_mac, s->nic.mac,   ETH_ALEN);
    eth->ethertype = hton16(ethertype);
    memcpy(frame + sizeof(eth_frame_t), payload, plen);

    printf("[ETH] TX  dst="); print_mac(dst_mac);
    printf("  src="); print_mac(s->nic.mac);
    printf("  type=0x%04X  len=%zu\n", ethertype, plen);

    phy_send(s, frame, sizeof(eth_frame_t) + plen);
}

/* eth_recv — called by stack when a frame arrives from PHY */
void eth_recv(stack_t *s, const uint8_t *frame, size_t flen) {
    if (flen < sizeof(eth_frame_t)) return;

    const eth_frame_t *eth = (const eth_frame_t *)frame;
    uint16_t type = ntoh16(eth->ethertype);

    printf("[ETH] RX  dst="); print_mac(eth->dst_mac);
    printf("  src="); print_mac(eth->src_mac);
    printf("  type=0x%04X\n", type);

    /* Drop frames not addressed to us (unless broadcast) */
    if (memcmp(eth->dst_mac, s->nic.mac,    ETH_ALEN) != 0 &&
        memcmp(eth->dst_mac, BROADCAST_MAC, ETH_ALEN) != 0) {
        printf("[ETH] Not for us — dropped\n");
        return;
    }

    const uint8_t *payload = frame + sizeof(eth_frame_t);
    size_t         plen    = flen  - sizeof(eth_frame_t);

    switch (type) {
    case ETH_TYPE_ARP:
        arp_recv(s, eth->src_mac, payload, plen);
        break;
    case ETH_TYPE_IP:
        ip_recv(s, eth->src_mac, payload, plen);
        break;
    default:
        printf("[ETH] Unknown EtherType 0x%04X — dropped\n", type);
    }
}

/* ============================================================
 *  ARP TABLE
 * ============================================================ */

void arp_table_add(stack_t *s, uint32_t ip, const uint8_t *mac) {
    /* Replace existing entry or find empty slot */
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        if (!s->arp_table[i].valid || s->arp_table[i].ip == ip) {
            s->arp_table[i].ip    = ip;
            s->arp_table[i].valid = 1;
            memcpy(s->arp_table[i].mac, mac, ETH_ALEN);
            printf("[ARP] Table: ");
            print_ip(ip);
            printf(" → "); print_mac(mac);
            printf("\n");
            return;
        }
    }
    printf("[ARP] Table full!\n");
}

uint8_t *arp_lookup(stack_t *s, uint32_t ip) {
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        if (s->arp_table[i].valid && s->arp_table[i].ip == ip)
            return s->arp_table[i].mac;
    }
    return NULL;
}

/* ============================================================
 *  ARP SEND
 * ============================================================ */

void arp_send_request(stack_t *s, uint32_t target_ip) {
    arp_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.hw_type    = hton16(1);            /* Ethernet          */
    pkt.proto_type = hton16(ETH_TYPE_IP);
    pkt.hw_len     = ETH_ALEN;
    pkt.proto_len  = 4;
    pkt.operation  = hton16(ARP_REQUEST);

    memcpy(pkt.sender_mac, s->nic.mac, ETH_ALEN);
    pkt.sender_ip  = hton32(s->nic.ip);

    memset(pkt.target_mac, 0, ETH_ALEN);  /* unknown           */
    pkt.target_ip  = hton32(target_ip);

    printf("[ARP] → REQUEST  who has "); print_ip(target_ip); printf("?\n");
    eth_send(s, BROADCAST_MAC, ETH_TYPE_ARP,
             (uint8_t *)&pkt, sizeof(pkt));
}

void arp_send_reply(stack_t *s, uint32_t target_ip,
                    const uint8_t *target_mac) {
    arp_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.hw_type    = hton16(1);
    pkt.proto_type = hton16(ETH_TYPE_IP);
    pkt.hw_len     = ETH_ALEN;
    pkt.proto_len  = 4;
    pkt.operation  = hton16(ARP_REPLY);

    memcpy(pkt.sender_mac, s->nic.mac, ETH_ALEN);
    pkt.sender_ip  = hton32(s->nic.ip);
    memcpy(pkt.target_mac, target_mac, ETH_ALEN);
    pkt.target_ip  = hton32(target_ip);

    printf("[ARP] → REPLY  "); print_ip(s->nic.ip);
    printf(" is at "); print_mac(s->nic.mac); printf("\n");
    eth_send(s, target_mac, ETH_TYPE_ARP,
             (uint8_t *)&pkt, sizeof(pkt));
}

/* ============================================================
 *  ARP RECEIVE
 * ============================================================ */

void arp_recv(stack_t *s, const uint8_t *src_mac,
              const uint8_t *pkt, size_t len) {
    if (len < sizeof(arp_packet_t)) return;

    const arp_packet_t *arp = (const arp_packet_t *)pkt;
    uint32_t sender_ip = ntoh32(arp->sender_ip);
    uint32_t target_ip = ntoh32(arp->target_ip);
    uint16_t op        = ntoh16(arp->operation);

    printf("[ARP] ← %s  sender=", op == ARP_REQUEST ? "REQUEST" : "REPLY");
    print_ip(sender_ip); printf("  target="); print_ip(target_ip);
    printf("\n");

    /* Always learn sender's MAC */
    arp_table_add(s, sender_ip, arp->sender_mac);

    if (op == ARP_REQUEST && target_ip == s->nic.ip) {
        /* Someone wants our MAC — tell them */
        arp_send_reply(s, sender_ip, arp->sender_mac);
    }
    /* If it's a REPLY the table entry was already added above. */
    (void)src_mac;
}
