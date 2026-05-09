/* layer4_udp.c
 *
 * LAYER 4 — TRANSPORT LAYER (UDP)
 * ================================
 * UDP = User Datagram Protocol (RFC 768)
 *
 * UDP is the "fire and forget" transport:
 *   • Adds source & destination PORT numbers (16-bit each)
 *   • No connection, no handshake, no retransmission
 *   • Great for DNS, video streaming, games
 *
 * UDP Header (8 bytes):
 *   [ src port 2B ][ dst port 2B ][ length 2B ][ checksum 2B ]
 *   [ payload ... ]
 *
 * Port numbers let one machine run many services simultaneously.
 * Port 53 = DNS, Port 67/68 = DHCP, Port 123 = NTP, etc.
 */

#include "tcpip.h"

/* ============================================================
 *  UDP SEND
 * ============================================================ */

void udp_send(stack_t *s, uint32_t dst_ip,
              uint16_t src_port, uint16_t dst_port,
              const uint8_t *data, size_t dlen) {

    uint8_t buf[MAX_PACKET_SIZE];
    udp_header_t *udp = (udp_header_t *)buf;

    uint16_t udp_len = (uint16_t)(sizeof(udp_header_t) + dlen);

    udp->src_port = hton16(src_port);
    udp->dst_port = hton16(dst_port);
    udp->length   = hton16(udp_len);
    udp->checksum = 0;  /* optional for IPv4 — we skip it */

    memcpy(buf + sizeof(udp_header_t), data, dlen);

    printf("[UDP] TX  %d → %d  len=%d\n", src_port, dst_port, udp_len);
    ip_send(s, dst_ip, IP_PROTO_UDP, buf, udp_len);
}

/* ============================================================
 *  UDP RECEIVE
 * ============================================================ */

void udp_recv(stack_t *s, uint32_t src_ip,
              const uint8_t *pkt, size_t len) {
    if (len < sizeof(udp_header_t)) return;

    const udp_header_t *udp = (const udp_header_t *)pkt;
    uint16_t src_port = ntoh16(udp->src_port);
    uint16_t dst_port = ntoh16(udp->dst_port);
    uint16_t udp_len  = ntoh16(udp->length);

    printf("[UDP] RX  src="); print_ip(src_ip);
    printf(":%d  dst=%d  len=%d\n", src_port, dst_port, udp_len);

    const uint8_t *payload = pkt + sizeof(udp_header_t);
    size_t         plen    = udp_len - sizeof(udp_header_t);

    /* --- Demultiplex by port --- */
    /* DNS response (port 53) */
    if (dst_port == 53) {
        printf("[UDP] DNS query received (%zu bytes)\n", plen);
        /* A real stack would parse the DNS packet here */
    }
    /* Echo server on port 7 */
    else if (dst_port == 7) {
        printf("[UDP] Echo: bouncing %zu bytes back\n", plen);
        udp_send(s, src_ip, dst_port, src_port, payload, plen);
    }
    else {
        printf("[UDP] No handler for port %d\n", dst_port);
    }
    (void)plen;
}
