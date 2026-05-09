/* utils.c — helper functions used across all layers */
#include "tcpip.h"

/* ------------------------------------------------------------ *
 *  BYTE ORDER helpers (simulate htons/htonl without system headers)
 *  On little-endian machines (x86/ARM) we must swap bytes when
 *  putting 16-bit or 32-bit values into network (big-endian) packets.
 * ------------------------------------------------------------ */
uint16_t hton16(uint16_t v) {
    return (uint16_t)((v >> 8) | (v << 8));
}

uint32_t hton32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) |
           ((v & 0x0000FF00u) <<  8) |
           ((v & 0x00FF0000u) >>  8) |
           ((v & 0xFF000000u) >> 24);
}

/* Build a 32-bit IP from four octets (stored host-byte-order) */
uint32_t make_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) |
           ((uint32_t)c <<  8) |  (uint32_t)d;
}

/* ------------------------------------------------------------ *
 *  INTERNET CHECKSUM  (RFC 1071)
 *  Sum all 16-bit words; add carry; take one's complement.
 *  Used by IP, ICMP, UDP, TCP headers.
 * ------------------------------------------------------------ */
uint16_t checksum(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += (uint32_t)(p[0] << 8 | p[1]);
        p   += 2;
        len -= 2;
    }
    if (len == 1)           /* odd byte — pad with zero      */
        sum += (uint32_t)(*p << 8);

    /* Fold 32-bit into 16-bit */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum);
}

/* ------------------------------------------------------------ *
 *  TCP CHECKSUM uses a "pseudo-header" (RFC 793) that includes
 *  src IP, dst IP, protocol, and TCP segment length — ensures
 *  packets aren't mis-delivered even if IP header is corrupt.
 * ------------------------------------------------------------ */
uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                      const tcp_header_t *seg, size_t seg_len) {
    /* Build pseudo-header on the stack */
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t  zero;
        uint8_t  proto;
        uint16_t tcp_len;
    } __attribute__((packed)) pseudo;

    pseudo.src     = hton32(src_ip);
    pseudo.dst     = hton32(dst_ip);
    pseudo.zero    = 0;
    pseudo.proto   = IP_PROTO_TCP;
    pseudo.tcp_len = hton16((uint16_t)seg_len);

    /* Sum pseudo-header + TCP segment together */
    uint32_t sum = 0;
    const uint8_t *p;
    size_t         n;

    p = (const uint8_t *)&pseudo;
    n = sizeof(pseudo);
    while (n > 1) { sum += (uint32_t)(p[0] << 8 | p[1]); p += 2; n -= 2; }

    p = (const uint8_t *)seg;
    n = seg_len;
    while (n > 1) { sum += (uint32_t)(p[0] << 8 | p[1]); p += 2; n -= 2; }
    if (n == 1)   sum += (uint32_t)(*p << 8);

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

/* ------------------------------------------------------------ *
 *  Pretty-print helpers
 * ------------------------------------------------------------ */
void print_mac(const uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(uint32_t ip) {   /* ip is host-byte-order */
    printf("%u.%u.%u.%u",
           (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
           (ip >>  8) & 0xFF,  ip        & 0xFF);
}
