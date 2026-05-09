/* main.c — Demonstrates every layer of the TCP/IP stack
 *
 * We simulate a NIC at IP 10.0.0.2 / MAC aa:bb:cc:dd:ee:ff
 * and inject crafted packets to show each protocol in action.
 *
 * Run:  ./tcpip
 */

#include "tcpip.h"
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------ *
 *  Helper: build a raw Ethernet frame in a buffer
 *  Returns total length written.
 * ------------------------------------------------------------ */
static size_t build_eth(uint8_t *buf,
                         const uint8_t *dst_mac,
                         const uint8_t *src_mac,
                         uint16_t ethertype,
                         const uint8_t *payload, size_t plen) {
    memcpy(buf,             dst_mac, 6);
    memcpy(buf + 6,         src_mac, 6);
    buf[12] = (uint8_t)(ethertype >> 8);
    buf[13] = (uint8_t)(ethertype & 0xFF);
    memcpy(buf + 14, payload, plen);
    return 14 + plen;
}

static void separator(const char *label) {
    printf("\n═══════════════════════════════════════\n");
    printf("  DEMO: %s\n", label);
    printf("═══════════════════════════════════════\n");
}

int main(void) {
    /* ---- Set up our simulated NIC ---- */
    stack_t stack;
    uint8_t our_mac[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    uint32_t our_ip   = make_ip(10,  0, 0, 2);
    uint32_t netmask  = make_ip(255,255,255, 0);
    uint32_t gateway  = make_ip(10,  0, 0, 1);

    stack_init(&stack, our_mac, our_ip, netmask, gateway);

    /* MAC of the "remote host" we'll simulate packets from */
    uint8_t  remote_mac[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint32_t remote_ip    = make_ip(10, 0, 0, 1);

    /* Pre-populate ARP table so we can send replies */
    arp_table_add(&stack, remote_ip, remote_mac);

    /* ===================================================
     * DEMO 1 — ARP Request
     * Our stack doesn't know who 10.0.0.1 is.
     * It will broadcast an ARP request.
     * =================================================== */
    separator("ARP Request (we ask: who has 10.0.0.1?)");
    /* Evict the entry we just added so ARP fires */
    stack.arp_table[0].valid = 0;
    ip_send(&stack, remote_ip, IP_PROTO_ICMP,
            (uint8_t *)"\x08\x00\x00\x00\x00\x01\x00\x01", 8);
    /* Re-add so the rest of the demos work */
    arp_table_add(&stack, remote_ip, remote_mac);

    /* ===================================================
     * DEMO 2 — ARP Reply received
     * Simulate remote host replying to our ARP broadcast.
     * =================================================== */
    separator("ARP Reply (remote tells us their MAC)");
    {
        uint8_t arp_pkt[28];
        memset(arp_pkt, 0, sizeof(arp_pkt));
        /* hw_type=1, proto=0x0800, hw_len=6, proto_len=4 */
        arp_pkt[0]=0; arp_pkt[1]=1;
        arp_pkt[2]=8; arp_pkt[3]=0;
        arp_pkt[4]=6; arp_pkt[5]=4;
        /* operation = REPLY (2) */
        arp_pkt[6]=0; arp_pkt[7]=2;
        /* sender MAC = remote_mac */
        memcpy(arp_pkt + 8,  remote_mac, 6);
        /* sender IP = 10.0.0.1 */
        arp_pkt[14]=10; arp_pkt[15]=0; arp_pkt[16]=0; arp_pkt[17]=1;
        /* target MAC = our_mac */
        memcpy(arp_pkt + 18, our_mac, 6);
        /* target IP = 10.0.0.2 */
        arp_pkt[24]=10; arp_pkt[25]=0; arp_pkt[26]=0; arp_pkt[27]=2;

        uint8_t frame[64];
        size_t flen = build_eth(frame, our_mac, remote_mac,
                                ETH_TYPE_ARP, arp_pkt, 28);
        stack_inject_packet(&stack, frame, flen);
    }

    /* ===================================================
     * DEMO 3 — ICMP Ping (Echo Request → Echo Reply)
     * =================================================== */
    separator("ICMP Echo Request (Ping)");
    {
        /* ICMP echo request: type=8, code=0, id=1, seq=1, data="HELLO" */
        uint8_t icmp[13] = {
            8, 0,           /* type, code */
            0, 0,           /* checksum (will set below) */
            0, 1,           /* id = 1 */
            0, 1,           /* seq = 1 */
            'H','E','L','L','O'
        };
        icmp[2] = 0; icmp[3] = 0;
        uint16_t ck = checksum(icmp, sizeof(icmp));
        icmp[2] = (uint8_t)(ck >> 8);
        icmp[3] = (uint8_t)(ck & 0xFF);

        /* Wrap in IP */
        uint8_t ip_pkt[33];
        ip_pkt[0] = (4<<4)|5;           /* ver+IHL */
        ip_pkt[1] = 0;
        uint16_t tot = hton16(33);
        memcpy(ip_pkt+2, &tot, 2);
        ip_pkt[4]=0; ip_pkt[5]=0;       /* ID */
        ip_pkt[6]=0; ip_pkt[7]=0;       /* flags+frag */
        ip_pkt[8]=64;                   /* TTL */
        ip_pkt[9]=IP_PROTO_ICMP;
        ip_pkt[10]=0; ip_pkt[11]=0;     /* checksum placeholder */
        /* src = 10.0.0.1 */
        ip_pkt[12]=10; ip_pkt[13]=0; ip_pkt[14]=0; ip_pkt[15]=1;
        /* dst = 10.0.0.2 */
        ip_pkt[16]=10; ip_pkt[17]=0; ip_pkt[18]=0; ip_pkt[19]=2;
        memcpy(ip_pkt+20, icmp, 13);
        uint16_t ip_ck = checksum(ip_pkt, 20);
        ip_pkt[10]=(uint8_t)(ip_ck>>8); ip_pkt[11]=(uint8_t)(ip_ck&0xFF);

        uint8_t frame[128];
        size_t flen = build_eth(frame, our_mac, remote_mac,
                                ETH_TYPE_IP, ip_pkt, 33);
        stack_inject_packet(&stack, frame, flen);
    }

    /* ===================================================
     * DEMO 4 — UDP Echo
     * =================================================== */
    separator("UDP Packet (to echo port 7)");
    {
        uint8_t msg[] = "Hello UDP";
        uint16_t udp_len = (uint16_t)(8 + sizeof(msg));

        uint8_t udp_pkt[8 + sizeof(msg)];
        /* src port = 9999, dst port = 7 */
        udp_pkt[0]=0x27; udp_pkt[1]=0x0F;  /* 9999 */
        udp_pkt[2]=0x00; udp_pkt[3]=0x07;  /* 7 */
        uint16_t ulen = hton16(udp_len);
        memcpy(udp_pkt+4, &ulen, 2);
        udp_pkt[6]=0; udp_pkt[7]=0;        /* checksum optional */
        memcpy(udp_pkt+8, msg, sizeof(msg));

        uint8_t ip_pkt[20 + sizeof(udp_pkt)];
        ip_pkt[0]=(4<<4)|5; ip_pkt[1]=0;
        uint16_t tot = hton16((uint16_t)(20+sizeof(udp_pkt)));
        memcpy(ip_pkt+2,&tot,2);
        ip_pkt[4]=0; ip_pkt[5]=1;
        ip_pkt[6]=0; ip_pkt[7]=0;
        ip_pkt[8]=64; ip_pkt[9]=IP_PROTO_UDP;
        ip_pkt[10]=0; ip_pkt[11]=0;
        ip_pkt[12]=10;ip_pkt[13]=0;ip_pkt[14]=0;ip_pkt[15]=1;
        ip_pkt[16]=10;ip_pkt[17]=0;ip_pkt[18]=0;ip_pkt[19]=2;
        memcpy(ip_pkt+20, udp_pkt, sizeof(udp_pkt));
        uint16_t ip_ck = checksum(ip_pkt, 20);
        ip_pkt[10]=(uint8_t)(ip_ck>>8); ip_pkt[11]=(uint8_t)(ip_ck&0xFF);

        uint8_t frame[256];
        size_t flen = build_eth(frame, our_mac, remote_mac,
                                ETH_TYPE_IP, ip_pkt,
                                20+sizeof(udp_pkt));
        stack_inject_packet(&stack, frame, flen);
    }

    /* ===================================================
     * DEMO 5 — TCP Three-Way Handshake + HTTP + Close
     * =================================================== */
    separator("TCP Handshake + HTTP request");

    /* Put our stack in LISTEN on port 80 */
    tcp_listen(&stack, 80);

    /* Helper lambda to build and inject a TCP segment */
    #define INJECT_TCP(flags_, seq_, ack_, data_, dlen_) do {       \
        uint8_t tcp_seg[40 + (dlen_)];                              \
        memset(tcp_seg, 0, sizeof(tcp_seg));                        \
        tcp_seg[0]=0x27; tcp_seg[1]=0x0F; /* src port 9999 */      \
        tcp_seg[2]=0x00; tcp_seg[3]=0x50; /* dst port 80 */        \
        uint32_t _s = hton32(seq_); memcpy(tcp_seg+4,  &_s, 4);   \
        uint32_t _a = hton32(ack_); memcpy(tcp_seg+8,  &_a, 4);   \
        tcp_seg[12] = (5<<4);  /* data offset = 20 bytes */        \
        tcp_seg[13] = (flags_);                                     \
        tcp_seg[14]=0x20; tcp_seg[15]=0x00; /* window 8192 */      \
        if ((dlen_) > 0) memcpy(tcp_seg+20, (data_), (dlen_));    \
        size_t seg_total = 20 + (dlen_);                            \
        uint8_t ip_buf[60 + (dlen_)];                               \
        ip_buf[0]=(4<<4)|5; ip_buf[1]=0;                           \
        uint16_t _t=hton16((uint16_t)(20+seg_total));               \
        memcpy(ip_buf+2,&_t,2);                                     \
        ip_buf[4]=0;ip_buf[5]=2;ip_buf[6]=0;ip_buf[7]=0;           \
        ip_buf[8]=64;ip_buf[9]=IP_PROTO_TCP;                        \
        ip_buf[10]=0;ip_buf[11]=0;                                  \
        ip_buf[12]=10;ip_buf[13]=0;ip_buf[14]=0;ip_buf[15]=1;      \
        ip_buf[16]=10;ip_buf[17]=0;ip_buf[18]=0;ip_buf[19]=2;      \
        memcpy(ip_buf+20, tcp_seg, seg_total);                      \
        uint16_t _ck=checksum(ip_buf,20);                           \
        ip_buf[10]=(uint8_t)(_ck>>8);ip_buf[11]=(uint8_t)(_ck&0xFF);\
        uint8_t _fr[256]; size_t _fl=build_eth(_fr,our_mac,         \
            remote_mac,ETH_TYPE_IP,ip_buf,20+seg_total);            \
        stack_inject_packet(&stack, _fr, _fl);                      \
    } while(0)

    /* Step 1: SYN from client (seq=100) */
    printf("\n--- Client sends SYN ---\n");
    INJECT_TCP(TCP_FLAG_SYN, 100, 0, NULL, 0);

    /* Step 3: ACK from client (completes handshake; acks our SYN-ACK) */
    printf("\n--- Client sends ACK (handshake complete) ---\n");
    INJECT_TCP(TCP_FLAG_ACK, 101, 0x2001, NULL, 0);

    /* Data: HTTP GET */
    printf("\n--- Client sends HTTP GET ---\n");
    const char *http_req = "GET /hello HTTP/1.0\r\nHost: 10.0.0.2\r\n\r\n";
    INJECT_TCP(TCP_FLAG_ACK | TCP_FLAG_PSH, 101, 0x2001,
               (const uint8_t *)http_req, strlen(http_req));

    printf("\n═══════════════════════════════════════\n");
    printf("  All demos complete!\n");
    printf("═══════════════════════════════════════\n\n");

    return 0;
}
