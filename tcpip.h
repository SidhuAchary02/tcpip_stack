#ifndef TCPIP_H
#define TCPIP_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ============================================================
 *  TCP/IP STACK — LEARNING IMPLEMENTATION
 *  Layers (bottom to top):
 *    1. Physical      — raw bits / bytes on the wire
 *    2. Data Link     — Ethernet frames (MAC addressing)
 *    3. Network       — IPv4 packets (IP addressing, routing)
 *    4. Transport     — TCP segments / UDP datagrams
 *    5. Application   — HTTP echo demo
 * ============================================================ */

/* ---------- sizes & limits --------------------------------- */
#define MAX_PACKET_SIZE   1500   /* Ethernet MTU                */
#define MAX_PAYLOAD_SIZE  1460   /* MTU - IP header - TCP header */
#define ARP_TABLE_SIZE      16
#define CONN_TABLE_SIZE     16

/* ---------- Ethernet (Layer 2) ------------------------------ */
#define ETH_ALEN      6          /* MAC address length in bytes  */
#define ETH_TYPE_IP   0x0800     // ipv4
#define ETH_TYPE_ARP  0x0806     // arp

typedef struct {
    uint8_t  dst_mac[ETH_ALEN];
    uint8_t  src_mac[ETH_ALEN];
    uint16_t ethertype;          /* big-endian                   */
    uint8_t  payload[];          /* flexible array               */
} __attribute__((packed)) eth_frame_t;

/* ---------- ARP (Layer 2.5) --------------------------------- */
#define ARP_REQUEST 1
#define ARP_REPLY   2

typedef struct {
    uint16_t hw_type;            /* 1 = Ethernet                 */
    uint16_t proto_type;         /* 0x0800 = IPv4                */
    uint8_t  hw_len;             /* 6 bytes                      */
    uint8_t  proto_len;          /* 4 bytes                      */
    uint16_t operation;          /* REQUEST or REPLY             */
    uint8_t  sender_mac[ETH_ALEN];
    uint32_t sender_ip;
    uint8_t  target_mac[ETH_ALEN];
    uint32_t target_ip;
} __attribute__((packed)) arp_packet_t;

typedef struct {
    uint32_t ip;
    uint8_t  mac[ETH_ALEN];
    uint8_t  valid;
} arp_entry_t;

/* ---------- IPv4 (Layer 3) ---------------------------------- */
#define IP_PROTO_ICMP  1  /* this are official protocol numbers */
#define IP_PROTO_TCP   6
#define IP_PROTO_UDP  17

typedef struct {
    uint8_t  ver_ihl;            /* version(4 bits) + IHL~header length(4 bits) */
    uint8_t  dscp_ecn;
    uint16_t total_len;
    uint16_t identification;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t  payload[];
} __attribute__((packed)) ip_header_t;

/* ---------- ICMP (Layer 3.5 — for ping) --------------------- */
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY   0

typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
    uint8_t  data[];
} __attribute__((packed)) icmp_header_t;

/* ---------- UDP (Layer 4) ----------------------------------- */
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
    uint8_t  payload[];
} __attribute__((packed)) udp_header_t; 

/* ---------- TCP (Layer 4) ----------------------------------- */
#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset;        /* upper 4 bits = header length */
    uint8_t  flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
    uint8_t  payload[];
} __attribute__((packed)) tcp_header_t;

/* ---------- TCP connection state machine -------------------- */
typedef enum {
    TCP_CLOSED,
    TCP_LISTEN,
    TCP_SYN_RECEIVED,
    TCP_SYN_SENT,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_LAST_ACK,
    TCP_TIME_WAIT
} tcp_state_t;

typedef struct {
    tcp_state_t state;
    uint32_t    local_ip;
    uint32_t    remote_ip;
    uint16_t    local_port;
    uint16_t    remote_port;
    uint32_t    seq_num;         /* our next send sequence       */
    uint32_t    ack_num;         /* next expected from remote    */
    uint32_t    send_window;
    uint8_t     active;
} tcp_conn_t;

/* ---------- The NIC / network interface --------------------- */
typedef struct {
    uint8_t  mac[ETH_ALEN];
    uint32_t ip;                 /* host-byte-order              */
    uint32_t netmask;
    uint32_t gateway;
    /* Simulated TX/RX buffers */
    uint8_t  tx_buf[MAX_PACKET_SIZE];
    uint8_t  rx_buf[MAX_PACKET_SIZE];
    size_t   tx_len;
    size_t   rx_len;
} nic_t;

/* ---------- Global stack context ---------------------------- */
typedef struct {
    nic_t       nic;
    arp_entry_t arp_table[ARP_TABLE_SIZE];
    tcp_conn_t  conn_table[CONN_TABLE_SIZE];
    uint16_t    ip_id_counter;
} stack_t;

/* ============================================================
 *  Function declarations (each layer in its own .c file)
 * ============================================================ */

/* utils */
uint16_t checksum(const void *data, size_t len);
uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                      const tcp_header_t *seg, size_t seg_len);
void     print_mac(const uint8_t *mac);
void     print_ip(uint32_t ip);
uint32_t make_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d);
uint16_t hton16(uint16_t v);
uint32_t hton32(uint32_t v);
#define  ntoh16 hton16
#define  ntoh32 hton32

/* Layer 1 — physical */
void     phy_send(stack_t *s, const uint8_t *data, size_t len);
size_t   phy_recv(stack_t *s, uint8_t *buf, size_t max);

/* Layer 2 — ethernet */
void     eth_send(stack_t *s, const uint8_t *dst_mac,
                  uint16_t ethertype,
                  const uint8_t *payload, size_t plen);
void     eth_recv(stack_t *s, const uint8_t *frame, size_t flen);

/* Layer 2.5 — ARP */
void     arp_send_request(stack_t *s, uint32_t target_ip);
void     arp_send_reply  (stack_t *s, uint32_t target_ip,
                          const uint8_t *target_mac);
void     arp_recv        (stack_t *s, const uint8_t *src_mac,
                          const uint8_t *pkt, size_t len);
uint8_t *arp_lookup      (stack_t *s, uint32_t ip);
void     arp_table_add   (stack_t *s, uint32_t ip, const uint8_t *mac);

/* Layer 3 — IP */
void     ip_send (stack_t *s, uint32_t dst_ip, uint8_t proto,
                  const uint8_t *payload, size_t plen);
void     ip_recv (stack_t *s, const uint8_t *src_mac,
                  const uint8_t *pkt, size_t len);

/* Layer 3.5 — ICMP */
void     icmp_recv(stack_t *s, uint32_t src_ip,
                   const uint8_t *pkt, size_t len);
void     icmp_send_reply(stack_t *s, uint32_t dst_ip,
                         uint16_t id, uint16_t seq,
                         const uint8_t *data, size_t dlen);

/* Layer 4 — UDP */
void     udp_send(stack_t *s, uint32_t dst_ip,
                  uint16_t src_port, uint16_t dst_port,
                  const uint8_t *data, size_t dlen);
void     udp_recv(stack_t *s, uint32_t src_ip,
                  const uint8_t *pkt, size_t len);

/* Layer 4 — TCP */
tcp_conn_t *tcp_find_conn   (stack_t *s, uint32_t rip,
                              uint16_t rport, uint16_t lport);
tcp_conn_t *tcp_new_conn    (stack_t *s);
void        tcp_send_segment(stack_t *s, tcp_conn_t *c,
                              uint8_t flags,
                              const uint8_t *data, size_t dlen);
void        tcp_recv        (stack_t *s, uint32_t src_ip,
                              const uint8_t *pkt, size_t len);
void        tcp_connect     (stack_t *s, uint32_t dst_ip,
                              uint16_t dst_port, uint16_t src_port);
void        tcp_listen      (stack_t *s, uint16_t port);
void        tcp_send_data   (stack_t *s, tcp_conn_t *c,
                              const uint8_t *data, size_t dlen);
void        tcp_close       (stack_t *s, tcp_conn_t *c);
const char *tcp_state_str   (tcp_state_t st);

/* Layer 5 — application */
void     app_http_echo(stack_t *s, tcp_conn_t *c,
                       const uint8_t *data, size_t dlen);

/* stack init */
void     stack_init(stack_t *s,
                    const uint8_t mac[ETH_ALEN],
                    uint32_t ip, uint32_t netmask, uint32_t gw);
void     stack_inject_packet(stack_t *s,
                              const uint8_t *pkt, size_t len);

#endif /* TCPIP_H */
