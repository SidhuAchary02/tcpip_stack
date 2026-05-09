/* layer4_tcp.c
 *
 * LAYER 4 — TRANSPORT LAYER (TCP)
 * ================================
 * TCP = Transmission Control Protocol (RFC 793)
 *
 * TCP gives you a RELIABLE, ORDERED, FULL-DUPLEX byte stream.
 * It achieves this through:
 *   1. Connection setup   — Three-way handshake (SYN, SYN-ACK, ACK)
 *   2. Sequence numbers   — Every byte has a number; receiver ACKs them
 *   3. Retransmission     — Unacknowledged data is resent (simplified here)
 *   4. Flow control       — Window size limits how much can be in-flight
 *   5. Connection teardown — Four-way FIN handshake
 *
 * TCP Header (20 bytes minimum):
 *   src port | dst port | seq num | ack num | offset | flags |
 *   window | checksum | urgent ptr | [options]
 *
 * State Machine:
 *   CLOSED → LISTEN → SYN_RECEIVED → ESTABLISHED → CLOSE_WAIT → LAST_ACK → CLOSED
 *   CLOSED → SYN_SENT → ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED
 */

#include "tcpip.h"

/* ============================================================
 *  HELPERS
 * ============================================================ */

const char *tcp_state_str(tcp_state_t st) {
    switch (st) {
    case TCP_CLOSED:       return "CLOSED";
    case TCP_LISTEN:       return "LISTEN";
    case TCP_SYN_RECEIVED: return "SYN_RECEIVED";
    case TCP_SYN_SENT:     return "SYN_SENT";
    case TCP_ESTABLISHED:  return "ESTABLISHED";
    case TCP_FIN_WAIT_1:   return "FIN_WAIT_1";
    case TCP_FIN_WAIT_2:   return "FIN_WAIT_2";
    case TCP_CLOSE_WAIT:   return "CLOSE_WAIT";
    case TCP_CLOSING:      return "CLOSING";
    case TCP_LAST_ACK:     return "LAST_ACK";
    case TCP_TIME_WAIT:    return "TIME_WAIT";
    }
    return "UNKNOWN";
}

/* Find an existing connection */
tcp_conn_t *tcp_find_conn(stack_t *s, uint32_t rip,
                          uint16_t rport, uint16_t lport) {
    for (int i = 0; i < CONN_TABLE_SIZE; i++) {
        tcp_conn_t *c = &s->conn_table[i];
        if (c->active &&
            c->remote_ip   == rip   &&
            c->remote_port == rport &&
            c->local_port  == lport)
            return c;
    }
    return NULL;
}

/* Find a LISTEN socket on a given local port */
static tcp_conn_t *tcp_find_listener(stack_t *s, uint16_t lport) {
    for (int i = 0; i < CONN_TABLE_SIZE; i++) {
        tcp_conn_t *c = &s->conn_table[i];
        if (c->active &&
            c->state == TCP_LISTEN &&
            c->local_port == lport)
            return c;
    }
    return NULL;
}

/* Allocate a new connection slot */
tcp_conn_t *tcp_new_conn(stack_t *s) {
    for (int i = 0; i < CONN_TABLE_SIZE; i++) {
        if (!s->conn_table[i].active) {
            memset(&s->conn_table[i], 0, sizeof(tcp_conn_t));
            s->conn_table[i].active = 1;
            return &s->conn_table[i];
        }
    }
    return NULL;  /* table full */
}

/* ============================================================
 *  TCP SEND SEGMENT
 * ============================================================ */

void tcp_send_segment(stack_t *s, tcp_conn_t *c,
                      uint8_t flags,
                      const uint8_t *data, size_t dlen) {

    uint8_t buf[MAX_PACKET_SIZE];
    tcp_header_t *tcp = (tcp_header_t *)buf;
    size_t hdr_len = 20;  /* no options */

    tcp->src_port    = hton16(c->local_port);
    tcp->dst_port    = hton16(c->remote_port);
    tcp->seq_num     = hton32(c->seq_num);
    tcp->ack_num     = (flags & TCP_FLAG_ACK) ? hton32(c->ack_num) : 0;
    tcp->data_offset = (uint8_t)((hdr_len / 4) << 4);
    tcp->flags       = flags;
    tcp->window_size = hton16(8192);  /* advertise 8 KB window */
    tcp->checksum    = 0;
    tcp->urgent_ptr  = 0;

    if (dlen > 0)
        memcpy(buf + hdr_len, data, dlen);

    size_t seg_len = hdr_len + dlen;

    /* Compute TCP checksum (includes pseudo-header) */
    tcp->checksum = tcp_checksum(c->local_ip, c->remote_ip,
                                 tcp, seg_len);

    printf("[TCP] TX  %d→%d  flags=0x%02X [", 
           c->local_port, c->remote_port, flags);
    if (flags & TCP_FLAG_SYN) printf("SYN ");
    if (flags & TCP_FLAG_ACK) printf("ACK ");
    if (flags & TCP_FLAG_FIN) printf("FIN ");
    if (flags & TCP_FLAG_RST) printf("RST ");
    if (flags & TCP_FLAG_PSH) printf("PSH ");
    printf("] seq=%u ack=%u data=%zu\n",
           c->seq_num, c->ack_num, dlen);

    /* Advance sequence number
     * SYN and FIN each consume 1 sequence number (they're logical bytes) */
    if (flags & TCP_FLAG_SYN) c->seq_num++;
    if (flags & TCP_FLAG_FIN) c->seq_num++;
    c->seq_num += (uint32_t)dlen;

    ip_send(s, c->remote_ip, IP_PROTO_TCP, buf, seg_len);
}

/* ============================================================
 *  TCP LISTEN  (open a server port)
 * ============================================================ */

void tcp_listen(stack_t *s, uint16_t port) {
    tcp_conn_t *c = tcp_new_conn(s);
    if (!c) { printf("[TCP] No free connection slots\n"); return; }

    c->state      = TCP_LISTEN;
    c->local_ip   = s->nic.ip;
    c->local_port = port;

    printf("[TCP] Listening on port %d\n", port);
}

/* ============================================================
 *  TCP CONNECT  (active open — client side)
 * ============================================================ */

void tcp_connect(stack_t *s, uint32_t dst_ip,
                 uint16_t dst_port, uint16_t src_port) {
    tcp_conn_t *c = tcp_new_conn(s);
    if (!c) return;

    c->local_ip    = s->nic.ip;
    c->local_port  = src_port;
    c->remote_ip   = dst_ip;
    c->remote_port = dst_port;
    c->seq_num     = 0x1000;  /* initial sequence number (ISN) */
    c->state       = TCP_SYN_SENT;

    printf("[TCP] Connecting to "); print_ip(dst_ip);
    printf(":%d from port %d\n", dst_port, src_port);

    /* Step 1 of handshake: send SYN */
    tcp_send_segment(s, c, TCP_FLAG_SYN, NULL, 0);
}

/* ============================================================
 *  TCP SEND DATA
 * ============================================================ */

void tcp_send_data(stack_t *s, tcp_conn_t *c,
                   const uint8_t *data, size_t dlen) {
    if (c->state != TCP_ESTABLISHED) {
        printf("[TCP] Cannot send — not ESTABLISHED\n");
        return;
    }
    printf("[TCP] Sending %zu bytes of data\n", dlen);
    tcp_send_segment(s, c, TCP_FLAG_ACK | TCP_FLAG_PSH, data, dlen);
}

/* ============================================================
 *  TCP CLOSE  (active close — initiator)
 * ============================================================ */

void tcp_close(stack_t *s, tcp_conn_t *c) {
    printf("[TCP] Closing connection (state=%s)\n",
           tcp_state_str(c->state));
    if (c->state == TCP_ESTABLISHED || c->state == TCP_CLOSE_WAIT) {
        tcp_send_segment(s, c, TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0);
        c->state = (c->state == TCP_ESTABLISHED) ?
                   TCP_FIN_WAIT_1 : TCP_LAST_ACK;
    }
}

/* ============================================================
 *  TCP RECEIVE — the state machine
 * ============================================================ */

void tcp_recv(stack_t *s, uint32_t src_ip,
              const uint8_t *pkt, size_t len) {
    if (len < 20) return;

    const tcp_header_t *tcp = (const tcp_header_t *)pkt;
    uint16_t src_port  = ntoh16(tcp->src_port);
    uint16_t dst_port  = ntoh16(tcp->dst_port);
    uint32_t seq       = ntoh32(tcp->seq_num);
    uint32_t ack       = ntoh32(tcp->ack_num);
    uint8_t  flags     = tcp->flags;
    uint8_t  hdr_bytes = (tcp->data_offset >> 4) * 4;

    const uint8_t *payload = pkt + hdr_bytes;
    size_t         plen    = (len > hdr_bytes) ? len - hdr_bytes : 0;

    printf("[TCP] RX  src="); print_ip(src_ip);
    printf(":%d  dst=%d  flags=[", src_port, dst_port);
    if (flags & TCP_FLAG_SYN) printf("SYN ");
    if (flags & TCP_FLAG_ACK) printf("ACK ");
    if (flags & TCP_FLAG_FIN) printf("FIN ");
    if (flags & TCP_FLAG_RST) printf("RST ");
    if (flags & TCP_FLAG_PSH) printf("PSH ");
    printf("] seq=%u ack=%u data=%zu\n", seq, ack, plen);

    /* Find existing connection first */
    tcp_conn_t *c = tcp_find_conn(s, src_ip, src_port, dst_port);

    /* ---- SYN received — someone wants to connect ---- */
    if (!c && (flags & TCP_FLAG_SYN) && !(flags & TCP_FLAG_ACK)) {
        tcp_conn_t *listener = tcp_find_listener(s, dst_port);
        if (!listener) {
            printf("[TCP] RST — port %d not listening\n", dst_port);
            /* send RST (omitted for brevity) */
            return;
        }
        /* Create a new connection for this incoming SYN */
        c = tcp_new_conn(s);
        if (!c) return;
        c->local_ip    = s->nic.ip;
        c->local_port  = dst_port;
        c->remote_ip   = src_ip;
        c->remote_port = src_port;
        c->seq_num     = 0x2000;            /* our ISN */
        c->ack_num     = seq + 1;           /* ACK the SYN */
        c->state       = TCP_SYN_RECEIVED;

        printf("[TCP] New conn  state: %s\n", tcp_state_str(c->state));

        /* Step 2: send SYN-ACK */
        tcp_send_segment(s, c, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0);
        return;
    }

    if (!c) {
        printf("[TCP] No connection found — dropped\n");
        return;
    }

    printf("[TCP] State: %s\n", tcp_state_str(c->state));

    /* ---- State machine transitions ---- */
    switch (c->state) {

    case TCP_SYN_SENT:
        /* We sent SYN, expecting SYN-ACK */
        if ((flags & TCP_FLAG_SYN) && (flags & TCP_FLAG_ACK)) {
            c->ack_num = seq + 1;
            c->state   = TCP_ESTABLISHED;
            printf("[TCP] ★ ESTABLISHED (client)\n");
            /* Step 3: send ACK to complete handshake */
            tcp_send_segment(s, c, TCP_FLAG_ACK, NULL, 0);
        }
        break;

    case TCP_SYN_RECEIVED:
        /* We sent SYN-ACK, expecting ACK */
        if (flags & TCP_FLAG_ACK) {
            c->state = TCP_ESTABLISHED;
            printf("[TCP] ★ ESTABLISHED (server)\n");
        }
        break;

    case TCP_ESTABLISHED:
        /* Update our ACK counter for received data */
        if (plen > 0) {
            c->ack_num = seq + (uint32_t)plen;
            /* Hand payload up to the application layer */
            app_http_echo(s, c, payload, plen);
        }
        /* Remote is closing */
        if (flags & TCP_FLAG_FIN) {
            c->ack_num = seq + 1;
            c->state   = TCP_CLOSE_WAIT;
            printf("[TCP] Got FIN → CLOSE_WAIT\n");
            tcp_send_segment(s, c, TCP_FLAG_ACK, NULL, 0);
            /* Application decides when to close; we close immediately */
            tcp_close(s, c);
        }
        break;

    case TCP_FIN_WAIT_1:
        if (flags & TCP_FLAG_ACK) {
            c->state = TCP_FIN_WAIT_2;
            printf("[TCP] → FIN_WAIT_2\n");
        }
        if (flags & TCP_FLAG_FIN) {
            c->ack_num = seq + 1;
            tcp_send_segment(s, c, TCP_FLAG_ACK, NULL, 0);
            c->state = TCP_TIME_WAIT;
            printf("[TCP] → TIME_WAIT (will close shortly)\n");
            /* Real stack waits 2*MSL (~60s); we close immediately */
            c->active = 0;
        }
        break;

    case TCP_FIN_WAIT_2:
        if (flags & TCP_FLAG_FIN) {
            c->ack_num = seq + 1;
            tcp_send_segment(s, c, TCP_FLAG_ACK, NULL, 0);
            c->state   = TCP_TIME_WAIT;
            printf("[TCP] → TIME_WAIT\n");
            c->active  = 0;
        }
        break;

    case TCP_LAST_ACK:
        if (flags & TCP_FLAG_ACK) {
            c->state  = TCP_CLOSED;
            c->active = 0;
            printf("[TCP] → CLOSED\n");
        }
        break;

    default:
        printf("[TCP] Unhandled state %s\n", tcp_state_str(c->state));
        break;
    }
}
