/* layer1_physical.c
 *
 * LAYER 1 — PHYSICAL LAYER
 * ========================
 * In a real system this is the hardware NIC driver: it puts electrical
 * signals / radio waves / light pulses on the wire and receives them.
 *
 * Here we simulate it with a simple memory buffer.
 * TX  = copy bytes into nic.tx_buf (pretend we "sent" them)
 * RX  = read bytes from nic.rx_buf (pretend we "received" them)
 *
 * The physical layer knows NOTHING about MACs, IPs, or ports.
 * It just moves raw bytes.
 */

#include "tcpip.h"

/* phy_send — "put bits on the wire" */
void phy_send(stack_t *s, const uint8_t *data, size_t len) {
    if (len > MAX_PACKET_SIZE) {
        fprintf(stderr, "[PHY] TX dropped — packet too large (%zu)\n", len);
        return;
    }
    memcpy(s->nic.tx_buf, data, len);
    s->nic.tx_len = len;

    printf("[PHY] TX %zu bytes → wire\n", len);
    /* In a real driver we'd write to a hardware register here. */
}

/* phy_recv — "read bits off the wire" */
size_t phy_recv(stack_t *s, uint8_t *buf, size_t max) {
    size_t n = s->nic.rx_len;
    if (n == 0) return 0;
    if (n > max) n = max;

    memcpy(buf, s->nic.rx_buf, n);
    s->nic.rx_len = 0;              /* consume the buffer */

    printf("[PHY] RX %zu bytes ← wire\n", n);
    return n;
}
