/* stack.c — initialize the stack and glue the layers together */

#include "tcpip.h"

void stack_init(stack_t *s,
                const uint8_t mac[ETH_ALEN],
                uint32_t ip, uint32_t netmask, uint32_t gw) {
    memset(s, 0, sizeof(*s));
    memcpy(s->nic.mac, mac, ETH_ALEN);
    s->nic.ip      = ip;
    s->nic.netmask = netmask;
    s->nic.gateway = gw;

    printf("[STACK] Initialized\n");
    printf("  MAC: "); print_mac(mac); printf("\n");
    printf("  IP:  "); print_ip(ip);   printf("\n");
    printf("  GW:  "); print_ip(gw);   printf("\n\n");
}

/* Inject a raw packet into the stack as if it arrived from the wire.
 * Used in tests / simulations. */
void stack_inject_packet(stack_t *s, const uint8_t *pkt, size_t len) {
    memcpy(s->nic.rx_buf, pkt, len);
    s->nic.rx_len = len;

    uint8_t tmp[MAX_PACKET_SIZE];
    size_t  n = phy_recv(s, tmp, sizeof(tmp));
    if (n > 0)
        eth_recv(s, tmp, n);
}
