/* layer5_application.c
 *
 * LAYER 5 — APPLICATION LAYER
 * ============================
 * This is where YOUR program lives.
 * The layers below deliver a reliable byte stream to us (via TCP)
 * or datagrams (via UDP). We interpret the bytes as a protocol.
 *
 * Here we implement a tiny HTTP/1.0 echo server:
 *   • Parse the first line of the HTTP request
 *   • Reply with a valid HTTP/1.0 response
 *   • Close the connection after the response
 *
 * Real application protocols: HTTP, FTP, SMTP, DNS, SSH, TLS ...
 */

#include "tcpip.h"
#include <string.h>
#include <stdio.h>

/* ============================================================
 *  HTTP Echo Handler
 *  Called by TCP layer when new data arrives on an established
 *  connection.
 * ============================================================ */

void app_http_echo(stack_t *s, tcp_conn_t *c,
                   const uint8_t *data, size_t dlen) {

    printf("[APP] HTTP request (%zu bytes):\n", dlen);

    /* Print received request (safely) */
    for (size_t i = 0; i < dlen && i < 256; i++) {
        if (data[i] == '\r') continue;
        putchar(data[i]);
    }
    printf("\n--- end of request ---\n");

    /* Parse first line: "METHOD /path HTTP/1.x\r\n" */
    char method[16] = {0};
    char path[128]  = {0};
    char version[16]= {0};
    sscanf((const char *)data, "%15s %127s %15s", method, path, version);

    /* Build HTTP response */
    char body[512];
    int  body_len = snprintf(body, sizeof(body),
        "<html><body>"
        "<h2>TCP/IP Stack Echo</h2>"
        "<p>Method: <b>%s</b></p>"
        "<p>Path: <b>%s</b></p>"
        "<p>From: %u.%u.%u.%u:%d</p>"
        "</body></html>\r\n",
        method, path,
        (c->remote_ip >> 24) & 0xFF, (c->remote_ip >> 16) & 0xFF,
        (c->remote_ip >>  8) & 0xFF,  c->remote_ip        & 0xFF,
        c->remote_port);

    char response[700];
    int  rlen = snprintf(response, sizeof(response),
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        body_len, body);

    printf("[APP] HTTP response (%d bytes)\n", rlen);

    /* Hand response down to TCP */
    tcp_send_data(s, c, (uint8_t *)response, (size_t)rlen);

    /* Close the connection after responding (HTTP/1.0 style) */
    tcp_close(s, c);
}