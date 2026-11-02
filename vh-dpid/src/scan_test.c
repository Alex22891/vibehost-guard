/*
 * The scan watch on made-up traffic, run by the build: a scanner is caught, a busy VPN or proxy is not.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "scan.h"

#define SYN 0x02
#define RST 0x04
#define ACK 0x10

static int failures;

#define CHECK(cond, what) do { if (!(cond)) { fprintf(stderr, "FAIL: %s\n", what); failures++; } } while (0)

static vh_tuple tcp4(const uint8_t src[4], const uint8_t dst[4], uint16_t sport, uint16_t dport) {
    vh_tuple t;
    memset(&t, 0, sizeof t);
    t.family = AF_INET;
    t.proto = IPPROTO_TCP;
    memcpy(t.src, src, 4);
    memcpy(t.dst, dst, 4);
    t.sport = sport;
    t.dport = dport;
    return t;
}

static vh_tuple back(const vh_tuple *t) {
    return tcp4(t->dst, t->src, t->dport, t->sport);
}

static size_t scanners(vh_scan *s, vh_scanner *out) {
    return vh_scan_list(s, out, 16, NULL);
}

int main(void) {
    vh_scanner out[16];
    uint64_t now = 1000000;

    /* The server itself tries port 22 on 150 addresses that never answer. */
    vh_scan *s = vh_scan_new();
    const uint8_t server[4] = {203, 0, 113, 5};
    for (int i = 0; i < 150; i++) {
        uint8_t dst[4] = {198, 51, (uint8_t) (100 + i / 250), (uint8_t) (i % 250 + 1)};
        vh_tuple t = tcp4(server, dst, (uint16_t) (40000 + i), 22);
        vh_scan_packet(s, &t, SYN, VH_HOOK_OUTPUT, now + (uint64_t) i);
    }
    vh_scan_tick(s, now + 2000);
    CHECK(scanners(s, out) == 0, "nothing is judged before the answers are due");
    vh_scan_tick(s, now + 4000);
    size_t n = scanners(s, out);
    CHECK(n == 1, "a server trying 150 silent addresses is a scanner");
    CHECK(n == 1 && out[0].local == 1, "the server itself is a local scanner");
    CHECK(n == 1 && out[0].nports >= 1 && out[0].ports[0] == 22, "its scanned port is 22");
    CHECK(vh_scan_stats_of(s)->events == 1, "one event");
    uint64_t v1, v2;
    vh_scan_list(s, out, 16, &v1);
    vh_scan_tick(s, now + 4000 + VH_SCAN_HOLD_MS + 1);
    vh_scan_list(s, out, 16, &v2);
    CHECK(scanners(s, out) == 0 && v2 != v1, "it is let go after the hold, and the list says so");
    vh_scan_free(s);

    /* A VPN user opening 150 sites that all answer: busy, not scanning. */
    s = vh_scan_new();
    const uint8_t user[4] = {10, 8, 0, 2};
    for (int i = 0; i < 150; i++) {
        uint8_t dst[4] = {93, 184, (uint8_t) (i / 250), (uint8_t) (i % 250 + 1)};
        vh_tuple t = tcp4(user, dst, (uint16_t) (40000 + i), 443);
        vh_scan_packet(s, &t, SYN, VH_HOOK_FORWARD, now);
        vh_tuple a = back(&t);
        vh_scan_packet(s, &a, SYN | ACK, VH_HOOK_FORWARD, now + 30);
    }
    vh_scan_tick(s, now + 5000);
    CHECK(scanners(s, out) == 0, "answered tries never make a scanner");
    CHECK(vh_scan_stats_of(s)->failed == 0, "and are not failures");
    vh_scan_free(s);

    /* A proxy: all its users leave from the server's own address. 3000 tries in a minute, one in ten refused
     * or unanswered - 300 failed addresses, over the line on its own, but a small share of the whole. */
    s = vh_scan_new();
    for (int i = 0; i < 3000; i++) {
        uint8_t dst[4] = {(uint8_t) (20 + i / 250 % 200), 51, (uint8_t) (i / 50), (uint8_t) (i % 250 + 1)};
        vh_tuple t = tcp4(server, dst, (uint16_t) (20000 + i), i % 7 ? 443 : 5222);
        uint64_t at = now + (uint64_t) i * 15;
        vh_scan_packet(s, &t, SYN, VH_HOOK_OUTPUT, at);
        if (i % 10 == 0) continue;  /* silence */
        vh_tuple a = back(&t);
        vh_scan_packet(s, &a, i % 10 == 5 ? RST | ACK : SYN | ACK, VH_HOOK_INPUT, at + 40);
        if (i % 100 == 0) vh_scan_tick(s, at);
    }
    vh_scan_tick(s, now + 3000 * 15 + 5000);
    CHECK(vh_scan_stats_of(s)->failed == 600, "the proxy failed 600 tries");
    CHECK(scanners(s, out) == 0, "a proxy whose tries are mostly answered is not a scanner");
    vh_scan_free(s);

    /* The same proxy with a scanner among its users: now most tries fail. */
    s = vh_scan_new();
    for (int i = 0; i < 1000; i++) {
        uint8_t dst[4] = {93, 184, (uint8_t) (i / 250), (uint8_t) (i % 250 + 1)};
        vh_tuple t = tcp4(server, dst, (uint16_t) (20000 + i), 443);
        vh_scan_packet(s, &t, SYN, VH_HOOK_OUTPUT, now);
        vh_tuple a = back(&t);
        vh_scan_packet(s, &a, SYN | ACK, VH_HOOK_INPUT, now + 40);
    }
    for (int i = 0; i < 2000; i++) {
        uint8_t dst[4] = {198, 18, (uint8_t) (i / 250), (uint8_t) (i % 250 + 1)};
        vh_tuple t = tcp4(server, dst, (uint16_t) (30000 + i), 3389);
        vh_scan_packet(s, &t, SYN, VH_HOOK_OUTPUT, now + 100);
    }
    vh_scan_tick(s, now + 5000);
    n = scanners(s, out);
    CHECK(n == 1 && out[0].local == 1 && out[0].ports[0] == 3389, "a scan through a proxy is still caught");
    vh_scan_free(s);

    /* A VPN user trying 300 ports of one host, every one refused. */
    s = vh_scan_new();
    const uint8_t user2[4] = {10, 8, 0, 3};
    const uint8_t host[4] = {192, 0, 2, 10};
    for (int i = 0; i < 300; i++) {
        vh_tuple t = tcp4(user2, host, (uint16_t) (50000 + i), (uint16_t) (1000 + i));
        vh_scan_packet(s, &t, SYN, VH_HOOK_FORWARD, now);
        vh_tuple a = back(&t);
        vh_scan_packet(s, &a, RST | ACK, VH_HOOK_FORWARD, now + 5);
    }
    n = scanners(s, out);
    CHECK(n == 1 && out[0].local == 0, "a VPN user refused on 300 ports is a scanner, not the server");
    CHECK(n == 1 && memcmp(out[0].addr, user2, 4) == 0, "and it is that user");
    vh_scan_free(s);

    /* Somebody scanning us, or a public address routed through us: not our scanner. */
    s = vh_scan_new();
    for (int i = 0; i < 300; i++) {
        uint8_t src[4] = {45, 1, (uint8_t) (i / 250), (uint8_t) (i % 250 + 1)};
        vh_tuple in = tcp4(src, server, (uint16_t) (40000 + i), 22);
        vh_scan_packet(s, &in, SYN, VH_HOOK_INPUT, now);
        uint8_t dst[4] = {198, 51, 100, (uint8_t) (i % 250 + 1)};
        vh_tuple routed = tcp4(src, dst, (uint16_t) (40000 + i), 22);
        vh_scan_packet(s, &routed, SYN, VH_HOOK_FORWARD, now);
    }
    vh_scan_tick(s, now + 5000);
    CHECK(scanners(s, out) == 0, "inbound and public forwarded tries are not ours");
    vh_scan_free(s);

    if (failures) return 1;
    printf("scan-test: ok\n");
    return 0;
}
