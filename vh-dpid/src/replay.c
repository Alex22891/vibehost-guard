/*
 * vh-dpid-replay: runs the decision engine over a capture, for the test corpus. Packets are cut to
 * what the kernel rule would copy, and only the first VH_TAP_PACKETS of a connection arrive, as live.
 * Prints one line per verdict and a summary. Exit code 0.
 *
 *   vh-dpid-replay <file> [I|O|F]     default hook: F, a forwarded VPN user
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <pcap/sll.h>
#include <stdio.h>
#include <string.h>

#include "engine.h"

static void on_verdict(const vh_tuple *t, vh_reason reason, void *user) {
    (void) user;
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    inet_ntop(t->family, t->src, src, sizeof src);
    inet_ntop(t->family, t->dst, dst, sizeof dst);
    printf("verdict %s %s %s:%u %s:%u\n", vh_reason_name(reason), t->proto == IPPROTO_TCP ? "tcp" : "udp",
           src, t->sport, dst, t->dport);
}

/* Offset of the IP header, or -1. */
static int l3_offset(int link, const uint8_t *p, size_t n) {
    switch (link) {
        case DLT_RAW: return 0;
        case DLT_NULL: case DLT_LOOP: return 4;
        case DLT_LINUX_SLL: return 16;
        case DLT_LINUX_SLL2: return 20;
        case DLT_EN10MB: {
            size_t off = 12;
            /* VLAN tags. */
            while (n >= off + 2 && ((p[off] == 0x81 && p[off + 1] == 0x00) || (p[off] == 0x88 && p[off + 1] == 0xa8))) off += 4;
            if (n < off + 2) return -1;
            if (!((p[off] == 0x08 && p[off + 1] == 0x00) || (p[off] == 0x86 && p[off + 1] == 0xdd))) return -1;
            return (int) off + 2;
        }
        default: return -1;
    }
}

int main(int argc, char **argv) {
    char err[PCAP_ERRBUF_SIZE];
    if (argc < 2) {
        fprintf(stderr, "usage: vh-dpid-replay <file> [I|O|F]\n");
        return 2;
    }
    char hook = argc > 2 ? argv[2][0] : VH_HOOK_FORWARD;
    pcap_t *pc = pcap_open_offline(argv[1], err);
    if (!pc) {
        fprintf(stderr, "%s\n", err);
        return 2;
    }
    vh_engine *e = vh_engine_new(on_verdict, NULL);
    if (!e) return 3;
    int link = pcap_datalink(pc);
    struct pcap_pkthdr *h;
    const uint8_t *p;
    uint64_t now = 0;
    while (pcap_next_ex(pc, &h, &p) == 1) {
        int off = l3_offset(link, p, h->caplen);
        if (off < 0 || (size_t) off >= h->caplen) continue;
        now = (uint64_t) h->ts.tv_sec * 1000 + (uint64_t) h->ts.tv_usec / 1000;
        vh_engine_packet(e, p + off, h->caplen - (size_t) off, hook, now);
    }
    const vh_stats *s = vh_engine_stats(e);
    printf("summary packets=%llu flows=%llu strong=%llu weak_confirmed=%llu peer=%llu udp_port=%llu tainted=%llu weak_alone=%llu exempt=%llu\n",
           (unsigned long long) s->packets, (unsigned long long) s->flows,
           (unsigned long long) s->reasons[VH_STRONG], (unsigned long long) s->reasons[VH_WEAK_CONFIRMED],
           (unsigned long long) s->reasons[VH_PEER], (unsigned long long) s->reasons[VH_UDP_PORT],
           (unsigned long long) s->reasons[VH_TAINTED], (unsigned long long) s->weak_alone,
           (unsigned long long) s->exempt);
    vh_engine_free(e);
    pcap_close(pc);
    return 0;
}
