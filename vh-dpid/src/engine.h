/*
 * vh-dpid decision engine: reads copies of the first packets of each connection and decides which
 * connections are BitTorrent. It never touches traffic itself; the caller acts on a verdict.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
#ifndef VH_ENGINE_H
#define VH_ENGINE_H

#include <stddef.h>
#include <stdint.h>

/* Packets of a connection the kernel rule copies to us; the rule and this must agree. */
#define VH_TAP_PACKETS 12
/* Bytes of each packet the rule copies. */
#define VH_TAP_BYTES 512

/* Which netfilter hook the copy came from. */
#define VH_HOOK_INPUT 'I'
#define VH_HOOK_OUTPUT 'O'
#define VH_HOOK_FORWARD 'F'

typedef enum {
    VH_STRONG = 0,      /* the protocol's own bytes in the right place */
    VH_WEAK_CONFIRMED,  /* the library said BitTorrent, and this source or peer had a strong hit */
    VH_PEER,            /* new connection to a peer a strong hit named */
    VH_UDP_PORT,        /* new UDP connection on a local port a strong hit named */
    VH_TAINTED,         /* unrecognised connection from a VPN user who just had a strong hit */
    VH_REASONS
} vh_reason;

typedef struct {
    int family;         /* AF_INET or AF_INET6 */
    uint8_t proto;      /* IPPROTO_TCP or IPPROTO_UDP */
    uint8_t src[16], dst[16];
    uint16_t sport, dport;  /* host order */
} vh_tuple;

/*
 * Returns 0 if the verdict could not be carried out yet: the kernel has no conntrack entry until the
 * connection's first packet has left the hook, and may never have one if a string rule dropped it.
 * The engine asks again on the connection's next packet.
 */
typedef int (*vh_verdict_fn)(const vh_tuple *flow, vh_reason reason, void *user);

#define VH_TOP_PORTS 64

typedef struct {
    uint16_t port;
    uint64_t hits;
} vh_port_count;

typedef struct {
    uint64_t packets;
    uint64_t flows;
    uint64_t reasons[VH_REASONS];
    uint64_t weak_alone;   /* the library said BitTorrent, nothing confirms it: counted, never blocked */
    uint64_t exempt;       /* TLS, QUIC, DNS: never judged */
    uint64_t overflow;     /* connections not analysed because the table was full */
    vh_port_count strong_ports[VH_TOP_PORTS];
    vh_port_count weak_ports[VH_TOP_PORTS];
} vh_stats;

typedef struct vh_engine vh_engine;

vh_engine *vh_engine_new(vh_verdict_fn fn, void *user);
void vh_engine_free(vh_engine *e);

/* One copied packet, starting at the IP header. The buffer is not kept. */
void vh_engine_packet(vh_engine *e, const uint8_t *packet, size_t len, char hook, uint64_t now_ms);

/* Drops idle connections and expired memories. Call every few seconds. */
void vh_engine_sweep(vh_engine *e, uint64_t now_ms);

const vh_stats *vh_engine_stats(const vh_engine *e);

/* The scan watch that sees the same copies (scan.h). */
struct vh_scan;
const struct vh_scan *vh_engine_scan(const vh_engine *e);
const char *vh_reason_name(vh_reason r);

/* Exposed for tests: whether a payload carries the protocol's own bytes in the right place. */
int vh_strong_signature(uint8_t proto, const uint8_t *p, size_t n);

#endif
