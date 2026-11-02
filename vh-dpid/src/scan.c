/*
 * vh-dpid scan watch. See scan.h.
 *
 * Only tries that started on our side count: a SYN going out of the server, or out of a VPN user or a
 * container behind it. Each waits VH_SCAN_ANSWER_MS for its SYN-ACK; a reset or silence makes it a
 * failure. A source gathers its failures per minute as two bitmaps - addresses, and address:port
 * pairs - and counts its answered tries beside them: a crowd of users behind one proxy fails hundreds of
 * tries a minute, but most of its tries are answered, so it never adds up to a scanner.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
#include "scan.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#define PROBE_SLOTS (1u << 16)
#define SOURCE_SLOTS 1024u
#define PROBE 8u
#define BITS 4096u

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

typedef struct {
    vh_tuple tuple;      /* the try as it left: src is ours */
    uint64_t sent_ms;    /* 0: free */
    char hook;
} probe;

typedef struct {
    int family;
    uint8_t addr[16];
    uint8_t local;
    uint8_t used;
    uint64_t window_ms;
    uint32_t hosts, pairs;
    uint32_t fails, oks;  /* tries in the window that failed, and that were answered */
    uint8_t host_bits[BITS / 8];
    uint8_t pair_bits[BITS / 8];
    uint64_t until_ms;   /* a scanner until then */
    uint64_t seen_ms;
    vh_port_count ports[VH_SCAN_PORTS * 2];
} source;

struct vh_scan {
    probe *probes;
    source *sources;
    uint64_t version;
    vh_scan_stats stats;
};

static uint32_t mix(const uint8_t *b, size_t n, uint32_t h) {
    for (size_t i = 0; i < n; i++) h = (h ^ b[i]) * 16777619u;
    return h;
}

static size_t addr_len(int family) {
    return family == AF_INET ? 4 : 16;
}

static int is_private(int family, const uint8_t *a) {
    if (family == AF_INET) {
        return a[0] == 10 || (a[0] == 172 && (a[1] & 0xf0) == 16) || (a[0] == 192 && a[1] == 168)
            || (a[0] == 100 && (a[1] & 0xc0) == 64);
    }
    return (a[0] & 0xfe) == 0xfc;
}

vh_scan *vh_scan_new(void) {
    vh_scan *s = calloc(1, sizeof(vh_scan));
    if (!s) return NULL;
    s->probes = calloc(PROBE_SLOTS, sizeof(probe));
    s->sources = calloc(SOURCE_SLOTS, sizeof(source));
    if (!s->probes || !s->sources) {
        vh_scan_free(s);
        return NULL;
    }
    return s;
}

void vh_scan_free(vh_scan *s) {
    if (!s) return;
    free(s->probes);
    free(s->sources);
    free(s);
}

/* A probe's key is the try's own tuple; the answer is found by turning the answer's tuple round. */
static uint32_t probe_hash(const vh_tuple *t) {
    size_t al = addr_len(t->family);
    uint32_t h = mix(t->src, al, 2166136261u);
    h = mix(t->dst, al, h);
    h = mix((const uint8_t *) &t->sport, 2, h);
    return mix((const uint8_t *) &t->dport, 2, h);
}

static int same_try(const vh_tuple *a, const vh_tuple *b) {
    size_t al = addr_len(a->family);
    return a->family == b->family && a->sport == b->sport && a->dport == b->dport
        && memcmp(a->src, b->src, al) == 0 && memcmp(a->dst, b->dst, al) == 0;
}

static probe *probe_find(vh_scan *s, const vh_tuple *t) {
    uint32_t h = probe_hash(t);
    for (uint32_t i = 0; i < PROBE; i++) {
        probe *p = &s->probes[(h + i) % PROBE_SLOTS];
        if (p->sent_ms && same_try(&p->tuple, t)) return p;
    }
    return NULL;
}

static void probe_put(vh_scan *s, const vh_tuple *t, char hook, uint64_t now_ms) {
    uint32_t h = probe_hash(t);
    probe *oldest = NULL;
    for (uint32_t i = 0; i < PROBE; i++) {
        probe *p = &s->probes[(h + i) % PROBE_SLOTS];
        if (p->sent_ms && same_try(&p->tuple, t)) return;  /* a retransmitted SYN: the first one counts */
        if (!oldest || p->sent_ms < oldest->sent_ms) oldest = p;
    }
    oldest->tuple = *t;
    oldest->sent_ms = now_ms;
    oldest->hook = hook;
}

static source *source_get(vh_scan *s, int family, const uint8_t *addr, uint8_t local, uint64_t now_ms) {
    uint8_t key[17] = {0};
    memcpy(key, addr, addr_len(family));
    key[16] = local;
    uint32_t h = mix(key, sizeof key, 2166136261u);
    source *free_slot = NULL, *oldest = NULL;
    for (uint32_t i = 0; i < PROBE; i++) {
        source *src = &s->sources[(h + i) % SOURCE_SLOTS];
        if (src->used && src->family == family && src->local == local
            && memcmp(src->addr, addr, addr_len(family)) == 0) return src;
        if (!src->used && !free_slot) free_slot = src;
        /* A scanner is never pushed out for a newcomer. */
        if (src->used && src->until_ms <= now_ms && (!oldest || src->seen_ms < oldest->seen_ms)) oldest = src;
    }
    source *slot = free_slot ? free_slot : oldest;
    if (!slot) return NULL;
    memset(slot, 0, sizeof *slot);
    slot->used = 1;
    slot->family = family;
    memcpy(slot->addr, addr, addr_len(family));
    slot->local = local;
    slot->window_ms = now_ms;
    return slot;
}

static int set_bit(uint8_t *bits, uint32_t h) {
    uint32_t b = h % BITS;
    uint8_t m = (uint8_t) (1u << (b & 7));
    if (bits[b >> 3] & m) return 0;
    bits[b >> 3] |= m;
    return 1;
}

static void count_port(vh_port_count *table, size_t n, uint16_t port) {
    vh_port_count *lowest = &table[0];
    for (size_t i = 0; i < n; i++) {
        if (table[i].port == port && table[i].hits) {
            table[i].hits++;
            return;
        }
        if (table[i].hits < lowest->hits) lowest = &table[i];
    }
    lowest->port = port;
    lowest->hits = 1;
}

/* The try's source, its window started afresh if the last one is over. */
static source *source_of(vh_scan *s, const probe *p, uint64_t now_ms) {
    const vh_tuple *t = &p->tuple;
    source *src = source_get(s, t->family, t->src, p->hook != VH_HOOK_FORWARD, now_ms);
    if (!src) return NULL;
    src->seen_ms = now_ms;
    if (now_ms - src->window_ms >= VH_SCAN_WINDOW_MS) {
        src->window_ms = now_ms;
        src->hosts = src->pairs = src->fails = src->oks = 0;
        memset(src->host_bits, 0, sizeof src->host_bits);
        memset(src->pair_bits, 0, sizeof src->pair_bits);
    }
    return src;
}

static void answered(vh_scan *s, const probe *p, uint64_t now_ms) {
    source *src = source_of(s, p, now_ms);
    if (src) src->oks++;
}

static void failed(vh_scan *s, const probe *p, uint64_t now_ms) {
    const vh_tuple *t = &p->tuple;
    s->stats.failed++;
    source *src = source_of(s, p, now_ms);
    if (!src) return;
    src->fails++;
    size_t al = addr_len(t->family);
    uint32_t host = mix(t->dst, al, 2166136261u);
    src->hosts += (uint32_t) set_bit(src->host_bits, host);
    src->pairs += (uint32_t) set_bit(src->pair_bits, mix((const uint8_t *) &t->dport, 2, host));
    count_port(src->ports, VH_SCAN_PORTS * 2, t->dport);

    int over = (src->hosts >= VH_SCAN_HOSTS || src->pairs >= VH_SCAN_PAIRS)
        && (uint64_t) src->fails * 100u >= (uint64_t) (src->fails + src->oks) * VH_SCAN_FAIL_SHARE;
    if (src->until_ms > now_ms) count_port(s->stats.ports, VH_TOP_PORTS, t->dport);
    if (!over) return;
    if (src->until_ms <= now_ms) {
        s->stats.events++;
        s->version++;
    } else if (src->until_ms - now_ms < VH_SCAN_HOLD_MS - VH_SCAN_WINDOW_MS) {
        /* Still at it: held for another full period, and the list says so once a minute at most. */
        s->version++;
    } else {
        return;
    }
    src->until_ms = now_ms + VH_SCAN_HOLD_MS;
}

void vh_scan_packet(vh_scan *s, const vh_tuple *t, uint8_t flags, char hook, uint64_t now_ms) {
    if (t->proto != IPPROTO_TCP) return;
    if ((flags & (TCP_SYN | TCP_ACK | TCP_RST | TCP_FIN)) == TCP_SYN) {
        /* A try. Ours only: out of the server, or out of a private address behind it. */
        if (hook == VH_HOOK_INPUT) return;
        if (hook == VH_HOOK_FORWARD && !is_private(t->family, t->src)) return;
        probe_put(s, t, hook, now_ms);
        return;
    }
    if (!(flags & (TCP_SYN | TCP_RST))) return;
    /* An answer: SYN-ACK or a reset, travelling the other way. */
    vh_tuple back = *t;
    memcpy(back.src, t->dst, sizeof back.src);
    memcpy(back.dst, t->src, sizeof back.dst);
    back.sport = t->dport;
    back.dport = t->sport;
    probe *p = probe_find(s, &back);
    if (!p) return;
    if (flags & TCP_RST) failed(s, p, now_ms);
    else answered(s, p, now_ms);
    p->sent_ms = 0;
}

void vh_scan_tick(vh_scan *s, uint64_t now_ms) {
    for (uint32_t i = 0; i < PROBE_SLOTS; i++) {
        probe *p = &s->probes[i];
        if (p->sent_ms && now_ms - p->sent_ms >= VH_SCAN_ANSWER_MS) {
            failed(s, p, now_ms);
            p->sent_ms = 0;
        }
    }
    for (uint32_t i = 0; i < SOURCE_SLOTS; i++) {
        source *src = &s->sources[i];
        if (src->used && src->until_ms && src->until_ms <= now_ms) {
            src->until_ms = 0;
            s->version++;
        }
    }
}

size_t vh_scan_list(const vh_scan *s, vh_scanner *out, size_t max, uint64_t *version) {
    size_t n = 0;
    if (version) *version = s->version;
    for (uint32_t i = 0; i < SOURCE_SLOTS && n < max; i++) {
        const source *src = &s->sources[i];
        if (!src->used || !src->until_ms) continue;
        vh_scanner *o = &out[n++];
        memset(o, 0, sizeof *o);
        o->family = src->family;
        memcpy(o->addr, src->addr, sizeof o->addr);
        o->local = src->local;
        o->until_ms = src->until_ms;
        int used[VH_SCAN_PORTS * 2] = {0};
        for (int k = 0; k < VH_SCAN_PORTS; k++) {
            int best = -1;
            for (int j = 0; j < VH_SCAN_PORTS * 2; j++) {
                if (!used[j] && src->ports[j].hits && (best < 0 || src->ports[j].hits > src->ports[best].hits)) best = j;
            }
            if (best < 0) break;
            used[best] = 1;
            o->ports[o->nports++] = src->ports[best].port;
        }
    }
    return n;
}

const vh_scan_stats *vh_scan_stats_of(const vh_scan *s) {
    return &s->stats;
}
