/*
 * vh-dpid scan watch: notices a source on this server that opens connections to many addresses or
 * ports and gets no answer - what an outbound port scan looks like from the inside. It only keeps
 * counts; what to do about a scanner is the caller's choice (guard.sh blocks it when told to).
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
#ifndef VH_SCAN_H
#define VH_SCAN_H

#include <stddef.h>
#include <stdint.h>

#include "engine.h"

/* A try that got no SYN-ACK within this long, or a reset, failed. */
#define VH_SCAN_ANSWER_MS 3000u
/* The counting window. */
#define VH_SCAN_WINDOW_MS 60000u
/* Failed tries in one window that make a scanner: different addresses, or different address:port pairs. */
#define VH_SCAN_HOSTS 100u
#define VH_SCAN_PAIRS 200u
/* ...and only if at least this share of its tries in the window failed, in percent. A scan is almost all
 * failures; a proxy or a VPN whose users all leave from the server's own address fails a few hundred tries a
 * minute too, but among thousands that are answered. */
#define VH_SCAN_FAIL_SHARE 50u
/* How long a scanner stays one after its last window over the line. */
#define VH_SCAN_HOLD_MS (15u * 60u * 1000u)
/* Ports reported per scanner. */
#define VH_SCAN_PORTS 8

typedef struct {
    int family;
    uint8_t addr[16];
    uint8_t local;                  /* the server itself, not a VPN user or a container */
    uint64_t until_ms;
    uint16_t ports[VH_SCAN_PORTS];  /* the ports it tried most, most first */
    uint8_t nports;
} vh_scanner;

typedef struct {
    uint64_t failed;   /* failed outgoing tries seen */
    uint64_t events;   /* times a source became a scanner */
    vh_port_count ports[VH_TOP_PORTS];  /* ports scanners tried */
} vh_scan_stats;

typedef struct vh_scan vh_scan;

vh_scan *vh_scan_new(void);
void vh_scan_free(vh_scan *s);

/* One copied TCP packet: its tuple, its flags, the hook it came from. */
void vh_scan_packet(vh_scan *s, const vh_tuple *t, uint8_t tcp_flags, char hook, uint64_t now_ms);

/* Turns unanswered tries into failures and lets old scanners go. Call every few seconds. */
void vh_scan_tick(vh_scan *s, uint64_t now_ms);

/* The scanners now; *version changes whenever the list does. Returns how many. */
size_t vh_scan_list(const vh_scan *s, vh_scanner *out, size_t max, uint64_t *version);

const vh_scan_stats *vh_scan_stats_of(const vh_scan *s);

#endif
