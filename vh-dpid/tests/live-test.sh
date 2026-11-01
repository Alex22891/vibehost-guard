#!/bin/sh
# vh-dpid on a real kernel: a client namespace forwarded through this one, as a VPN user is.
# Run as root in a privileged container, with the binary at $1. Prints PASS/FAIL per case; exit 0 if all passed.
set -u
BIN=${1:-/vh-dpid}
STATS=/run/vh-dpid-test.stats
BIT=0x100000
fail=0

ok() { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }

cleanup() {
    pkill -x vh-dpid 2>/dev/null
    pkill -f /tmp/peer.py 2>/dev/null
    ip netns del vhc 2>/dev/null
    ip netns del vhs 2>/dev/null
    iptables -t nat -D POSTROUTING -o vs0 -j MASQUERADE 2>/dev/null
    iptables -D FORWARD -j VH_GUARD 2>/dev/null
    iptables -F VH_GUARD 2>/dev/null; iptables -X VH_GUARD 2>/dev/null
}
trap cleanup EXIT
cleanup

ip netns add vhc; ip netns add vhs
ip link add vc0 type veth peer name vc1; ip link add vs0 type veth peer name vs1
ip link set vc1 netns vhc; ip link set vs1 netns vhs
ip addr add 10.9.0.1/24 dev vc0; ip addr add 203.0.113.1/24 dev vs0
ip link set vc0 up; ip link set vs0 up
ip netns exec vhc ip addr add 10.9.0.2/24 dev vc1; ip netns exec vhc ip link set vc1 up
ip netns exec vhc ip link set lo up; ip netns exec vhc ip route add default via 10.9.0.1
ip netns exec vhs ip addr add 203.0.113.2/24 dev vs1; ip netns exec vhs ip link set vs1 up
ip netns exec vhs ip link set lo up; ip netns exec vhs ip route add default via 203.0.113.1
sysctl -qw net.ipv4.ip_forward=1
# A customer's own mark on every connection must survive ours.
iptables -t mangle -C FORWARD -j CONNMARK --or-mark 0x7 2>/dev/null || iptables -t mangle -A FORWARD -j CONNMARK --or-mark 0x7

# Behind NAT, as a VPN user is.
iptables -t nat -A POSTROUTING -o vs0 -j MASQUERADE
iptables -N VH_GUARD
iptables -A VH_GUARD -m connmark --mark $BIT/$BIT -m comment --comment vhdpi -j DROP
iptables -A VH_GUARD -m connbytes --connbytes 1:12 --connbytes-dir both --connbytes-mode packets \
    -m limit --limit 10000/s --limit-burst 10000 -j NFLOG --nflog-group 4711 --nflog-size 512
iptables -I FORWARD 1 -j VH_GUARD

# The far side answers every chunk on TCP and UDP, so a blocked connection shows as no answer.
cat > /tmp/peer.py <<'EOF'
import socket, threading, sys
def serve_tcp(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(50)
    while True:
        c, _ = s.accept()
        def run(c):
            try:
                while True:
                    d = c.recv(4096)
                    if not d: break
                    c.sendall(b"ack")
            except OSError: pass
        threading.Thread(target=run, args=(c,), daemon=True).start()
def serve_udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", port))
    while True:
        d, a = s.recvfrom(4096); s.sendto(b"ack", a)
for p in sys.argv[1:]:
    threading.Thread(target=serve_tcp, args=(int(p),), daemon=True).start()
    threading.Thread(target=serve_udp, args=(int(p),), daemon=True).start()
threading.Event().wait()
EOF
ip netns exec vhs python3 /tmp/peer.py 6881 8080 27015 40000 40001 40002 443 &
sleep 1

# Sends chunks over one connection; prints how many got an answer.
cat > /tmp/talk.py <<'EOF'
import socket, sys, binascii
kind, port, first = sys.argv[1], int(sys.argv[2]), binascii.unhexlify(sys.argv[3])
rounds = int(sys.argv[4]) if len(sys.argv) > 4 else 5
answered = 0
if kind == "tcp":
    s = socket.socket(); s.settimeout(1.0)
    try:
        s.connect(("203.0.113.2", port))
    except OSError:
        print(0); sys.exit(0)
    for i in range(rounds):
        try:
            s.sendall(first if i == 0 else b"x" * 200)
            if s.recv(100): answered += 1
        except OSError:
            break
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.7)
    for i in range(rounds):
        s.sendto(first if i == 0 else b"x" * 200, ("203.0.113.2", port))
        try:
            if s.recv(100): answered += 1
        except OSError:
            pass
print(answered)
EOF
hex() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
talk() { ip netns exec vhc python3 /tmp/talk.py "$@"; }

HS=13$(hex 'BitTorrent protocol')0000000000000000$(hex 'aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbb')
DHT=$(hex 'd1:ad2:id20:aaaaaaaaaaaaaaaaaaaa6:target20:bbbbbbbbbbbbbbbbbbbbe1:q9:find_node1:t2:aa1:y1:qe')
HTML=$(hex 'GET /page HTTP/1.1
Host: x

BitTorrent protocol info_hash= peer_id= /announce? urn:btih:')
PLAIN=$(hex 'hello world, this is an ordinary protocol')
CHELLO=160301002a0100002603030000000000000000000000000000000000000000000000000000000000000000

stat() { sed -n "s/.*\"$1\":\([0-9]*\).*/\1/p" "$STATS"; }
start() {
    rm -f $STATS
    "$BIN" --mode "$1" --stats $STATS &
    sleep 1
    kill -0 $! 2>/dev/null || { bad "daemon did not start ($1)"; exit 1; }
    PID=$!
}
stopd() {
    kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
    conntrack -F >/dev/null 2>&1
}

echo "--- shadow: nothing is touched, everything is counted"
start shadow
[ "$(talk tcp 6881 "$HS")" = 5 ] && ok "shadow: handshake passes" || bad "shadow: handshake was blocked"
stopd
[ "$(stat strong)" -ge 1 ] && ok "shadow: handshake counted" || bad "shadow: handshake not counted"
[ "$(stat marked)" = 0 ] && ok "shadow: no conntrack mark" || bad "shadow: marked a connection"

echo "--- enforce: BitTorrent"
start enforce
[ "$(talk tcp 8080 "$PLAIN")" = 5 ] && ok "plain TCP passes" || bad "plain TCP blocked"
[ "$(talk tcp 8080 "$HTML")" = 5 ] && ok "HTTP page with torrent words passes" || bad "HTTP page with torrent words blocked"
[ "$(talk udp 27015 "$PLAIN")" = 5 ] && ok "plain UDP passes" || bad "plain UDP blocked"
a=$(talk tcp 6881 "$HS")
[ "$a" -le 1 ] && ok "TCP handshake: cut after $a answers" || bad "TCP handshake: $a answers"
a=$(talk udp 40000 "$DHT")
[ "$a" -le 1 ] && ok "DHT: cut after $a answers" || bad "DHT: $a answers"
sleep 1
a=$(talk tcp 6881 "$PLAIN")
[ "$a" = 0 ] && ok "remembered peer: new connection gets nothing" || bad "remembered peer: $a answers"

echo "--- enforce: this VPN user is marked now"
a=$(talk tcp 40001 "$PLAIN" 14)
[ "$a" -lt 14 ] && ok "unrecognised TCP on a high port cut after $a answers" || bad "unrecognised TCP not cut"
a=$(talk tcp 443 "$CHELLO" 14)
[ "$a" = 14 ] && ok "TLS still passes for a marked user" || bad "TLS blocked for a marked user: $a"

echo "--- the customer's mark"
ip netns exec vhc python3 /tmp/talk.py tcp 40002 "$HS" 3 >/dev/null
m=$(conntrack -L -p tcp --dport 40002 2>/dev/null | sed -n 's/.*mark=\([0-9]*\).*/\1/p' | head -n 1)
[ -n "$m" ] && [ $((m & 0x100000)) -ne 0 ] && [ $((m & 0x7)) -eq 7 ] && ok "our bit set, customer's bits kept (mark=$m)" \
    || bad "mark wrong: ${m:-none}"

stopd
[ "$(stat markFailed)" = 0 ] && ok "no failed marks" || bad "failed marks: $(stat markFailed)"

echo "--- daemon gone: traffic is untouched"
start enforce
kill -9 "$PID"; wait "$PID" 2>/dev/null
[ "$(talk tcp 8080 "$PLAIN")" = 5 ] && ok "plain TCP after kill -9" || bad "plain TCP broken after kill -9"
conntrack -F >/dev/null 2>&1

echo "--- removing the DROP rule releases everything at once"
start enforce
talk tcp 6881 "$HS" 1 >/dev/null
iptables -D VH_GUARD 1
stopd
[ "$(talk tcp 6881 "$PLAIN")" = 5 ] && ok "flow passes once the rule is gone" || bad "flow still blocked"
stopd

[ "$fail" = 0 ] && echo ALL PASSED
exit $fail
