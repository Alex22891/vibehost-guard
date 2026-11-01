#!/bin/sh
# After guard-test.sh on a systemd host: the sandboxed unit, in enforce mode, really cuts a forwarded
# connection and leaves an ordinary one alone. The API stand-in must be running on :9099.
set -u
export VH_GUARD_API=http://127.0.0.1:9099/api/v1/guard
echo enforce > /tmp/api/mode
/usr/local/lib/vibehost-guard/guard.sh tick
sleep 7
/usr/local/lib/vibehost-guard/guard.sh tick

ip netns add sc; ip netns add ss
ip link add sc0 type veth peer name sc1; ip link add ss0 type veth peer name ss1
ip link set sc1 netns sc; ip link set ss1 netns ss
ip addr add 10.77.0.1/24 dev sc0; ip addr add 198.51.100.1/24 dev ss0; ip link set sc0 up; ip link set ss0 up
ip netns exec sc sh -c 'ip addr add 10.77.0.2/24 dev sc1; ip link set sc1 up; ip route add default via 10.77.0.1'
ip netns exec ss sh -c 'ip addr add 198.51.100.2/24 dev ss1; ip link set ss1 up; ip route add default via 198.51.100.1'
sysctl -qw net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -o ss0 -j MASQUERADE

cat > /tmp/srv.py <<'EOF'
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", 6881)); s.listen(20)
def run(c):
    try:
        while True:
            if not c.recv(4096): break
            c.sendall(b"ack")
    except OSError: pass
while True:
    c, _ = s.accept(); threading.Thread(target=run, args=(c,), daemon=True).start()
EOF
cat > /tmp/cli.py <<'EOF'
import socket, sys
first = b"\x13BitTorrent protocol" + b"\0"*8 + b"a"*40 if sys.argv[1] == "bt" else b"hello there"
s = socket.socket(); s.settimeout(1); n = 0
s.connect(("198.51.100.2", 6881))
for i in range(4):
    try:
        s.sendall(first if i == 0 else b"x"*100)
        if s.recv(10): n += 1
    except OSError: break
print(n)
EOF
ip netns exec ss python3 /tmp/srv.py &
SRV=$!
sleep 1
# The string rule also drops the handshake: take it out, so what is measured is the analyser alone.
iptables -D VH_GUARD -m string --algo bm --string "BitTorrent protocol" -m comment --comment "vh:bt-handshake" -j DROP

echo "ordinary, answers of 4: $(ip netns exec sc python3 /tmp/cli.py plain)"
echo "handshake, answers of 4: $(ip netns exec sc python3 /tmp/cli.py bt)"
sleep 1
tr ',' '\n' < /run/vibehost-guard-dpid/stats >/dev/null
sleep 30
grep -o '"strong":[0-9]*\|"marked":[0-9]*\|"markFailed":[0-9]*' /run/vibehost-guard-dpid/stats | tr '\n' ' '; echo
grep -E '^(Uid|CapEff|VmRSS):' "/proc/$(systemctl show -p MainPID --value vibehost-guard-dpid.service)/status" | tr '\n' ' '; echo
kill $SRV 2>/dev/null
