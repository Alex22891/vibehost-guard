#!/bin/sh
# A private swarm with no internet: a real seeder and real clients behind the guard, so the numbers
# mean something and no outside peer is involved. The tracker speaks TLS, the way a client learns of
# peers without us seeing it; that leaves encrypted peer traffic as the only thing to catch.
# Run as root in a privileged container with: iptables ip6tables iproute2 python3 openssl curl
# procps conntrack-tools aria2. Arguments: <guard.sh> <vh-dpid.gz>
set -u
SCRIPT=$1
GZ=$2
SECS=${SECS:-25}
LIB=/usr/local/lib/vibehost-guard
W=/tmp/sw
SEED=198.18.0.2
mkdir -p "$W/seed" "$W/cert" "$LIB" /etc/vibehost-guard

cp "$SCRIPT" "$LIB/guard.sh"; chmod 755 "$LIB/guard.sh"
gunzip -c "$GZ" > "$LIB/vh-dpid"; chmod 755 "$LIB/vh-dpid"
sed -n 's/^DPI_SHA_AMD64=//p' "$SCRIPT" > "$LIB/vh-dpid.sha"

ip netns add swc; ip netns add sws
ip link add sc0 type veth peer name sc1; ip link add ss0 type veth peer name ss1
ip link set sc1 netns swc; ip link set ss1 netns sws
ip addr add 10.66.0.1/24 dev sc0; ip addr add 198.18.0.1/24 dev ss0; ip link set sc0 up; ip link set ss0 up
ip netns exec swc sh -c 'ip addr add 10.66.0.2/24 dev sc1; ip link set sc1 up; ip link set lo up; ip route add default via 10.66.0.1'
ip netns exec sws sh -c "ip addr add $SEED/24 dev ss1; ip link set ss1 up; ip link set lo up; ip route add default via 198.18.0.1"
sysctl -qw net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.66.0.0/24 -o ss0 -j MASQUERADE

dd if=/dev/urandom of="$W/seed/data.bin" bs=1M count=200 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/cert/k.pem" -out "$W/cert/c.pem" -days 2 -subj /CN=tracker >/dev/null 2>&1

cat > "$W/tools.py" <<'EOF'
import hashlib, sys, ssl, http.server, urllib.parse, struct
def make(path, out, announce):
    plen = 256 * 1024
    data = open(path, "rb"); pieces = b""; length = 0
    while True:
        b = data.read(plen)
        if not b: break
        pieces += hashlib.sha1(b).digest(); length += len(b)
    name = b"data.bin"
    info = b"d6:lengthi%de4:name%d:%s12:piece lengthi%de6:pieces%d:" % (length, len(name), name, plen, len(pieces)) + pieces + b"e"
    a = announce.encode()
    open(out, "wb").write(b"d8:announce%d:%s4:info" % (len(a), a) + info + b"e")
PEERS = {}
class T(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query, encoding="latin-1")
        h = q.get("info_hash", [""])[0]; port = int(q.get("port", ["0"])[0])
        peers = PEERS.setdefault(h, set())
        if self.client_address[0] == "198.18.0.2" and port: peers.add(("198.18.0.2", port))
        comp = b"".join(bytes(map(int, ip.split("."))) + struct.pack(">H", p) for ip, p in peers)
        body = b"d8:intervali5e5:peers%d:" % len(comp) + comp + b"e"
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
if sys.argv[1] == "make":
    make(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), T)
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(sys.argv[2], sys.argv[3])
    srv.socket = c.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()
EOF
python3 "$W/tools.py" make "$W/seed/data.bin" "$W/t.torrent" "https://$SEED:8443/announce"

ip netns exec sws python3 "$W/tools.py" serve "$W/cert/c.pem" "$W/cert/k.pem" &
sleep 1
ip netns exec sws aria2c -q --check-integrity=true --bt-seed-unverified=true --seed-ratio=0 --seed-time=600 --check-certificate=false \
    --listen-port=51413 --enable-dht=false --bt-enable-lpd=false --dir="$W/seed" "$W/t.torrent" >/dev/null 2>&1 &
sleep 8

guard() {
    pkill -x vh-dpid 2>/dev/null
    rm -f /run/vibehost-guard-dpid/stats /run/vibehost-guard-dpid/pid
    for h in INPUT OUTPUT FORWARD; do
        while iptables -D $h -j VH_GUARD 2>/dev/null; do :; done
        while ip6tables -D $h -j VH_GUARD 2>/dev/null; do :; done
    done
    iptables -F VH_GUARD 2>/dev/null; iptables -X VH_GUARD 2>/dev/null
    ip6tables -F VH_GUARD 2>/dev/null; ip6tables -X VH_GUARD 2>/dev/null
    rm -f /etc/vibehost-guard/dpi.mode
    conntrack -F >/dev/null 2>&1
    [ "$1" = none ] && return 0
    echo "$1" > /etc/vibehost-guard/dpi.mode
    "$LIB/guard.sh" apply >/dev/null 2>&1
    if [ "$1" != off ]; then
        "$LIB/guard.sh" tick >/dev/null 2>&1
        sleep 7
        "$LIB/guard.sh" tick >/dev/null 2>&1
    fi
}

# A strong hit from this client first, as a torrent client's DHT would send before anything else.
dht_ping() {
    ip netns exec swc python3 - <<EOF
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(3):
    s.sendto(b"d1:ad2:id20:aaaaaaaaaaaaaaaaaaaae1:q4:ping1:t2:aa1:y1:qe", ("$SEED", 6881))
EOF
    sleep 1
}

download() {
    enc=$1
    d="$W/dl"; rm -rf "$d"; mkdir -p "$d"
    crypto="--bt-require-crypto=false --bt-force-encryption=false"
    [ "$enc" = enc ] && crypto="--bt-require-crypto=true --bt-force-encryption=true --bt-min-crypto-level=arc4"
    ip netns exec swc timeout -s KILL "$SECS" aria2c -q --seed-time=0 --file-allocation=none --check-certificate=false \
        --enable-dht=false --bt-enable-lpd=false --enable-peer-exchange=false --max-overall-download-limit=4M \
        --dir="$d" $crypto "$W/t.torrent" >/dev/null 2>&1
    find "$d" -type f -name 'data.bin' -exec du -k {} + 2>/dev/null | awk '{s+=$1} END {print s+0}'
}

stats() {
    sleep 31
    tr ',' '\n' < /run/vibehost-guard-dpid/stats 2>/dev/null \
        | grep -E '"(strong|weakConfirmed|peer|tainted|weakAlone|marked|markFailed)"' | tr -d '"' | tr '\n' ' '
}

printf '%-30s %10s\n' case got
for enc in plain enc; do
    guard none;    printf '%-30s %7s KB\n' "no guard, $enc" "$(download $enc)"
    guard off;     printf '%-30s %7s KB\n' "strings only, $enc" "$(download $enc)"
    guard enforce; printf '%-30s %7s KB\n' "enforce, $enc" "$(download $enc)"; echo "    $(stats)"
done
guard enforce; dht_ping; printf '%-30s %7s KB\n' "enforce, enc, after DHT hit" "$(download enc)"; echo "    $(stats)"
guard off;     dht_ping; printf '%-30s %7s KB\n' "strings only, enc, after DHT" "$(download enc)"
guard none
echo DONE
