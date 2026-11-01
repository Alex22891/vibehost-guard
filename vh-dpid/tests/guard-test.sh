#!/bin/sh
# guard.sh v3 against a stand-in for our API, on a real kernel: the mode from the report, the rule
# profiles, and the way back when the analyser dies. Run as root in a privileged container.
#   guard-test.sh <guard.sh> <vh-dpid.gz>
set -u
SCRIPT=$1
GZ=$2
LIB=/usr/local/lib/vibehost-guard
API_DIR=/tmp/api
fail=0

ok() { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }

mkdir -p "$API_DIR/bin"
cp "$GZ" "$API_DIR/bin/vh-dpid-amd64.gz"
cat > /tmp/api.py <<'EOF'
import http.server, json, os
MODE = "/tmp/api/mode"
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, body, ctype="application/json"):
        self.send_response(200); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        path = "/tmp/api/" + self.path.split("/guard/")[-1]
        if not os.path.isfile(path):
            self.send_response(404); self.end_headers(); return
        self._send(open(path, "rb").read(), "application/octet-stream")
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path.endswith("/enroll"):
            self._send(b'{"token":"t"}'); return
        open("/tmp/api/last-report", "wb").write(body)
        self._send(json.dumps({"version": 3, "dpi": open(MODE).read().strip()}).encode())
http.server.HTTPServer(("127.0.0.1", 9099), H).serve_forever()
EOF
echo off > "$API_DIR/mode"
python3 /tmp/api.py &
API_PID=$!
sleep 1
export VH_GUARD_API=http://127.0.0.1:9099/api/v1/guard

tick() { "$LIB/guard.sh" tick; }
rules() { iptables -S VH_GUARD 2>/dev/null; }
has() { rules | grep -q -- "$1"; }
report() { sed -n "s/.*\"$1\":\"\([a-z]*\)\".*/\1/p" "$API_DIR/last-report" | tail -n 1; }

sh "$SCRIPT" somecode >/dev/null 2>&1
[ -x "$LIB/guard.sh" ] && ok "installed" || bad "not installed"

echo "--- off: exactly the old rules"
tick
has vh:tracker-peer-id && ok "off: full string rules" || bad "off: strings missing"
has vhdpi && bad "off: analyser rules present" || ok "off: no analyser rules"
[ ! -e "$LIB/vh-dpid" ] && ok "off: nothing downloaded" || bad "off: downloaded the analyser"
[ "$(report state)" = off ] && ok "off: reported" || bad "off: report says '$(report state)'"

echo "--- shadow: it reads, the strings keep cutting"
echo shadow > "$API_DIR/mode"
tick
[ -x "$LIB/vh-dpid" ] && ok "shadow: analyser installed" || bad "shadow: no analyser"
has vhdpi-tap && ok "shadow: copies go to it" || bad "shadow: no tap rule"
has vhdpi-drop && bad "shadow: must not drop by mark" || ok "shadow: no drop by mark"
has vh:tracker-peer-id && ok "shadow: full string rules stay" || bad "shadow: strings gone"
pgrep -x vh-dpid >/dev/null && ok "shadow: running" || bad "shadow: not running"
tick
[ "$(report state)" = running ] && ok "shadow: reported running" || bad "shadow: report says '$(report state)'"
[ "$(report mode)" = shadow ] && ok "shadow: reports its mode" || bad "shadow: mode '$(report mode)'"

echo "--- enforce: the loose strings go"
echo enforce > "$API_DIR/mode"
tick
has vhdpi-drop && ok "enforce: drop by mark" || bad "enforce: no drop rule"
tick
has vh:tracker-peer-id && bad "enforce: loose strings stayed" || ok "enforce: loose strings gone"
has vh:magnet && bad "enforce: magnet stayed" || ok "enforce: magnet gone"
has vh:bt-handshake && ok "enforce: handshake rule stays" || bad "enforce: handshake rule gone"
has vh:dht-query && ok "enforce: DHT rule stays" || bad "enforce: DHT rule gone"
pgrep -x vh-dpid | head -n 1 > /tmp/pid1
tick
[ "$(pgrep -x vh-dpid | head -n 1)" = "$(cat /tmp/pid1)" ] && ok "enforce: a check does not restart it" || bad "enforce: restarted on a check"

echo "--- analyser dies: the strings are back at the next check"
pkill -9 -x vh-dpid
rm -f /run/vibehost-guard-dpid/stats
"$LIB/guard.sh" apply
has vh:tracker-peer-id && ok "dead: full strings back at once on apply" || bad "dead: strings not back"
tick
pgrep -x vh-dpid >/dev/null && ok "dead: a check restarts it" || bad "dead: not restarted"

echo "--- someone flushes the rules"
iptables -F VH_GUARD
tick
has vh:bt-handshake && ok "flushed: rules restored" || bad "flushed: not restored"

echo "--- tampered download is refused"
echo off > "$API_DIR/mode"
tick
pgrep -x vh-dpid >/dev/null && bad "off: still running" || ok "off: analyser stopped"
has vhdpi && bad "off: analyser rules left" || ok "off: analyser rules removed"
has vh:tracker-peer-id && ok "off: full strings back" || bad "off: strings missing"
rm -f "$LIB/vh-dpid" "$LIB/vh-dpid.sha"
echo garbage | gzip -c > "$API_DIR/bin/vh-dpid-amd64.gz"
echo shadow > "$API_DIR/mode"
tick
[ ! -e "$LIB/vh-dpid" ] && ok "tampered: not installed" || bad "tampered: installed"
has vh:tracker-peer-id && ok "tampered: strings still work" || bad "tampered: strings gone"
tick
[ "$(report state)" = unavailable ] && ok "tampered: reported unavailable" || bad "tampered: report says '$(report state)'"

kill $API_PID 2>/dev/null
[ "$fail" = 0 ] && echo ALL PASSED
exit $fail
