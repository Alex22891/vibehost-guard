#!/bin/sh
# Torrent guard. Usage: guard.sh <code> | apply | tick
set -u

VERSION=4
API="${VH_GUARD_API:-https://api.vibehost.net/api/v1/guard}"
LIB=/usr/local/lib/vibehost-guard
CONF_DIR=/etc/vibehost-guard
CONF="$CONF_DIR/agent.conf"
CHAIN=VH_GUARD
DPI_MODE_FILE="$CONF_DIR/dpi.mode"
DPI_BIN="$LIB/vh-dpid"
DPI_RUN=/run/vibehost-guard-dpid
DPI_STATS="$DPI_RUN/stats"
DPI_PID="$DPI_RUN/pid"
DPI_BIT=0x100000
DPI_PACKETS=12
DPI_BYTES=512
DPI_SHA_AMD64=8935376c89bb30e71dd4a09e32c1e903f0a8ff3f4bcb03025febb4da4bbe4547
DPI_SHA_ARM64=ed8b87ce1d10102e62fda6fb03b3d158ba5e111e291e688b8c2b45a8024be851

SIGNATURES='bt-handshake|BitTorrent protocol
dht-query|d1:ad2:id20:
dht-reply|d1:rd2:id20:
dht-get-peers|9:get_peers
dht-announce|13:announce_peer
dht-find-node|9:find_node
tracker-info-hash|info_hash=
tracker-peer-id|peer_id=
tracker-announce|/announce?
tracker-scrape|/scrape?
lsd|BT-SEARCH
magnet|urn:btih:'
SIGNATURES_LOOSE='tracker-info-hash tracker-peer-id tracker-announce tracker-scrape magnet'
UDP_TRACKER_HEX='|0000041727101980|'

log() { echo "vibehost-guard: $*" >&2; }

tables() {
    command -v iptables >/dev/null 2>&1 && echo iptables
    command -v ip6tables >/dev/null 2>&1 && echo ip6tables
}

hooks() {
    echo INPUT
    echo OUTPUT
    echo FORWARD
    $1 -n -L DOCKER-USER >/dev/null 2>&1 && echo DOCKER-USER
}

signatures() {
    if [ "$(dpi_mode)" = enforce ] && dpi_running && $1 -w -S $CHAIN 2>/dev/null | grep -q -- vhdpi-tap; then
        echo "$SIGNATURES" | while IFS='|' read -r name pattern; do
            case " $SIGNATURES_LOOSE " in *" $name "*) ;; *) echo "$name|$pattern" ;; esac
        done
    else
        echo "$SIGNATURES"
    fi
}

tap_rule() {
    $1 -w $2 $CHAIN ${3:-} -m connbytes --connbytes 1:$DPI_PACKETS --connbytes-dir both --connbytes-mode packets \
        -m limit --limit 10000/s --limit-burst 10000 -m comment --comment vhdpi-tap \
        -j NFLOG --nflog-group 4711 --nflog-size $DPI_BYTES 2>/dev/null \
        || log "$1: no copies for the analyser, the string rules stay"
}

apply_dpi_rules() {
    t=$1
    mode=$(dpi_mode)
    if [ "$mode" = enforce ]; then
        $t -w -A $CHAIN -m connmark --mark $DPI_BIT/$DPI_BIT -m comment --comment vhdpi-drop -j DROP || return 1
    fi
    [ "$mode" = off ] || tap_rule "$t" -A
    return 0
}

apply_table() {
    t=$1
    $t -w -N $CHAIN 2>/dev/null || $t -w -F $CHAIN || return 1
    apply_dpi_rules "$t" || return 1
    $t -w -A $CHAIN -m connbytes --connbytes 4097: --connbytes-dir both --connbytes-mode bytes -j RETURN || return 1
    signatures "$t" | while IFS='|' read -r name pattern; do
        [ -n "$name" ] || continue
        $t -w -A $CHAIN -m string --algo bm --string "$pattern" -m comment --comment "vh:$name" -j DROP || exit 1
    done || return 1
    $t -w -A $CHAIN -p udp -m string --algo bm --hex-string "$UDP_TRACKER_HEX" -m comment --comment "vh:udp-tracker" -j DROP || return 1
    hook_table "$t"
}

jumps() {
    $1 -w -S "$2" 2>/dev/null | grep -c -- "-j $CHAIN\$"
}

hook_table() {
    t=$1
    for h in $(hooks "$t"); do
        n=$(jumps "$t" "$h")
        while [ "$n" -gt 1 ]; do
            $t -w -D "$h" -j $CHAIN || return 1
            n=$((n - 1))
        done
        [ "$n" -eq 1 ] || $t -w -I "$h" 1 -j $CHAIN || return 1
    done
}

intact_table() {
    t=$1
    want=$(signatures "$t" | grep -c '|')
    have=$($t -w -S $CHAIN 2>/dev/null | grep -c -- '--comment "\{0,1\}vh:')
    [ "$have" -eq $((want + 1)) ] || return 1
    want=0
    [ "$(dpi_mode)" = enforce ] && want=1
    [ "$($t -w -S $CHAIN 2>/dev/null | grep -c -- vhdpi-drop)" -eq "$want" ] || return 1
    have=$($t -w -S $CHAIN 2>/dev/null | grep -c -- vhdpi-tap)
    if [ "$(dpi_mode)" = off ]; then
        [ "$have" -eq 0 ] || return 1
    elif [ "$have" -eq 0 ]; then
        tap_rule "$t" -I 1
    fi
    for h in $(hooks "$t"); do
        [ "$(jumps "$t" "$h")" -eq 1 ] || return 1
    done
}

lock() {
    [ -z "${VH_GUARD_LOCKED:-}" ] || return 0
    command -v flock >/dev/null 2>&1 || return 0
    d=/run
    [ -d "$d" ] && [ -w "$d" ] || d=/tmp
    exec 9>"$d/vibehost-guard.lock"
    flock -w 120 9 2>/dev/null || flock -n 9 2>/dev/null || true
}

apply() {
    rc=0
    found=
    for t in $(tables); do
        found=1
        if ! apply_table "$t"; then
            log "$t: rules not applied (no string/connbytes match in this kernel?)"
            rc=1
        fi
    done
    [ -n "$found" ] || { log "iptables not found"; return 1; }
    return $rc
}

ensure() {
    rc=0
    for t in $(tables); do
        intact_table "$t" || apply_table "$t" || rc=1
    done
    return $rc
}

counters() {
    for t in $(tables); do
        $t -w -nvxL $CHAIN 2>/dev/null
    done | awk '/vh:/ { for (i = 1; i <= NF; i++) if ($i ~ /^vh:/) { n[substr($i, 4)] += $1 } }
        END { s = ""; for (k in n) { s = s (s == "" ? "" : ",") "\"" k "\":" n[k] }; print s }'
}


dpi_mode() {
    m=off
    [ -r "$DPI_MODE_FILE" ] && m=$(cat "$DPI_MODE_FILE" 2>/dev/null)
    case "$m" in shadow|enforce) echo "$m" ;; *) echo off ;; esac
}

dpi_running() {
    [ -n "$(find "$DPI_STATS" -mmin -3 2>/dev/null)" ]
}

dpi_tapped() {
    for t in $(tables); do
        $t -w -S $CHAIN 2>/dev/null | grep -q -- vhdpi-tap && return 0
    done
    return 1
}

dpi_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo amd64 ;;
        aarch64|arm64) echo arm64 ;;
    esac
}

dpi_install_binary() {
    arch=$(dpi_arch)
    case "$arch" in
        amd64) wanted=$DPI_SHA_AMD64 ;;
        arm64) wanted=$DPI_SHA_ARM64 ;;
        *) return 1 ;;
    esac
    [ -x "$DPI_BIN" ] && [ "$(cat "$DPI_BIN.sha" 2>/dev/null)" = "$wanted" ] && return 0
    command -v sha256sum >/dev/null 2>&1 && command -v gunzip >/dev/null 2>&1 || return 1
    tmp="$LIB/vh-dpid.gz.new"
    fetch "$API/bin/vh-dpid-$arch.gz" "$tmp" || { rm -f "$tmp"; return 1; }
    [ "$(sha256sum "$tmp" | cut -d' ' -f1)" = "$wanted" ] || { log "analyser download does not match"; rm -f "$tmp"; return 1; }
    gunzip -c "$tmp" > "$DPI_BIN.new" && chmod 755 "$DPI_BIN.new" || { rm -f "$tmp" "$DPI_BIN.new"; return 1; }
    rm -f "$tmp"
    dpi_stop
    mv "$DPI_BIN.new" "$DPI_BIN" && echo "$wanted" > "$DPI_BIN.sha"
    cat > "$LIB/NOTICE" <<EOF
vh-dpid is built on nDPI by ntop.org, LGPLv3 (https://github.com/ntop/nDPI).
Sources and the build, to relink against another nDPI: https://github.com/VIBEHOST-LLC/vibehost-guard
EOF
}

dpi_systemd() {
    command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]
}

dpi_write_unit() {
    cat > /etc/systemd/system/vibehost-guard-dpid.service <<EOF
[Unit]
Description=VibeHost torrent guard analyser
After=network-pre.target vibehost-guard.service

[Service]
ExecStart=$DPI_BIN --mode $1 --stats $DPI_STATS
Restart=on-failure
RestartSec=30
RestartPreventExitStatus=2 3
DynamicUser=yes
RuntimeDirectory=vibehost-guard-dpid
RuntimeDirectoryMode=0755
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_NETLINK AF_UNIX
RestrictNamespaces=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
Nice=10
CPUQuota=25%
MemoryMax=96M

[Install]
WantedBy=multi-user.target
EOF
}

dpi_stop() {
    if dpi_systemd; then
        systemctl stop vibehost-guard-dpid.service >/dev/null 2>&1
    elif [ -r "$DPI_PID" ]; then
        kill "$(cat "$DPI_PID")" 2>/dev/null
        rm -f "$DPI_PID"
    fi
    rm -f "$DPI_STATS"
}

dpi_start() {
    if command -v modprobe >/dev/null 2>&1; then
        modprobe -q nfnetlink_log 2>/dev/null
        modprobe -q nf_conntrack_netlink 2>/dev/null
    fi
    if dpi_systemd; then
        dpi_write_unit "$1"
        systemctl daemon-reload
        systemctl enable vibehost-guard-dpid.service >/dev/null 2>&1
        systemctl restart vibehost-guard-dpid.service >/dev/null 2>&1
    else
        mkdir -p "$DPI_RUN"
        nohup "$DPI_BIN" --mode "$1" --stats "$DPI_STATS" >/dev/null 2>&1 9>&- &
        echo $! > "$DPI_PID"
    fi
}

dpi_alive() {
    if dpi_systemd; then
        systemctl is-active --quiet vibehost-guard-dpid.service
    else
        [ -r "$DPI_PID" ] && kill -0 "$(cat "$DPI_PID")" 2>/dev/null
    fi
}

dpi_sync() {
    mode=$(dpi_mode)
    if [ "$mode" = off ]; then
        if dpi_systemd && [ -f /etc/systemd/system/vibehost-guard-dpid.service ]; then
            systemctl disable vibehost-guard-dpid.service >/dev/null 2>&1
            dpi_stop
            rm -f /etc/systemd/system/vibehost-guard-dpid.service
            systemctl daemon-reload
        elif ! dpi_systemd; then
            dpi_stop
        fi
        return 0
    fi
    dpi_install_binary || return 1
    running_mode=$(sed -n 's/.*"mode":"\([a-z]*\)".*/\1/p' "$DPI_STATS" 2>/dev/null)
    if ! dpi_alive || { [ -n "$running_mode" ] && [ "$running_mode" != "$mode" ]; }; then
        dpi_start "$mode"
    fi
}

dpi_report() {
    mode=$(dpi_mode)
    if [ "$mode" = off ]; then
        printf '"state":"off"'
    elif dpi_running && dpi_tapped; then
        printf '"state":"running",%s' "$(cat "$DPI_STATS" 2>/dev/null)"
    else
        printf '"state":"unavailable","mode":"%s","arch":"%s"' "$mode" "$(uname -m | tr -cd 'a-z0-9_')"
    fi
}

os_name() {
    if [ -r /etc/os-release ]; then
        . /etc/os-release
        echo "${ID:-linux}-${VERSION_ID:-}"
    else
        uname -s
    fi
}

post() {
    url=$1 body=$2 token=${3:-}
    if command -v curl >/dev/null 2>&1; then
        if [ -n "$token" ]; then
            curl -fsS -m 20 -X POST -H 'Content-Type: application/json' -H "X-Agent-Token: $token" -d "$body" "$url"
        else
            curl -fsS -m 20 -X POST -H 'Content-Type: application/json' -d "$body" "$url"
        fi
    else
        if [ -n "$token" ]; then
            wget -q -T 20 -O - --header='Content-Type: application/json' --header="X-Agent-Token: $token" --post-data="$body" "$url"
        else
            wget -q -T 20 -O - --header='Content-Type: application/json' --post-data="$body" "$url"
        fi
    fi
}

fetch() {
    if command -v curl >/dev/null 2>&1; then curl -fsS -m 60 -o "$2" "$1"; else wget -q -T 60 -O "$2" "$1"; fi
}

json_field() {
    sed -n "s/.*\"$1\" *: *\"\{0,1\}\([^\",}]*\).*/\1/p" | head -n 1
}

install_packages() {
    fw=
    dl=
    command -v iptables >/dev/null 2>&1 || fw=iptables
    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || dl=curl
    [ -n "$fw$dl" ] || return 0
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get install -y -q $fw $dl >/dev/null 2>&1 \
            || { apt-get update -q >/dev/null 2>&1 && apt-get install -y -q $fw $dl >/dev/null 2>&1; }
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q ${fw:+iptables-nft} $dl >/dev/null 2>&1 || dnf install -y -q $fw $dl >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q $fw $dl >/dev/null 2>&1
    elif command -v zypper >/dev/null 2>&1; then
        zypper -n -q in $fw $dl >/dev/null 2>&1
    elif command -v apk >/dev/null 2>&1; then
        apk add -q ${fw:+iptables ip6tables} $dl >/dev/null 2>&1
    fi
    command -v iptables >/dev/null 2>&1
}

install_units() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        cat > /etc/systemd/system/vibehost-guard.service <<EOF
[Unit]
Description=VibeHost torrent guard
After=network-pre.target firewalld.service ufw.service docker.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$LIB/guard.sh apply

[Install]
WantedBy=multi-user.target
EOF
        cat > /etc/systemd/system/vibehost-guard-tick.service <<EOF
[Unit]
Description=VibeHost torrent guard check

[Service]
Type=oneshot
ExecStart=$LIB/guard.sh tick
EOF
        cat > /etc/systemd/system/vibehost-guard-tick.timer <<EOF
[Unit]
Description=VibeHost torrent guard check every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
EOF
        systemctl daemon-reload
        systemctl enable vibehost-guard.service >/dev/null 2>&1
        systemctl enable --now vibehost-guard-tick.timer >/dev/null 2>&1
    else
        mkdir -p /etc/cron.d
        cat > /etc/cron.d/vibehost-guard <<EOF
@reboot root $LIB/guard.sh apply
*/5 * * * * root $LIB/guard.sh tick
EOF
    fi
}

enroll() {
    code=$1
    answer=$(post "$API/enroll" "{\"code\":\"$code\",\"os\":\"$(os_name)\",\"version\":$VERSION}") || return 1
    token=$(echo "$answer" | json_field token)
    [ -n "$token" ] || return 1
    umask 077
    mkdir -p "$CONF_DIR"
    printf 'VIBEHOST_GUARD_TOKEN=%s\n' "$token" > "$CONF"
}

install_guard() {
    code=$1
    [ "$(id -u)" -eq 0 ] || { log "run as root"; exit 1; }
    install_packages </dev/null || { log "could not install iptables"; exit 1; }
    mkdir -p "$LIB"
    if [ "$0" != "$LIB/guard.sh" ]; then
        if [ -f "$0" ]; then cp "$0" "$LIB/guard.sh"; else fetch "$API/guard.sh" "$LIB/guard.sh" || exit 1; fi
    fi
    chmod 755 "$LIB/guard.sh"
    install_units
    if apply; then echo "vibehost-guard: torrent traffic is blocked"; else exit 1; fi
    if [ -n "$code" ]; then
        if enroll "$code"; then echo "vibehost-guard: linked to VibeHost"; else log "torrent traffic is blocked, but the server is not linked to VibeHost: the command is used or expired, take it again from the server card"; fi
    fi
    tick >/dev/null 2>&1 || true
}

tick() {
    VIBEHOST_GUARD_TOKEN=
    [ -r "$CONF" ] && . "$CONF"
    dpi_sync </dev/null || true
    ok=true
    ensure || ok=false
    [ -n "$VIBEHOST_GUARD_TOKEN" ] || return 0
    body="{\"version\":$VERSION,\"rulesOk\":$ok,\"os\":\"$(os_name)\",\"counters\":{$(counters)},\"dpi\":{$(dpi_report)}}"
    answer=$(post "$API/heartbeat" "$body" "$VIBEHOST_GUARD_TOKEN") || return 0
    wanted=$(echo "$answer" | json_field dpi)
    case "$wanted" in off|shadow|enforce)
        if [ "$wanted" != "$(dpi_mode)" ]; then
            mkdir -p "$CONF_DIR"
            echo "$wanted" > "$DPI_MODE_FILE"
            dpi_sync </dev/null || true
            [ "$wanted" = off ] || sleep 6
            ensure || true
        fi
        ;;
    esac
    latest=$(echo "$answer" | json_field version)
    if [ -n "$latest" ] && [ "$latest" -gt "$VERSION" ] 2>/dev/null; then
        if fetch "$API/guard.sh" "$LIB/guard.sh.new" && sh -n "$LIB/guard.sh.new"; then
            chmod 755 "$LIB/guard.sh.new" && mv "$LIB/guard.sh.new" "$LIB/guard.sh" && VH_GUARD_LOCKED=1 "$LIB/guard.sh" apply
        else
            rm -f "$LIB/guard.sh.new"
        fi
    fi
}

case "${1:-}" in
    apply) lock; apply ;;
    tick) lock; tick ;;
    *) lock; install_guard "${1:-}" ;;
esac
