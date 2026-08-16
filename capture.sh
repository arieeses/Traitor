#!/bin/bash
# Traitor 抓包核心（由 systemd 前台运行）。只抓握手，不抓流量，1C1G 友好。
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IPFILE="${TRAITOR_IPS:-$DIR/ips.txt}"
OUT="${TRAITOR_OUT:-/var/lib/traitor/pcap}"
IFACE="${TRAITOR_IFACE:-$(ip route 2>/dev/null | awk '/default/{print $5; exit}')}"
IFACE="${IFACE:-eth0}"
SNAP="${TRAITOR_SNAP:-512}"

# 端口来自 ports.txt(本地，用 traitor.sh port 管理)，没有则用 ports.default
build_ports(){
  local pf="$DIR/ports.txt"; [ -f "$pf" ] || pf="$DIR/ports.default"
  local out="" line proto spec part
  while read -r line || [ -n "$line" ]; do
    line=$(echo "$line" | xargs); [ -z "$line" ] && continue
    case "$line" in \#*) continue;; esac
    proto=tcp; spec="$line"
    case "$line" in udp:*) proto=udp; spec="${line#udp:}";; tcp:*) proto=tcp; spec="${line#tcp:}";; esac
    if [[ "$spec" == *-* ]]; then part="$proto portrange $spec"; else part="$proto port $spec"; fi
    out=${out:+$out or }$part
  done < "$pf"
  echo "$out"
}
PORTS="${TRAITOR_PORTS:-$(build_ports)}"
[ -z "$PORTS" ] && { echo "没有有效端口(ports.txt/ports.default)" >&2; exit 1; }

mkdir -p "$OUT"

# 由 ips.txt 生成 host 过滤（双向，才能看到 SYN-ACK 判断是否真连上）
FILTER=""
while read -r IP || [ -n "$IP" ]; do
  IP=$(echo "$IP" | xargs); [ -z "$IP" ] && continue
  case "$IP" in \#*) continue;; esac
  FILTER=${FILTER:+$FILTER or }"host $IP"
done < "$IPFILE"
[ -z "$FILTER" ] && { echo "ips.txt 里没有有效IP: $IPFILE" >&2; exit 1; }

# 只抓：TCP SYN/SYN-ACK  或  TLS/QUIC 握手记录（payload首字节=0x16）
HS='tcp[tcpflags] & tcp-syn != 0 or (tcp[((tcp[12]&0xf0)>>2)] = 22)'
BPF="($FILTER) and ($PORTS) and ($HS or udp)"

echo "[traitor] iface=$IFACE snap=$SNAP out=$OUT"
# 前台 exec，systemd 托管；-B 2048 省内存
exec tcpdump -i "$IFACE" -n -s "$SNAP" -B 2048 "$BPF" \
  -G 3600 -W 24 -w "$OUT/fingerprint-%Y%m%d-%H%M%S.pcap"
