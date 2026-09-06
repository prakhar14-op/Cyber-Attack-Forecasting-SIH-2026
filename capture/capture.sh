#!/usr/bin/env bash
# Lab network capture (M11.1). Run on the GATEWAY laptop that hosts the lab
# hotspot; all attack/benign devices connect to that hotspot only.
#
#   sudo capture/capture.sh <interface> [minutes]
#
# Records ONLY the lab hotspot interface, to a timestamped pcap under
# capture/takes/. Read capture/CONSENT.md and capture/attack_scenarios.md first.
# This must NOT be run on a network carrying other people's traffic.
set -euo pipefail

IFACE="${1:?usage: sudo capture/capture.sh <interface> [minutes]}"
MINUTES="${2:-25}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$HERE/takes"
mkdir -p "$OUT_DIR"

if [ "$(id -u)" -ne 0 ]; then
    echo "tcpdump needs root: re-run with sudo" >&2
    exit 1
fi
if [ ! -f "$HERE/CONSENT.md" ] || ! grep -q "Signature" "$HERE/CONSENT.md"; then
    echo "capture/CONSENT.md missing — obtain written consent before capturing" >&2
    exit 1
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
PCAP="$OUT_DIR/take-$STAMP.pcap"
LOG="$OUT_DIR/take-$STAMP.operator-log.txt"

echo "Interface : $IFACE"
echo "Duration  : $MINUTES min"
echo "Output    : $PCAP"
echo
echo "Static-IP checklist (set these on the devices BEFORE capturing):"
echo "  gateway/attacker  172.20.0.1"
echo "  victim            172.20.0.10"
echo "  pivot target      172.20.0.20"
echo "  benign devices    172.20.0.100+"
echo
echo "Record each scenario's exact start/end time in: $LOG"
echo "  (label_capture.py turns that log into per-window stage labels)"
echo
printf 'session_id\t%s\n' "$STAMP" > "$LOG"
printf 'iface\t%s\n' "$IFACE" >> "$LOG"
printf '# columns: <stage>\t<HH:MM:SS start>\t<HH:MM:SS end>\t<attacker_ip>\t<victim_ip>\n' >> "$LOG"

echo "Starting tcpdump — Ctrl-C to stop early."
# -s 0 full packets, -w write, one file (rotation adds complexity for a short take)
exec tcpdump -i "$IFACE" -s 0 -w "$PCAP" -Z root \
    "not host 127.0.0.1" &
TCPDUMP_PID=$!

# Auto-stop after MINUTES unless interrupted.
( sleep "$((MINUTES * 60))"; kill "$TCPDUMP_PID" 2>/dev/null || true ) &
wait "$TCPDUMP_PID" 2>/dev/null || true
echo "Capture written: $PCAP"
echo "Operator log:    $LOG  (fill in the scenario times, then run label_capture.py)"
