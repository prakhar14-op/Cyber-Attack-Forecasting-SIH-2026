"""Generate a SYNTHETIC demo capture (not a real lab capture).

    python -m capture.make_synthetic_demo

Writes app/assets/synthetic_demo.pcap + its operator log. This is an
ILLUSTRATIVE file so the offline app can be demonstrated on the full
packet-feature path (and can show lateral_movement / exfiltration, which no
public dataset contains) WITHOUT hardware. It is deterministic, hand-authored
traffic — NOT evaluation data, and never used for any reported metric. The real
lab capture (capture/capture.sh + attack_scenarios.md) remains the genuine M11
deliverable; see app/assets/README.md.
"""

from __future__ import annotations

import sys
from pathlib import Path

from scapy.all import IP, TCP, UDP, Ether, wrpcap

ATTACKER = "203.0.113.7"    # external attacker (documentation range)
VICTIM = "10.20.0.10"      # internal (10.0.0.0/8 is configured internal)
PIVOT = "10.20.0.20"       # internal pivot target
BENIGN = ["10.20.0.100", "10.20.0.101", "10.20.0.102"]
BASE = 1_760_000_000.0  # fixed epoch -> deterministic windows


def _pkt(ts, src, dst, sport, dport, flags="S", payload=b"", proto="tcp", ttl=64):
    if proto == "udp":
        p = Ether() / IP(src=src, dst=dst, ttl=ttl) / UDP(sport=sport, dport=dport) / payload
    else:
        p = (Ether() / IP(src=src, dst=dst, ttl=ttl)
             / TCP(sport=sport, dport=dport, flags=flags, seq=1, window=8192) / payload)
    p.time = ts
    return p


def build() -> tuple[list, list[str]]:
    pkts = []
    log = ["session_id\tsynthetic-demo", "iface\tsynthetic",
           "# columns: stage\tstart\tend\tattacker_ip\tvictim_ip"]

    def hhmmss(offset):
        import datetime
        return datetime.datetime.utcfromtimestamp(BASE + offset).strftime("%H:%M:%S")

    # 0. benign warm-up 0-120s: HTTP-ish request/response between benign hosts + victim
    t = 0.0
    while t < 120:
        b = BENIGN[int(t) % len(BENIGN)]
        pkts.append(_pkt(BASE + t, b, VICTIM, 40000 + int(t) % 2000, 80, "PA", b"GET / HTTP/1.1\r\n"))
        pkts.append(_pkt(BASE + t + 0.02, VICTIM, b, 80, 40000 + int(t) % 2000, "PA", b"200 OK " + b"x" * 400))
        t += 1.5
    log.append(f"benign\t{hhmmss(0)}\t{hhmmss(120)}\t\t")

    # 1. recon: sequential SYN scan attacker -> victim, ports 1..800 over 130-190s
    for i, port in enumerate(range(1, 801)):
        pkts.append(_pkt(BASE + 130 + i * 0.07, ATTACKER, VICTIM, 55000, port, "S"))
    log.append(f"recon\t{hhmmss(130)}\t{hhmmss(190)}\t{ATTACKER}\t{VICTIM}")

    # 2. initial access: SSH brute force -> victim:22, many SYN/PA over 200-260s
    for i in range(700):
        ts = BASE + 200 + i * 0.08
        pkts.append(_pkt(ts, ATTACKER, VICTIM, 56000 + i % 500, 22, "S"))
        pkts.append(_pkt(ts + 0.01, ATTACKER, VICTIM, 56000 + i % 500, 22, "PA", b"SSH-2.0-attempt" + b"z" * 20))
    log.append(f"initial_access\t{hhmmss(200)}\t{hhmmss(260)}\t{ATTACKER}\t{VICTIM}")

    # 3. lateral movement: internal SYN sweep victim -> pivot target, 30+ ports
    #    per window over 270-320s (an internal->internal scan reads as lateral)
    for i, port in enumerate(range(20, 220)):  # 200 ports, sequential
        pkts.append(_pkt(BASE + 270 + i * 0.25, VICTIM, PIVOT, 57000, port, "S"))
    log.append(f"lateral_movement\t{hhmmss(270)}\t{hhmmss(320)}\t{VICTIM}\t{PIVOT}")

    # 4. exfiltration: heavy outbound transfer victim -> attacker over 330-390s
    #    (~70 KB/window to a single peer, few SYNs -> the exfil signature)
    for i in range(3000):
        pkts.append(_pkt(BASE + 330 + i * 0.02, VICTIM, ATTACKER, 58000, 4444, "PA", b"D" * 1400))
    log.append(f"exfiltration\t{hhmmss(330)}\t{hhmmss(390)}\t{VICTIM}\t{ATTACKER}")

    # trailing benign so the last attack window closes cleanly
    for i in range(60):
        pkts.append(_pkt(BASE + 395 + i, BENIGN[i % 3], VICTIM, 41000 + i, 80, "PA", b"GET /"))

    pkts.sort(key=lambda p: p.time)
    return pkts, log


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    assets = root / "app" / "assets"
    assets.mkdir(parents=True, exist_ok=True)

    pkts, log = build()
    pcap = assets / "synthetic_demo.pcap"
    wrpcap(str(pcap), pkts)
    (assets / "synthetic_demo.operator-log.txt").write_text("\n".join(log) + "\n", encoding="utf-8")
    print(f"wrote {pcap} ({len(pkts):,} packets, synthetic — illustrative only)")
    print(f"wrote {assets / 'synthetic_demo.operator-log.txt'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
