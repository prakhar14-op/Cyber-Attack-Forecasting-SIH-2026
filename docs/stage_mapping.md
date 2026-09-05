# Stage mapping (CIC-IDS-2018 attacks → 7 kill-chain stages)

The single source of truth for attack facts is [`data/attack_timeline.yaml`](../data/attack_timeline.yaml)
(UNB Table 2, verified 2026-09-05): attacker/victim addresses (internal testbed +
NAT'd public forms) and start/end times per attack. `data/timeline_labels.py` (M3)
turns that table into per-window stage labels — a window is labelled only if the
attacking/victim host actually transmits inside it (no smearing across the day).

## Provisional stage assignments (finalised with argument at M3)

| Day | Attack | Stage | Rationale (to be defended here at M3) |
|---|---|---|---|
| 2018-02-14 | FTP-BruteForce | `initial_access` | Credential guessing against a service = attempted entry |
| 2018-02-14 | SSH-Bruteforce | `initial_access` | Same, over SSH |
| 2018-02-16 | DoS-SlowHTTPTest | `impact` | Availability attack, no entry attempt |
| 2018-02-16 | DoS-Hulk | `impact` | Availability attack |
| 2018-02-28 | Infiltration (both sessions) | `c2` | External host drives an internal victim (reverse shell); in-interval internal scanning windows are `recon` candidates per-window |
| 2018-03-02 | Bot (both sessions) | `c2` | External C2 to ten infected internal machines |

`lateral_movement` and `exfiltration` have **no CIC-IDS-2018 coverage** — they come only
from our own lab capture (M11). Per-class metrics for them must always say so.

## Class counts

TBD — printed by the window builder at M3.4 and recorded here per split.
