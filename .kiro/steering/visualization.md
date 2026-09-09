# Visualization

## Core rule: 3D must be meaningful

Use 3D **only where it communicates network/attack structure that 2D cannot**. 3D is
not a style choice; it must earn its place by revealing structure.

### 3D is justified for
- **Host attack graph** — nodes are hosts, edges are flows. This is the graph the TGN
  encoder actually operates on (`result.graph`). A 3D force layout separates dense
  clusters, exposes attacker→victim fan-out and blast radius, and lets edges leaving an
  alerting host glow red to tell a propagation story. This is the flagship 3D view.
- **Temporal attack progression** — replaying the host graph across window time to show
  the kill chain forming and to make **lead time** legible (first-alert and
  attack-completion markers). Driven by the timeline scrubber.

### The only allowed decorative 3D
- A single low-cost ambient shader **backdrop on the landing page**. This is the one
  exception to "3D must be meaningful." It is confined to the landing route, DPR-capped,
  and disabled under reduced motion. **Nowhere else may 3D be purely decorative.**

## Prefer 2D for
- **SHAP / feature contributions** — signed 2D bars (sign and magnitude must stay clear;
  3D would obscure them).
- **Forecast metrics** — 2D line charts for AUROC-vs-horizon and lead-vs-horizon.
- **Ledger information** — a 2D chain-of-blocks / hash-link diagram, not a 3D scene.
- Timelines, distributions, KPI trends, tables.

## Reduced motion

- Respect `prefers-reduced-motion`. When set: disable the landing shader, stop graph
  auto-orbit and looping animations, and fall back to a static 2D graph rendering.
- Keep interactions available without animation; animation is enhancement, never a
  requirement for using a view.

## Real data only

- **Every visualization uses real SIH data** from the backend
  (`predict_file` result, `panels.*`, `eval/ablation.py`, `results/`, the ledger).
- Never fabricate nodes, edges, alerts, probabilities, forecast points, or metrics to
  fill or "improve" a chart. An empty or sparse result renders as empty/sparse.
- Named features in explanations must be the real feature names (e.g. `distinct_dst_ips`,
  `payload_hist_3`), never embedding indices or invented labels.
- Attack-stage colors and the probability ramp follow `design-system.md` consistently
  across every chart and the 3D graph.

## Performance & offline

- Bundle Three.js / R3F and all chart libraries locally — no CDN, no runtime fetches.
- Cap device pixel ratio and node/edge counts in the 3D scene for smooth interaction;
  when the graph is trimmed for readability, say so in the UI (never silently drop data).
