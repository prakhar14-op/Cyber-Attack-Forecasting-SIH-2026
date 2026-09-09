# Design System

## Principle

A premium **dark SOC (Security Operations Center) aesthetic**: deep, calm backgrounds,
glass panels, high data density made legible through generous radius, soft shadows and a
consistent typographic rhythm. **Accessibility and readability take priority over
decoration** — if a visual flourish reduces contrast or legibility, drop it.

## Store all design tokens

All design values live as **tokens** (CSS variables + a Tailwind theme extension) in one
place (`styles/`). Components reference tokens, never hardcoded hex/px. Changing a token
must ripple through the whole app.

## Color

### Base (dark, primary)
```
--bg-void:      #060d1a
--bg-page:      #0a1424
--bg-panel:     #0f1c30
--bg-card:      #12233b
--bg-elevated:  #16294a
--border-soft:  rgba(96,165,250,0.08)
--border-med:   rgba(96,165,250,0.16)
--text-main:    #e8f0fe
--text-sub:     #9db8e0
--text-muted:   #5f83b8
--accent:       #38bdf8
--accent-dim:   rgba(56,189,248,0.08)
--accent-deep:  #2563eb
```

### Semantic attack-stage colors
Each of the 7 stages has a fixed color used everywhere it appears (badges, timeline
bands, graph nodes, legends). Do not vary these per view.
```
benign            #34d399   green
recon             #38bdf8   cyan
initial_access    #a78bfa   violet
lateral_movement  #f59e0b   amber
c2                #fb7185   rose
exfiltration      #f43f5e   red
impact            #ef4444   deep red
```
General status: success `#34d399`, warn `#f59e0b`, danger `#ef4444`, info `#818cf8`.
Probability magnitude uses a single continuous cool→hot ramp (YlOrRd-style), reused for
graph nodes and SHAP magnitude so the same encoding means the same thing everywhere.

## Typography

- Headings / display values: **Space Grotesk** (700–900).
- Body: **Inter** (400–600).
- Data, labels, mono, code: **JetBrains Mono**.
- **Self-host all fonts** as local `.woff2` via `@font-face` — no CDN import (offline).
- Type scale: 32 / 24 / 18 / 15 / 13 / 11 / 9 px.
- Apply `font-variant-numeric: tabular-nums` to all numeric metrics so values don't jitter.

## Spacing

- 4px base unit. Card padding 16–18px. Grid gaps 10–12px. Section rhythm 20–24px.
- Keep spacing consistent across pages via tokens/utilities, not ad-hoc values.

## Border, radius, shadows

```
--r-sm: 8px    --r-md: 12px    --r-lg: 16px    (pills: 999px)

--border-soft: rgba(96,165,250,0.08)
--border-med:  rgba(96,165,250,0.16)

--shadow-sm: 0 1px 3px rgba(4,10,22,0.5)
--shadow-md: 0 4px 14px rgba(4,10,22,0.55)
--shadow-lg: 0 12px 34px rgba(4,10,22,0.65)
--glow-accent: 0 0 20px rgba(56,189,248,0.18)
```

## Glass / gradients

- Glass: `rgba(18,35,59,0.55)` + `backdrop-filter: blur(14px)` + `--border-soft`.
  Fully local; use for overlays, side panels, top bar.
- Gradient text: `linear-gradient(135deg,#38bdf8,#818cf8)`.
- Threat gradient: `linear-gradient(90deg,#34d399,#f59e0b,#ef4444)`.

## Accessibility & readability (priority)

- Maintain WCAG AA contrast for text and essential UI against panel backgrounds.
- Never encode meaning by color alone — pair stage/severity color with a label or icon.
- Visible focus rings (`:focus-visible`), keyboard-navigable controls, ARIA labels on
  charts and interactive graph elements.
- Honor `prefers-reduced-motion` (see `visualization.md`).
- Prefer legibility over density: if a data-dense panel becomes hard to scan, simplify.
