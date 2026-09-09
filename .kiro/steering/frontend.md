# Frontend

## Stack

- **React 18 + TypeScript + Vite.**
- Tailwind CSS for styling, driven by the design tokens (see `design-system.md`).
- `motion` (Framer Motion) for animation, `lucide-react` for icons.
- Recharts for 2D charts; Three.js / React Three Fiber only for the 3D host graph
  and the landing backdrop (see `visualization.md`).
- All dependencies must be bundled locally — **no CDN, no runtime downloads**.

## Architecture: component-first

- **Component-first.** Build the UI from small, composable, single-responsibility
  components. Compose pages out of components; do not grow logic inside pages.
- **Prefer reusable components.** Shared primitives live in a common components layer
  (e.g. `Panel`, `GlassPanel`, `KPICard`, `StatusPill`, `StageBadge`, `SeverityBar`,
  `AnimatedNumber`, `Skeleton`, `SectionHeader`). Reach for an existing primitive before
  writing a new one; promote a pattern to a shared component once it appears twice.
- **Avoid giant page components.** A page file orchestrates layout and data wiring only.
  If a page component grows large or accumulates rendering logic, extract sections into
  child components. No monolithic multi-hundred-line page files.

## Separation of concerns

- **Keep API access separate from UI.** All backend communication goes through a
  dedicated data/service layer (e.g. `services/api.ts` plus typed hooks). Components
  receive data via props or hooks and never call `fetch` directly.
- Define TypeScript interfaces for the backend data contract in one place and import
  them everywhere; the contract mirrors the Python result dict exactly.
- Keep presentational components pure where possible; isolate side effects (fetching,
  polling the bridge, file upload) in hooks/services.

## TypeScript

- **Use strict TypeScript.** Enable `strict` in `tsconfig` (`noImplicitAny`,
  `strictNullChecks`, etc.). No `any` in committed code except at genuinely untyped
  boundaries, and even then prefer `unknown` + narrowing.
- Type every API response, component prop, and hook return value.
- Model backend enums (attack stages, decisions) as string-literal union types.

## Structure (suggested)

```
frontend/src/
  app/            # routing + page shells (thin)
  components/     # reusable primitives + domain components
  features/       # feature-scoped composites (dashboard, graph, incident, ledger...)
  services/       # api.ts, hooks, typed data layer (no UI here)
  styles/         # tokens, tailwind theme, @font-face
  types/          # shared TypeScript interfaces (backend contract)
```

## Quality bar

- Build must succeed with zero TypeScript errors.
- Confirm no external network requests in the browser Network panel (offline mandate).
- Every rendered metric traces to real backend output — never fabricate values.
