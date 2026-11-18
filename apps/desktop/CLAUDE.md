# Desktop app (Tauri 2 + Vue 3) — conventions

## Stack
- Vue 3 `<script setup lang="ts">`, Vite, TypeScript strict, Pinia, Vue Router, pnpm.
- Tailwind CSS v4 with tokens from `docs/DESIGN.md` (`src/styles/tokens.css`). No raw hex in components.
- **shadcn-vue** components live in `src/components/ui/` (generated, then themed to Crimson Sentinel; edit freely).
- Icons: `lucide-vue-next`; utilities: VueUse.
- Fonts (self-hosted via `@fontsource`): Bricolage Grotesque (headings), Geist Sans (body),
  JetBrains Mono (default mono) + Geist Mono. Mono is user-selectable through `--font-mono`.
- Charts + world map: ECharts via `vue-echarts` (tree-shaken imports). World GeoJSON bundled (Natural Earth).
- Tables: TanStack Vue Table + TanStack Virtual for anything that can exceed 200 rows.
- i18n: vue-i18n. `en` is the base and fallback. On first run detect the OS locale (Rust side,
  `sys-locale`): `es-*` → `es`, `pt-*` → `pt-BR`, else `en`. User override in Settings → Language.
- Tauri plugins: updater, notification, autostart, single-instance, dialog, opener; tray icon enabled.
- Tests: Vitest + @vue/test-utils. Lint: ESLint (flat config) + Prettier.

## Layout
```
src/
├─ app/            # main.ts, router, i18n setup, appearance (theme/density/size/motion/mono)
├─ api/            # ONLY place that calls invoke()/Channel. Typed wrappers per domain.
├─ types/generated # ts-rs output from pw-proto (never edit by hand)
├─ stores/         # Pinia: agent, live, alerts, guardian, firewall, diag, intel, settings, appearance
├─ features/<x>/   # page + components per feature (dashboard, traffic, capture, guardian, …)
├─ components/ui/  # shadcn-vue primitives
├─ components/pw/  # app-specific shared parts (StatTile, IpCell, SeverityBadge, LiveChart, DataTable)
├─ styles/
└─ locales/        # en.json (source of truth), es.json, pt-BR.json
```

## Rules
- Components never call Tauri directly — go through `src/api/*`.
- The UI requires the agent service. If the pipe is unavailable, route to `AgentUnavailable` view
  (Start / Repair buttons → elevated helper), never to a half-working app.
- Live data: stores keep fixed-size ring buffers (e.g. 300 points); never grow arrays unbounded.
  Throttle chart updates to the agent tick; pause rendering when the window is hidden (tray only).
- Notifications are shown by this process (the service cannot show UI). Keep a lightweight alert
  subscription alive while minimized to tray.
- Every string through i18n, keys in `en.json` first. `es` and `pt-BR` must be complete before closing a milestone.
- IPs, ports and hostnames render in mono with a copy button and a context menu (Lookup, Block, Allow, MTR).
- Destructive or lockout-capable actions (block CIDR, disable firewall, Guardian Active, purge) need a
  confirmation dialog that states the consequence.
- Empty/error states explain the cause and the fix (e.g. "Npcap not installed — basic capture active. Install
  Npcap for full capture.").
- Branding stays discreet: "by XeroHost" footer, About page, "Contact XeroHost support" link. No promotions.
- Accessibility: keyboard navigation for nav and tables, visible focus ring (`--brand`), AA contrast,
  respect Appearance → reduce motion.
- Window: min 1100×700; must work at 1280×720 inside an RDP session (test with Compact density too).

## Notes from M0
- UI preferences (language + Appearance) live in `%AppData%\PacketWard\ui.json`, read/written by the Rust
  commands `ui_prefs_load` / `ui_prefs_save` (`src-tauri/src/prefs.rs`, validated, atomic write). The TS side
  is `src/api/uiPrefs.ts`; keep both in sync. Outside Tauri (browser, Vitest) the defaults apply and nothing is saved.
- ESLint forbids importing `@tauri-apps/*` outside `src/api/`.
- TypeScript is pinned to 6.0.x: `vue-tsc` and `typescript-eslint` do not support 7.x yet.
- shadcn-vue's CLI imports `cn` from the `cn` package and icons from `@lucide/vue`; after `shadcn-vue add`,
  rewrite those to `@/lib/utils` and `lucide-vue-next` and drop the extra packages.
- The branding-kit logos carry their own rounded background (dark: `#0B0F19`, light: white). Use them as shipped.
