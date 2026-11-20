# PacketWard — Design system ("Warm Sentinel")

## Principle
Calm and simple, in the spirit of Claude Desktop: warm neutral greys, generous space, almost no borders, and **one**
accent. Colour carries meaning only where it matters:
- **Sky blue** (`--brand`, the blue of "Ward" in the logo) is the accent: the primary action, links, focus ring. Never a status.
- **Red** (`--danger`) is a threat: attacks, blocked traffic, high/critical alerts, an exposed RDP.
- **Green** (`--success`) is protected: Guardian Active, healthy, allowed.
- **Amber** (`--warning`) is look at this: Guardian Monitor, thresholds, a peer that is not trusted.
- **Blue** (`--info`, the same family as the accent) is inbound traffic and neutral information; violet is outbound.
Never encode meaning with colour alone: pair it with an icon, a word or a shape.

## Color tokens
Defined as CSS variables on `:root[data-theme="dark"]` (default) and `:root[data-theme="light"]`, exposed to
Tailwind v4 via `@theme`. Components use **semantic tokens only**, never raw hex.

| Token | Dark (default) | Light | Use |
|---|---|---|---|
| `--bg` | `#1C1B1A` | `#EBE8DF` | The window (and the sidebar, which has no background of its own) |
| `--surface` | `#262624` | `#FAF9F5` | The content panel |
| `--surface-2` | `#2F2E2B` | `#F1EFE7` | Inputs, wells, hover |
| `--surface-3` | `#3A3835` | `#E6E3D8` | Selected pill, menus |
| `--border` | `#3A3835` | `#DDD9CC` | Rarely: dividers are `--hairline` |
| `--text` | `#ECE9E1` | `#1F1E1D` | Primary text |
| `--text-muted` | `#A09D94` | `#6B685F` | Secondary text |
| `--brand` | `#0284C7` | `#0284C7` | Primary button fill |
| `--brand-hover` | `#0369A1` | `#0369A1` | Hover / pressed |
| `--brand-fg` | `#38BDF8` | `#0369A1` | Accent text, links, icons on the background |
| `--on-brand` | `#FFFFFF` | `#FFFFFF` | Text on the primary fill |
| `--danger` | `#E5786D` | `#C0392B` | Threat |
| `--warning` | `#E0A94F` | `#A8680F` | Attention |
| `--success` | `#7DBB8A` | `#2F7D4A` | Protected, healthy |
| `--info` | `#38BDF8` | `#0369A1` | Inbound traffic, information |
| `--glow` | green at 35 % | green at 25 % | The Guardian-active halo |

Text on a `--danger`, `--warning` or `--success` fill uses `--bg` (dark text on the soft colours); only the blue
fill takes white. Measured and re-checked when a token changes.

### Flags and the attack map
- Country flags are SVG images (`country-flag-icons`, MIT), never emoji (Windows draws those as two letters), shown before every address (`IpCell`, the Connections grid) and in the country lists. Each flag is a lazy chunk; private and unknown addresses show none, and without a GeoIP database nothing is asked or shown.
- Placement is local: `stores/geo.ts` batches lookups to the agent (`intel.lookup`, GeoIP database) and remembers the answers.
- **Attack map** (Threat Intel): world countries from Natural Earth via `world-atlas` (ISC) + `topojson-client` (ISC), regions named by ISO alpha-2 (`i18n-iso-countries`, MIT), shaded in `--danger` by how many distinct addresses are behind alerts and blocks, with the top countries beside it. Trusted (protected) sources are never counted as attackers.

### Chart palette
- Inbound: `--info` (blue) · Outbound: violet (`#B49AD6` dark, `#8266B0` light) · Blocked/attack: `--danger` · Warning: `--warning`.
- Protocols: TCP `--info`, UDP violet, ICMP `--warning`, Other warm grey.
- Map: land `--surface-2`, borders `--border`, server marker `--info`, attack arcs `--danger` with `--glow`.
- Never encode meaning with color alone: pair with icon, label or pattern.

## Typography
- Headings: **Bricolage Grotesque** (SemiBold/Bold, h1–h3, page titles, big stat numbers).
- Body / UI: **Geist Sans** (Regular/Medium). Numbers: `font-variant-numeric: tabular-nums`.
- Both self-hosted as WOFF2 (`@fontsource` packages, OFL license) — no CDN, servers may be offline.
- Mono (IPs, ports, MTR tables, logs): **configurable** via `--font-mono`. Default **JetBrains Mono**; options
  Geist Mono and System (`Consolas, "Cascadia Mono", monospace`). JetBrains Mono and Geist Mono are bundled.
- Scale: 12 / 13 / 14 (base) / 16 / 20 / 24 / 32. Dense UI: base 14, tables 13.
- Text size setting multiplies the root font size (90 / 100 / 110 / 125 %); use `rem` everywhere.

## Layout: floating panels (2026-11 redesign)
Inspired by the structure of Zen Browser's UI, not its functions.
- **Title bar** (40 px, `--titlebar-h`): the window has no native frame. Brand at the left over the sidebar, a drag area,
  the Agent and Guardian status at the right, and Windows-style minimize / maximize / close (46 px wide; close turns `--danger`).
  The agent-unavailable and connecting screens carry the same bar, so the window can always be moved and closed.
- **Sidebar** (216 px, `--sidebar-w`): no background and no divider; it *is* the window. Four small section labels
  (Observe, Defend, Tools, System). The active page is a soft panel-colored pill that slides between rows on a spring;
  each icon draws itself once when its row is hovered or focused. The active page is not coloured.
- **Panel**: one container, `--radius-panel` 14 px, `--gutter` 8 px from the window edge (right and bottom), `--surface` fill,
  an inset 1 px `--hairline` instead of a border. The page title (Bricolage Grotesque 28 px) is the first thing inside it.
- **Backdrop**: solid `--bg` by default. With **Mica** (`<html data-backdrop="mica">`, Windows 11 build 22000+ with
  transparency effects on) the window is transparent and the sidebar shows the system material; the panel stays opaque.
  Windows Server 2019/2022 and Windows 10 never get Mica.
- **Composition per page, not a template.** No row of identical cards with a big number on every page. The Dashboard has
  one hero (inbound traffic, the biggest type on the screen) with the chart under it, a quiet "Protection" column beside it,
  plain rows below. Other pages are recomposed for their task.
- **Forbidden:** decorative gradients, emojis, everything centered, colour as decoration, animated backgrounds.

### Page vocabulary (shared by every page)
Pages are composed from a few primitives instead of boxed cards. Each page still has its own composition.
| Piece | What it is |
|---|---|
| `.pw-note` (`data-tone` warning / danger / success / info) | A notice inside a page: tinted rounded block, no border. Replaces every bordered alert. |
| `.pw-well` | A soft `--surface-2` block (12 px radius) for code, grouped controls and result summaries. |
| `.pw-rows` | Tables: quiet uppercase headers, hairline rows, no zebra, no outer border. |
| `.pw-dialog` | Native dialog: 18 px radius, hairline outline, veil behind; opens with `springDialog`. |
| `.pw-appear` | One short rise for something that appears inside a page (a result, a confirmation). |
| `SettingRow` | "What it is and why" on the left (16 rem), its controls on the right; rows split by hairlines. Used by Settings, RDP Shield, Threat Intel. |
| `TabBar` | Tabs over a hairline with an underline that slides on a spring (Firewall, Diagnostics). WAI-ARIA tabs. |
| `SegmentedControl` | Exclusive choices in a soft well with a sliding raised pill (Alerts filter). Radio-group semantics. |
| `CountingValue` | A live number that eases to its new value on a spring; the first value is shown as is. |
| `HIcon` / `components/pw/icons.ts` | Hugeicons (MIT) drawn as SVG; the stroke draws itself once on hover/focus. `icons.ts` keeps the names pages already use. |
- **Readout, not tiles:** key numbers sit on one line separated by hairlines (Traffic, Capture, Guardian, RDP Shield) or inside a hero (Dashboard, Speed test).
- **Fields:** `FIELD` is a soft `--surface-2` well with an accent focus ring and no border; buttons are 10 px with a press scale (`active:scale-[0.97]`); "outline" buttons are soft wells.
- **Severity** is a rail *and* a word (Alerts, RDP findings), never colour alone; red only for high/critical.
- Page transitions use Vue `<Transition :css="false">` with motion hooks (`panelTransition`) and a safety timer: the page always ends visible even if the window gets no animation frames (hidden or throttled).

### Layout tokens
| Token | Value | Use |
|---|---|---|
| `--radius-panel` | 14 px | The content panel |
| `--gutter` | 8 px | Panel inset from the window edge |
| `--titlebar-h` | 40 px | Title bar height |
| `--sidebar-w` | 216 px | Sidebar width |
| `--hairline` | text at 7 % (dark) / 8 % (light) | Dividers and panel outline: borders are almost invisible |
| `--hairline-strong` | text at 14 % / 16 % | Scrollbar thumbs, stronger separators |

## Motion
Library: **Motion for Vue** (`motion-v`). Vocabulary in `src/lib/motion.ts`: `springPage` (stiffness 420, damping 38) for pages and
panels, `springSnappy` (520/40) for the active-page pill and small controls, `springDialog` (360/30) for dialogs and popovers,
`exitFast` (120 ms ease-in) because exits are quicker than entrances, and a 25 ms list stagger.
- **Always on.** `<MotionConfig reduced-motion="never">` at the root; no CSS `prefers-reduced-motion` anywhere (Windows Server turns
  visual effects off and browsers read that as "reduce"). The only off switch is Settings > Appearance > **Reduce animations**,
  off by default and ignoring the system (`data-motion="reduced"`, which also stills the status halo).
- **Where:** hover and focus feedback, page entry (rise 10 px + fade, spring) and exit (drop 4 px, 120 ms), dialogs, list rows entering
  with a stagger, live numbers easing to their new value (`CountingValue`, spring), icons drawing their stroke once (`HIcon`).
- **Where not:** infinite loops and animated backgrounds (particles, stars, gradients). The one allowed loop is a *state* indicator:
  the Guardian "active" halo (`.pw-pulse`).
- **Cost:** transform and opacity only; it has to be smooth over RDP on a VPS without a GPU. The traffic chart does not animate.
- **Icons:** Hugeicons free (MIT) through `src/lib/icons.ts` and `HIcon.vue`. Add an icon by exporting it from that file.

## Appearance settings (Settings → Appearance)
Applied as attributes on `<html>` so CSS alone reacts:
`data-theme="dark|light"` (System resolves via `prefers-color-scheme`), `data-density="comfortable|compact"`,
`data-motion="full|reduced"` (set **only** by the "Reduce animations" setting, off by default; the OS preference is ignored on purpose, see Motion), `data-backdrop="mica|solid"` (set by the shell), `--font-mono`, root `font-size`.
- Compact density tightens the whole app through tokens in `tokens.css` (components and pages read them, nothing hard-codes a height):
  `--row-h` 28 px (36), `--control-h` 30 px (36: buttons, inputs, selects), `--control-sm-h` 26 px (32), `--nav-h` 30 px (36), `--card-p` 12 px (16),
  `--table-fs` 12 px (13), page padding 24/20/24 px (36/32/40), page title 22 px (28) with a 16 px gap (28), `--section-gap` 32 px (56),
  `--setting-py` 18 px (28), `--stack-gap` 10 px (16). New components must use these tokens instead of fixed `h-9`/`py-7`.
- **Window theme.** With the Mica backdrop the system draws the window (title bar, sidebar) in the *window's* theme, which is the OS one unless
  the app sets it. `appearance` calls `setWindowTheme(light|dark)` whenever the resolved theme changes (capability `core:window:allow-set-theme`),
  so a light app on a dark system no longer keeps a black window behind the panel.
- Reduced animations: no page, list or number animation, no icon drawing, no Guardian halo, no map arcs; the tray icon does not blink.

## Shape & spacing
- Radius 6 px (inputs, buttons), 10 px (rows, pills, cards), 14 px (the content panel). Spacing scale 4 px; page padding 36 px sides, 32 px top.
- Borders over shadows in dark mode; soft shadows allowed in light mode.
- Motion: springs and short ease-out tweens, see Motion above. Never gated on `prefers-reduced-motion`.

## Logo concept
A shield outline drawn with a single stroke. The logo files in `branding-kit/` have no background and are copied to `src/assets/brand/`. Inside, three horizontal "packet" bars enter from the left;
the middle one is the accent colour and stops at a vertical ward line — packets stopped at the gate. Must read at 16 px
(favicon/tray: shield + one accent bar). Wordmark: "Packet" in `--text`, "Ward" in `--brand`, Bricolage Grotesque SemiBold.
Tray icon states: neutral (Guardian off), green (Active), red pulsing (blocking now), amber (Monitor).
