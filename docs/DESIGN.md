# PacketWard — Design system ("Crimson Sentinel")

## Principle
Crimson means **threat or guard**. Use it for the brand mark, the primary action, Guardian state, attacks and
blocked traffic. Never as decoration. Legitimate/your own traffic is cyan. That way, when the screen turns red,
it means something.

## Color tokens
Defined as CSS variables on `:root[data-theme="dark"]` (default) and `:root[data-theme="light"]`, exposed to
Tailwind v4 via `@theme`. Components use **semantic tokens only**, never raw hex.

| Token | Dark (default) | Light | Use |
|---|---|---|---|
| `--bg` | `#0B0D12` | `#F6F7F9` | App background |
| `--surface` | `#11141B` | `#FFFFFF` | Cards, panels |
| `--surface-2` | `#171B24` | `#EEF0F4` | Inputs, table header, hover |
| `--surface-3` | `#1F2430` | `#E4E7EC` | Selected row, popovers |
| `--border` | `#262C38` | `#DCE0E7` | Dividers, outlines |
| `--text` | `#E8EAF0` | `#12151C` | Primary text |
| `--text-muted` | `#8A93A6` | `#5A6376` | Secondary text, axes |
| `--brand` | `#E8173F` | `#C40E34` | Primary button fill, active nav bar, logo |
| `--brand-hover` | `#C40E34` | `#960C28` | Hover/pressed |
| `--brand-fg` | `#FF4D6A` | `#C40E34` | Crimson text/icons on background |
| `--on-brand` | `#FFFFFF` | `#FFFFFF` | Text on brand fill |
| `--danger` | `#FF4D6A` | `#C40E34` | Attacks, blocked, critical alerts |
| `--warning` | `#F5A524` | `#B45309` | Suspicious, thresholds near |
| `--success` | `#2DD4A0` | `#047857` | Healthy, allowed, test passed |
| `--info` | `#22D3EE` | `#0E7490` | Legit inbound traffic, info |
| `--glow` | `rgba(232,23,63,.35)` | `rgba(196,14,52,.18)` | Guardian active halo, map arcs |

Measured contrast (WCAG): dark text on bg 16.2:1, muted 6.3:1, `--brand-fg` 6.0:1, white on `#E8173F` 4.5:1;
light text 17.0:1, muted 6.0:1, `#C40E34` on white 6.1:1. Do not use `#E8173F` for small text on dark (4.3:1).

### Chart palette
- Inbound: `--info` (cyan) · Outbound: `#A78BFA` (violet) · Blocked/attack: `--danger` · Warning: `--warning`.
- Protocols: TCP `#22D3EE`, UDP `#A78BFA`, ICMP `#F5A524`, Other `#8A93A6`.
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
  each icon draws itself once when its row is hovered or focused. Crimson is not used for the active page.
- **Panel**: one container, `--radius-panel` 14 px, `--gutter` 8 px from the window edge (right and bottom), `--surface` fill,
  an inset 1 px `--hairline` instead of a border. The page title (Bricolage Grotesque 28 px) is the first thing inside it.
- **Backdrop**: solid `--bg` by default. With **Mica** (`<html data-backdrop="mica">`, Windows 11 build 22000+ with
  transparency effects on) the window is transparent and the sidebar shows the system material; the panel stays opaque.
  Windows Server 2019/2022 and Windows 10 never get Mica.
- **Composition per page, not a template.** No row of identical cards with a big number on every page. The Dashboard has
  one hero (inbound traffic, the biggest type on the screen) with the chart under it, a quiet "Protection" column beside it,
  plain rows below. Other pages are recomposed for their task.
- **Forbidden:** decorative gradients, emojis, everything centered, crimson as decoration, animated backgrounds.

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
- Compact density: row height 28 px (vs 36), card padding 12 px (vs 16), table font 12 px.
- Reduced animations: no page, list or number animation, no icon drawing, no Guardian halo, no map arcs; the tray icon does not blink.

## Shape & spacing
- Radius 6 px (inputs, buttons), 10 px (rows, pills, cards), 14 px (the content panel). Spacing scale 4 px; page padding 36 px sides, 32 px top.
- Borders over shadows in dark mode; soft shadows allowed in light mode.
- Motion: springs and short ease-out tweens, see Motion above. Never gated on `prefers-reduced-motion`.

## Logo concept
A shield outline drawn with a single stroke. Inside, three horizontal "packet" bars enter from the left;
the middle one is crimson and stops at a vertical ward line — packets stopped at the gate. Must read at 16 px
(favicon/tray: shield + one crimson bar). Wordmark: "Packet" in `--text`, "Ward" in `--brand`, Bricolage Grotesque SemiBold.
Tray icon states: neutral (Guardian off), crimson (Active), crimson pulsing (blocking now), amber (Monitor).
