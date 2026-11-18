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

## Appearance settings (Settings → Appearance)
Applied as attributes on `<html>` so CSS alone reacts:
`data-theme="dark|light"` (System resolves via `prefers-color-scheme`), `data-density="comfortable|compact"`,
`data-motion="full|reduced"` (also forced by OS `prefers-reduced-motion`), `--font-mono`, root `font-size`.
- Compact density: row height 28 px (vs 36), card padding 12 px (vs 16), table font 12 px.
- Reduced motion: no map arcs/pulses, no chart transitions, tray icon does not blink.

## Shape & spacing
- Radius 6 px (inputs, buttons), 10 px (cards). Spacing scale 4 px.
- Borders over shadows in dark mode; soft shadows allowed in light mode.
- Motion: 150–200 ms ease-out; respect `prefers-reduced-motion` (map arcs become static dots).

## Logo concept
A shield outline drawn with a single stroke. Inside, three horizontal "packet" bars enter from the left;
the middle one is crimson and stops at a vertical ward line — packets stopped at the gate. Must read at 16 px
(favicon/tray: shield + one crimson bar). Wordmark: "Packet" in `--text`, "Ward" in `--brand`, Bricolage Grotesque SemiBold.
Tray icon states: neutral (Guardian off), crimson (Active), crimson pulsing (blocking now), amber (Monitor).
