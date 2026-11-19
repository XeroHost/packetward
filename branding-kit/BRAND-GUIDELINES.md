# PacketWard — Manual de Identidad Visual & Branding Kit

## 1. Concepto y Geometría del Isotipo (Trazos Diagonales 45°)

El nombre **PacketWard** fusiona **Packet** (paquetes de red / flujo de datos) y **Ward** (escudo / custodia perimetral).

- **Escudo Hexagonal Abierto (45° Cyber-Defense):** Construido exclusivamente con líneas rectas ortogonales (`0°` y `90°`) y bordes biselados a **`45°`**, evitando las curvas de un escudo medieval clásico. El flanco superior-izquierdo permanece abierto en ángulo de `45°` formando una compuerta de recepción de tráfico.
- **Tres Paquetes Diagonales Entrantes (`45°`):** Tres trazos paralelos entran a `45°` simulando paquetes de red:
  - Los dos trazos laterales (`#F8FAFC` en modo oscuro / `#0F172A` en modo claro) representan tráfico legítimo inspeccionado.
  - El **trazo central** (`#38BDF8`) viaja sobre el eje axial `y - x = 2` e impacta en el corazón del escudo (`x=35, y=37`), donde se transforma en un **pulso / nodo bloqueado** (rombo a `45°` con núcleo de intercepción `#F43F5E`).
- **Escalabilidad Extremo a Extremo:** Diseñado sobre una retícula modular de `64×64` (múltiplo exacto de `16×16 px`) con variante micro *pixel-hinted* para barras de título y bandeja del sistema en **Windows Server**.

---

## 2. Sistema Tipográfico Oficial

- **Con el Logo (`PacketWard` / `PACKETWARD`):** `Bricolage Grotesque`
  - **`Packet`** en peso **SemiBold (600)** — color neutro principal (`#F8FAFC` sobre oscuro / `#0F172A` sobre claro).
  - **`Ward`** en peso **Bold (700)** — color acento de marca (`#38BDF8` sobre oscuro / `#0284C7` sobre claro).
  - *Tracking principal:* `-0.025em` · *Tracking versión mayúsculas (`PACKETWARD`):* `+0.12em`.
- **Headings (Títulos y Encabezados):** `Bricolage Grotesque` (SemiBold 600 / Bold 700).
- **Body (Cuerpo de texto, UI y Subtítulos):** `Geist Sans` (Regular 400 / Medium 500).

---

## 3. Paleta de Color Oficial

| Rol | Nombre del Token | HEX | RGB | Uso Principal |
| :--- | :--- | :--- | :--- | :--- |
| **Fondo Base** | `Obsidian Canvas` | `#060911` | `6, 9, 17` | Fondo exterior, banners y consola |
| **Superficie** | `Armor Slate` | `#0B0F19` | `11, 15, 25` | Fondo de paneles, ventanas e interior del nodo |
| **Acento Principal** | `Ward Cyan` | `#38BDF8` | `56, 189, 248` | Logotipo `Ward`, paquete central y borde del nodo |
| **Acento Escudo** | `Custody Blue` | `#0EA5E9` → `#0284C7` | `14, 165, 233` | Gradiente estructural del escudo biselado |
| **Intercepción** | `Blocked Pulse` | `#F43F5E` | `244, 63, 94` | Núcleo del nodo central bloqueado / alerta |
| **Paquetes / Texto** | `Pure Packet` | `#F8FAFC` | `248, 250, 252` | Logotipo `Packet` y paquetes laterales |

---

## 4. Inventario de Archivos del Branding Kit

- `packetward-icon.svg` / `.png` — Isotipo principal (fondo transparente, para temas oscuros).
- `packetward-icon-light.svg` / `.png` — Isotipo para fondos claros.
- `packetward-icon-mono-white.svg` / `packetward-icon-mono-black.svg` — Versiones monocromáticas.
- `packetward-16x16.svg` / `.png` — Icono micro *pixel-hinted* para ventanas `16×16 px` en Windows Server.
- `packetward.ico` — Icono nativo de Windows con 6 resoluciones integradas (`16×16`, `24×24`, `32×32`, `48×48`, `64×64`, `256×256`).
- `packetward-logo-dark.svg` / `.png` — Logotipo horizontal principal sobre fondo oscuro.
- `packetward-logo-light.svg` / `.png` — Logotipo horizontal sobre fondo claro.
- `packetward-logo-uppercase.svg` / `.png` — Variante en mayúsculas `PACKETWARD`.
- `packetward-avatar.svg` / `.png` — Icono de aplicación / avatar de GitHub (`512×512 px`).
- `packetward-github-banner.svg` / `.png` — Banner oficial para repositorio de GitHub (`1280×640 px`).
- `packetward-construction-grid.svg` / `.png` — Plano técnico de construcción a `45°`.
- `design-tokens.css` & `design-tokens.json` — Tokens listos para producción.
- `index.html` & `packetward-branding-kit-board.png` — Presentación visual completa (`3×3` Brand Board).
