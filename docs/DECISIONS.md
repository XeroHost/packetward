# PacketWard — Product decisions (from the founder interview, 2026-11-18)

These are settled. Do not re-open them in code; if one blocks you, ask.

| Topic | Decision |
|---|---|
| License | **GPL-3.0-or-later**. All dependencies must be GPLv3-compatible (MIT, Apache-2.0, BSD, ISC, Zlib, MPL-2.0, Unicode, OFL for fonts). |
| Minimum OS | **Windows Server 2019+ / Windows 10 1809+**, x64. |
| Run model | **Agent service + desktop UI only. No portable mode.** The UI requires the agent service; if it is missing or stopped, the UI shows a screen to start/repair it. |
| Branding | **Discreet**: "by XeroHost" in sidebar footer and About, a "Contact XeroHost support" link, XeroHost speed-test nodes as defaults. No upsell or plan promotion in the app. Useful to anyone, not only XeroHost customers. |
| Guardian default | **Monitor** (dry-run) after install. User switches to Active explicitly. |
| Support bundle | **Local zip only.** Never uploaded. The user attaches it to their ticket. |
| Speed test servers | **XeroHost nodes (Miami, Brazil, …) + user-defined custom servers.** `tools/speed-server` is deployed by XeroHost. |
| Threat intel v1 | GeoIP + ASN offline (DB-IP Lite) · AbuseIPDB (user's own key) · public blocklists (opt-in, downloaded at runtime) · **XeroHost shared blocklist** from a public GitHub repo, signature-verified. |
| Shared blocklist source | Public repo `XeroHost/packetward-blocklist`: plain-text CIDR list + minisign signature, fetched via raw GitHub URL. Public key pinned in the app. |
| Languages | **English is the base and fallback.** Auto-detect system locale: `es-*` → Spanish, `pt-*` → Portuguese (BR), anything else → English. User can override in Settings. |
| Fonts | Headings **Bricolage Grotesque**, body **Geist Sans**, mono **configurable** (default **JetBrains Mono**; options Geist Mono, System mono/Consolas). |
| Settings → Appearance | Theme (Dark default / Light / System), mono font, density (Comfortable / Compact), text size (90 / 100 / 110 / 125 %), reduce motion. |
| Palette | **Crimson Sentinel** (see DESIGN.md). |
| Code signing | Not available yet. Releases start unsigned (SmartScreen warning documented in README); CI has an optional signing step that activates when secrets exist. |
| Repo docs language | English. |
| Alerts | **Windows toast notifications + tray icon** (color/state changes). No webhooks/email in v1. |
| CLI | **Basic `pwctl` in v1**: `status`, `guardian off|monitor|active`, `unblock --all`, `firewall purge`, `support-bundle`. |
| UI kit | **shadcn-vue** (components copied into the repo, on Reka UI + Tailwind v4). |
| Update channels | **Stable + Beta**, selectable in Settings. |
| Guardian: which RDP clients are protected (2026-11-19) | **Addresses with a successful RDP logon in the last 30 days** (configurable, 1–365): Security 4624 type 10 or 7 (remote address only) and TerminalServices 1149. Not "connected now", not `WTSClientAddress`, not every peer of the RDP port. Learned with `EvtSubscribe` plus one bounded initial load, never by searching the log. If the "Audit Logon" policy (success/failure) is off, the UI and `pwctl status` warn, because without those events neither the protection nor RdpBruteForce work. See ARCHITECTURE §6.3. |
