# PacketWard — instructions for Claude Code

PacketWard is a source-available network defense and diagnostics toolkit for **Windows Server VPS / RDP machines**,
built by XeroHost for its customers. It helps a non-expert answer, in minutes:
*"Am I being attacked? From where? How much? Is it my network or the route? Block it."*

Stack: **Rust** (Cargo workspace) + **Tauri 2** desktop shell + **Vue 3 / TypeScript** UI.
Target OS: Windows Server 2019/2022/2025 and Windows 10 1809+/11 (x64). Core logic must also build and test on Linux.
License: PolyForm Shield 1.0.0 (source-available; see `LICENSE`).

## Read these first (in order)
1. `docs/DECISIONS.md` — settled product decisions. Do not re-open them.
2. `docs/ARCHITECTURE.md` — crates, processes, data flow, security model. **Source of truth.**
3. `docs/ROADMAP.md` — milestones with acceptance criteria. Work one milestone at a time.
4. `docs/DESIGN.md` — color tokens, typography, appearance settings, UI rules.
5. `apps/desktop/CLAUDE.md` — frontend conventions (only when touching the UI).

If code and `ARCHITECTURE.md` disagree, stop and ask, or update the doc in the same change with a short rationale.

## How to work in this repo
- Pick the **first unchecked milestone** in `docs/ROADMAP.md`. Plan, implement, test, then tick the boxes.
- Keep changes small and vertical (proto type → engine → IPC → UI) rather than building every crate in isolation.
- Never invent a new crate, process or IPC channel without adding it to `ARCHITECTURE.md`.
- When a Windows API is involved, write a trait in the platform-agnostic crate and a `#[cfg(windows)]` impl
  in a `sys/windows.rs` module, plus a `fake` impl for tests. Most logic must be testable on Linux.

## Commands
```bash
# Rust
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                     # Linux: Windows-only crates compile their fakes
cargo deny check                           # licenses + advisories

# Frontend (apps/desktop)
pnpm install
pnpm lint && pnpm typecheck && pnpm test
pnpm tauri dev                             # Windows only; needs the agent service installed and running
# Dev agent: cargo run -p packetward-agent -- run --console   (elevated shell, no service install)

# Regenerate TS types from Rust (pw-proto -> apps/desktop/src/types/generated)
cargo test -p pw-proto --features ts-export
```
A change is done only when fmt, clippy, tests, lint and typecheck all pass.

## Rust rules
- Edition 2021, stable toolchain pinned in `rust-toolchain.toml`. MSRV is what that file says.
- Libraries: `thiserror` errors. Binaries: `anyhow` at the edges only.
- **No `unwrap()` / `expect()` outside tests** except for truly impossible states, with a comment.
- `unsafe` only inside `sys/` modules, each block with a `// SAFETY:` comment.
- Async runtime: `tokio`. Logging: `tracing` (never `println!` in libraries).
- Hot paths (packet processing) must not allocate per packet, must not block, and use **bounded** channels
  with drop-and-count on overflow. Never send per-packet events to the UI — aggregate.
- **Do not shell out** to `netsh`, `powershell`, `cmd` or `route` for core features. Use Win32/COM via the
  `windows` crate. (Exception: the support bundle may run read-only diagnostic commands.)
- Every IPC/proto type lives in `pw-proto`, derives `Serialize, Deserialize, TS`, and is versioned.

## Safety rules (non-negotiable — this tool can lock people out of their servers)
- The Guardian/auto-blocker must **never** block: the current RDP client IPs, allowlisted IPs/CIDRs,
  default gateway, configured DNS servers, loopback, and the XeroHost management ranges in config.
- Every automatic block has a TTL, is written to the audit log, and is reversible with `pwctl unblock --all`.
- All PacketWard firewall rules live in the rule group `PacketWard` and are removed on uninstall.
- Rate-limit automatic blocks (circuit breaker). Fresh installs start in **Monitor** (dry-run) mode.
- Blocklists (XeroHost shared list, public lists) go through the same protected set; the XeroHost list
  is rejected unless its minisign signature verifies against the pinned public key.
- No telemetry. No network calls except: update check, speed test servers, GeoIP DB download, enabled
  blocklist refreshes, and AbuseIPDB **only when the user configured a key**. Proxy settings apply to all.
- The support bundle is written locally only. Never upload it.
- Secrets (API keys) go to Windows Credential Manager via `keyring`, never to plain config or logs.

## Licensing constraints
- **Npcap must NOT be bundled** in the installer (its free license forbids redistribution). Detect it at
  runtime, load `wpcap.dll` lazily, and offer a link to npcap.com. Without Npcap, fall back to the built-in
  raw-socket backend. The app must start fine without Npcap installed.
- GeoIP: DB-IP Lite (CC BY 4.0) with attribution in About. Do not ship MaxMind GeoLite2 files.
- Public blocklists are downloaded at runtime by the user's choice, never committed or bundled.
- The project is source-available under PolyForm Shield 1.0.0: new dependencies must be redistributable under
  permissive licenses (MIT, Apache-2.0, BSD, ISC, Zlib, MPL-2.0, Unicode; OFL for fonts) and pass `cargo deny`
  (see `deny.toml`). Add `// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0` to new source files.

## Git
- Conventional Commits (`feat(capture): …`, `fix(guardian): …`). One milestone item per commit when practical.
- Do not commit generated binaries, `.pcapng` captures larger than 1 MB, or anything under `target/`.
