# PacketWard — Threat model (review for 1.0)

Scope: the agent service, the pipe, the desktop shell/webview, the downloads (GeoIP, blocklists, speed nodes, updates),
the files in `%ProgramData%\PacketWard`, and the installer. This is a review of the design as built, with the
evidence (test or code) for each control and what is still open. See `docs/ARCHITECTURE.md` §8 for the model itself.

## Assets
1. **Availability of the server** — the worst failure of this tool is locking its owner out (RDP, DNS, gateway).
2. **Integrity of the firewall rules** — only PacketWard rules in the `PacketWard` group, never anything else.
3. **Confidentiality** of captures, support bundles, the AbuseIPDB key and the audit log.
4. **Integrity of the code path to the user**: installer, updates, blocklists.

## Trust boundaries
| Boundary | Who is on the other side | Control |
|---|---|---|
| Named pipe `\\.\pipe\packetward` | local processes | ACL: SYSTEM, Administrators, `PacketWard Operators` with a restricted mask (no `CREATE_PIPE_INSTANCE`); first-instance flag against name squatting; remote clients rejected; clients open with `SECURITY_IDENTIFICATION` |
| Webview → shell | the Vue app (compromise = XSS) | strict CSP, no remote content, no shell/fs plugin, one `agent_call` command with a **method allowlist** (`CALLABLE_METHODS`), dedicated commands for the few local actions |
| Agent → network | hostile servers / on-path attacker | HTTPS only for downloads (custom speed servers may use `http://` by choice); body-size caps; strict list parsing; minisign for the XeroHost list; error messages without URLs |
| Agent ↔ state files | non-admin local users | the data folder is restricted to SYSTEM + Administrators at every agent start, before any state is read |
| Installer / updater | supply chain | signed updater artifacts (key supplied by the owner, fail-closed with a placeholder), `cargo deny`, `cargo audit` in CI, unsigned-installer SmartScreen note |

## Threats and mitigations (STRIDE, abridged)
| # | Threat | Mitigation | Evidence |
|---|---|---|---|
| T1 | Guardian or a blocklist blocks the gateway, DNS, the admin's RDP client or the allowlist → lock-out | One protected set applied to manual blocks, Guardian and every list (carved out, re-applied each pass); Monitor by default; TTLs; circuit breaker; `pwctl unblock --all`; RDP Shield changes auto-revert in 120 s agent-side | `defense.rs`, `intel.rs`, `rdp_shield.rs` tests |
| T2 | Attacker spoofs the source of a flood so the Guardian blocks a legitimate address | Protected set; TTL ladder; one decision per incident; blocks wider than /8 refused | defense tests |
| T3 | A tampered or broken blocklist cuts everything | Cleaning (private ranges, too-broad blocks), size/line caps, last good list kept, signature required for the XeroHost list and **no list without a pinned key** | `pw-intel` + `intel.rs` tests |
| T4 | Local non-admin user controls the agent | Pipe ACL; the Operators group is a deliberate, documented grant; Guardian Active needs an explicit confirmation | pipe tests, TESTING §C/§D |
| T5 | Local user plants `defense.json` / `settings.json` (Active mode, allowlist, proxy) | Data folder ACL at start; unreadable files fall back to defaults | `sys/` ACL code, settings tests |
| T6 | Compromised webview calls arbitrary agent methods | Allowlist in the shell; the agent validates every payload | `bridge.rs` tests |
| T7 | Malformed IPC frames crash or exhaust the agent | 4 MB frame cap checked before allocating; typed errors; connection closed when the stream cannot be re-aligned | `crates/pw-ipc/tests/robustness.rs` (seeded random + mutation, in CI) and `crates/pw-ipc/fuzz` (cargo-fuzz target, run on a nightly toolchain) |
| T8 | A secret leaks to logs / bundles | Keys only in Credential Manager; `AbuseKeyRequest` has a redacted `Debug`; errors carry no URLs; the support bundle is local only and can anonymise local addresses | `pw-intel`, `support.rs` tests |
| T9 | Proxy setting used to exfiltrate | Proxy only carries the app's own allowed requests; credentials in the URL refused; change needs the pipe (admin/operator) | `settings.rs` tests |
| T10 | Spreadsheet formula injection from the audit export | Cells starting with `=`, `+`, `-`, `@` are neutralised | `stores/logs.test.ts` |
| T11 | Capture or detectors overwhelmed by an attack (DoS of the defender) | Bounded channels with drop-and-count, no per-packet allocation, aggregates only over IPC, "capture is blind" warning | capture/detect tests; load check pending (below) |
| T12 | Installer abuse (DLL planting, wrong ACLs) | Per-machine install under Program Files; the agent loads `wpcap.dll` only from an absolute system path; the installer script is tolerant and logs | `pw-capture` loader, installer hooks (reviewed statically) |
| T13 | (Planned, M11) An AI client uses the MCP server to block, unblock or reconfigure the firewall, or is steered by prompt injection hidden in hostnames, process names or payload text | Master switch off by default; execution tools disabled by default and set one by one; risky actions need a human approval in the desktop (5 min, the AI cannot approve); never-exposed list (firewall off/purge, RDP Shield, allowlist, protected set); protected set applies; write rate limit; audit actor `mcp`; untrusted fields marked and sanitized; enforcement in the agent per connection kind | ARCHITECTURE §6.14; tests listed in ROADMAP M11 (not written yet) |

## Residual risks and open items
- **A state file owned by a non-admin before the first protected start** is not detected (recorded in DECISIONS). Fresh installs are unaffected.
- **Operators group** members can switch the Guardian to Monitor/Active and unblock; treat membership as an admin-light grant.
- **MCP is a guardrail, not a sandbox** (planned, M11): pipe authorization is by group, so an AI client with a shell under an Operator account can call `pwctl` directly. Deny `pwctl` in the client's own permissions; Settings → MCP will say so.
- **Raw-socket capture is inbound-blind on the dev VPS** (hypothesis: Windows Firewall); the installer adds the allow rule, still to be verified on a test VPS (TESTING §F4).
- **The updater key was generated on the dev VPS** (2026-11-21) and its private half sits in a file there until the owner backs it up and the file is deleted (RELEASE-KEYS §1.4); it is also a repository secret, so anyone who can run Actions with secrets (repo admins, workflows on pushed branches) can sign. Keep the repo's collaborators few, review workflow changes, and rotate the key if in doubt. **No Authenticode certificate or blocklist key yet**: releases are unsigned for SmartScreen and the XeroHost list stays disabled.
- **Live verification pending** for every write path to the firewall, RDP and service control (they were exercised only with fakes on the dev VPS, by rule); see TESTING §F6–F11.
- **Fuzzing** with libFuzzer has not been run (nightly toolchain needed); the seeded robustness test is the CI substitute.
- **Resource budget** (idle < 1 % CPU, < 60 MB) is measured on the dev VPS and reported in PROGRESS; a 1 vCPU / 2 GB test VPS run under the attack fixtures is pending.
