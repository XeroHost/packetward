# Contributing to PacketWard

PacketWard is licensed under **PolyForm Shield 1.0.0**, a source-available license. By contributing you
agree that your contribution is released under the same license.

## License and SPDX headers

- Every new source file (`.rs`, `.ts`, `.vue`, `.css`, `.toml` scripts, workflows) starts with an SPDX line:
  - Rust / TypeScript: `// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0`
  - Vue: `<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->`
  - CSS / shell / YAML: `/* ... */` or `# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0` as the file type allows.
  - Generated files are exempt: `apps/desktop/src/types/generated/` (written by `cargo test -p pw-proto
    --features ts-export`; CI fails if it is stale, so commit the regenerated files).
- Generated shadcn-vue components in `apps/desktop/src/components/ui/` keep their upstream MIT attribution
  (see the `NOTICE.md` there) instead of a per-file header.
- New dependencies must be redistributable under a permissive license (MIT, Apache-2.0, BSD, ISC, Zlib,
  MPL-2.0, Unicode; OFL for fonts) and pass `cargo deny check`. Do not add a dependency that is not listed
  in `docs/ARCHITECTURE.md` without discussing it first.
- Do not bundle Npcap, MaxMind GeoLite2 files or public blocklists.

## Before you open a pull request

Read `docs/DECISIONS.md` (settled, do not re-open), `docs/ARCHITECTURE.md` and `docs/ROADMAP.md`.
Work on one milestone at a time and keep changes small and vertical.

```bash
# Rust
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo audit

# Frontend (apps/desktop)
pnpm install
pnpm lint && pnpm typecheck && pnpm test
```

A change is done only when all of these pass.

## Conventions

- Conventional Commits: `feat(capture): ...`, `fix(guardian): ...`. One milestone item per commit when practical.
- Rust: no `unwrap()` / `expect()` outside tests, `unsafe` only in `sys/` modules with a `// SAFETY:` comment,
  no shelling out for core features. See `CLAUDE.md` for the full rules.
- UI: every string goes through i18n; keys are added to `en.json` first and `es` / `pt-BR` must be complete.
- Do not commit generated binaries, `.pcapng` captures larger than 1 MB, or anything under `target/`.
