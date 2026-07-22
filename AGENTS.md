# AGENTS.md

Guidance for AI agents (and humans) working on `smoke`.

## Project

`smoke` is a Linux privacy / anti-fingerprinting suite written in Rust.
See `docs/SPEC.md` and `docs/IMPLEMENTATION-PLAN.md` for the full picture.
Always read both before making non-trivial changes.

## Quick reference

- **Language:** Rust (stable, edition 2024)
- **License:** GPL-3.0-only. Every source file must carry the standard
  header. Do not add code under incompatible licenses.
- **Style:** `cargo fmt` is canonical. No comments unless asked. No em
  dashes (use a hyphen or rephrase).
- **Targets for 0.1:** Arch Linux + Debian/Ubuntu. Other distros may work
  but are not tested yet.
- **Init system:** systemd is the primary target; code must keep an
  init-agnostic core so openrc/runit/dinit can be added later.

## Common commands

```sh
cargo build                                # debug build
cargo build --release                      # release build
cargo test                                 # run all unit + integration tests
cargo test --package smoke-core            # tests for one crate only
cargo fmt --all                            # format
cargo fmt --all -- --check                 # verify formatting (CI gate)
cargo clippy --all-targets -- -D warnings  # lints (CI gate)
cargo doc --no-deps --open                 # view docs
```

## Layout

```
crates/
  smoke-cli/        # the `smoke` binary
  smoke-core/       # shared types, config, state, module trait
  smoke-modules/    # one file/submodule per identifier group
  smoke-kmod/       # kernel module (Phase 3, C)
  smoke-bpf/        # eBPF programs (Phase 3, libbpf-rs)
  smoke-preload/    # LD_PRELOAD shim (Phase 3)
  smoke-scan/       # memory scanner (Phase 5 / R&D)
dist/               # systemd, udev, networkd, modprobe.d artifacts
docs/               # specs and plans
tests/              # cross-crate integration tests
```

## Commit policy

- Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `test:`,
  `refactor:`, `perf:`). Optional scope: `feat(cli): ...`.
- **Short subject lines.** No body unless genuinely needed. No walls of
  text. Examples: `feat(mod-mac): enumerate NICs`, `fix(core): state
  load race`.
- **One logical change per commit.** The implementation plan lists the
  intended commits per phase. Do not bundle unrelated changes.
- **Never commit secrets, state files, or `/var/lib/smoke/` content.**
- Do NOT push unless explicitly asked. Do NOT amend or force-push
  unless explicitly asked.

## Branch policy

Default branch is `master`. Feature work happens on
`<type>/<short-slug>` branches (e.g. `feat/mod-machine-id`). Keep
branches short-lived.

## Testing gates

Before declaring a commit done:

1. `cargo build` succeeds.
2. `cargo fmt --all -- --check` is clean.
3. `cargo clippy --all-targets -- -D warnings` is clean.
4. `cargo test` passes.
5. If the commit adds a new module, the module has at least one unit
   test that runs without root and one doc comment with an example.

## Root-requiring tests

Tests that need root (bind-mounts, raw ioctls, FS UUID rewrites) must be
gated behind `#[cfg(feature = "root-integration")]` and skipped in CI.
CI runs only the non-root subset.

## Fixing failures

- **Local failure** (fmt, clippy, build, test broken before push): amend
  the current commit and fix it in place.
- **Remote failure** (CI fails after push, or something already
  released): create a new fix commit. Do not amend or force-push
  published history.

## Don't

- Do not add comments to code unless requested.
- Do not add emojis anywhere.
- Do not create new top-level markdown files unless requested.
- Do not change the public CLI surface without updating `docs/SPEC.md`.
- Do not introduce new dependencies without checking license
  compatibility (must be GPL-3.0-compatible) and listing them in the
  commit message.

## Documentation hygiene

Keep all documents (`SPEC.md`, `IMPLEMENTATION-PLAN.md`, `README.md`,
`AGENTS.md`) up to date at every iteration. When a decision replaces an
earlier one, **replace the old text in-place**; do not strike it
through, append addenda, or leave stale information behind. The goal is
lean, readable documents that always reflect the current state.

## When in doubt

Open a question in `docs/IMPLEMENTATION-PLAN.md` under the current
phase's "Open questions" section rather than guessing. Update the plan
as decisions are made.
