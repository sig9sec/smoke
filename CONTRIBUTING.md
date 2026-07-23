# Contributing to smoke

## Project layout

```
crates/
  smoke-core/       # shared types, config, state, module trait, RNG
  smoke-cli/        # the `smoke` binary (clap, all commands)
  smoke-scan/       # memory scanner (process_vm_readv + boreal YARA)
  smoke-modules/    # one crate per identifier group (Phase 1+)
  smoke-kmod/       # kernel module (Phase 3, C)
  smoke-bpf/        # eBPF programs (Phase 3, libbpf-rs)
  smoke-preload/    # LD_PRELOAD shim (Phase 3)
dist/               # systemd, udev, networkd, modprobe.d artifacts
docs/               # specs and plans
tests/              # cross-crate integration tests
```

## Prerequisites

- Rust stable (see `rust-toolchain.toml`)
- Linux (Arch or Debian/Ubuntu for CI parity)

## Building

```sh
cargo build
cargo build --release
```

## Testing

```sh
cargo test                       # all tests
cargo test --package smoke-core  # core only
```

Tests that need root are gated behind `#[cfg(feature = "root-integration")]`.

## Formatting and linting

```sh
cargo fmt --all                            # format
cargo fmt --all -- --check                 # verify (CI gate)
cargo clippy --all-targets -- -D warnings  # lint (CI gate)
```

## Adding a module

1. Create `crates/smoke-modules/mod-<name>/`.
2. Implement `SmokeModule` trait from `smoke-core`.
3. Register in `smoke-cli`'s `main.rs` (add to `Registry::new()`).
4. Add at least one unit test that runs without root.
5. Add a doc comment with an example.

Note: `smoke-modules/` does not exist yet. It will be created in
Phase 1 when the first module (`mod-machine-id`) lands.

## Commit conventions

See `AGENTS.md` for the full policy. Short version:

- Conventional Commits: `feat(scope): subject`
- One logical change per commit.
- Run all gates before committing.
- Update docs when reality diverges from the plan.
