# Contributing to smoke

## Project layout

```
crates/
  smoke-core/       # shared types, config, state, module trait
  smoke-cli/        # the `smoke` binary (clap)
  smoke-scan/       # memory scanner (R&D / Phase 0)
docs/               # specs and plans
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
3. Register in `smoke-cli`'s main.
4. Add at least one unit test that runs without root.
5. Add a doc comment with an example.

## Commit conventions

See `AGENTS.md` for the full policy. Short version:

- Conventional Commits: `feat(scope): subject`
- One logical change per commit.
- Run all gates before committing.
- Update docs when reality diverges from the plan.
