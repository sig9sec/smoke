# smoke - Implementation Plan

**Audience:** AI agents doing the work, plus the human reviewer.
**Cadence:** reassess and update this document at the end of every
iteration. Commit lists below are **proposals**, not contracts - when a
step turns out larger or smaller than expected, split or merge commits
and update this file in the same PR.

See [`SPEC.md`](./SPEC.md) for the what-and-why. This document is the
how-and-when.

---

## How to use this document

1. **Read `SPEC.md` first.** Especially §2 (decisions), §4 (strategies),
   §5 (identifier catalog with per-row target tier), §6 (architecture).
2. **Pick the next unchecked commit in the current phase.** Each commit
   lists its scope, the files it touches, its acceptance criteria, and
   its dependencies. Do not skip ahead.
3. **One commit = one logical change.** If a step grew, split it and
   update this file. If a step is trivially small, merge with the next
   and update this file.
4. **Before every commit**, run `cargo build`, `cargo fmt --all -- --check`,
   `cargo clippy --all-targets -- -D warnings`, and `cargo test`. Fix
   any failures before committing.
5. **Commit message convention:** Conventional Commits, short subject
   line, no body unless genuinely needed. Scope is the area
   (`core`, `cli`, `mod-machine-id`, `mod-mac`, `mod-fsuuid`, …).
6. **Branch per feature:** `<type>/<short-slug>` off `master`.
7. **Update this file** when reality diverges from the plan. Mark done
   commits with `[x]`, add new ones, raise open questions at the bottom
   of the relevant phase.
8. **At the end of each phase**, verify all exit criteria are met before
   moving on. If criteria are not met, stay in the current phase.

### Commit list notation

```
- [ ] `feat(scope): subject` - one-line scope description.
      Files: paths touched. Acceptance: how to know it's done.
      Deps: prior commits required.
```

---

## Phase 0 - Foundation

**Goal:** a runnable `smoke` binary with no modules, but with the full
core (config, state, backup, randomization, module trait, registry),
read-only CLI commands (`list`, `dump`, `fingerprint`, `status`), CI,
and the R&D spike for the memory scanner.

**Exit criteria:**
- `cargo build`, `cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo test` all clean.
- `smoke list`, `smoke dump`, `smoke fingerprint`, `smoke status`
  produce real output on Arch and Debian.
- Memory-scan R&D report committed under `docs/`.

### P0 - Commits

- [x] `chore: cargo workspace skeleton`
      Files: `Cargo.toml` (workspace), `.gitignore`, `rust-toolchain.toml`.
      Acceptance: `cargo build` succeeds with empty workspace.
      Deps: none.

- [x] `chore: add rustfmt and clippy config`
      Files: `.rustfmt.toml`, `clippy.toml`.
      Acceptance: `cargo fmt --check` and `cargo clippy` run with
      project-wide rules (max-width 100, deny warnings, etc.).
      Deps: previous.

- [x] `ci: add github actions workflow`
      Files: `.github/workflows/ci.yml`.
      Acceptance: workflow runs fmt + clippy + test on Arch container
      and Debian container for every PR and push to `master`.
      Deps: previous.

- [x] `feat(core): crate skeleton with GPL headers`
      Files: `crates/smoke-core/Cargo.toml`, `crates/smoke-core/src/lib.rs`,
      `crates/smoke-core/build.rs` (header check).
      Acceptance: `cargo build -p smoke-core` succeeds. Every `.rs`
      carries the GPLv3 header.
      Deps: chore workspace.

- [x] `feat(core): error types and Result alias`
      Files: `crates/smoke-core/src/error.rs`, re-export from `lib.rs`.
      Adds: `SmokeError` enum (Io, Config, State, Permission, Module,
      NotRoot, Verify, Unsupported), `type Result<T>`.
      Acceptance: unit tests for common error Display.
      Deps: previous.

- [x] `feat(core): identifier model`
      Files: `crates/smoke-core/src/identifier.rs`.
      Adds: `IdentifierId` (string newtype), `Category` enum
      (Dmi, MachineId, Hostname, Net, Storage, FsUuid, Bootloader,
      Kernel, Tpm, Edid, Usb, Battery, Acpi, Logs, Services, Misc),
      `Finding { id, category, source, value, read_path }`,
      `Findings { items, partial_failures }`.
      Acceptance: serde round-trip, unit tests.
      Deps: error types.

- [x] `feat(core): coverage / risk / requirements enums`
      Files: `crates/smoke-core/src/coverage.rs`.
      Adds: `Tier` enum (`None`, `PartialUserspace`, `PartialUdev`,
      `FullKernel`, `FullBoot` with `label()` returning "T0".."T4"),
      `Strategy` enum (`FileOverwrite`, `BindMount`, `UdevRule`,
      `KernelBpf`, `Disable`, `PeriodicRotation`, `BootPatch` stored
      as `Vec<Strategy>`), `Coverage { achieved_tier, strategies }`,
      `Risk { level, summary, mitigations }`, `Requirements
      { root, kmod, bpf, reboot, degraded_mode }`.
      Acceptance: unit tests for tier ordering + requirements default.
      Deps: identifier model.

- [x] `feat(core): SmokeModule trait`
      Files: `crates/smoke-core/src/module.rs`.
      Adds: the trait from SPEC §6.2 plus `ApplyCtx`, `RotateCtx`,
      `ApplyReport`, `RotateReport`, `RevertReport`, `ModuleStatus`.
      Acceptance: trait compiles, doc examples.
      Deps: identifier, coverage.

- [x] `feat(core): vendor catalog seed`
      Files: `crates/smoke-core/src/vendors.rs` + `data/vendors.toml`.
      Adds: curated OUI table (~50 entries), DMI vendor+board+BIOS
      presets, disk vendor+model presets. Powers the `consistent`
      profile.
      Acceptance: parsing test; `pick(vendor=QEMU)` returns coherent
      set.
      Deps: identifier model.

- [x] `feat(core): randomization engine - common types`
      Files: `crates/smoke-core/src/rng/mod.rs`.
      Adds: `Profile` enum, `ValueOverride` enum (UseProfile, Fixed,
      Random, Keep), `ValueGenerator` trait, `create_generator()`
      factory. Profiles use `ChaCha20Rng` directly via `Mutex`.
      Acceptance: reproducible output from fixed seed.
      Deps: vendors.

- [x] `feat(core): randomization engine - random profile`
      Files: `crates/smoke-core/src/rng/random.rs`.
      Adds: pure-random generation per identifier kind (MAC, UUID,
      DMI string, serial, hostname).
      Acceptance: unit tests for each kind (format checks, no panic).
      Deps: rng common.

- [x] `feat(core): randomization engine - consistent profile`
      Files: `crates/smoke-core/src/rng/consistent.rs`.
      Adds: pick a vendor, then derive coherent values across all
      identifier kinds.
      Acceptance: golden test - fixed seed produces the same
      coherent profile every time.
      Deps: random profile.

- [x] `feat(core): randomization engine - locally-administered MAC`
      Files: `crates/smoke-core/src/rng/lam.rs`.
      Adds: LAM-bit MAC generation; everything else returns Keep.
      Acceptance: test that bit 1 of first octet is set.
      Deps: rng common.

- [x] `feat(core): randomization engine - pinned profile`
      Files: `crates/smoke-core/src/rng/pinned.rs`.
      Adds: load identity from a TOML file.
      Acceptance: round-trip test (write then read).
      Deps: rng common.

- [x] `feat(core): config schema`
      Files: `crates/smoke-core/src/config/mod.rs`.
      Adds: `SmokeConfig { version, profile, modules: Map<ModuleId,
      ModuleConfig>, rotation: RotationConfig, log_scrub: … }`,
      `ModuleConfig { enabled, overrides: Map<IdentifierId,
      ValueOverride> }`.
      Acceptance: serde TOML round-trip test on a representative
      config; validation errors tested.
      Deps: rng.

- [x] `feat(core): config load/save + default path resolution`
      Files: `crates/smoke-core/src/config/io.rs`.
      Adds: load from `/etc/smoke/smoke.toml` or `--config` override;
      XDG fallback for unprivileged runs. Atomic save (write tmp +
      rename).
      Acceptance: tests using tempdir.
      Deps: config schema.

- [x] `feat(core): state store schema`
      Files: `crates/smoke-core/src/state/mod.rs`.
      Adds: `State { version, modules: Map<ModuleId, ModuleState> }`,
      `ModuleState { last_applied, last_rotated, rotation_count,
      current_values: Map<IdentifierId, String> }`.
      Acceptance: serde JSON round-trip, schema version field set
      to `1`.
      Deps: config.

- [x] `feat(core): state store load/save`
      Files: `crates/smoke-core/src/state/io.rs`.
      Adds: atomic load/save to `/var/lib/smoke/state.json`; version
      migration stub.
      Acceptance: tests using tempdir; corrupt-file error path
      tested.
      Deps: state schema.

- [x] `feat(core): backup store + integrity manifest`
      Files: `crates/smoke-core/src/backup/mod.rs`,
      `crates/smoke-core/src/backup/manifest.rs`.
      Adds: write original value blobs to `/var/lib/smoke/backup/`,
      compute SHA-256 manifest. Signed with optional ed25519 key
      (`smoke.toml::backup.signing_key`).
      Acceptance: round-trip + tamper-detection tests.
      Deps: state.

- [x] `feat(core): module registry and dispatch`
      Files: `crates/smoke-core/src/registry.rs`.
      Adds: `Registry` holding `Vec<Box<dyn SmokeModule>>`, with
      `by_id`, `by_category`, `iter_enabled(config)`.
      Acceptance: register a no-op test module, look it up.
      Deps: module trait, config.

- [x] `feat(core): executor (apply/rotate/revert driver)`
      Files: `crates/smoke-core/src/executor.rs`.
      Adds: drives a set of modules through their lifecycle, updates
      state, writes backups, produces aggregate reports.
      Acceptance: tests using a fake module that records calls.
      Deps: registry, state, backup.

- [x] `feat(cli): crate skeleton with clap`
      Files: `crates/smoke-cli/Cargo.toml`, `src/main.rs`,
      `src/cli.rs`.
      Adds: `clap` parser matching SPEC section 7. Subcommands are
      stubs returning `unimplemented!()` except `--version`. Global
      `--config` flag for config path override.
      Acceptance: `smoke --version`, `smoke --help`, `smoke list
      --help` all work.
      Deps: core.

- [x] `feat(cli): JSON output`
      Files: `crates/smoke-cli/src/output.rs`.
      Adds: `--json` flag on `Status`, table printer, JSON printer.
      `--verbose` / `tracing` not yet wired (deferred to Phase 1
      when real modules produce diagnostic output).
      Acceptance: `smoke status --json` returns valid JSON.
      Deps: cli skeleton.

- [x] `feat(cli): smoke list`
      Files: `crates/smoke-cli/src/main.rs` (`cmd_list`).
      Adds: list known identifier groups from registry; `--category`
      and `--status` filters implemented and tested.
      Acceptance: filters work, output matches registry contents.
      Deps: registry, output.

- [x] `feat(cli): smoke status`
      Files: `crates/smoke-cli/src/main.rs` (`cmd_status`).
      Adds: read state.json, summarize per-module coverage and
      last-applied. `--json` respects `--module` filter.
      Acceptance: works on dev box.
      Deps: state.

- [x] `feat(cli): smoke config show/validate`
      Files: `crates/smoke-cli/src/main.rs` (`cmd_config_show`,
      `cmd_config_validate`).
      Adds: print or validate config; `validate` exits 2 on errors.
      Acceptance: validate catches bad config, exits non-zero.
      Deps: config io.

- [x] `feat(cli): smoke selftest`
      Files: `crates/smoke-cli/src/main.rs` (`cmd_selftest`).
      Adds: verify config parses, state parses, registry non-empty.
      Exits non-zero on failures.
      Acceptance: returns 0 in dev env.
      Deps: status.

- [ ] `feat(cli): smoke dump`
      Files: `crates/smoke-cli/src/main.rs` (`cmd_dump`).
      Adds: walk every registered module's `enumerate()`, emit
      JSON/text. `--out FILE`, `--real` (skip spoofed view),
      `--spoofed`.
      Acceptance: smoke dump runs end-to-end on the dev box without
      modules; integrates with stub modules.
      Deps: list.

- [ ] `feat(cli): smoke fingerprint`
      Files: `crates/smoke-cli/src/main.rs` (`cmd_fingerprint`).
      Adds: SHA-256 over canonicalized dump output. Stable across
      re-runs if input is stable.
      Acceptance: same machine -> same fingerprint (modulo real
      changes); test with canned dump.
      Deps: dump.

- [ ] `test: integration harness for dump before/after`
      Files: `tests/dump_diff.rs`.
      Adds: scenario that runs `smoke dump` once, applies a fake
      change via a test module, dumps again, asserts the diff is
      exactly the spoofed field. Uses `assert_cmd` + `predicates`.
      Acceptance: test green in CI.
      Deps: dump, executor.

- [x] `feat(spike): /proc/pid/mem walker prototype`
      Files: `crates/smoke-scan/Cargo.toml`, `src/lib.rs`,
      `src/walker.rs`.
      Adds: R&D prototype that reads `/proc/<pid>/maps`, walks
      readable regions via `process_vm_readv`, scans for a substring.
      Reports complexity back.
      Acceptance: prototype can find a known string in `cat`'s
      memory in a test process.
      Deps: none (sandbox crate).

- [x] `feat(spike): yara integration feasibility probe`
      Files: `crates/smoke-scan/src/yara_probe.rs`.
      Adds: small experiment linking `yara-rust` (or vendored YARA),
      confirming license compatibility and binary size cost.
      Acceptance: report committed as
      `docs/rnd/memory-scan.md` (next commit).
      Deps: walker.

- [x] `docs(rnd): memory scan complexity report`
      Files: `docs/rnd/memory-scan.md`.
      Adds: findings from the two spikes: LoC, license, latency,
      recommendation for 0.1 (ship / defer). Updates SPEC §9.3 with
      the decision.
      Acceptance: human-readable; answers all questions in SPEC §9.3.
      Deps: yara probe.

- [x] `docs: contributor guide`
      Files: `CONTRIBUTING.md`.
      Adds: how to add a module, how to run tests, where things live.
      Acceptance: a fresh agent can follow it.
      Deps: Phase 0 mostly done.

- [x] `feat(cli): smoke scan and watch commands`
      Files: `crates/smoke-cli/src/main.rs`, `src/cli.rs`,
      `crates/smoke-cli/Cargo.toml`.
      Adds: `smoke scan` (one-shot memory scan with pattern or YARA
      rule) and `smoke watch` (polling watch mode). Wires
      `smoke-scan` as a dependency of `smoke-cli`.
      Acceptance: `smoke scan "pattern"` finds the pattern in self
      memory.
      Deps: smoke-scan.

### P0 - Phase 0 cleanup

- [x] `fix(core): coherent consistent profile + ValueGenerator trait`
      Files: `rng/mod.rs`, `rng/consistent.rs`, `rng/random.rs`,
      `rng/lam.rs`, `rng/pinned.rs`, `vendors.rs`, `data/vendors.toml`.
      Fixes: ConsistentProfile now picks DMI first, finds matching
      OUI for that vendor (coherent MAC+DMI). Adds ValueGenerator
      trait + factory. Expands OUI table to ~48 entries.

- [x] `fix(core): backup store preserves history + integrity manifest`
      Files: `backup/mod.rs`, `backup/manifest.rs`.
      Fixes: backup snapshots are timestamped; originals never
      clobbered. SHA-256 manifest wired into BackupStore.

- [x] `fix(core): executor writes backups, verifies, enforces requires/risks`
      Files: `executor.rs`, `module.rs`.
      Fixes: ApplyCtx carries Profile + overrides + generator.
      Executor enforces root requirement and risk gating. Writes
      backups, updates current_values, clears state on revert.

- [x] `fix(cli): implement list filters, --config override, exit codes`
      Files: `main.rs`, `cli.rs`, `config/io.rs`.
      Fixes: --category/--status filters work. XDG_CONFIG_HOME
      respected. --config global flag. Exit codes per SPEC.

- [x] `fix(scan): harden walker and output layer`
      Files: `walker.rs`, `yara_probe.rs`, `output.rs`.
      Fixes: empty-needle panic guard, parse_maps preserves paths
      with spaces, scan_bytes returns Result, SAFETY comment added,
      dead verbose helpers removed.

### P0 - Open questions

- Q-P0-1: **Resolved.** Using `boreal` (pure Rust YARA, MPL-2.0),
  not upstream YARA (GPLv3). MPL-2.0 is GPL-3.0-compatible per
  MPL section 6.1. No license issue.
- Q-P0-2: **Resolved.** SHA-256 manifest only, no ed25519 signing
  in 0.1. The manifest is wired into BackupStore and verified on
  load.
- Q-P0-3: `--redact` flag for `smoke dump` - deferred to when dump
  is implemented.

### P0 - Remaining technical debt

All resolved. Kept for reference:

- [x] `docs(core): add doc comments to all public types`
- [x] `chore: build.rs header check for cli and scan crates`
- [x] `test(cli): unit tests for list, status, config validate`
- [x] `chore: centralize workspace dependencies`
- [x] `chore: add crate metadata`
- [x] `ci: add cargo caching and cargo-audit`
- [x] `feat(cli): --verbose flag and tracing integration`

---

## Phase 1 - Userspace MVP

**Goal:** `smoke 0.1` covers T1+T2 for the items below, with full
apply / rotate / status / revert / doctor, persistence via systemd,
and CI-tested end-to-end on Arch and Debian.

**Scope (matches SPEC §5 target rows marked T1 or T2 in 0.1):**
- machine-id family (§5.2)
- hostname family + DHCP DUID/IAID (§5.3)
- NIC active MAC + Wi-Fi cloned-mac + saved-network scrub (§5.4)
- disk serial udev presentation (§5.5, T2 only - explicit doctor
  warning that ioctl path is uncovered)
- filesystem & partition UUIDs (§5.6) plus bootloader cascade (§5.7)
- kernel uname/`/proc` bind-mounts (§5.16) - opt-in
- SSH host keys (§5.18)
- service installer (systemd)

**Out of scope for 0.1** (explicit doctor warnings):
- DMI raw tables, NVMe Identify, NIC BIA, EDID i2c, TPM EK, CPUID.
- Bluetooth, WWAN, Wi-Fi probe requests.

### P1.A - machine-id module

All done.

- [x] `feat(mod-machine-id): crate + enumerate`
- [x] `feat(mod-machine-id): apply + revert with backup`
- [x] `feat(mod-machine-id): rotation`
- [x] `feat(mod-machine-id): register and doctor coverage`
- [x] `test(mod-machine-id): root-integration test`

### P1.B - hostname module

- [ ] `feat(mod-hostname): crate + enumerate`
      Files: `crates/smoke-modules/mod-hostname/`.
      Adds: enumerate static/pretty/transient hostname, domainname,
      mailname.
      Acceptance: returns Findings.
      Deps: P0 core.

- [ ] `feat(mod-hostname): static hostname apply/revert`
      Files: same, `static_name.rs`.
      Adds: rewrite `/etc/hostname`; use `hostnamectl set-hostname`
      when available.
      Acceptance: tempdir test.
      Deps: enumerate.

- [ ] `feat(mod-hostname): pretty/transient + rotate`
      Files: same, `transient.rs`, `rotate.rs`.
      Adds: hostnamectl pretty name; rotation timer hook.
      Acceptance: rotation produces new name.
      Deps: static.

- [ ] `feat(mod-hostname): domainname + resolv.conf search domain`
      Files: same, `domain.rs`.
      Adds: rewrite `/etc/resolv.conf` search/domain lines (when
      not systemd-resolved-managed) or NetworkManager dispatcher
      script.
      Acceptance: tempdir test.
      Deps: transient.

- [ ] `feat(mod-hostname): avahi/samba name sync (opt-in)`
      Files: same, `avahi_samba.rs`.
      Adds: if services detected, regenerate configs. Marked opt-in;
      warns if running services would conflict.
      Acceptance: test on a system with avahi installed.
      Deps: domainname.

- [ ] `feat(mod-hostname): register + doctor`
      Files: `lib.rs`, registry.
      Acceptance: end-to-end `smoke apply --module hostname` works.
      Deps: avahi/samba.

### P1.C - DHCP identifiers module

- [ ] `feat(mod-dhcp): enumerate DUID/IAID across NM/dhclient/networkd`
      Files: `crates/smoke-modules/mod-dhcp/`.
      Acceptance: returns Findings for whichever client is present.
      Deps: P0 core.

- [ ] `feat(mod-dhcp): rotate DUID + IAID`
      Files: same, `rotate.rs`.
      Adds: stop client, rewrite files, restart client.
      Acceptance: tempdir test for each client.
      Deps: enumerate.

- [ ] `feat(mod-dhcp): per-network client-id policy`
      Files: same, `per_network.rs`.
      Adds: stable per-network identifier policy (avoid cross-network
      correlation). NM connection profile rewrite.
      Acceptance: test.
      Deps: rotate.

- [ ] `feat(mod-dhcp): register + doctor`
      Deps: per-network.

### P1.D - NIC MAC module

- [ ] `feat(mod-mac): enumerate NICs and current/perm MACs`
      Files: `crates/smoke-modules/mod-mac/`.
      Adds: walk `/sys/class/net/`, capture current MAC; capture
      permanent MAC via `ethtool -P` for doctor reporting (cannot
      spoof in 0.1 → flagged as T1 partial).
      Acceptance: returns Findings.
      Deps: P0 core.

- [ ] `feat(mod-mac): set active MAC via ip link`
      Files: same, `apply.rs`.
      Adds: `ip link set dev <if> address <mac>`. Handles link-down
      / link-up correctly. Refuses to touch the default route's
      interface without `--allow-disruption`.
      Acceptance: root-integration test on a veth pair.
      Deps: enumerate.

- [ ] `feat(mod-mac): persist via systemd .link files`
      Files: same, `persist.rs`, `dist/systemd/70-smoke.link`.
      Adds: generate a `.link` file under
      `/etc/systemd/network/70-smoke.link` that pins the chosen MAC
      per interface by current MAC match.
      Acceptance: survives reboot in container test.
      Deps: apply.

- [ ] `feat(mod-mac): NetworkManager wifi.cloned-mac-address integration`
      Files: same, `nm_wifi.rs`.
      Adds: rewrite each NM connection profile to set
      `wifi.cloned-mac-address` per policy (random / stable / pin).
      Acceptance: test on a profile copy.
      Deps: persist.

- [ ] `feat(mod-mac): rotate timer`
      Files: same, `rotate.rs`.
      Adds: periodic regeneration of active MAC for chosen
      interfaces.
      Acceptance: rotation changes MAC and updates state.
      Deps: NM wifi.

- [ ] `feat(mod-mac): saved-network BSSID scrub`
      Files: same, `bssid_scrub.rs`.
      Adds: scrub BSSIDs from NM connection profiles (opt-in).
      Acceptance: test on profile copies.
      Deps: NM wifi.

- [ ] `feat(mod-mac): doctor + register`
      Acceptance: doctor reports T1 (active MAC), partial (perm MAC
      readable via ethtool).
      Deps: bssid scrub.

### P1.E - Filesystem UUID module (highest-risk area)

- [ ] `feat(mod-fsuuid): enumerate filesystems and partition tables`
      Files: `crates/smoke-modules/mod-fsuuid/`.
      Adds: walk `/proc/mounts`, `lsblk`, `blkid`; enumerate FS UUID
      per type, GPT GUIDs, MBR signature, LUKS UUID, LVM, mdadm,
      swap.
      Acceptance: returns Findings on dev box.
      Deps: P0 core.

- [ ] `feat(mod-fsuuid): consumer discovery (fstab/crypttab/grub/initramfs/efi/cmdline)`
      Files: same, `consumers.rs`.
      Adds: find every file that references a UUID/GUID and produce
      an edit plan (find/replace map). This is what makes the rewrite
      safe.
      Acceptance: test on a chroot layout in tempdir.
      Deps: enumerate.

- [ ] `feat(mod-fsuuid): ext4 UUID regen via tune2fs`
      Files: same, `backends/ext4.rs`.
      Acceptance: test on a loop-mounted ext4 image in tempdir.
      Deps: consumers.

- [ ] `feat(mod-fsuuid): xfs UUID regen`
      Files: `backends/xfs.rs`.
      Acceptance: loop-image test.
      Deps: ext4.

- [ ] `feat(mod-fsuuid): btrfs UUID regen`
      Files: `backends/btrfs.rs`.
      Acceptance: loop-image test (carefully: btrfstune is in-place).
      Deps: ext4.

- [ ] `feat(mod-fsuuid): f2fs / fat / exfat / ntfs backends`
      Files: one per FS.
      Acceptance: loop-image test where tooling available.
      Deps: ext4.

- [ ] `feat(mod-fsuuid): swap UUID regen`
      Files: `backends/swap.rs`.
      Acceptance: test on loop swap.
      Deps: ext4.

- [ ] `feat(mod-fsuuid): LUKS UUID regen`
      Files: `backends/luks.rs`. **Careful:** requires re-key slot
      tracking. Refuses to proceed on a mounted LUKS without
      `--i-understand-luks-risks`.
      Acceptance: loop-LUKS test.
      Deps: ext4.

- [ ] `feat(mod-fsuuid): LVM PV/VG/LV UUID regen`
      Files: `backends/lvm.rs`.
      Acceptance: loop-LVM test.
      Deps: ext4.

- [ ] `feat(mod-fsuuid): mdadm array UUID + homehost`
      Files: `backends/mdadm.rs`.
      Acceptance: loop-md test.
      Deps: ext4.

- [ ] `feat(mod-fsuuid): GPT GUID regen via sgdisk`
      Files: `backends/gpt.rs`. Keeps partition type GUIDs stable;
      only randomizes disk GUID and partition-unique GUIDs.
      Acceptance: loop-image test.
      Deps: ext4.

- [ ] `feat(mod-fsuuid): MBR disk signature regen`
      Files: `backends/mbr.rs`.
      Acceptance: loop-image test.
      Deps: ext4.

- [ ] `feat(mod-fsuuid): consumer rewrite (fstab/crypttab/mdadm/crypttab/keyfiles)`
      Files: `consumers.rs` (apply path).
      Adds: atomic rewrite of every discovered consumer file, with
      backup.
      Acceptance: end-to-end loop test - bootable config preserved.
      Deps: all backends + consumers discovery.

- [ ] `feat(mod-fsuuid): grub.cfg rewrite + EFI NVRAM via efibootmgr`
      Files: `consumers_grub.rs`.
      Acceptance: chroot test that grub.cfg still resolves root.
      Deps: consumer rewrite.

- [ ] `feat(mod-fsuuid): initramfs rebuild hook`
      Files: `consumers_initramfs.rs`, `dist/initramfs/smoke-hook`.
      Adds: regenerate initramfs (dracut + initramfs-tools) with new
      UUIDs embedded.
      Acceptance: chroot test.
      Deps: grub.

- [ ] `feat(mod-fsuuid): kernel cmdline resume= update`
      Files: `consumers_cmdline.rs`.
      Adds: rewrite GRUB cmdline for hibernation resume device.
      Acceptance: test.
      Deps: grub.

- [ ] `feat(mod-fsuuid): apply / revert driver integration`
      Files: crate `apply.rs`, `revert.rs`.
      Adds: orchestrates the per-FS backends + consumer rewrites,
      with full backup and revert.
      Acceptance: end-to-end apply/revert on a loop-based disk
      layout.
      Deps: all backends + all consumers.

- [ ] `feat(mod-fsuuid): register + doctor + risk declaration`
      Acceptance: doctor flags this module as `Risk::High`; requires
      `--force` or explicit `smoke.toml` opt-in.
      Deps: apply/revert.

- [ ] `test(mod-fsuuid): full-disk chroot integration test`
      Files: `tests/root/fsuuid_chroot.rs`.
      Acceptance: in a container with a loop disk + chroot, apply
      rewrites every UUID, chroot still boots init, revert restores
      every original UUID.
      Deps: previous.

### P1.F - Kernel-string bind-mount module (opt-in)

- [ ] `feat(mod-kernelbind): enumerate uname / proc/cpuinfo / proc/version / proc/cmdline / proc/uptime / proc/stat btime`
      Files: `crates/smoke-modules/mod-kernelbind/`.
      Acceptance: returns Findings.
      Deps: P0 core.

- [ ] `feat(mod-kernelbind): bind-mount overlay generator`
      Files: same, `overlay.rs`.
      Adds: produces spoofed content for each file; bind-mounts over
      the originals (root-only). Records mounts in state for revert.
      Acceptance: root-integration test that `cat /proc/cpuinfo`
      shows spoofed content after apply.
      Deps: enumerate.

- [ ] `feat(mod-kernelbind): doctor + risk + opt-in flag`
      Acceptance: doctor notes T1 coverage; warns that bind-mounts
      don't fool direct syscalls or `/dev/mem`.
      Deps: overlay.

- [ ] `feat(mod-kernelbind): register`
      Deps: doctor.

### P1.G - SSH host-keys module

- [ ] `feat(mod-sshkeys): enumerate host keys`
      Files: `crates/smoke-modules/mod-sshkeys/`.
      Acceptance: returns Findings + fingerprints.
      Deps: P0 core.

- [ ] `feat(mod-sshkeys): regenerate host keys`
      Files: same, `apply.rs`.
      Adds: backup originals; generate new keypairs for every
      algorithm present (or a sane default set); `ssh-keygen -A`.
      Acceptance: tempdir test.
      Deps: enumerate.

- [ ] `feat(mod-sshkeys): rotate + restart service`
      Files: same, `rotate.rs`.
      Adds: produce new keys on schedule; restart `sshd` if running.
      Acceptance: rotation test.
      Deps: apply.

- [ ] `feat(mod-sshkeys): register + doctor`
      Acceptance: end-to-end.
      Deps: rotate.

### P1.H - Disk serial udev presentation module (T2 only)

- [ ] `feat(mod-diskid): enumerate disk serials / WWNs via SG_IO`
      Files: `crates/smoke-modules/mod-diskid/`.
      Adds: read serials via SG_IO INQUIRY (so doctor confirms T3
      is still needed); present T2 fix via udev.
      Acceptance: returns Findings on dev box.
      Deps: P0 core.

- [ ] `feat(mod-diskid): udev rules to override presentation`
      Files: same, `udev.rs`, `dist/udev/60-smoke-disk.rules`.
      Adds: ENV overrides for `ID_SERIAL`, `ID_WWN_WITH_EXTENSION`
      so `lsblk`/`/dev/disk/by-id/` reflect spoofed values.
      Acceptance: test on loop disk.
      Deps: enumerate.

- [ ] `feat(mod-diskid): register + doctor (T2 with explicit T3 warning)`
      Acceptance: doctor reports T2 achieved, T3 outstanding.
      Deps: udev.

### P1.I - Apply/Rotate/Revert/Doctor CLI

- [ ] `feat(cli): smoke apply`
      Files: `crates/smoke-cli/src/cmd/apply.rs`.
      Adds: orchestrator using core executor; `--module`,
      `--profile`, `--dry-run`, `--force`. Refuses high-risk without
      `--force`.
      Acceptance: tests using fake modules.
      Deps: executor + at least one real module.

- [ ] `feat(cli): smoke rotate`
      Files: `crates/smoke-cli/src/cmd/rotate.rs`.
      Adds: invoke `rotate()` on selected modules; print rotation
      counters.
      Acceptance: test.
      Deps: apply.

- [ ] `feat(cli): smoke revert`
      Files: `crates/smoke-cli/src/cmd/revert.rs`.
      Adds: `--all` or per-module; full state cleanup.
      Acceptance: end-to-end with at least one real module.
      Deps: apply.

- [ ] `feat(cli): smoke doctor`
      Files: `crates/smoke-cli/src/cmd/doctor.rs`.
      Adds: re-read every identifier via every declared path;
      produce coverage report; `--fix` attempts safe fixes (e.g.
      re-apply drifted values).
      Acceptance: doctor flags known partial-coverage modules.
      Deps: all P1 modules.

### P1.J - Service / persistence

- [ ] `feat(service): service backend trait + systemd adapter`
      Files: `crates/smoke-core/src/service/mod.rs`,
      `crates/smoke-core/src/service/systemd.rs`.
      Adds: `ServiceBackend` trait; systemd adapter renders unit
      files from module persistence requirements.
      Acceptance: render test.
      Deps: P0 core.

- [ ] `feat(service): smoke-apply systemd unit template`
      Files: `dist/systemd/smoke-apply.service`,
      `dist/systemd/smoke-apply.service.in`.
      Acceptance: renders for a sample set of modules.
      Deps: systemd adapter.

- [ ] `feat(service): smoke-rotate timer + service`
      Files: `dist/systemd/smoke-rotate.{service,timer}`.
      Acceptance: test that timer triggers service on schedule.
      Deps: apply unit.

- [ ] `feat(cli): smoke service install`
      Files: `crates/smoke-cli/src/cmd/service.rs`.
      Adds: install/enable units; detect running init system;
      degrade gracefully on non-systemd.
      Acceptance: install in a systemd container.
      Deps: units.

### P1.K - Tests, docs, release

- [ ] `test: e2e apply/revert on Arch container`
      Files: `.github/workflows/e2e-arch.yml`, `tests/e2e/arch.sh`.
      Acceptance: green pipeline on Arch container running real
      apply/revert for the in-scope modules.
      Deps: all P1 modules.

- [ ] `test: e2e apply/revert on Debian container`
      Files: `.github/workflows/e2e-debian.yml`,
      `tests/e2e/debian.sh`.
      Acceptance: green on Debian.
      Deps: Arch e2e.

- [ ] `docs: user guide v0.1`
      Files: `docs/USER-GUIDE.md`.
      Adds: install, first run, common recipes, troubleshooting,
      explicit list of what's NOT covered in 0.1.
      Deps: all of P1.

- [ ] `docs: module reference index`
      Files: `docs/modules/README.md` plus one stub per module.
      Acceptance: every shipped module has a doc page.
      Deps: all modules.

- [ ] `release: v0.1.0`
      Files: `CHANGELOG.md`, tag `v0.1.0`.
      Acceptance: cargo publish dry-run clean (we may not publish to
      crates.io - decide then).
      Deps: docs.

### P1 - Open questions

- Q-P1-1: Should `mod-fsuuid` be opt-in by default (high risk) or
  opt-out? Recommendation: **opt-in by default** in `smoke.toml`
  (`modules.fsuuid.enabled = false` until user turns on).
- Q-P1-2: For systems where `/etc/resolv.conf` is symlinked to
  `/run/systemd/resolve/stub-resolv.conf`, do we maintain a dispatcher
  script or refuse to touch it? Recommendation: dispatcher script.
- Q-P1-3: For `mod-mac` on the interface holding the default route,
  default-deny or default-allow-with-warning? Recommendation:
  default-deny unless `--allow-disruption`.
- Q-P1-4: Loop-image tests for `mod-fsuuid` need root in CI; do we
  run them in a privileged container on a self-hosted runner, or in
  `root-integration` only? Recommendation: `root-integration` only,
  documented; CI runs the non-root subset.

---

## Phase 2 - Wide userspace coverage

**Goal:** raise 0.1 modules to "every naive reader" coverage and add
the remaining userspace-treatable identifier groups. Kernel/eBPF still
out of scope; `doctor` reports what's left for Phase 3.

**In scope:**
- §5.1 DMI sysfs bind-mounts (T1 only; raw table reads still flagged
  T3-pending).
- §5.10 EDID via `drm.edid_firmware` (DRM path T1; i2c path still
  T3-pending).
- §5.13 USB serials via udev + renames (T2).
- §5.14 battery via sysfs bind-mount.
- §5.15 (partial) ACPI table OEM IDs via initramfs patcher (T4 spike).
- §5.17 log scrubbers.
- §5.18 cert rotation, mDNS/UPnP disable.
- §5.10 GPU/DRM sysfs bind-mount.
- §5.19 PCI/NUMA/topology sysfs bind-mounts (opt-in).
- `smoke wrap` - per-app bubblewrap namespace sandbox (pulled forward
  from Phase 5; reuses Phase 1 spoofing infrastructure).

### P2 - Commit sketch (to be detailed when Phase 1 lands)

- `feat(mod-dmi): enumerate DMI sysfs`
- `feat(mod-dmi): sysfs bind-mount generator`
- `feat(mod-dmi): persist + revert + doctor`
- `feat(mod-dmi): doctor exposes dmidecode/raw-table gap`
- `feat(mod-edid): enumerate via drm sysfs`
- `feat(mod-edid): generate fake EDID binary`
- `feat(mod-edid): drm.edid_firmware kernel cmdline installer`
- `feat(mod-edid): doctor exposes i2c gap`
- `feat(mod-usb): enumerate usb serials`
- `feat(mod-usb): udev rule to override presentation`
- `feat(mod-usb): register + doctor`
- `feat(mod-battery): enumerate + bind-mount spoof`
- `feat(mod-gpu): drm sysfs bind-mount`
- `feat(mod-acpi-spike): initramfs OEM-ID patcher R&D`
- `feat(mod-logs): journald vacuum + filter rules`
- `feat(mod-logs): shell history scrub + disable`
- `feat(mod-logs): package-manager log scrub`
- `feat(mod-services): TLS cert rotation framework`
- `feat(mod-services): mDNS/UPnP disable helpers`
- `feat(mod-sysfs): generic opt-in bind-mount for pci/numa/topology`
- `feat(wrap): generate spoofed content tree for namespace`
      Adds: given a Profile, materialize all spoofed files (machine-id,
      hostname, DMI sysfs, /proc/cpuinfo, MAC config, etc.) into a
      temp directory. Reuses module enumerate/generate logic in a
      "dry render" mode that writes to a directory instead of the host.
- `feat(wrap): bubblewrap namespace launcher`
      Adds: `smoke wrap <command>` runs the target inside a bwrap
      namespace with spoofed paths bind-mounted over the real ones.
      Flags: `--unshare-net` (network isolation), `--profile NAME`,
      `--module NAME` (selective spoofing). No root required (user
      namespaces).
- `feat(wrap): doctor coverage for namespace sandbox`
      Adds: doctor verifies that spoofed paths inside the namespace
      differ from host values. Reports which identifiers are covered.
- `feat(profiles): --mimic <model> hardware template`
      Adds: generate a profile matching a specific real hardware model
      (e.g. `--mimic "ThinkPad X1 Carbon Gen 11"`). Uses the vendor
      catalog to produce a maximally plausible DMI/MAC combination.
- `feat(doctor): drift detection systemd timer`
      Adds: optional systemd timer that runs `smoke doctor` every N
      minutes and alerts if any identifier has drifted back to its
      real value (e.g. after a package update regenerated
      `/etc/machine-id`).
- `test(p2): e2e coverage on Arch and Debian`
- `release: v0.2.0`

### P2 - Open questions

- Q-P2-1: For the ACPI initramfs patcher (T4 spike) - do we ship it
  enabled-by-default in 0.2 or only as an experimental flag? Likely
  experimental; gate behind `--enable-experimental`.
- Q-P2-2: EDID firmware override requires a kernel reboot to take
  effect. Document as `needs-reboot` (exit code 3).
- Q-P2-3: For `smoke wrap`, do we use `bubblewrap` as an external
  dependency or implement raw `clone(CLONE_NEWNS | CLONE_NEWUSER)` +
  `mount --bind`? Recommendation: start with bubblewrap (simpler,
  widely available), add raw-namespace path later if the dependency
  is undesirable.
- Q-P2-4: Should `smoke wrap --unshare-net` also create a veth pair
  with a spoofed MAC, or just isolate with no network? Recommendation:
  offer both: default = no network, `--net` = veth with spoofed MAC.

---

## Phase 3 - Kernel / eBPF interception

**Goal:** raise coverage to T3 for everything that has an ioctl/syscall
read path. Ship `smoke-kmod` (C) and `smoke-bpf` (libbpf-rs), plus
`smoke-preload` (LD_PRELOAD) as an additional cheap layer.

**In scope:**
- §5.1 DMI raw table rewrite (kretprobe on `dmi_walk`).
- §5.5 SG_IO / NVME_IOCTL / MMC ioctl kretprobes returning spoofed
  INQUIRY/Identify buffers.
- §5.4 ETHTOOL permaddr hook (NIC BIA).
- §5.11 EDID i2c transfer hook.
- §5.13 USB descriptor read hook.
- §5.12 (TPM) hook for `TPM2_GetCapability` vendor ID (EK still
  disabled-only).
- LD_PRELOAD `libsmoke.so` for libc-based reads.
- MOK signing tooling (optional, off by default).

### P3 - Commit sketch

- `feat(kmod): smoke-kmod build system (kbuild + out-of-tree)`
- `feat(kmod): kprobe registration framework`
- `feat(kmod): dmi_walk table rewrite`
- `feat(bpf): libbpf-rs skeleton + loader in smoke-cli`
- `feat(bpf): sg_io kretprobe`
- `feat(bpf): nvme_ioctl kretprobe`
- `feat(bpf): mmc_ioctl kretprobe`
- `feat(bpf): ethtool permaddr kretprobe`
- `feat(bpf): i2c transfer kretprobe (EDID)`
- `feat(bpf): usbdevfs descriptor kretprobe`
- `feat(preload): libsmoke.so libc interception skeleton`
- `feat(preload): intercept open/read on spoofed paths`
- `feat(preload): intercept ioctl`
- `feat(cli): --layer={userspace,kmod,bpf,preload} flag`
- `feat(doctor): report T3 coverage when kernel layer loaded`
- `feat(signing): MOK enrolment helper (experimental)`
- `feat(scan): eBPF watch mode for memory scanner`
- `test(p3): kmod load/unload integration on Arch`
- `test(p3): bpf load integration on Arch`
- `release: v0.3.0`

### P3 - Open questions

- Q-P3-1: When both kmod and BPF can do the job, which loads first
  and which is fallback? Recommendation: try BPF first (safer,
  verifier-bounded), fall back to kmod.
- Q-P3-2: How do we handle kernels where BPF is restricted (LSM
  BPF locked down)? Detect and degrade to kmod-only or userspace.

---

## Phase 4 - Network & radio hardening

**Goal:** cover the radio and network-side identifiers and process
fingerprints.

**In scope:**
- §5.4 Bluetooth BD_ADDR (kernel HCI patch + persistence).
- §5.4 Wi-Fi probe request suppression/randomization.
- §5.4 WWAN IMEI/IMSI disable-only module.
- §5.18 TCP/IP stack fingerprint normalization (sysctls + nftables
  mangle for TTL/MSS/window).
- §5.18 DNS leak protection (force DoH/DoT).
- §5.18 mDNS/NetBIOS/SSDP suppression.
- Per-network MAC policy binding.
- Optional Tor integration.

### P4 - Commit sketch

- `feat(mod-bt): enumerate + disable`
- `feat(mod-bt): bd_addr spoof via kernel patch`
- `feat(mod-wifi-probe): driver-level randomization R&D`
- `feat(mod-wwan): modem detection + disable-only module`
- `feat(mod-netfp): sysctl profile for TCP/IP normalization`
- `feat(mod-netfp): nftables mangle rules`
- `feat(mod-dns): force DoH/DoT via dispatcher`
- `feat(mod-mdns): avahi/samba/ssdp suppression`
- `feat(mod-mac-policy): per-network NM profile binding`
- `feat(mod-tor): optional integration`
- `test(p4): e2e on Arch + Debian`
- `release: v0.4.0`

---

## Phase 5 - Bonus & polish

**Goal:** the "would be nice" features from SPEC §11.

### P5 - Commit sketch

- `feat(vm): smoke vm launcher (libvirt/qemu with spoofed cpu/dmi/edid)`
- `feat(panic): smoke panic (wipe state + backup + zeroize)`
- `feat(profiles): preset policy profiles`
- `feat(tui): smoke tui dashboard`
- `feat(fleet): pinned-fleet sync`
- `feat(browser): hardened browser profile generator`
- `pkg: pacman packaging`
- `pkg: deb packaging`
- `pkg: rpm packaging`
- `pkg: nix packaging`
- `release: v1.0.0`

---

## Cross-phase backlogs

### Hardening

- Fuzz every parser (config, EDID, SPD, maps file, `/proc` readers)
  with `cargo-fuzz`.
- Property-test the randomization engine.
- Audit every `unsafe` block; document or remove.

### Documentation

- Per-module reference page (one per commit that adds a module).
- Threat-model document (`docs/THREAT-MODEL.md`) - derived from SPEC
  §3 once Phase 1 lands.
- Architecture deep-dive (`docs/ARCHITECTURE.md`) once Phase 3 lands.

### Packaging

- Static musl build of `smoke-cli` for portable binary.
- Man pages (`dist/man/smoke.1` etc.).
- Shell completions (`smoke completions bash/zsh/fish`).

---

## Updating this plan

At the end of every iteration:

1. Tick done commits `[x]`.
2. Drop or merge commits that turned out unnecessary.
3. Split commits that turned out too large; insert new ones in
   dependency order.
4. Promote open questions to decisions; raise new open questions.
5. Commit the plan update as `docs: update implementation plan` (or
   similar) - separately from feature work.
