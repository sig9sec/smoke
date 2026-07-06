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
6. **Branch per feature:** `<type>/<short-slug>` off `main`.
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

- [ ] `chore: cargo workspace skeleton`
      Files: `Cargo.toml` (workspace), `.gitignore`, `rust-toolchain.toml`.
      Acceptance: `cargo build` succeeds with empty workspace.
      Deps: none.

- [ ] `chore: add rustfmt and clippy config`
      Files: `.rustfmt.toml`, `clippy.toml`.
      Acceptance: `cargo fmt --check` and `cargo clippy` run with
      project-wide rules (max-width 100, deny warnings, etc.).
      Deps: previous.

- [ ] `ci: add github actions workflow`
      Files: `.github/workflows/ci.yml`.
      Acceptance: workflow runs fmt + clippy + test on Arch container
      and Debian container for every PR and push to `main`.
      Deps: previous.

- [ ] `feat(core): crate skeleton with GPL headers`
      Files: `crates/smoke-core/Cargo.toml`, `crates/smoke-core/src/lib.rs`,
      `crates/smoke-core/build.rs` (header check).
      Acceptance: `cargo build -p smoke-core` succeeds. Every `.rs`
      carries the GPLv3 header.
      Deps: chore workspace.

- [ ] `feat(core): error types and Result alias`
      Files: `crates/smoke-core/src/error.rs`, re-export from `lib.rs`.
      Adds: `SmokeError` enum (Io, Config, State, Permission, Module,
      NotRoot, Verify, Unsupported), `type Result<T>`.
      Acceptance: unit tests for common error Display.
      Deps: previous.

- [ ] `feat(core): identifier model`
      Files: `crates/smoke-core/src/identifier.rs`.
      Adds: `IdentifierId` (string newtype), `Category` enum
      (Dmi, MachineId, Hostname, Net, Storage, FsUuid, Bootloader,
      Kernel, Tpm, Edid, Usb, Battery, Acpi, Logs, Services, Misc),
      `Finding { id, category, source, value, read_path }`,
      `Findings { items, partial_failures }`.
      Acceptance: serde round-trip, unit tests.
      Deps: error types.

- [ ] `feat(core): coverage / risk / requirements enums`
      Files: `crates/smoke-core/src/coverage.rs`.
      Adds: `Tier { T0, T1, T2, T3, T4 }`, `Strategy` bitflag
      (S1..S7), `Coverage { achieved_tier, by_strategy }`,
      `Risk { level, summary, mitigations }`, `Requirements
      { root, kmod, bpf, reboot, degraded_mode }`.
      Acceptance: unit tests for bitflag ops.
      Deps: identifier model.

- [ ] `feat(core): SmokeModule trait`
      Files: `crates/smoke-core/src/module.rs`.
      Adds: the trait from SPEC §6.2 plus `ApplyCtx`, `RotateCtx`,
      `ApplyReport`, `RotateReport`, `RevertReport`, `ModuleStatus`.
      Acceptance: trait compiles, doc examples.
      Deps: identifier, coverage.

- [ ] `feat(core): vendor catalog seed`
      Files: `crates/smoke-core/src/vendors.rs` + `data/vendors.toml`.
      Adds: curated OUI table (~50 entries), DMI vendor+board+BIOS
      presets, disk vendor+model presets. Powers the `consistent`
      profile.
      Acceptance: parsing test; `pick(vendor=QEMU)` returns coherent
      set.
      Deps: identifier model.

- [ ] `feat(core): randomization engine - common types`
      Files: `crates/smoke-core/src/rng/mod.rs`.
      Adds: `Rng` (SeedableRng wrapper around ChaCha20Rng),
      `Profile` enum, `ValueOverride` enum (UseProfile, Fixed,
      Random, Keep).
      Acceptance: reproducible output from fixed seed.
      Deps: vendors.

- [ ] `feat(core): randomization engine - random profile`
      Files: `crates/smoke-core/src/rng/random.rs`.
      Adds: pure-random generation per identifier kind (MAC, UUID,
      DMI string, serial, hostname).
      Acceptance: unit tests for each kind (format checks, no panic).
      Deps: rng common.

- [ ] `feat(core): randomization engine - consistent profile`
      Files: `crates/smoke-core/src/rng/consistent.rs`.
      Adds: pick a vendor, then derive coherent values across all
      identifier kinds.
      Acceptance: golden test - fixed seed produces the same
      coherent profile every time.
      Deps: random profile.

- [ ] `feat(core): randomization engine - locally-administered MAC`
      Files: `crates/smoke-core/src/rng/lam.rs`.
      Adds: LAM-bit MAC generation; everything else returns Keep.
      Acceptance: test that bit 1 of first octet is set.
      Deps: rng common.

- [ ] `feat(core): randomization engine - pinned profile`
      Files: `crates/smoke-core/src/rng/pinned.rs`.
      Adds: load identity from a TOML file.
      Acceptance: round-trip test (write then read).
      Deps: rng common.

- [ ] `feat(core): config schema`
      Files: `crates/smoke-core/src/config/mod.rs`.
      Adds: `SmokeConfig { version, profile, modules: Map<ModuleId,
      ModuleConfig>, rotation: RotationConfig, log_scrub: … }`,
      `ModuleConfig { enabled, overrides: Map<IdentifierId,
      ValueOverride> }`.
      Acceptance: serde TOML round-trip test on a representative
      config; validation errors tested.
      Deps: rng.

- [ ] `feat(core): config load/save + default path resolution`
      Files: `crates/smoke-core/src/config/io.rs`.
      Adds: load from `/etc/smoke/smoke.toml` or `--config` override;
      XDG fallback for unprivileged runs. Atomic save (write tmp +
      rename).
      Acceptance: tests using tempdir.
      Deps: config schema.

- [ ] `feat(core): state store schema`
      Files: `crates/smoke-core/src/state/mod.rs`.
      Adds: `State { version, modules: Map<ModuleId, ModuleState> }`,
      `ModuleState { last_applied, last_rotated, rotation_count,
      current_values: Map<IdentifierId, String> }`.
      Acceptance: serde JSON round-trip, schema version field set
      to `1`.
      Deps: config.

- [ ] `feat(core): state store load/save`
      Files: `crates/smoke-core/src/state/io.rs`.
      Adds: atomic load/save to `/var/lib/smoke/state.json`; version
      migration stub.
      Acceptance: tests using tempdir; corrupt-file error path
      tested.
      Deps: state schema.

- [ ] `feat(core): backup store + integrity manifest`
      Files: `crates/smoke-core/src/backup/mod.rs`,
      `crates/smoke-core/src/backup/manifest.rs`.
      Adds: write original value blobs to `/var/lib/smoke/backup/`,
      compute SHA-256 manifest. Signed with optional ed25519 key
      (`smoke.toml::backup.signing_key`).
      Acceptance: round-trip + tamper-detection tests.
      Deps: state.

- [ ] `feat(core): module registry and dispatch`
      Files: `crates/smoke-core/src/registry.rs`.
      Adds: `Registry` holding `Vec<Box<dyn SmokeModule>>`, with
      `by_id`, `by_category`, `iter_enabled(config)`.
      Acceptance: register a no-op test module, look it up.
      Deps: module trait, config.

- [ ] `feat(core): executor (apply/rotate/revert driver)`
      Files: `crates/smoke-core/src/executor.rs`.
      Adds: drives a set of modules through their lifecycle, updates
      state, writes backups, produces aggregate reports.
      Acceptance: tests using a fake module that records calls.
      Deps: registry, state, backup.

- [ ] `feat(cli): crate skeleton with clap`
      Files: `crates/smoke-cli/Cargo.toml`, `src/main.rs`,
      `src/cli.rs`.
      Adds: `clap` parser matching SPEC §7. Subcommands are stubs
      returning `unimplemented!()` except `--version`.
      Acceptance: `smoke --version`, `smoke --help`, `smoke list
     --help` all work.
      Deps: core.

- [ ] `feat(cli): logging and JSON output`
      Files: `crates/smoke-cli/src/output.rs`.
      Adds: `--json` flag, `--verbose`, structured logging via
      `tracing` + `tracing-subscriber`. Human output via a thin
      `Display` impl layer.
      Acceptance: `smoke --json status` returns valid JSON even for
      stub output.
      Deps: cli skeleton.

- [ ] `feat(cli): smoke list`
      Files: `crates/smoke-cli/src/cmd/list.rs`.
      Adds: list known identifier groups from registry; `--category`
      and `--status` filters.
      Acceptance: output matches registry contents; tests with fake
      modules.
      Deps: registry, output.

- [ ] `feat(cli): smoke dump`
      Files: `crates/smoke-cli/src/cmd/dump.rs`.
      Adds: walk every registered module's `enumerate()`, emit
      JSON/text. `--out FILE`, `--real` (skip spoofed view),
      `--spoofed`.
      Acceptance: smoke dump runs end-to-end on the dev box without
      modules; integrates with stub modules.
      Deps: list.

- [ ] `feat(cli): smoke fingerprint`
      Files: `crates/smoke-cli/src/cmd/fingerprint.rs`.
      Adds: SHA-256 over canonicalized dump output. Stable across
      re-runs if input is stable.
      Acceptance: same machine → same fingerprint (modulo real
      changes); test with canned dump.
      Deps: dump.

- [ ] `feat(cli): smoke status`
      Files: `crates/smoke-cli/src/cmd/status.rs`.
      Adds: read state.json, summarize per-module coverage and
      last-applied.
      Acceptance: tests with seeded state file.
      Deps: state.

- [ ] `feat(cli): smoke config show/validate`
      Files: `crates/smoke-cli/src/cmd/config.rs`.
      Adds: print or validate config; `validate` exits non-zero on
      schema errors with a helpful message.
      Acceptance: validation tests for good/bad configs.
      Deps: config io.

- [ ] `feat(cli): smoke selftest`
      Files: `crates/smoke-cli/src/cmd/selftest.rs`.
      Adds: smoke-the-binary - verify state/backup dirs writable
      (when root), config parses, registry non-empty.
      Acceptance: returns 0 in dev env.
      Deps: status.

- [ ] `test: integration harness for dump before/after`
      Files: `tests/dump_diff.rs`.
      Adds: scenario that runs `smoke dump` once, applies a fake
      change via a test module, dumps again, asserts the diff is
      exactly the spoofed field. Uses `assert_cmd` + `predicates`.
      Acceptance: test green in CI.
      Deps: dump, executor.

- [ ] `feat(spike): /proc/pid/mem walker prototype`
      Files: `crates/smoke-scan/Cargo.toml`, `src/lib.rs`,
      `src/walker.rs`.
      Adds: R&D prototype that reads `/proc/<pid>/maps`, walks
      readable regions via `process_vm_readv`, scans for a substring.
      Reports complexity back.
      Acceptance: prototype can find a known string in `cat`'s
      memory in a test process.
      Deps: none (sandbox crate).

- [ ] `feat(spike): yara integration feasibility probe`
      Files: `crates/smoke-scan/src/yara_probe.rs`.
      Adds: small experiment linking `yara-rust` (or vendored YARA),
      confirming license compatibility and binary size cost.
      Acceptance: report committed as
      `docs/rnd/memory-scan.md` (next commit).
      Deps: walker.

- [ ] `docs(rnd): memory scan complexity report`
      Files: `docs/rnd/memory-scan.md`.
      Adds: findings from the two spikes: LoC, license, latency,
      recommendation for 0.1 (ship / defer). Updates SPEC §9.3 with
      the decision.
      Acceptance: human-readable; answers all questions in SPEC §9.3.
      Deps: yara probe.

- [ ] `docs: contributor guide`
      Files: `CONTRIBUTING.md`.
      Adds: how to add a module, how to run tests, where things live.
      Acceptance: a fresh agent can follow it.
      Deps: Phase 0 mostly done.

### P0 - Open questions

- Q-P0-1: YARA is GPLv3 - but it's a *runtime* dependency. Confirm we
  can depend on it under GPLv3-only without GPLv3-only incompatibility
  (it should be fine). If not, use `/proc/<pid>/mem` walker only.
- Q-P0-2: Do we want ed25519 signing for the backup manifest in 0.1,
  or defer to "integrity only via SHA-256"? Recommendation: defer
  signing; keep SHA-256 manifest only.
- Q-P0-3: Should `smoke dump` include a `--redact` flag for safe
  sharing (replaces values with hashes)? Likely yes; add during P0.

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

- [ ] `feat(mod-machine-id): crate + enumerate`
      Files: `crates/smoke-modules/mod-machine-id/`.
      Adds: enumerate `/etc/machine-id`, `/var/lib/dbus/machine-id`,
      `/var/lib/systemd/random-seed`, `/etc/hostid`, plus
      `/var/lib/*/machine-id` glob. Doc example.
      Acceptance: enumerate returns Findings on dev box.
      Deps: P0 core + executor.

- [ ] `feat(mod-machine-id): apply + revert with backup`
      Files: same crate, `apply.rs`.
      Adds: write new value (default profile-consistent UUIDv4);
      backup original; revert restores from backup. Atomic per file.
      Acceptance: round-trip test in tempdir.
      Deps: enumerate.

- [ ] `feat(mod-machine-id): rotation`
      Files: same crate, `rotate.rs`.
      Adds: produce new value, call apply.
      Acceptance: rotation counter increments in state.
      Deps: apply.

- [ ] `feat(mod-machine-id): register and doctor coverage`
      Files: same crate, `lib.rs`, registry registration in
      `smoke-cli`.
      Adds: module wired into `smoke list`/`status`/`apply`. Doctor
      coverage report notes "covered: file readers; uncovered: none
      in 0.1 scope".
      Acceptance: `smoke apply --module machine-id --dry-run` lists
      changes.
      Deps: rotate.

- [ ] `test(mod-machine-id): root-integration test`
      Files: `tests/root/machine_id.rs` (gated by `root-integration`
      feature).
      Adds: real apply/revert on `/etc/machine-id` in a container.
      Acceptance: passes when run with `cargo test --features
      root-integration` as root.
      Deps: previous.

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
- `test(p2): e2e coverage on Arch and Debian`
- `release: v0.2.0`

### P2 - Open questions

- Q-P2-1: For the ACPI initramfs patcher (T4 spike) - do we ship it
  enabled-by-default in 0.2 or only as an experimental flag? Likely
  experimental; gate behind `--enable-experimental`.
- Q-P2-2: EDID firmware override requires a kernel reboot to take
  effect. Document as `needs-reboot` (exit code 3).

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
- `feat(wrap): smoke wrap (bubblewrap namespace)`
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
