# smoke - Specification

**Version:** 0.1 (draft)
**Status:** living document; updated as decisions are made.
**Scope:** this document defines what `smoke` is, what it covers, how it
is architected, and what its non-goals are. The phased rollout and
per-commit plan live in [`IMPLEMENTATION-PLAN.md`](./IMPLEMENTATION-PLAN.md).

---

## 1. Purpose

`smoke` is a Linux systems-level privacy suite whose goal is to **remove,
spoof, randomize, rotate, or conceal every hardware- and OS-level
identifier** that can be used to permanently or semi-permanently
fingerprint a host, an OS install, or a network presence. It also
**disrupts processes** whose job is to gather those identifiers.

It is layered: early releases work purely in userspace; later phases add
kernel/eBPF interception for identifiers that cannot be reached from
userspace.

---

## 2. Decisions (locked-in for 0.1)

| Area | Decision |
|---|---|
| Implementation language | **Rust**, edition 2024, stable channel |
| Phase-1 scope | **Userspace-first**, plus any low-hanging kernel/boot items found during R&D that fit naturally into an MVP. Full kernel/boot coverage is deferred. |
| Kernel module signing | **Unsigned** for now; Secure Boot / MOK signing is a later phase. |
| Default randomization | **Consistent profile** (coherent fake hardware). Each individual value is **independently overridable** by the user. |
| Distro targeting | **Common Linux stack** (systemd, bash, Wayland, GNOME, coreutils, util-linux, iproute2, dbus, udev, polkit, NetworkManager). Distro-specific features are **flagged** in code and docs. Phase-0/1 CI matrix: **Arch + Debian/Ubuntu**. |
| License | **GPL-3.0-only**, applied to every source file. |
| Memory scanner | R&D'd during 0.1; complexity/cost quoted; included only if cost is reasonable. Default plan: defer to a later phase. |
| Init system | **systemd** is the primary target. Core logic stays **init-agnostic** (plain files + an `apply` CLI) so openrc/runit/dinit glue can be added later. |

---

## 3. Threat model

### 3.1 In scope

We defend against an adversary that can:

1. Run any userspace program (root or unprivileged) that reads IDs from
   `/sys`, `/proc`, `/etc`, device nodes, via ioctls (SG_IO, NVME_IOCTL,
   HDIO_*, ETHTOOL, MMC, USBDEVFS, HIDIOCGRECORD), via CPUID/MSR, via
   TPM commands, via libusb, via X11/Wayland, via DBus.
2. Sniff the local network segment: passive link observer, DHCP server,
   Wi-Fi probe sniffer, Bluetooth scanner, mDNS/SSDP/NetBIOS peer, NTP
   server, TLS peer doing host-key correlation.
3. Re-identify the same hardware or install across reboots or across
   networks.

### 3.2 Out of scope (called out, not solved)

- Browser/JIT fingerprints (separate tool; we may integrate hardened
  profiles but do not solve them here).
- Application-layer accounts, cookies, login sessions.
- Adversaries with **physical access** who can dump SPI flash, JTAG, or
  read TPM NVRAM externally.
- Hardware side-channels beyond clock/timing basics (acoustic, power,
  RF/TEMPEST).

### 3.3 Coverage tiers

Each identifier in §5 carries a coverage tier describing what
`smoke` can realistically achieve against an attacker reading it from
each path:

- **T0 - None.** Hardware-burned, no mitigation possible without
  disabling the device.
- **T1 - Partial (userspace).** Defeats processes that read sysfs / proc
  / config files. Bypassed by direct ioctls or memory scans.
- **T2 - Partial (udev).** Defeats tools that use udev/`lsblk` style
  enumeration. Bypassed by pass-through ioctls.
- **T3 - Full (kernel).** Defeats all userspace readers including those
  using pass-through ioctls, by hooking in kernel/eBPF.
- **T4 - Full (boot).** Defeats everything including early-boot
  observers, by patching firmware tables before kernel start (kexec /
  EFI stub / bootloader).

The MVP (Phase 1) targets **T1 + T2** for everything in its scope.
Phase 3 raises most items to **T3**. A few items reach **T4** later.

---

## 4. Strategy catalog

`smoke` uses one or more of these strategies per identifier. Each module
declares which strategies it implements; `doctor` reports the resulting
coverage tier.

| Code | Name | Description | Tier |
|---|---|---|---|
| **S1** | File overwrite | Replace `/etc/machine-id`, hostname, ssh keys, FS UUIDs. | T1 |
| **S2** | Bind-mount / overlay | Mount spoofed content over `/sys`, `/proc`, `/etc` read-only pseudo-files. | T1 |
| **S3** | udev / .link / hotplug rule | Change MAC, USB serial presentation, disk presentation via udev ENV overrides. | T2 |
| **S4** | Kernel / eBPF interception | Hook syscalls/ioctls (SG_IO, NVME_IOCTL, MMC, ETHTOOL, `dmi_walk`, i2c transfers, USB descriptor reads, TPM). | T3 |
| **S5** | Disable / remove | Turn the device or service off (TPM, WWAN, mDNS, UPnP, webcam). | T1-T3 |
| **S6** | Periodic rotation | Regenerate and re-apply on a timer (MAC every 10 min, machine-id per boot, ssh keys weekly). | T1+ |
| **S7** | Boot-stage patch | Rewrite firmware tables before kernel start (kexec into patched kernel, EFI stub, initramfs pre-hook). | T4 |

---

## 5. Identifier catalog

Organized by layer. Each entry lists: source paths, how an attacker
reads it, persistence (P=permanent hardware, F=firmware/NVRAM,
S=software/state file, V=volatile per-boot), and target strategy tier
for 0.1.

### 5.1 SMBIOS / DMI (firmware-resident)

| # | Identifier | Sources | Attacker read path | Persist | 0.1 target |
|---|---|---|---|---|---|
| 1 | Product UUID | `/sys/class/dmi/id/product_uuid` | sysfs | F | **T1** (S2); T3 later |
| 2 | Product serial | `/sys/class/dmi/id/product_serial` | sysfs | F | T1 (S2) |
| 3 | Board serial | `/sys/class/dmi/id/board_serial` | sysfs | F | T1 (S2) |
| 4 | Chassis serial | `/sys/class/dmi/id/chassis_serial` | sysfs | F | T1 (S2) |
| 5 | Asset tag | `/sys/class/dmi/id/asset_tag` | sysfs | F | T1 (S2) |
| 6 | BIOS version/vendor/date | `/sys/class/dmi/id/bios_*` | sysfs | F | T1 (S2) |
| 7 | sys_vendor / product_name / version / sku / family | `/sys/class/dmi/id/*` | sysfs | F | T1 (S2) |
| 8 | board_vendor / name / version | `/sys/class/dmi/id/board_*` | sysfs | F | T1 (S2) |
| 9 | chassis vendor / type / version | `/sys/class/dmi/id/chassis_*` | sysfs | F | T1 (S2) |
| 10 | Processor version (SMBIOS type 4) | `dmidecode -t 4` | dmidecode | F | **deferred** (T3 only) |
| 11 | Full SMBIOS/DMI tables | `/sys/firmware/dmi/tables/{DMI,SMBIOS}` | direct file | F | **deferred** (T3 only) |
| 12 | Memory device serials (type 17) | `dmidecode -t memory` | dmidecode | F | **deferred** (T3 only) |

> **Critical:** `dmidecode` and raw table reads bypass sysfs
> bind-mounts. Full coverage (rows 10-12) requires S4 (kernel rewrite
> of the table buffer in `dmi_walk`). This is the hardest single
> problem in the project; deferred from 0.1.

### 5.2 Machine / install identity

| # | Identifier | Sources | Persist | 0.1 target |
|---|---|---|---|---|
| 13 | systemd machine-id | `/etc/machine-id`, `/var/lib/dbus/machine-id` | S | **T1** (S1 + S6) |
| 14 | boot_id | `/proc/sys/kernel/random/boot_id` | V | accept (already rotates per boot) |
| 15 | systemd random-seed | `/var/lib/systemd/random-seed` | S | T1 (S1) |
| 16 | hostid | `/etc/hostid` (mostly BSD) | S | T1 (S1) |
| 17 | Per-package install IDs | `/var/lib/*/machine-id`, `*/identifier` | S | T1 (S1 scrub) |

### 5.3 Hostname / identity strings

| # | Identifier | Sources | Persist | 0.1 target |
|---|---|---|---|---|
| 18 | static hostname | `/etc/hostname` | S | **T1** (S1) |
| 19 | pretty/transient hostname | systemd-hostnamed, `hostnamectl` | V/S | T1 (S1 + S6) |
| 20 | domainname | `/proc/sys/kernel/domainname`, `/etc/resolv.conf` | S | T1 (S1) |
| 21 | mailname | `/etc/mailname` | S | T1 (S1) |
| 22 | mDNS hostname (avahi) | avahi config | V | T1 (S1 + config) |
| 23 | NetBIOS name | samba | S | T1 (S1) |
| 24 | DHCP Client Identifier / DUID | NetworkManager, dhclient, systemd-networkd | S | T1 (S1 + S6) |
| 25 | DHCPv6 DUID-LLT / DUID-UUID | `/var/lib/NetworkManager/`, `/var/lib/dhcp/` | S | T1 (S1 + S6) |
| 26 | IAID | DHCPv6 | V/S | T1 (S6) |

### 5.4 Network interfaces

| # | Identifier | Sources | Attacker read path | Persist | 0.1 target |
|---|---|---|---|---|---|
| 27 | NIC MAC (current) | `/sys/class/net/*/address`, `ip link` | sysfs/ioctl | F (BIA) | **T1+T2** (S3 + S6) |
| 28 | NIC permanent MAC (BIA) | `ethtool -P`, `ETHTOOL_GPERMADDR` | ioctl | F | **deferred** (T3 only) |
| 29 | Wi-Fi MAC | same as 27 | same | F | T1+T2 (NM `wifi.cloned-mac-address`) |
| 30 | Wi-Fi saved-network BSSIDs | `/etc/NetworkManager/system-connections/*` | file | S | T1 (S1 scrub) |
| 31 | Wi-Fi probe requests | driver firmware | RF | F | deferred (T3 driver patch) |
| 32 | Bluetooth BD_ADDR | `/sys/class/bluetooth/hci*/address`, HCI socket | HCI | F | deferred to Phase 4 |
| 33 | Bluetooth paired cache | `/var/lib/bluetooth/` | file | S | T1 (S1 scrub) |
| 34 | WWAN IMEI | ModemManager / QMI / `AT+CGSN` | modem dev | **F, immutable** | T0 - **disable only** (S5) |
| 35 | WWAN IMSI / ICCID | modem / SIM | modem dev | F | T0 - disable only |
| 36 | IPv6 SLAAC (EUI-64 from MAC) | derived | derived | V | T1+T2 (rides MAC rotation) |
| 37 | IPv4 / IPv6 addresses | DHCP/RA | network | V | T1 (S6 lease rotation) |
| 38 | TCP timestamps & clock skew | `net.ipv4.tcp_timestamps` | network | V | T1 (sysctl) - perf cost noted |
| 39 | ICMP timestamp | kernel | network | V | T1 (sysctl / firewall) |

### 5.5 Storage device identifiers

| # | Identifier | Sources | Read path | Persist | 0.1 target |
|---|---|---|---|---|---|
| 40 | SATA/SCSI disk serial | `lsblk -o SERIAL`, `/dev/disk/by-id/`, SG_IO INQUIRY | SG_IO ioctl | F | **T2** (S3 udev ENV); T3 later |
| 41 | Disk WWN / WWID | `lsblk -o WWN`, `/dev/disk/by-id/wwn-*` | SG_IO | F | T2 (S3) |
| 42 | NVMe NGUID / EUI64 / VS / OUI | NVME_IOCTL_ADMIN_CMD Identify | ioctl | F | deferred (T3 only) |
| 43 | NVMe serial/model/firmware | NVMe Identify | ioctl | F | T2 (S3 scsi_id) |
| 44 | eMMC CID/CSD/OCR/FWREV/MID/OID | `/sys/block/mmcblk*/device/*` | sysfs + MMC ioctl | F | T1 (S2) for sysfs; ioctl deferred |
| 45 | SD card CID | `/sys/block/mmcblk*/device/cid`, MMC ioctl | sysfs/ioctl | F | T1 (S2) |
| 46 | UFS serial | UFS ioctl | ioctl | F | deferred |
| 47 | USB-storage serial | `lsusb -v`, `/dev/disk/by-id/usb-*` | libusb/SG_IO | F | T2 (S3 udev) |

### 5.6 Filesystem & partition identifiers

| # | Identifier | Sources | Persist | 0.1 target |
|---|---|---|---|---|
| 48 | GPT disk GUID | `/dev/disk/by-partuuid/`, `sgdisk -p` | F | **T1** (S1 sgdisk rewrite) |
| 49 | GPT partition GUIDs | same | F | T1 (S1) |
| 50 | MBR disk signature | first sector | F | T1 (S1) |
| 51 | ext2/3/4 UUID | `/dev/disk/by-uuid/`, `tune2fs -l` | F | **T1** (S1 `tune2fs -U random`) |
| 52 | xfs UUID | `xfs_admin -U` | F | T1 (S1) |
| 53 | btrfs UUID + dev_uuid | `btrfstune -u` | F | T1 (S1, careful) |
| 54 | f2fs UUID | `fsck.f2fs` | F | T1 (S1) |
| 55 | FAT/exFAT serial | `mlabel` | F | T1 (S1) |
| 56 | NTFS serial | `ntfslabel` / hex edit | F | T1 (S1) |
| 57 | LUKS UUID | `cryptsetup luksUUID` | F | T1 (S1, careful) |
| 58 | LVM PV/VG/LV UUIDs | `pvs/vgs/lvs -o +uuid` | S on disk | T1 (S1 pv/vg/lv change) |
| 59 | mdadm array UUID + homehost | `mdadm --detail`, `/etc/mdadm.conf` | F+S | T1 (S1) |
| 60 | Swap UUID/label | `swaplabel` | F | T1 (S1) |
| 61 | ZFS pool/dataset GUID | `zpool` | F | T1 (S1) - flagged distro-specific |
| 62 | bcachefs UUID | `bcachefs` | F | T1 (S1) |

> **Critical cascade:** rewriting FS UUIDs requires updating fstab,
> crypttab, grub.cfg, EFI entries, initramfs, and resume= in the kernel
> command line atomically, plus a verified revert path. This is the
> highest-risk area of Phase 1.

### 5.7 Bootloader

| # | Identifier | Sources | Persist | 0.1 target |
|---|---|---|---|---|
| 63 | initramfs embedded host info | initrd cpio | S | T1 (S1 rebuild) |
| 64 | GRUB UUID refs (`root=UUID=`, `cryptomount`) | `/boot/grub/grub.cfg`, EFI | S | T1 (S1 regen config) |
| 65 | EFI NVRAM entries (BootOrder, BootXXXX) | `/sys/firmware/efi/efivars/` | F | T1 (S1 `efibootmgr`) |

### 5.8 CPU / microcode

| # | Identifier | Sources | Read path | Persist | 0.1 target |
|---|---|---|---|---|---|
| 66 | CPUID (family/model/stepping/feature) | `cpuid` instr | any proc | F | **T0** - deferred (needs KVM; future `smoke vm`) |
| 67 | CPUID PSN (P3-era) | cpuid | any | F | verify disabled, else warn |
| 68 | Microcode revision | MSR 0x8B | root MSR | F | deferred (T3) |
| 69 | `/proc/cpuinfo` strings | `/proc/cpuinfo` | sysfs | F | T1 (S2 bind-mount) |
| 70 | cache/tlb/topology | `/sys/devices/system/cpu/...` | sysfs | F | T1 (S2) |
| 71 | RDRAND unicity | `RDRAND` instr | any | F | T0 (none possible) |
| 72 | TSC frequency / clock skew | `RDTSC` | any | F | mitigations only |

### 5.9 Memory / I2C / SPD

| # | Identifier | Sources | Read path | Persist | 0.1 target |
|---|---|---|---|---|---|
| 73 | DIMM SPD (mfr/serial/lot) | `decode-dimms`, `/dev/i2c-*` EEPROM | I2C ioctl | F | T1 (S5: blacklist `i2c-dev`); T3 later |
| 74 | DDR5 PMIC serials | I2C | i2c-dev | F | T1 (S5) |
| 75 | Memory controller PCI IDs | PCI config space | `/sys/bus/pci/` | F | T1 (S2) |

### 5.10 GPU / graphics

| # | Identifier | Sources | Read path | Persist | 0.1 target |
|---|---|---|---|---|---|
| 76 | NVIDIA GPU UUID | `nvidia-smi -q`, NVML | NVML lib | F | deferred (T3 LD_PRELOAD/module) |
| 77 | DRM card info | `/sys/class/drm/card*/device/`, PCI cfg | sysfs | F | T1 (S2) |
| 78 | GL/Vulkan renderer string | `glxinfo`, env | GL/Vulkan | F | T1 (env override + LD_PRELOAD) |

### 5.11 Display / monitor

| # | Identifier | Sources | Read path | Persist | 0.1 target |
|---|---|---|---|---|---|
| 79 | EDID (mfr/model/serial/year/week) | `/sys/class/drm/.../edid`, `parse-edid`, `/dev/i2c-*` DDC | sysfs + i2c | F | **T1** (S7: `drm.edid_firmware`) for DRM path; i2c path deferred to T3 |
| 80 | Monitor serial in EDID block 0 | EDID | i2c | F | T3 only |
| 81 | DisplayID / block-map checksums | EDID | i2c | F | T3 only |

### 5.12 TPM

| # | Identifier | Sources | Read path | Persist | 0.1 target |
|---|---|---|---|---|---|
| 82 | TPM EK certificate (unique pubkey) | `/sys/class/tpm/tpm0/`, `tpm2_readcertificate` | TPM cmd | **F, burned** | **T0** - S5 disable only |
| 83 | TPM EK pubkey hash | TPM2_CreatePrimary EK | TPM cmd | F | T0 - disable only |
| 84 | TPM vendor ID | `TPM2_GetCapability` | TPM cmd | F | deferred (T3) |
| 85 | Persistent handles | `tpm2_getcap handles-persistent` | TPM cmd | F | T1 (S1 clear) |

> **Impossible to change in hardware.** Only mitigation is to disable
> TPM or replace with `swtpm` (software TPM, breaks measured boot).
> Tradeoff documented; module refuses to "spoof" and only offers
> disable/clear.

### 5.13 USB / HID / peripherals

| # | Identifier | Sources | Read path | Persist | 0.1 target |
|---|---|---|---|---|---|
| 86 | USB device serial | `lsusb -v`, libusb `get_string_descriptor` | libusb/usbfs | F | T2 (S3 udev); T3 later |
| 87 | USB VID/PID | `lsusb` | libusb | F | T2 (S3) |
| 88 | HID descriptor strings | `lsusb -v`, hidraw | hidraw | F | deferred (T3) |
| 89 | Webcam serial (UVC) | `v4l2-ctl`, UVC descriptor | v4l2 ioctl | F | T1 (S2 sysfs) |
| 90 | Audio codec ID | `/proc/asound/card*/codec*` | sysfs | F | T1 (S2) |
| 91 | HDA codec subsystem/vendor ID | `/sys/class/sound/hdaC*` | sysfs | F | T1 (S2) |

### 5.14 Battery / power

| # | Identifier | Sources | Persist | 0.1 target |
|---|---|---|---|---|
| 92 | Battery serial | `/sys/class/power_supply/BAT*/serial_number` | F | T1 (S2) |
| 93 | Battery mfr/model | `/sys/class/power_supply/BAT*/{manufacturer,model_name,technology}` | F | T1 (S2) |
| 94 | Charger / AC info | `/sys/class/power_supply/AC*/` | F | T1 (S2) |

### 5.15 ACPI / firmware tables

| # | Identifier | Sources | Persist | 0.1 target |
|---|---|---|---|---|
| 95 | ACPI OEM ID / table ID (RSDP/RSDT/XSDT) | `/sys/firmware/acpi/tables/` | F | **deferred** (T4: early-boot patch only) |
| 96 | FADT/DSDT/SSDT OEM fields | `acpidump`, sysfs | F | deferred (T4) |
| 97 | BGRT boot logo | `/sys/firmware/acpi/bgrt/` | F | T1 (S2) |
| 98 | UEFI variables (BootOrder etc.) | `/sys/firmware/efi/efivars/` | F | T1 (S1 selective) |
| 99 | SMBIOS type-11 OEM strings | dmidecode | F | deferred (T3) |

### 5.16 Kernel / runtime state

| # | Identifier | Sources | Persist | 0.1 target |
|---|---|---|---|---|
| 100 | Kernel version string | `uname -a`, `/proc/version`, `/proc/sys/kernel/*` | S | T1 (S2) - breaks tools, opt-in |
| 101 | Kernel command line | `/proc/cmdline` | S | T1 (S2) |
| 102 | Loaded modules list | `/proc/modules`, `/sys/module` | V | T1 (S2) - opt-in |
| 103 | Boot time / uptime | `/proc/uptime`, `/proc/stat btime` | V | T1 (S2) - opt-in |
| 104 | Build timestamp | `/proc/version`, BTF | S | T1 (S2) |

### 5.17 Logs & state containing IDs

| # | Identifier | Persist | 0.1 target |
|---|---|---|---|
| 105 | dmesg ring (hw prints) | S | T1 (S5 restrict + S1 scrub) |
| 106 | journald history | S | T1 (S1 scrub + filter rules) |
| 107 | auth.log / syslog | S | T1 (S1 scrub) |
| 108 | NetworkManager logs | S | T1 (S1 scrub) |
| 109 | shell histories (`~/.bash_history`, zsh) | S | T1 (S1 scrub + disable) |
| 110 | X11/Wayland logs | S | T1 (S1 scrub) |
| 111 | package manager logs | S | T1 (S1 scrub) |
| 112 | editor caches (VS Code, etc.) | S | T1 (S1 scrub) |

### 5.18 Service / process fingerprints

| # | Identifier | Sources | Persist | 0.1 target |
|---|---|---|---|---|
| 113 | SSH host keys | `/etc/ssh/ssh_host_*` | S | **T1** (S1 regen + S6 rotate) |
| 114 | SSH `authorized_keys` correlation | `~/.ssh/` | S | T1 (user-managed) |
| 115 | GPG keys | `~/.gnupg/` | S | user-managed |
| 116 | TLS server certs (services) | various | S | T1 (S1 rotate) |
| 117 | WireGuard peer public keys | `/etc/wireguard/` | S | T1 (S1) |
| 118 | Kerberos / Samba machine account | various | S | T1 (S1) |
| 119 | mDNS service records | avahi | V | T1 (S5 disable) |
| 120 | UPnP/SSDP device serials | miniupnpd etc. | V | T1 (S5 disable) |
| 121 | DNS resolver of ISP | `/etc/resolv.conf` | S | T1 (S1 force DoH/DoT) - flagged opt-in |
| 122 | TCP/IP stack fingerprint (p0f, nmap) | network | V | T1 (sysctl tuning) - best effort |

### 5.19 Misc

| # | Identifier | Persist | 0.1 target |
|---|---|---|---|
| 123 | RTC model & skew | hwclock | accept (sync to NTP) |
| 124 | HWRNG model | `/dev/hwrng` | T1 (S5 if paranoid) - opt-in |
| 125 | PCI config space device IDs | `/sys/bus/pci/devices/` | F | T1 (S2) - opt-in |
| 126 | NUMA / clocksource / topology | sysfs | F | T1 (S2) - opt-in |
| 127 | `/etc/passwd` user list | S | T1 (S1 randomize) - opt-in, risky |
| 128 | timezone / locale | `/etc/timezone`, `locale` | S | T1 (S1) - opt-in |
| 129 | keyboard layout | `/etc/vconsole.conf`, Xkb | S | T1 (S1) - opt-in |
| 130 | installed package list | pacman/dpkg/rpm | S | T1 (S1) - opt-in, risky |

---

## 6. Architecture

### 6.1 Crates

```
crates/
  smoke-cli/        # the `smoke` binary (clap)
  smoke-core/       # shared types, config, state, module trait
  smoke-modules/    # one file/submodule per identifier group
  smoke-kmod/       # kernel module (Phase 3, C)
  smoke-bpf/        # eBPF programs (Phase 3, libbpf-rs)
  smoke-preload/    # LD_PRELOAD shim (Phase 3)
  smoke-scan/       # memory scanner (Phase 5 / R&D)
```

### 6.2 Module trait

Every identifier group is implemented as a `SmokeModule`:

```rust
pub trait SmokeModule: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn category(&self) -> Category;
    fn requires(&self) -> Requirements;
    fn enumerate(&self) -> Result<Findings>;
    fn apply(&self, ctx: &ApplyCtx) -> Result<ApplyReport>;
    fn rotate(&self, ctx: &RotateCtx) -> Result<RotateReport>;
    fn status(&self) -> Result<ModuleStatus>;
    fn revert(&self) -> Result<RevertReport>;
    fn coverage(&self) -> Coverage;     // which strategies are active -> tier
    fn risks(&self) -> Risk;            // breakage risk profile
}
```

- `enumerate()` is **read-only** and powers `list`, `dump`, `fingerprint`,
  `doctor`. It must never fail closed - partial findings are reported.
- `apply()` is **destructive** and must be atomic per-module: write
  backup first, then change, then verify by re-enumerating.
- `rotate()` is `apply()` with a "produce new value" step.
- `revert()` restores from backup; must be safe to call multiple times.
- `coverage()` is what `doctor` consumes to tell the user "this module
  covers sysfs readers but not ioctl readers - upgrade to Phase 3 for
  full coverage."

### 6.3 State

- `/etc/smoke/smoke.toml` - user config.
- `/var/lib/smoke/state.json` - current values per module, rotation
  counters, last-applied timestamps.
- `/var/lib/smoke/backup/` - original values, with a signed manifest.
- Optionally LUKS-encrypted at rest; documented as opt-in.

State schema is versioned; `state.version` field drives migrations.

### 6.4 Randomization profiles

- `random` - pure random per field. Highest anonymity, easiest to
  detect as spoofed.
- `consistent` - **default**. Generates a coherent fake hardware profile
  (DMI vendor + board + serial + BIOS coherent; MAC OUI matching the
  spoofed vendor; disk vendor + model matching). Drawn from a curated
  vendor catalog (`smoke-core::vendors`).
- `locally-administered` - MAC-only profile (sets LAM bit, iOS/Android
  style). Other identifiers untouched.
- `pinned` - load identity from a file. Same identity across a fleet
  (honey-pots, VM pools).

Each individual value is independently overridable in
`smoke.toml::[modules.<id>]` regardless of profile.

### 6.5 Init-system policy

- Core logic is **plain Rust** with no systemd dependency. A module
  expresses its persistence requirements as data ("needs to run at boot
  before `multi-user.target`", "needs to run every 10 minutes").
- A `systemd` adapter lives in `smoke-cli::service::systemd` and
  generates units from those requirements.
- Future adapters: `openrc`, `runit`, `dinit`. The trait they implement
  is `ServiceBackend` in `smoke-core::service`.

---

## 7. CLI

```
smoke apply    [--module NAME ...] [--profile NAME|pinned:FILE] [--dry-run]
smoke rotate   [--module NAME ...] [--period 1h|boot|daily]
smoke status   [--module NAME] [--json]
smoke doctor   [--fix]
smoke revert   [--module NAME ...] [--all] [--force]
smoke enable   <module>
smoke disable  <module>
smoke list     [--category NAME] [--status covered|partial|exposed]
smoke dump     [--out FILE] [--real | --spoofed]
smoke scan     <pattern|--yara FILE> [--pid N|--all]            # R&D, may defer
smoke watch    <pattern|--yara FILE> [--poll 1s|--ebpf]         # R&D, may defer
smoke fingerprint
smoke diff
smoke config   {edit|show|validate}
smoke service  {install|enable-rotate-timer|status}
smoke selftest
smoke --version
```

Exit codes: `0` ok, `1` partial, `2` error, `3` needs-reboot,
`4` needs-kmod.

### 7.1 `smoke doctor`

The doctor verifies each module's claimed coverage by **re-reading every
identifier via every read path the module declares** - not just the
path the module patched. If a module patched `/sys/class/dmi/id/product_uuid`
but the real value is still reachable via `dmidecode`, doctor reports
`coverage = partial` for that module. This is the single most important
verification step in the project.

---

## 8. Critical / difficult / impossible points

### 8.1 Critical (architecture-defining)

1. **DMI/SMBIOS raw table reads** (`dmidecode`, `/sys/firmware/dmi/tables/`)
   bypass sysfs bind-mounts. T3 requires in-kernel rewrite of the table
   buffer (`dmi_walk` hook). Deferred from 0.1.
2. **Disk serial via SG_IO / NVME_IOCTL pass-through.** udev renames
   don't help. T3 requires kretprobes on `sg_io`, `nvme_submit_user_cmd`,
   `mmc_ioctl`. Deferred from 0.1; 0.1 covers T2 (udev presentation).
3. **NIC permanent MAC (BIA)** via `ethtool -P` / `ETHTOOL_GPERMADDR`.
   T3 only. Documented limitation in 0.1.
4. **EDID via direct i2c-dev reads.** T1 covers DRM/sysfs via
   `drm.edid_firmware`; i2c path is T3.
5. **TPM EK certificate.** Hardware-burned, immutable. Only S5 (disable)
   or `swtpm` substitution. Module refuses to spoof.
6. **CPUID.** Unprivileged instruction; cannot be intercepted without
   KVM. Future `smoke vm` (libvirt/qemu with spoofed CPUID) is the only
   true mitigation. Out of scope for 0.1.
7. **Network-side clock skew** (TCP timestamps, ICMP). Cannot be
   eliminated, only uniformized. Documented as best-effort.
8. **Secure Boot.** Unsigned kmods/eBPF won't load. 0.1 ships
   userspace-only and a `--degraded` flag is documented for the
   eventual kernel features.
9. **Persistence across reboots.** Most spoofings are not persistent
   without an early-boot hook. `smoke-apply.service` in
   `multi-user.target` + `smoke-initramfs` hook handle this.
10. **FS-UUID rewrite cascade.** Changing a FS UUID breaks fstab,
    crypttab, grub.cfg, EFI entries, initramfs, and `resume=`. All
    consumers must be rewritten atomically with a verified revert path.
    Highest-risk area of Phase 1.
11. **Breakage cascade.** Changing machine-id wipes the systemd journal,
    NetworkManager state, paired BT devices, etc. Each module declares
    `risks()`; `apply` refuses high-risk combos without `--force`.

### 8.2 Impossible / not solvable

- TPM EK (above).
- CPUID without VM.
- Cellular IMEI (also **illegal** in most jurisdictions - `smoke`
  refuses to change IMEI under any flag; only offers disable).
- Hardware clock drift (mitigable, not eliminable).
- Per-sensor noise (webcam/mic) - physical only.
- AC power / RF emanations (TEMPEST).

### 8.3 Legally sensitive

- IMEI changing is illegal; `smoke` will not implement it.
- Disabling TPM may break disk encryption that relies on it; document
  tradeoffs and refuse to proceed without `--i-understand-tpm-risks`.

---

## 9. Memory scanner (bonus, R&D during 0.1)

The user has asked for an R&D pass on a `smoke scan` / `smoke watch`
feature that searches process memory for known identifier strings and
alerts when one appears.

### 9.1 Feasibility summary

- **Search (one-shot):** reliable. Use `/proc/<pid>/mem` walking or
  `YARA` over live processes.
- **Watch (live):** reliable via polling; low-latency via eBPF/kmod
  hooks on `copy_to_user` / `vfs_read` / `mmap`.

### 9.2 Implementation options to cost during R&D

| Option | Scope | Cost estimate | Coverage |
|---|---|---|---|
| `/proc/<pid>/mem` walker + YARA | scan only | **Low** (≈1 crate, ~500 LoC) | All accessible processes |
| Polling watch (YARA every N s) | watch | **Low** (extends above) | Latency ≥ poll interval |
| eBPF on `copy_to_user` w/ substring match | watch, low latency | **High** (verifier bounds, ~1500 LoC + kmod fallback) | All userspace |
| kmod hook on `copy_to_user` | watch, low latency | **High** (~1000 LoC C, signed-kernel caveat) | All userspace + some kernel |
| frida injection per target | watch single app | **Medium** (~800 LoC, frida dep) | One process |

### 9.3 0.1 decision

**Decision: `smoke scan` ships in 0.1.**

The R&D spike confirmed:
- Walker + YARA fits in ~280 LoC (well under 1500).
- `boreal` (pure Rust YARA, MPL-2.0) is GPL-3.0-compatible.
- Polling latency is acceptable (~100ms for typical process).

`smoke scan` ships in 0.1 with `process_vm_readv` walker + `boreal`
YARA matching. `smoke watch` ships polling-only in 0.1 and gains eBPF
in Phase 3. See `docs/rnd/memory-scan.md` for the full report.

---

## 10. Distribution

- Source repo + `cargo install` for 0.1.
- Distro packaging later: pacman (Arch), deb (Debian/Ubuntu), rpm
  (Fedora), Nix.
- systemd unit templates ship under `dist/systemd/` and are installed by
  `smoke service install`.

---

## 11. Future / additional features (not in 0.1)

- `smoke vm` - one-command QEMU/libvirt VM with full CPUID/DMI/EDID
  spoofing (the "truest" anti-fingerprint sandbox).
- `smoke panic` - wipe state + backup + zeroize random-seed, for
  adversarial situations.
- `smoke wrap <app>` - run an app inside a bubblewrap namespace with all
  spoofed mounts so a specific app sees the spoofed view without
  affecting the host.
- Fleet profile sync (pin many hosts to one identity for honey-potting).
- TUI dashboard (`smoke tui`).
- Preset policy profiles (`paranoid`, `balanced`, `stealth-vpn`,
  `lab-vm`).
- Browser-hardening profile generator (adjacent, opt-in).

---

## 12. Glossary

- **BIA** - Burned-In Address (hardware MAC).
- **CID** - Card IDentification register (eMMC/SD).
- **DUID** - DHCP Unique IDentifier.
- **EDID** - Extended Display IDentification Data.
- **EK** - Endorsement Key (TPM).
- **IAID** - Identity Association IDentifier (DHCPv6).
- **LAM** - Locally Administered MAC bit.
- **NGUID** - Namespace Globally Unique IDentifier (NVMe).
- **SPD** - Serial Presence Detect (RAM).
- **WWN** - World Wide Name (storage).
