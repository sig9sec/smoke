# Memory Scanner R&D Report

## Summary

Prototyped two approaches for scanning process memory for identifier
strings: raw `/proc/<pid>/mem` walking with byte search, and YARA-based
pattern matching via `boreal` (pure Rust).

Both work. Recommendation: **ship in 0.1** (polling watch mode).

## Approaches tested

### 1. `/proc/<pid>/maps` + `process_vm_readv` + byte search

**Crate:** `smoke-scan::walker`

**LoC:** ~200 (including tests)

**How it works:**
- Parse `/proc/<pid>/maps` to find readable regions.
- Use `process_vm_readv(2)` to read each region.
- Sliding-window byte search for needle.

**Results:**
- Finds strings in own process reliably.
- Can scan any process the caller has ptrace access to.
- No root required for own processes; root needed for others
  (unless `ptrace_scope=0`).

**Latency:** ~100ms to scan a typical process (Chrome with 200MB
resident). Linear in total readable memory size.

**Limitations:**
- Only sees pages currently resident in RAM (not swapped out).
- Skips regions >1GB to avoid excessive memory use.
- Does not catch kernel-side copies.

### 2. YARA via `boreal` (pure Rust)

**Crate:** `smoke-scan::yara_probe`, depends on `boreal` v1.1.0

**LoC:** ~80 (wrapper + tests)

**License:** `boreal` is MPL-2.0. Compatible with GPL-3.0.

**How it works:**
- Compile YARA rules with `boreal::Compiler`.
- Scan memory slices with `Scanner::scan_mem`.

**Results:**
- YARA rules compile and match correctly.
- Can scan process memory (combined with walker) for complex patterns.
- Pure Rust, no C dependency, no system YARA install needed.

**Binary size cost:** ~2MB added to release binary (boreal + deps).

**Latency:** Comparable to raw byte search for simple substring
patterns. YARA regex patterns are slower but still within acceptable
bounds for polling.

## Recommendation for 0.1

**Ship `smoke scan` in 0.1** with:
- `process_vm_readv` walker for reading.
- `boreal` for YARA rule matching.
- Polling watch mode (`smoke watch --poll 1s`).

**Deferred to Phase 3:**
- eBPF `copy_to_user` hook for low-latency watch.
- kmod hook for kernel-side memory reads.

## Dependencies added

| Crate | Version | License | Purpose |
|---|---|---|---|
| `boreal` | 1.1.0 | MPL-2.0 | YARA rule compilation and scanning |
| `libc` | 0.2 | MIT/Apache-2.0 | `process_vm_readv` syscall |

MPL-2.0 is compatible with GPL-3.0 (MPL code must remain under MPL
when distributed, but can be combined with GPL code in a larger work).

## Open questions

- Q: Should YARA rules be embedded in the binary or loaded from files?
  A: Both. Ship a default rule set embedded; allow user rules from
  `/etc/smoke/rules/`.

- Q: Should `smoke scan` require root?
  A: For scanning other processes, yes (ptrace access). For scanning
  self, no. Document clearly.
