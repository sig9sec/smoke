// smoke - Linux privacy / anti-fingerprinting suite
// Copyright (C) 2026  Michele Federici (@ps1dr3x) <michele@federici.tech>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#![cfg(feature = "root-integration")]

use smoke_core::SmokeModule;
use smoke_core::module::{ApplyCtx, RevertCtx};
use smoke_core::rng;
use smoke_modules::MachineIdModule;
use std::collections::HashMap;
use std::fs;

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn read_machine_id() -> String {
    fs::read_to_string("/etc/machine-id")
        .unwrap()
        .trim()
        .to_string()
}

#[test]
fn real_apply_revert_roundtrip() {
    if !is_root() {
        eprintln!("skipping: not running as root");
        return;
    }

    let original = read_machine_id();
    let module = MachineIdModule::new();

    let ctx = ApplyCtx {
        dry_run: false,
        force: false,
        profile: smoke_core::Profile::Random,
        overrides: HashMap::new(),
        generator: rng::create_generator(smoke_core::Profile::Random, 42),
    };

    let report = module.apply(&ctx).unwrap();
    assert!(
        report
            .changed
            .iter()
            .any(|c| c.identifier == "system-machine-id"),
        "expected system-machine-id in changes"
    );

    let after_apply = read_machine_id();
    assert_ne!(after_apply, original, "machine-id should have changed");
    assert_eq!(after_apply.len(), 32, "machine-id should be 32 hex chars");

    let mut originals = HashMap::new();
    for change in &report.changed {
        originals.insert(change.identifier.clone(), change.old_value.clone());
    }

    let revert_ctx = RevertCtx {
        dry_run: false,
        originals,
    };
    module.revert(&revert_ctx).unwrap();

    let after_revert = read_machine_id();
    assert_eq!(after_revert, original, "machine-id should be restored");
}

#[test]
fn real_enumerate_finds_machine_id() {
    let module = MachineIdModule::new();
    let findings = module.enumerate().unwrap();

    let has_mid = findings
        .items
        .iter()
        .any(|f| f.id.as_str() == "system-machine-id");
    assert!(has_mid, "enumerate should find /etc/machine-id");
}

#[test]
fn real_apply_is_idempotent() {
    if !is_root() {
        eprintln!("skipping: not running as root");
        return;
    }

    let original = read_machine_id();
    let module = MachineIdModule::new();

    let ctx = ApplyCtx {
        dry_run: false,
        force: false,
        profile: smoke_core::Profile::Random,
        overrides: HashMap::from([(
            smoke_core::identifier::IdentifierId::new("system-machine-id"),
            smoke_core::rng::ValueOverride::Fixed(original.clone()),
        )]),
        generator: rng::create_generator(smoke_core::Profile::Random, 42),
    };

    let report = module.apply(&ctx).unwrap();
    let mid_changed = report
        .changed
        .iter()
        .any(|c| c.identifier == "system-machine-id");
    assert!(!mid_changed, "applying the same value should be a no-op");
}
