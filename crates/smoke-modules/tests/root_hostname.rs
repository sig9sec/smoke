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
use smoke_core::identifier::IdentifierId;
use smoke_core::module::{ApplyCtx, RevertCtx};
use smoke_core::rng;
use smoke_core::rng::ValueOverride;
use smoke_modules::HostnameModule;
use std::collections::HashMap;
use std::fs;

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn read_hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .unwrap()
        .trim()
        .to_string()
}

fn read_kernel_hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap()
        .trim()
        .to_string()
}

fn read_kernel_domainname() -> String {
    fs::read_to_string("/proc/sys/kernel/domainname")
        .unwrap()
        .trim()
        .to_string()
}

#[test]
fn real_hostname_apply_revert_roundtrip() {
    if !is_root() {
        eprintln!("skipping: not running as root");
        return;
    }

    let original = read_hostname();
    let original_kernel = read_kernel_hostname();
    let module = HostnameModule::new();

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
            .any(|c| c.identifier == "static-hostname"),
        "expected static-hostname in changes"
    );

    let after_apply = read_hostname();
    assert_ne!(after_apply, original, "hostname should have changed");

    let after_kernel = read_kernel_hostname();
    assert_ne!(
        after_kernel, original_kernel,
        "kernel hostname should have changed"
    );

    let mut originals = HashMap::new();
    for change in &report.changed {
        originals.insert(change.identifier.clone(), change.old_value.clone());
    }

    let revert_ctx = RevertCtx {
        dry_run: false,
        originals,
    };
    module.revert(&revert_ctx).unwrap();

    let after_revert = read_hostname();
    assert_eq!(after_revert, original, "hostname should be restored");

    let after_revert_kernel = read_kernel_hostname();
    assert_eq!(
        after_revert_kernel, original_kernel,
        "kernel hostname should be restored"
    );
}

#[test]
fn real_hostname_enumerate() {
    let module = HostnameModule::new();
    let findings = module.enumerate().unwrap();

    let has_static = findings
        .items
        .iter()
        .any(|f| f.id.as_str() == "static-hostname");
    assert!(has_static, "enumerate should find /etc/hostname");
}

#[test]
fn real_domainname_apply_revert() {
    if !is_root() {
        eprintln!("skipping: not running as root");
        return;
    }

    let original_domain = read_kernel_domainname();
    let original_hostname = read_hostname();
    let module = HostnameModule::new();

    let ctx = ApplyCtx {
        dry_run: false,
        force: false,
        profile: smoke_core::Profile::Random,
        overrides: HashMap::from([(
            IdentifierId::new("static-hostname"),
            ValueOverride::Fixed("testhost.example.com".into()),
        )]),
        generator: rng::create_generator(smoke_core::Profile::Random, 42),
    };

    let report = module.apply(&ctx).unwrap();
    assert!(
        report
            .changed
            .iter()
            .any(|c| c.identifier == "static-hostname"),
        "expected static-hostname in changes"
    );

    let after_domain = read_kernel_domainname();
    assert_eq!(
        after_domain, "example.com",
        "kernel domainname should be set"
    );

    let domain_change = report.changed.iter().find(|c| c.identifier == "domainname");
    assert!(
        domain_change.is_some(),
        "expected domainname in changes when hostname is FQDN"
    );
    assert_eq!(domain_change.unwrap().new_value, "example.com");

    let mut originals = HashMap::new();
    for change in &report.changed {
        originals.insert(change.identifier.clone(), change.old_value.clone());
    }

    let revert_ctx = RevertCtx {
        dry_run: false,
        originals,
    };
    module.revert(&revert_ctx).unwrap();

    let reverted_domain = read_kernel_domainname();
    assert_eq!(
        reverted_domain, original_domain,
        "kernel domainname should be restored"
    );

    let reverted_hostname = read_hostname();
    assert_eq!(
        reverted_hostname, original_hostname,
        "hostname should be restored"
    );
}
