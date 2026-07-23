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

//! systemd machine-id and related install-identity files.
//!
//! Covers SPEC section 5.2:
//! - `/etc/machine-id` (systemd)
//! - `/var/lib/dbus/machine-id` (dbus copy)
//! - `/var/lib/systemd/random-seed` (binary seed)
//! - `/etc/hostid` (mostly BSD)
//! - `/var/lib/*/machine-id` glob (per-package install IDs)
//!
//! # Example
//!
//! ```
//! use smoke_core::SmokeModule;
//! use smoke_modules::MachineIdModule;
//!
//! let module = MachineIdModule::new();
//! let findings = module.enumerate().unwrap();
//! for item in &findings.items {
//!     println!("{}: {}", item.source, item.value);
//! }
//! ```

use smoke_core::Category;
use smoke_core::Result;
use smoke_core::coverage::{Coverage, Requirements, Risk, RiskLevel, Strategy, Tier};
use smoke_core::identifier::{Finding, Findings, IdentifierId};
use smoke_core::module::*;

use std::path::Path;

const PATHS: &[(&str, &str)] = &[
    ("system-machine-id", "/etc/machine-id"),
    ("dbus-machine-id", "/var/lib/dbus/machine-id"),
    ("random-seed", "/var/lib/systemd/random-seed"),
    ("hostid", "/etc/hostid"),
];

const GLOB_PARENT: &str = "/var/lib";

/// Spoofing module for the machine-id family (SPEC 5.2).
pub struct MachineIdModule;

impl MachineIdModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MachineIdModule {
    fn default() -> Self {
        Self::new()
    }
}

fn read_finding(id: &str, path: &Path) -> Option<Finding> {
    if !path.exists() {
        return None;
    }
    let content = std::fs::read(path).ok()?;
    let value = if id == "random-seed" {
        format!("<binary, {} bytes>", content.len())
    } else {
        String::from_utf8_lossy(&content).trim().to_string()
    };
    Some(Finding {
        id: IdentifierId::new(id),
        category: Category::MachineId,
        source: path.to_string_lossy().to_string(),
        value,
        read_path: "file".into(),
    })
}

fn enumerate_at(base: &Path) -> Findings {
    let mut findings = Findings::new();
    let mut seen: Vec<std::path::PathBuf> = Vec::new();

    for (id, rel) in PATHS {
        let path = base.join(rel.trim_start_matches('/'));
        if let Some(f) = read_finding(id, &path) {
            seen.push(path);
            findings.push(f);
        }
    }

    if let Ok(entries) = std::fs::read_dir(base.join(GLOB_PARENT.trim_start_matches('/'))) {
        for entry in entries.flatten() {
            let pkg_dir = entry.path();
            if !pkg_dir.is_dir() {
                continue;
            }
            let mid = pkg_dir.join("machine-id");
            if mid.exists() && !seen.contains(&mid) {
                if let Some(f) = read_finding("pkg-machine-id", &mid) {
                    findings.push(f);
                }
            }
        }
    }

    findings
}

impl SmokeModule for MachineIdModule {
    fn id(&self) -> &'static str {
        "machine-id"
    }

    fn name(&self) -> &'static str {
        "Machine / install identity"
    }

    fn category(&self) -> Category {
        Category::MachineId
    }

    fn requires(&self) -> Requirements {
        Requirements {
            root: true,
            ..Default::default()
        }
    }

    fn enumerate(&self) -> Result<Findings> {
        Ok(enumerate_at(Path::new("/")))
    }

    fn apply(&self, _ctx: &ApplyCtx) -> Result<ApplyReport> {
        unimplemented!("smoke mod-machine-id apply")
    }

    fn rotate(&self, _ctx: &RotateCtx) -> Result<RotateReport> {
        unimplemented!("smoke mod-machine-id rotate")
    }

    fn status(&self) -> Result<ModuleStatus> {
        Ok(ModuleStatus::default())
    }

    fn revert(&self) -> Result<RevertReport> {
        unimplemented!("smoke mod-machine-id revert")
    }

    fn coverage(&self) -> Coverage {
        Coverage {
            achieved_tier: Tier::PartialUserspace,
            strategies: vec![Strategy::FileOverwrite, Strategy::PeriodicRotation],
        }
    }

    fn risks(&self) -> Risk {
        Risk {
            level: RiskLevel::Medium,
            summary: "Changing machine-id wipes the systemd journal, \
                      NetworkManager state, and paired Bluetooth devices"
                .into(),
            mitigations: vec![
                "Backup is created automatically before apply".into(),
                "Use --dry-run to preview changes".into(),
                "Revert restores original values".into(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn enumerate_returns_findings() {
        let module = MachineIdModule::new();
        let findings = module.enumerate().unwrap();
        assert!(
            findings
                .items
                .iter()
                .all(|f| f.category == Category::MachineId)
        );
    }

    #[test]
    fn enumerate_from_tempdir() {
        let dir = tempfile::tempdir().unwrap();

        let mid_content = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\n";
        fs::create_dir_all(dir.path().join("etc")).unwrap();
        fs::write(dir.path().join("etc/machine-id"), mid_content).unwrap();

        let dbus_content = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\n";
        fs::create_dir_all(dir.path().join("var/lib/dbus")).unwrap();
        fs::write(dir.path().join("var/lib/dbus/machine-id"), dbus_content).unwrap();

        fs::create_dir_all(dir.path().join("var/lib/systemd")).unwrap();
        fs::write(
            dir.path().join("var/lib/systemd/random-seed"),
            b"\x00\x01\x02\x03",
        )
        .unwrap();

        let findings = enumerate_at(dir.path());
        assert_eq!(findings.len(), 3);

        let mid = findings
            .items
            .iter()
            .find(|f| f.id.as_str() == "system-machine-id")
            .unwrap();
        assert_eq!(mid.value, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6");

        let dbus = findings
            .items
            .iter()
            .find(|f| f.id.as_str() == "dbus-machine-id")
            .unwrap();
        assert_eq!(dbus.value, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6");

        let seed = findings
            .items
            .iter()
            .find(|f| f.id.as_str() == "random-seed")
            .unwrap();
        assert!(seed.value.starts_with("<binary"));
    }

    #[test]
    fn enumerate_finds_pkg_machine_id() {
        let dir = tempfile::tempdir().unwrap();

        fs::create_dir_all(dir.path().join("var/lib/foo")).unwrap();
        fs::write(
            dir.path().join("var/lib/foo/machine-id"),
            "aaaabbbbccccddddeeeeffff00112233\n",
        )
        .unwrap();

        let findings = enumerate_at(dir.path());
        let pkg = findings
            .items
            .iter()
            .find(|f| f.id.as_str() == "pkg-machine-id")
            .unwrap();
        assert!(pkg.source.ends_with("foo/machine-id"));
    }

    #[test]
    fn enumerate_skips_missing() {
        let dir = tempfile::tempdir().unwrap();
        let findings = enumerate_at(dir.path());
        assert!(findings.is_empty());
    }

    #[test]
    fn coverage_and_risks() {
        let module = MachineIdModule::new();
        assert_eq!(module.coverage().achieved_tier, Tier::PartialUserspace);
        assert_eq!(module.risks().level, RiskLevel::Medium);
        assert!(module.requires().root);
    }
}
