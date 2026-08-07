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

//! Hostname and identity-string spoofing (SPEC 5.3).
//!
//! Covers static hostname (`/etc/hostname`), pretty hostname
//! (`/etc/machine-info`), runtime hostname (`/proc/sys/kernel/hostname`),
//! NIS domainname (`/proc/sys/kernel/domainname`), mailname
//! (`/etc/mailname`), and optional avahi/samba name sync.
//!
//! # Example
//!
//! ```
//! use smoke_core::SmokeModule;
//! use smoke_modules::HostnameModule;
//!
//! let module = HostnameModule::new();
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

use crate::util::read_optional;
use std::path::Path;

const STATIC_HOSTNAME: &str = "/etc/hostname";
const MACHINE_INFO: &str = "/etc/machine-info";
const RUNTIME_HOSTNAME: &str = "/proc/sys/kernel/hostname";
const DOMAINNAME: &str = "/proc/sys/kernel/domainname";
const MAILNAME: &str = "/etc/mailname";

pub struct HostnameModule;

impl HostnameModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HostnameModule {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_machine_info(content: &str) -> Option<String> {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("PRETTY_HOSTNAME=") {
            let val = rest.trim_matches('"');
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

fn read_finding(id: &str, path: &Path, category: Category) -> Option<Finding> {
    let content = read_optional(path)?;
    if content.is_empty() {
        return None;
    }
    Some(Finding {
        id: IdentifierId::new(id),
        category,
        source: path.to_string_lossy().to_string(),
        value: content,
        read_path: "file".into(),
    })
}

fn enumerate_at(base: &Path) -> Findings {
    let mut findings = Findings::new();

    if let Some(f) = read_finding(
        "static-hostname",
        &base.join(STATIC_HOSTNAME.trim_start_matches('/')),
        Category::Hostname,
    ) {
        findings.push(f);
    }

    let mi_path = base.join(MACHINE_INFO.trim_start_matches('/'));
    if let Some(content) = read_optional(&mi_path) {
        if let Some(pretty) = parse_machine_info(&content) {
            findings.push(Finding {
                id: IdentifierId::new("pretty-hostname"),
                category: Category::Hostname,
                source: mi_path.to_string_lossy().to_string(),
                value: pretty,
                read_path: "file".into(),
            });
        }
    }

    if let Some(f) = read_finding(
        "runtime-hostname",
        &base.join(RUNTIME_HOSTNAME.trim_start_matches('/')),
        Category::Hostname,
    ) {
        findings.push(f);
    }

    if let Some(f) = read_finding(
        "domainname",
        &base.join(DOMAINNAME.trim_start_matches('/')),
        Category::Hostname,
    ) {
        findings.push(f);
    }

    if let Some(f) = read_finding(
        "mailname",
        &base.join(MAILNAME.trim_start_matches('/')),
        Category::Hostname,
    ) {
        findings.push(f);
    }

    findings
}

impl SmokeModule for HostnameModule {
    fn id(&self) -> &'static str {
        "hostname"
    }

    fn name(&self) -> &'static str {
        "Hostname / identity strings"
    }

    fn category(&self) -> Category {
        Category::Hostname
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
        unimplemented!("smoke mod-hostname apply")
    }

    fn rotate(&self, _ctx: &RotateCtx) -> Result<RotateReport> {
        unimplemented!("smoke mod-hostname rotate")
    }

    fn status(&self) -> Result<ModuleStatus> {
        Ok(ModuleStatus::default())
    }

    fn revert(&self, _ctx: &RevertCtx) -> Result<RevertReport> {
        unimplemented!("smoke mod-hostname revert")
    }

    fn coverage(&self) -> Coverage {
        Coverage {
            achieved_tier: Tier::PartialUserspace,
            strategies: vec![Strategy::FileOverwrite, Strategy::PeriodicRotation],
        }
    }

    fn risks(&self) -> Risk {
        Risk {
            level: RiskLevel::Low,
            summary: "Changing hostname may confuse running services that \
                      cache the name at startup"
                .into(),
            mitigations: vec![
                "Backup is created automatically before apply".into(),
                "Use --dry-run to preview changes".into(),
                "Revert restores original hostname".into(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerate_returns_findings() {
        let module = HostnameModule::new();
        let findings = module.enumerate().unwrap();
        assert!(
            findings
                .items
                .iter()
                .all(|f| f.category == Category::Hostname)
        );
    }

    #[test]
    fn enumerate_from_tempdir() {
        let dir = tempfile::tempdir().unwrap();

        std::fs::create_dir_all(dir.path().join("etc")).unwrap();
        std::fs::write(dir.path().join("etc/hostname"), "testhost\n").unwrap();
        std::fs::write(
            dir.path().join("etc/machine-info"),
            "PRETTY_HOSTNAME=\"Test Host\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("proc/sys/kernel")).unwrap();
        std::fs::write(dir.path().join("proc/sys/kernel/hostname"), "testhost\n").unwrap();
        std::fs::write(dir.path().join("proc/sys/kernel/domainname"), "(none)\n").unwrap();

        let findings = enumerate_at(dir.path());
        assert_eq!(findings.len(), 4);

        let static_h = findings
            .items
            .iter()
            .find(|f| f.id.as_str() == "static-hostname")
            .unwrap();
        assert_eq!(static_h.value, "testhost");

        let pretty = findings
            .items
            .iter()
            .find(|f| f.id.as_str() == "pretty-hostname")
            .unwrap();
        assert_eq!(pretty.value, "Test Host");

        let runtime = findings
            .items
            .iter()
            .find(|f| f.id.as_str() == "runtime-hostname")
            .unwrap();
        assert_eq!(runtime.value, "testhost");

        let domain = findings
            .items
            .iter()
            .find(|f| f.id.as_str() == "domainname")
            .unwrap();
        assert_eq!(domain.value, "(none)");
    }

    #[test]
    fn enumerate_skips_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let findings = enumerate_at(dir.path());
        assert!(findings.is_empty());
    }

    #[test]
    fn parse_machine_info_extracts_pretty() {
        let content = "PRETTY_HOSTNAME=\"My Laptop\"\nICON_NAME=computer-laptop\n";
        assert_eq!(parse_machine_info(content), Some("My Laptop".into()));
    }

    #[test]
    fn parse_machine_info_no_pretty() {
        let content = "ICON_NAME=computer-laptop\nCHASSIS=laptop\n";
        assert_eq!(parse_machine_info(content), None);
    }

    #[test]
    fn parse_machine_info_empty_pretty() {
        let content = "PRETTY_HOSTNAME=\"\"\n";
        assert_eq!(parse_machine_info(content), None);
    }

    #[test]
    fn enumerate_finds_mailname() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("etc")).unwrap();
        std::fs::write(dir.path().join("etc/mailname"), "example.org\n").unwrap();

        let findings = enumerate_at(dir.path());
        let mail = findings
            .items
            .iter()
            .find(|f| f.id.as_str() == "mailname")
            .unwrap();
        assert_eq!(mail.value, "example.org");
    }

    #[test]
    fn enumerate_machine_info_without_pretty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("etc")).unwrap();
        std::fs::write(
            dir.path().join("etc/machine-info"),
            "ICON_NAME=computer-laptop\nCHASSIS=laptop\n",
        )
        .unwrap();

        let findings = enumerate_at(dir.path());
        assert!(
            findings
                .items
                .iter()
                .all(|f| f.id.as_str() != "pretty-hostname"),
            "should not emit a pretty-hostname finding"
        );
    }

    #[test]
    fn coverage_and_risks() {
        let module = HostnameModule::new();
        assert_eq!(module.coverage().achieved_tier, Tier::PartialUserspace);
        assert_eq!(module.risks().level, RiskLevel::Low);
        assert!(module.requires().root);
    }
}
