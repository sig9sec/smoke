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
use smoke_core::SmokeError;
use smoke_core::coverage::{Coverage, Requirements, Risk, RiskLevel, Strategy, Tier};
use smoke_core::identifier::{Finding, Findings, IdentifierId};
use smoke_core::module::*;
use smoke_core::rng::ValueOverride;

use crate::util::atomic_write;
use crate::util::read_optional;
use std::collections::HashMap;
use std::path::Path;

const STATIC_HOSTNAME: &str = "/etc/hostname";
const MACHINE_INFO: &str = "/etc/machine-info";
const RUNTIME_HOSTNAME: &str = "/proc/sys/kernel/hostname";
const DOMAINNAME: &str = "/proc/sys/kernel/domainname";
const MAILNAME: &str = "/etc/mailname";
const AVAHI_CONF: &str = "/etc/avahi/avahi-daemon.conf";
const SAMBA_CONF: &str = "/etc/samba/smb.conf";

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

fn resolve_hostname(
    overrides: &HashMap<IdentifierId, ValueOverride>,
    generator: &dyn smoke_core::ValueGenerator,
) -> Option<String> {
    match overrides.get(&IdentifierId::new("static-hostname")) {
        Some(ValueOverride::Fixed(v)) => Some(v.clone()),
        Some(ValueOverride::Random) | Some(ValueOverride::UseProfile) | None => {
            Some(generator.hostname())
        }
        Some(ValueOverride::Keep) => None,
    }
}

fn set_kernel_hostname(name: &str) -> Result<()> {
    let c_name = std::ffi::CString::new(name)
        .map_err(|e| SmokeError::Module(format!("invalid hostname: {e}")))?;
    // SAFETY: c_name is a valid CString; the kernel only reads len bytes
    // from the pointer and does not retain it after the syscall returns.
    let ret = unsafe { libc::sethostname(c_name.as_ptr(), c_name.as_bytes().len()) };
    if ret != 0 {
        return Err(SmokeError::Module(format!(
            "sethostname failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn set_kernel_domainname(name: &str) -> Result<()> {
    let c_name = std::ffi::CString::new(name)
        .map_err(|e| SmokeError::Module(format!("invalid domainname: {e}")))?;
    // SAFETY: c_name is a valid CString; the kernel only reads len bytes
    // from the pointer and does not retain it after the syscall returns.
    let ret = unsafe { libc::setdomainname(c_name.as_ptr(), c_name.as_bytes().len()) };
    if ret != 0 {
        return Err(SmokeError::Module(format!(
            "setdomainname failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn hostname_to_pretty(hostname: &str) -> String {
    hostname
        .split('-')
        .filter(|w| !w.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().chain(chars).collect(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn extract_domain(hostname: &str) -> Option<String> {
    if hostname.starts_with('.') {
        return None;
    }
    if let Some(idx) = hostname.find('.') {
        let domain = &hostname[idx + 1..];
        if !domain.is_empty() && !domain.starts_with('.') {
            return Some(domain.to_string());
        }
    }
    None
}

fn update_machine_info(content: &str, pretty: &str) -> Result<String> {
    if pretty.contains('"') {
        return Err(SmokeError::Module(
            "pretty hostname contains invalid characters".into(),
        ));
    }
    let line = format!("PRETTY_HOSTNAME=\"{pretty}\"");
    let mut found = false;
    let mut result: Vec<String> = Vec::new();

    for l in content.lines() {
        if l.starts_with("PRETTY_HOSTNAME=") {
            result.push(line.clone());
            found = true;
        } else {
            result.push(l.to_string());
        }
    }
    if !found {
        result.push(line);
    }
    Ok(result.join("\n") + "\n")
}

fn remove_pretty_from_machine_info(content: &str) -> String {
    let filtered: Vec<&str> = content
        .lines()
        .filter(|l| !l.starts_with("PRETTY_HOSTNAME="))
        .collect();
    if filtered.is_empty() {
        String::new()
    } else {
        filtered.join("\n") + "\n"
    }
}

fn write_hostname(
    base: &Path,
    dry_run: bool,
    overrides: &HashMap<IdentifierId, ValueOverride>,
    generator: &dyn smoke_core::ValueGenerator,
) -> Result<ApplyReport> {
    let mut report = ApplyReport::default();
    let new_hostname = match resolve_hostname(overrides, generator) {
        Some(v) => v,
        None => return Ok(report),
    };

    let hostname_path = base.join(STATIC_HOSTNAME.trim_start_matches('/'));
    let old_hostname = read_optional(&hostname_path);
    if let Some(ref old) = old_hostname {
        if old != &new_hostname {
            if dry_run {
                report.changed.push(Change {
                    identifier: "static-hostname".into(),
                    old_value: old.clone(),
                    new_value: new_hostname.clone(),
                });
            } else {
                atomic_write(&hostname_path, &format!("{new_hostname}\n"))?;
                report.changed.push(Change {
                    identifier: "static-hostname".into(),
                    old_value: old.clone(),
                    new_value: new_hostname.clone(),
                });
            }
        }
    }

    let mi_path = base.join(MACHINE_INFO.trim_start_matches('/'));
    let mi_content = read_optional(&mi_path).unwrap_or_default();
    let old_pretty = parse_machine_info(&mi_content);
    let new_pretty = hostname_to_pretty(&new_hostname);
    if old_pretty.as_deref() != Some(new_pretty.as_str()) {
        if dry_run {
            report.changed.push(Change {
                identifier: "pretty-hostname".into(),
                old_value: old_pretty.unwrap_or_default(),
                new_value: new_pretty.clone(),
            });
        } else {
            let updated = update_machine_info(&mi_content, &new_pretty)?;
            atomic_write(&mi_path, &updated)?;
            report.changed.push(Change {
                identifier: "pretty-hostname".into(),
                old_value: old_pretty.unwrap_or_default(),
                new_value: new_pretty,
            });
        }
    }

    let mailname_path = base.join(MAILNAME.trim_start_matches('/'));
    let old_mailname = read_optional(&mailname_path);
    if let Some(ref old) = old_mailname {
        if old != &new_hostname {
            if dry_run {
                report.changed.push(Change {
                    identifier: "mailname".into(),
                    old_value: old.clone(),
                    new_value: new_hostname.clone(),
                });
            } else {
                atomic_write(&mailname_path, &format!("{new_hostname}\n"))?;
                report.changed.push(Change {
                    identifier: "mailname".into(),
                    old_value: old.clone(),
                    new_value: new_hostname.clone(),
                });
            }
        }
    }

    let domain_path = base.join(DOMAINNAME.trim_start_matches('/'));
    let old_domainname = read_optional(&domain_path);

    if let Some(domain) = extract_domain(&new_hostname) {
        let current_domain = old_domainname.as_deref().unwrap_or("");
        if current_domain != domain {
            if dry_run {
                report.changed.push(Change {
                    identifier: "domainname".into(),
                    old_value: current_domain.to_string(),
                    new_value: domain,
                });
            } else if base == Path::new("/") {
                report.changed.push(Change {
                    identifier: "domainname".into(),
                    old_value: current_domain.to_string(),
                    new_value: domain.clone(),
                });
                if let Err(e) = set_kernel_domainname(&domain) {
                    report
                        .warnings
                        .push(format!("setdomainname(2) failed: {e}"));
                }
            }
        }
    }

    if !dry_run && base == Path::new("/") {
        if let Err(e) = set_kernel_hostname(&new_hostname) {
            report.warnings.push(format!("sethostname(2) failed: {e}"));
        }
    }

    if let Some(change) = sync_optional_service(
        base,
        AVAHI_CONF,
        "server",
        "host-name",
        "avahi-hostname",
        &new_hostname,
        dry_run,
    )? {
        report.changed.push(change);
    }

    if let Some(change) = sync_optional_service(
        base,
        SAMBA_CONF,
        "global",
        "netbios name",
        "netbios-name",
        &new_hostname,
        dry_run,
    )? {
        report.changed.push(change);
    }

    Ok(report)
}

fn apply_at(base: &Path, ctx: &ApplyCtx) -> Result<ApplyReport> {
    write_hostname(base, ctx.dry_run, &ctx.overrides, &*ctx.generator)
}

fn revert_at(base: &Path, ctx: &RevertCtx) -> Result<RevertReport> {
    let mut report = RevertReport::default();

    for (id, rel) in [("static-hostname", STATIC_HOSTNAME), ("mailname", MAILNAME)] {
        let path = base.join(rel.trim_start_matches('/'));
        if !path.exists() {
            continue;
        }
        if let Some(original) = ctx.originals.get(id) {
            if ctx.dry_run {
                report.reverted.push(id.to_string());
                continue;
            }
            atomic_write(&path, &format!("{original}\n"))?;
            report.reverted.push(id.to_string());
        }
    }

    let mi_path = base.join(MACHINE_INFO.trim_start_matches('/'));
    if let Some(original) = ctx.originals.get("pretty-hostname") {
        if ctx.dry_run {
            report.reverted.push("pretty-hostname".into());
        } else if original.is_empty() {
            let mi_content = std::fs::read_to_string(&mi_path).unwrap_or_default();
            let stripped = remove_pretty_from_machine_info(&mi_content);
            if stripped.trim().is_empty() {
                let _ = std::fs::remove_file(&mi_path);
            } else {
                atomic_write(&mi_path, &stripped)?;
            }
            report.reverted.push("pretty-hostname".into());
        } else {
            let mi_content = std::fs::read_to_string(&mi_path).unwrap_or_default();
            let restored = update_machine_info(&mi_content, original)?;
            atomic_write(&mi_path, &restored)?;
            report.reverted.push("pretty-hostname".into());
        }
    }

    if !ctx.dry_run && base == Path::new("/") {
        if let Some(original) = ctx.originals.get("static-hostname") {
            if let Err(e) = set_kernel_hostname(original) {
                report
                    .warnings
                    .push(format!("sethostname(2) revert failed: {e}"));
            }
        }
        if let Some(original) = ctx.originals.get("domainname") {
            if let Err(e) = set_kernel_domainname(original) {
                report
                    .warnings
                    .push(format!("setdomainname(2) revert failed: {e}"));
            }
        }
    }

    if let Some(original) = ctx.originals.get("avahi-hostname") {
        if sync_optional_service(
            base,
            AVAHI_CONF,
            "server",
            "host-name",
            "avahi-hostname",
            original,
            ctx.dry_run,
        )?
        .is_some()
        {
            report.reverted.push("avahi-hostname".into());
        }
    }

    if let Some(original) = ctx.originals.get("netbios-name") {
        if sync_optional_service(
            base,
            SAMBA_CONF,
            "global",
            "netbios name",
            "netbios-name",
            original,
            ctx.dry_run,
        )?
        .is_some()
        {
            report.reverted.push("netbios-name".into());
        }
    }

    Ok(report)
}

fn rotate_at(base: &Path, ctx: &RotateCtx) -> Result<RotateReport> {
    let report = write_hostname(base, ctx.dry_run, &ctx.overrides, &*ctx.generator)?;
    Ok(RotateReport {
        rotated: report.changed.into_iter().map(|c| c.identifier).collect(),
        warnings: report.warnings,
    })
}

fn ini_key_matches(line: &str, target_key: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.starts_with('#') {
        return false;
    }
    if let Some(eq_idx) = trimmed.find('=') {
        let key = trimmed[..eq_idx].trim();
        key == target_key
    } else {
        false
    }
}

fn update_ini_key(content: &str, section: &str, key: &str, value: &str) -> String {
    let mut lines: Vec<String> = content.lines().map(String::from).collect();
    let mut in_section = false;
    let mut found = false;

    for line in &mut lines {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_section = trimmed == format!("[{section}]");
            continue;
        }
        if in_section && !found && ini_key_matches(line, key) {
            *line = format!("{key} = {value}");
            found = true;
        }
    }

    if !found {
        let insert_line = format!("{key} = {value}");
        let mut insert_idx = 0;
        for (i, line) in lines.iter().enumerate() {
            if line.trim() == format!("[{section}]") {
                insert_idx = i + 1;
            }
        }
        if insert_idx > 0 {
            lines.insert(insert_idx, insert_line);
        } else {
            lines.push(format!("[{section}]"));
            lines.push(insert_line);
        }
    }

    lines.join("\n") + "\n"
}

fn extract_ini_value(content: &str, section: &str, key: &str) -> Option<String> {
    let mut in_section = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_section = trimmed == format!("[{section}]");
            continue;
        }
        if in_section && ini_key_matches(line, key) {
            let uncommented = trimmed.strip_prefix('#').unwrap_or(trimmed);
            if let Some(eq_idx) = uncommented.find('=') {
                return Some(uncommented[eq_idx + 1..].trim().to_string());
            }
        }
    }
    None
}

fn sync_optional_service(
    base: &Path,
    conf_rel: &str,
    section: &str,
    key: &str,
    identifier: &str,
    hostname: &str,
    dry_run: bool,
) -> Result<Option<Change>> {
    let path = base.join(conf_rel.trim_start_matches('/'));
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path).map_err(|e| SmokeError::Io {
        path: path.clone(),
        source: e,
    })?;
    let old = extract_ini_value(&content, section, key);
    if old.as_deref() == Some(hostname) {
        return Ok(None);
    }
    if dry_run {
        return Ok(Some(Change {
            identifier: identifier.to_string(),
            old_value: old.unwrap_or_default(),
            new_value: hostname.to_string(),
        }));
    }
    let updated = update_ini_key(&content, section, key, hostname);
    atomic_write(&path, &updated)?;
    Ok(Some(Change {
        identifier: identifier.to_string(),
        old_value: old.unwrap_or_default(),
        new_value: hostname.to_string(),
    }))
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

    fn apply(&self, ctx: &ApplyCtx) -> Result<ApplyReport> {
        apply_at(Path::new("/"), ctx)
    }

    fn rotate(&self, ctx: &RotateCtx) -> Result<RotateReport> {
        rotate_at(Path::new("/"), ctx)
    }

    fn status(&self) -> Result<ModuleStatus> {
        Ok(ModuleStatus::default())
    }

    fn revert(&self, ctx: &RevertCtx) -> Result<RevertReport> {
        revert_at(Path::new("/"), ctx)
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

    fn setup_hostname_tempdir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("etc")).unwrap();
        std::fs::write(dir.path().join("etc/hostname"), "oldname\n").unwrap();
        dir
    }

    fn make_apply_ctx(seed: u64) -> ApplyCtx {
        ApplyCtx {
            dry_run: false,
            force: false,
            profile: smoke_core::Profile::Random,
            overrides: HashMap::new(),
            generator: smoke_core::rng::create_generator(smoke_core::Profile::Random, seed),
        }
    }

    #[test]
    fn apply_changes_hostname() {
        let dir = setup_hostname_tempdir();
        let ctx = make_apply_ctx(42);
        let report = apply_at(dir.path(), &ctx).unwrap();

        assert!(
            report
                .changed
                .iter()
                .any(|c| c.identifier == "static-hostname")
        );

        let after = std::fs::read_to_string(dir.path().join("etc/hostname"))
            .unwrap()
            .trim()
            .to_string();
        assert_ne!(after, "oldname");
        assert!(!after.is_empty());
    }

    #[test]
    fn apply_dry_run_no_write() {
        let dir = setup_hostname_tempdir();
        let mut ctx = make_apply_ctx(42);
        ctx.dry_run = true;
        let report = apply_at(dir.path(), &ctx).unwrap();

        assert!(
            report
                .changed
                .iter()
                .any(|c| c.identifier == "static-hostname")
        );

        let after = std::fs::read_to_string(dir.path().join("etc/hostname")).unwrap();
        assert_eq!(after.trim(), "oldname");
    }

    #[test]
    fn revert_restores_original() {
        let dir = setup_hostname_tempdir();
        let ctx = make_apply_ctx(42);
        apply_at(dir.path(), &ctx).unwrap();

        let revert_ctx = RevertCtx {
            dry_run: false,
            originals: HashMap::from([("static-hostname".into(), "oldname".into())]),
        };
        let report = revert_at(dir.path(), &revert_ctx).unwrap();
        assert!(report.reverted.iter().any(|id| id == "static-hostname"));

        let after = std::fs::read_to_string(dir.path().join("etc/hostname"))
            .unwrap()
            .trim()
            .to_string();
        assert_eq!(after, "oldname");
    }

    #[test]
    fn apply_revert_roundtrip() {
        let dir = setup_hostname_tempdir();

        let ctx = make_apply_ctx(99);
        let apply_report = apply_at(dir.path(), &ctx).unwrap();
        assert!(!apply_report.changed.is_empty());

        let mut originals = HashMap::new();
        for change in &apply_report.changed {
            originals.insert(change.identifier.clone(), change.old_value.clone());
        }

        let revert_ctx = RevertCtx {
            dry_run: false,
            originals,
        };
        revert_at(dir.path(), &revert_ctx).unwrap();

        let restored = std::fs::read_to_string(dir.path().join("etc/hostname"))
            .unwrap()
            .trim()
            .to_string();
        assert_eq!(restored, "oldname");
    }

    #[test]
    fn apply_with_pinned_value() {
        let dir = setup_hostname_tempdir();
        let mut ctx = make_apply_ctx(42);
        ctx.overrides.insert(
            IdentifierId::new("static-hostname"),
            ValueOverride::Fixed("pinned-host".into()),
        );
        let report = apply_at(dir.path(), &ctx).unwrap();

        let after = std::fs::read_to_string(dir.path().join("etc/hostname"))
            .unwrap()
            .trim()
            .to_string();
        assert_eq!(after, "pinned-host");

        let change = report
            .changed
            .iter()
            .find(|c| c.identifier == "static-hostname")
            .unwrap();
        assert_eq!(change.new_value, "pinned-host");
    }

    #[test]
    fn apply_changes_mailname() {
        let dir = setup_hostname_tempdir();
        std::fs::write(dir.path().join("etc/mailname"), "olddomain\n").unwrap();

        let ctx = make_apply_ctx(42);
        let report = apply_at(dir.path(), &ctx).unwrap();

        assert!(report.changed.iter().any(|c| c.identifier == "mailname"));

        let after = std::fs::read_to_string(dir.path().join("etc/mailname"))
            .unwrap()
            .trim()
            .to_string();
        assert_ne!(after, "olddomain");
    }

    #[test]
    fn apply_creates_machine_info() {
        let dir = setup_hostname_tempdir();
        let ctx = make_apply_ctx(42);
        let report = apply_at(dir.path(), &ctx).unwrap();

        assert!(
            report
                .changed
                .iter()
                .any(|c| c.identifier == "pretty-hostname")
        );

        let mi = std::fs::read_to_string(dir.path().join("etc/machine-info")).unwrap();
        assert!(mi.contains("PRETTY_HOSTNAME="));
    }

    #[test]
    fn apply_preserves_existing_machine_info_keys() {
        let dir = setup_hostname_tempdir();
        std::fs::write(
            dir.path().join("etc/machine-info"),
            "PRETTY_HOSTNAME=\"Old Name\"\nICON_NAME=computer-laptop\n",
        )
        .unwrap();

        let ctx = make_apply_ctx(42);
        apply_at(dir.path(), &ctx).unwrap();

        let mi = std::fs::read_to_string(dir.path().join("etc/machine-info")).unwrap();
        assert!(!mi.contains("Old Name"));
        assert!(mi.contains("PRETTY_HOSTNAME="));
        assert!(mi.contains("ICON_NAME=computer-laptop"));
    }

    #[test]
    fn revert_restores_machine_info_with_other_keys() {
        let dir = setup_hostname_tempdir();
        std::fs::write(
            dir.path().join("etc/machine-info"),
            "PRETTY_HOSTNAME=\"Old Name\"\nICON_NAME=computer-laptop\n",
        )
        .unwrap();

        let ctx = make_apply_ctx(42);
        apply_at(dir.path(), &ctx).unwrap();

        let revert_ctx = RevertCtx {
            dry_run: false,
            originals: HashMap::from([
                ("static-hostname".into(), "oldname".into()),
                ("pretty-hostname".into(), "Old Name".into()),
            ]),
        };
        revert_at(dir.path(), &revert_ctx).unwrap();

        let mi = std::fs::read_to_string(dir.path().join("etc/machine-info")).unwrap();
        assert!(mi.contains("\"Old Name\""));
        assert!(mi.contains("ICON_NAME=computer-laptop"));
    }

    #[test]
    fn revert_removes_pretty_but_preserves_other_keys() {
        let dir = setup_hostname_tempdir();
        std::fs::write(
            dir.path().join("etc/machine-info"),
            "ICON_NAME=computer-laptop\nCHASSIS=laptop\n",
        )
        .unwrap();

        let ctx = make_apply_ctx(42);
        apply_at(dir.path(), &ctx).unwrap();

        let revert_ctx = RevertCtx {
            dry_run: false,
            originals: HashMap::from([
                ("static-hostname".into(), "oldname".into()),
                ("pretty-hostname".into(), "".into()),
            ]),
        };
        revert_at(dir.path(), &revert_ctx).unwrap();

        let mi = std::fs::read_to_string(dir.path().join("etc/machine-info")).unwrap();
        assert!(!mi.contains("PRETTY_HOSTNAME"));
        assert!(mi.contains("ICON_NAME=computer-laptop"));
        assert!(mi.contains("CHASSIS=laptop"));
    }

    #[test]
    fn revert_deletes_machine_info_if_was_absent() {
        let dir = setup_hostname_tempdir();
        let ctx = make_apply_ctx(42);
        apply_at(dir.path(), &ctx).unwrap();
        assert!(dir.path().join("etc/machine-info").exists());

        let revert_ctx = RevertCtx {
            dry_run: false,
            originals: HashMap::from([
                ("static-hostname".into(), "oldname".into()),
                ("pretty-hostname".into(), "".into()),
            ]),
        };
        revert_at(dir.path(), &revert_ctx).unwrap();
        assert!(!dir.path().join("etc/machine-info").exists());
    }

    #[test]
    fn hostname_to_pretty_conversion() {
        assert_eq!(hostname_to_pretty("swift-oak-123"), "Swift Oak 123");
        assert_eq!(hostname_to_pretty("myhost"), "Myhost");
        assert_eq!(hostname_to_pretty(""), "");
        assert_eq!(hostname_to_pretty("swift--oak"), "Swift Oak");
    }

    #[test]
    fn extract_domain_from_fqdn() {
        assert_eq!(
            extract_domain("host.example.com"),
            Some("example.com".into())
        );
        assert_eq!(extract_domain("simple-name"), None);
        assert_eq!(extract_domain("host."), None);
        assert_eq!(extract_domain(".foo"), None);
    }

    #[test]
    fn rotate_produces_different_hostname() {
        let dir = setup_hostname_tempdir();

        let first = {
            let ctx = RotateCtx {
                dry_run: false,
                period: None,
                profile: smoke_core::Profile::Random,
                overrides: HashMap::new(),
                generator: smoke_core::rng::create_generator(smoke_core::Profile::Random, 1),
            };
            rotate_at(dir.path(), &ctx).unwrap();
            std::fs::read_to_string(dir.path().join("etc/hostname"))
                .unwrap()
                .trim()
                .to_string()
        };

        let second = {
            let ctx = RotateCtx {
                dry_run: false,
                period: None,
                profile: smoke_core::Profile::Random,
                overrides: HashMap::new(),
                generator: smoke_core::rng::create_generator(smoke_core::Profile::Random, 2),
            };
            rotate_at(dir.path(), &ctx).unwrap();
            std::fs::read_to_string(dir.path().join("etc/hostname"))
                .unwrap()
                .trim()
                .to_string()
        };

        assert_ne!(first, second);
    }

    #[test]
    fn apply_syncs_avahi_config() {
        let dir = setup_hostname_tempdir();
        std::fs::create_dir_all(dir.path().join("etc/avahi")).unwrap();
        std::fs::write(
            dir.path().join("etc/avahi/avahi-daemon.conf"),
            "[server]\n#host-name = oldname\nuse-ipv4=yes\n",
        )
        .unwrap();

        let ctx = make_apply_ctx(42);
        let report = apply_at(dir.path(), &ctx).unwrap();

        assert!(
            report
                .changed
                .iter()
                .any(|c| c.identifier == "avahi-hostname")
        );

        let conf = std::fs::read_to_string(dir.path().join("etc/avahi/avahi-daemon.conf")).unwrap();
        assert!(conf.contains("use-ipv4=yes"));
        assert!(
            conf.contains("#host-name = oldname"),
            "commented original should be preserved"
        );

        let change = report
            .changed
            .iter()
            .find(|c| c.identifier == "avahi-hostname")
            .unwrap();
        assert!(conf.contains(&format!("host-name = {}", change.new_value)));
    }

    #[test]
    fn apply_syncs_samba_config() {
        let dir = setup_hostname_tempdir();
        std::fs::create_dir_all(dir.path().join("etc/samba")).unwrap();
        std::fs::write(
            dir.path().join("etc/samba/smb.conf"),
            "[global]\nnetbios name = oldname\nworkgroup = WORKGROUP\n",
        )
        .unwrap();

        let ctx = make_apply_ctx(42);
        let report = apply_at(dir.path(), &ctx).unwrap();

        assert!(
            report
                .changed
                .iter()
                .any(|c| c.identifier == "netbios-name")
        );

        let conf = std::fs::read_to_string(dir.path().join("etc/samba/smb.conf")).unwrap();
        assert!(!conf.contains("oldname"));
        assert!(conf.contains("workgroup = WORKGROUP"));
    }

    #[test]
    fn apply_skips_missing_service_configs() {
        let dir = setup_hostname_tempdir();
        let ctx = make_apply_ctx(42);
        let report = apply_at(dir.path(), &ctx).unwrap();

        assert!(
            !report
                .changed
                .iter()
                .any(|c| c.identifier == "avahi-hostname")
        );
        assert!(
            !report
                .changed
                .iter()
                .any(|c| c.identifier == "netbios-name")
        );
    }

    #[test]
    fn ini_key_does_not_match_prefix_siblings() {
        let content = "[global]\nnetbios name = old\nnetbios alias = other\n";
        let updated = update_ini_key(content, "global", "netbios name", "new");
        assert!(updated.contains("netbios name = new"));
        assert!(updated.contains("netbios alias = other"));
        assert!(!updated.contains("netbios alias = new"));
    }

    #[test]
    fn ini_key_replaces_only_first_match() {
        let content = "[server]\nhost-name = a\nhost-name = b\n";
        let updated = update_ini_key(content, "server", "host-name", "new");
        assert!(updated.contains("host-name = new"));
        assert!(updated.contains("host-name = b"));
    }

    #[test]
    fn revert_restores_avahi_config() {
        let dir = setup_hostname_tempdir();
        std::fs::create_dir_all(dir.path().join("etc/avahi")).unwrap();
        std::fs::write(
            dir.path().join("etc/avahi/avahi-daemon.conf"),
            "[server]\n#host-name = oldname\nuse-ipv4=yes\n",
        )
        .unwrap();

        let ctx = make_apply_ctx(42);
        let report = apply_at(dir.path(), &ctx).unwrap();

        let avahi_change = report
            .changed
            .iter()
            .find(|c| c.identifier == "avahi-hostname")
            .unwrap();

        let revert_ctx = RevertCtx {
            dry_run: false,
            originals: HashMap::from([
                ("static-hostname".into(), "oldname".into()),
                ("pretty-hostname".into(), "".into()),
                ("avahi-hostname".into(), avahi_change.old_value.clone()),
            ]),
        };
        revert_at(dir.path(), &revert_ctx).unwrap();

        let conf = std::fs::read_to_string(dir.path().join("etc/avahi/avahi-daemon.conf")).unwrap();
        assert!(conf.contains("use-ipv4=yes"));
        assert!(
            conf.contains("#host-name = oldname"),
            "commented original should be preserved"
        );
        assert!(
            conf.contains(&format!("host-name = {}", avahi_change.old_value)),
            "active host-name should be restored to backed-up value"
        );
    }
}
