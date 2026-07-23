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

use serde::{Deserialize, Serialize};

/// Stable string key for a single identifier within a module.
///
/// Used as a HashMap key for overrides and current-value tracking.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentifierId(String);

impl IdentifierId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for IdentifierId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Coarse grouping of identifiers, used for `--category` filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Category {
    Dmi,
    MachineId,
    Hostname,
    Net,
    Storage,
    FsUuid,
    Bootloader,
    Kernel,
    Tpm,
    Edid,
    Usb,
    Battery,
    Acpi,
    Logs,
    Services,
    Misc,
}

/// One discovered identifier value from the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: IdentifierId,
    pub category: Category,
    pub source: String,
    pub value: String,
    pub read_path: String,
}

/// Collection of [`Finding`]s returned by `SmokeModule::enumerate`.
///
/// `partial_failures` records sources that could not be read (e.g.
/// permission denied) without aborting the entire enumeration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Findings {
    pub items: Vec<Finding>,
    pub partial_failures: Vec<String>,
}

impl Findings {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, finding: Finding) {
        self.items.push(finding);
    }

    pub fn push_failure(&mut self, msg: impl Into<String>) {
        self.partial_failures.push(msg.into());
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_id_display() {
        let id = IdentifierId::new("machine-id");
        assert_eq!(id.as_str(), "machine-id");
        assert_eq!(id.to_string(), "machine-id");
    }

    #[test]
    fn findings_push() {
        let mut findings = Findings::new();
        assert!(findings.is_empty());

        findings.push(Finding {
            id: IdentifierId::new("test-id"),
            category: Category::Misc,
            source: "/test".into(),
            value: "val".into(),
            read_path: "file".into(),
        });
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn serde_roundtrip() {
        let findings = Findings {
            items: vec![Finding {
                id: IdentifierId::new("product-uuid"),
                category: Category::Dmi,
                source: "/sys/class/dmi/id/product_uuid".into(),
                value: "fake-uuid".into(),
                read_path: "sysfs".into(),
            }],
            partial_failures: vec!["permission denied on /dev/mem".into()],
        };

        let json = serde_json::to_string(&findings).unwrap();
        let restored: Findings = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.items.len(), 1);
        assert_eq!(restored.items[0].id.as_str(), "product-uuid");
        assert_eq!(restored.items[0].category, Category::Dmi);
        assert_eq!(restored.partial_failures.len(), 1);
    }
}
