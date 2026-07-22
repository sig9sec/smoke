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

const VENDORS_TOML: &str = include_str!("../data/vendors.toml");

/// IEEE OUI prefix mapped to a vendor name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OuiEntry {
    pub prefix: String,
    pub vendor: String,
}

/// A complete DMI/SMBIOS preset for one machine model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmiPreset {
    pub sys_vendor: String,
    pub product_name: String,
    pub version: String,
    pub board_vendor: String,
    pub board_name: String,
    pub bios_vendor: String,
    pub bios_version: String,
}

/// A storage device vendor + model combo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskPreset {
    pub vendor: String,
    pub model: String,
    pub family: String,
}

/// Curated vendor data powering the `consistent` randomization profile.
///
/// The catalog is loaded from an embedded TOML file at compile time.
/// OUI entries are matched to DMI presets by `sys_vendor` so the
/// consistent profile can produce a coherent MAC + DMI combination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorCatalog {
    pub oui: Vec<OuiEntry>,
    pub dmi: Vec<DmiPreset>,
    pub disk: Vec<DiskPreset>,
}

impl VendorCatalog {
    pub fn load() -> Self {
        toml::from_str(VENDORS_TOML).expect("embedded vendors.toml is invalid")
    }

    pub fn pick_oui(&self, index: usize) -> &OuiEntry {
        assert!(!self.oui.is_empty(), "vendor catalog has no OUI entries");
        &self.oui[index % self.oui.len()]
    }

    pub fn pick_dmi(&self, index: usize) -> &DmiPreset {
        assert!(!self.dmi.is_empty(), "vendor catalog has no DMI presets");
        &self.dmi[index % self.dmi.len()]
    }

    pub fn pick_disk(&self, index: usize) -> &DiskPreset {
        assert!(!self.disk.is_empty(), "vendor catalog has no disk presets");
        &self.disk[index % self.disk.len()]
    }

    /// Find all OUI prefixes registered to a given vendor name.
    /// Used by the consistent profile to pick a MAC whose OUI matches
    /// the spoofed DMI `sys_vendor`.
    pub fn ouis_for_vendor(&self, vendor: &str) -> Vec<&OuiEntry> {
        self.oui.iter().filter(|e| e.vendor == vendor).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_catalog() {
        let catalog = VendorCatalog::load();
        assert!(!catalog.oui.is_empty());
        assert!(!catalog.dmi.is_empty());
        assert!(!catalog.disk.is_empty());
    }

    #[test]
    fn pick_wraps() {
        let catalog = VendorCatalog::load();
        let len = catalog.oui.len();
        let entry = catalog.pick_oui(len);
        assert_eq!(entry, catalog.pick_oui(0));
    }

    #[test]
    fn dmi_preset_fields() {
        let catalog = VendorCatalog::load();
        let preset = catalog.pick_dmi(0);
        assert!(!preset.sys_vendor.is_empty());
        assert!(!preset.product_name.is_empty());
        assert!(!preset.board_vendor.is_empty());
        assert!(!preset.bios_vendor.is_empty());
    }

    #[test]
    fn oui_vendor_matches_dmi() {
        let catalog = VendorCatalog::load();
        for dmi in &catalog.dmi {
            let ouis = catalog.ouis_for_vendor(&dmi.sys_vendor);
            assert!(
                !ouis.is_empty(),
                "no OUI entry for DMI vendor '{}'",
                dmi.sys_vendor
            );
        }
    }
}
