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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OuiEntry {
    pub prefix: String,
    pub vendor: String,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskPreset {
    pub vendor: String,
    pub model: String,
    pub family: String,
}

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
        &self.oui[index % self.oui.len()]
    }

    pub fn pick_dmi(&self, index: usize) -> &DmiPreset {
        &self.dmi[index % self.dmi.len()]
    }

    pub fn pick_disk(&self, index: usize) -> &DiskPreset {
        &self.disk[index % self.disk.len()]
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
}
