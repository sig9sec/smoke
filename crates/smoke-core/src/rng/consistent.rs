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

use super::random;
use crate::vendors::VendorCatalog;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub struct ConsistentProfile {
    rng: ChaCha20Rng,
    catalog: VendorCatalog,
    oui_idx: usize,
    dmi_idx: usize,
    disk_idx: usize,
}

impl ConsistentProfile {
    pub fn new(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let catalog = VendorCatalog::load();
        let oui_idx = rng.random_range(0..catalog.oui.len());
        let dmi_idx = rng.random_range(0..catalog.dmi.len());
        let disk_idx = rng.random_range(0..catalog.disk.len());
        Self {
            rng,
            catalog,
            oui_idx,
            dmi_idx,
            disk_idx,
        }
    }

    pub fn mac(&mut self) -> String {
        let oui = self.catalog.pick_oui(self.oui_idx);
        let prefix_bytes: Vec<u8> = oui
            .prefix
            .split(':')
            .map(|s| u8::from_str_radix(s, 16).unwrap())
            .collect();
        let mut suffix = [0u8; 3];
        self.rng.fill(&mut suffix);
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            prefix_bytes[0], prefix_bytes[1], prefix_bytes[2], suffix[0], suffix[1], suffix[2]
        )
    }

    pub fn uuid(&mut self) -> String {
        random::random_uuid_v4(&mut self.rng)
    }

    pub fn hostname(&mut self) -> String {
        random::random_hostname(&mut self.rng)
    }

    pub fn serial(&mut self, len: usize) -> String {
        random::random_serial(&mut self.rng, len)
    }

    pub fn dmi_sys_vendor(&self) -> &str {
        &self.catalog.pick_dmi(self.dmi_idx).sys_vendor
    }

    pub fn dmi_product_name(&self) -> &str {
        &self.catalog.pick_dmi(self.dmi_idx).product_name
    }

    pub fn dmi_version(&self) -> &str {
        &self.catalog.pick_dmi(self.dmi_idx).version
    }

    pub fn dmi_board_vendor(&self) -> &str {
        &self.catalog.pick_dmi(self.dmi_idx).board_vendor
    }

    pub fn dmi_board_name(&self) -> &str {
        &self.catalog.pick_dmi(self.dmi_idx).board_name
    }

    pub fn dmi_bios_vendor(&self) -> &str {
        &self.catalog.pick_dmi(self.dmi_idx).bios_vendor
    }

    pub fn dmi_bios_version(&self) -> &str {
        &self.catalog.pick_dmi(self.dmi_idx).bios_version
    }

    pub fn disk_vendor(&self) -> &str {
        &self.catalog.pick_disk(self.disk_idx).vendor
    }

    pub fn disk_model(&self) -> &str {
        &self.catalog.pick_disk(self.disk_idx).model
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coherent_vendor() {
        let mut p = ConsistentProfile::new(12345);
        let mac = p.mac();
        let oui_prefix = &mac[..8];
        let oui = p.catalog.pick_oui(p.oui_idx);
        assert_eq!(oui_prefix, oui.prefix);
    }

    #[test]
    fn deterministic() {
        let mut p1 = ConsistentProfile::new(99);
        let mut p2 = ConsistentProfile::new(99);
        assert_eq!(p1.mac(), p2.mac());
        assert_eq!(p1.uuid(), p2.uuid());
        assert_eq!(p1.hostname(), p2.hostname());
    }

    #[test]
    fn dmi_fields() {
        let p = ConsistentProfile::new(1);
        assert!(!p.dmi_sys_vendor().is_empty());
        assert!(!p.dmi_product_name().is_empty());
        assert!(!p.dmi_board_vendor().is_empty());
        assert!(!p.dmi_bios_vendor().is_empty());
    }
}
