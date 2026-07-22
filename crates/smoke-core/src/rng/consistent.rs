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

use super::ValueGenerator;
use super::random;
use crate::vendors::{DiskPreset, DmiPreset, OuiEntry, VendorCatalog};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::sync::Mutex;

/// Generates a coherent fake hardware profile.
///
/// A DMI preset is selected first, then an OUI prefix matching that
/// DMI vendor is found. Disk presets are selected independently
/// (disks from any vendor can ship in any machine). This produces a
/// MAC + DMI combination that survives cross-referencing the OUI
/// against the spoofed `sys_vendor`.
pub struct ConsistentProfile {
    rng: Mutex<ChaCha20Rng>,
    #[allow(dead_code)]
    catalog: VendorCatalog,
    oui: OuiEntry,
    dmi: DmiPreset,
    disk: DiskPreset,
}

impl ConsistentProfile {
    pub fn new(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let catalog = VendorCatalog::load();

        let dmi_idx = rng.random_range(0..catalog.dmi.len());
        let dmi = catalog.dmi[dmi_idx].clone();

        let ouis = catalog.ouis_for_vendor(&dmi.sys_vendor);
        let oui = if ouis.is_empty() {
            let idx = rng.random_range(0..catalog.oui.len());
            catalog.oui[idx].clone()
        } else {
            let idx = rng.random_range(0..ouis.len());
            ouis[idx].clone()
        };

        let disk_idx = rng.random_range(0..catalog.disk.len());
        let disk = catalog.disk[disk_idx].clone();

        Self {
            rng: Mutex::new(rng),
            catalog,
            oui,
            dmi,
            disk,
        }
    }
}

fn mac_from_oui(oui: &OuiEntry, rng: &mut ChaCha20Rng) -> String {
    let prefix_bytes: Vec<u8> = oui
        .prefix
        .split(':')
        .map(|s| u8::from_str_radix(s, 16).unwrap_or(0))
        .collect();
    let mut suffix = [0u8; 3];
    rng.fill(&mut suffix);
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        prefix_bytes[0], prefix_bytes[1], prefix_bytes[2], suffix[0], suffix[1], suffix[2]
    )
}

impl ValueGenerator for ConsistentProfile {
    fn mac(&self) -> String {
        mac_from_oui(&self.oui, &mut self.rng.lock().unwrap())
    }

    fn uuid(&self) -> String {
        random::random_uuid_v4(&mut self.rng.lock().unwrap())
    }

    fn hostname(&self) -> String {
        random::random_hostname(&mut self.rng.lock().unwrap())
    }

    fn serial(&self, len: usize) -> String {
        random::random_serial(&mut self.rng.lock().unwrap(), len)
    }

    fn dmi_sys_vendor(&self) -> Option<&str> {
        Some(&self.dmi.sys_vendor)
    }

    fn dmi_product_name(&self) -> Option<&str> {
        Some(&self.dmi.product_name)
    }

    fn dmi_version(&self) -> Option<&str> {
        Some(&self.dmi.version)
    }

    fn dmi_board_vendor(&self) -> Option<&str> {
        Some(&self.dmi.board_vendor)
    }

    fn dmi_board_name(&self) -> Option<&str> {
        Some(&self.dmi.board_name)
    }

    fn dmi_bios_vendor(&self) -> Option<&str> {
        Some(&self.dmi.bios_vendor)
    }

    fn dmi_bios_version(&self) -> Option<&str> {
        Some(&self.dmi.bios_version)
    }

    fn disk_vendor(&self) -> Option<&str> {
        Some(&self.disk.vendor)
    }

    fn disk_model(&self) -> Option<&str> {
        Some(&self.disk.model)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_matches_oui_vendor() {
        let p = ConsistentProfile::new(12345);
        let mac = p.mac();
        let mac_vendor_prefix = &mac[..8];
        let expected = &p.oui.prefix;
        assert_eq!(
            mac_vendor_prefix, expected,
            "MAC prefix must match the selected OUI"
        );
    }

    #[test]
    fn dmi_oui_coherence() {
        for seed in 0..50 {
            let p = ConsistentProfile::new(seed);
            let ouis = p.catalog.ouis_for_vendor(p.dmi.sys_vendor.as_str());
            assert!(
                ouis.iter().any(|o| o.prefix == p.oui.prefix),
                "seed {seed}: OUI prefix {} does not belong to DMI vendor '{}'",
                p.oui.prefix,
                p.dmi.sys_vendor
            );
        }
    }

    #[test]
    fn deterministic() {
        let p1 = ConsistentProfile::new(99);
        let p2 = ConsistentProfile::new(99);
        assert_eq!(p1.mac(), p2.mac());
        assert_eq!(p1.uuid(), p2.uuid());
        assert_eq!(p1.hostname(), p2.hostname());
        assert_eq!(p1.dmi_sys_vendor(), p2.dmi_sys_vendor());
    }

    #[test]
    fn dmi_fields() {
        let p = ConsistentProfile::new(1);
        assert!(!p.dmi_sys_vendor().unwrap().is_empty());
        assert!(!p.dmi_product_name().unwrap().is_empty());
        assert!(!p.dmi_board_vendor().unwrap().is_empty());
        assert!(!p.dmi_bios_vendor().unwrap().is_empty());
    }

    #[test]
    fn disk_fields() {
        let p = ConsistentProfile::new(1);
        assert!(!p.disk_vendor().unwrap().is_empty());
        assert!(!p.disk_model().unwrap().is_empty());
    }
}
