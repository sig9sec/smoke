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
use super::random::random_mac;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use crate::{Result, SmokeError};

/// A fixed identity loaded from a TOML file. Used to pin many hosts
/// to the same spoofed identity (honeypots, VM pools).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedIdentity {
    pub hostname: Option<String>,
    pub machine_id: Option<String>,
    pub mac: Option<HashMap<String, String>>,
    pub dmi: Option<PinnedDmi>,
}

/// DMI/SMBIOS fields inside a [`PinnedIdentity`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedDmi {
    pub sys_vendor: Option<String>,
    pub product_name: Option<String>,
    pub version: Option<String>,
    pub board_vendor: Option<String>,
    pub board_name: Option<String>,
    pub bios_vendor: Option<String>,
    pub bios_version: Option<String>,
}

impl PinnedIdentity {
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| SmokeError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        toml::from_str(&content)
            .map_err(|e| SmokeError::Config(format!("invalid pinned identity: {e}")))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| SmokeError::Config(format!("serialize error: {e}")))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| SmokeError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        fs::write(path, &content).map_err(|e| SmokeError::Io {
            path: path.to_path_buf(),
            source: e,
        })
    }
}

/// Generator backed by a [`PinnedIdentity`]. Returns fixed values from
/// the loaded file. Identifiers not present in the file fall back to
/// random generation so the profile never produces `None`.
pub struct PinnedProfile {
    identity: PinnedIdentity,
    rng: Mutex<ChaCha20Rng>,
}

impl PinnedProfile {
    pub fn new(seed: u64) -> Self {
        Self {
            identity: PinnedIdentity {
                hostname: None,
                machine_id: None,
                mac: None,
                dmi: None,
            },
            rng: Mutex::new(ChaCha20Rng::seed_from_u64(seed)),
        }
    }

    pub fn from_identity(identity: PinnedIdentity, seed: u64) -> Self {
        Self {
            identity,
            rng: Mutex::new(ChaCha20Rng::seed_from_u64(seed)),
        }
    }
}

impl ValueGenerator for PinnedProfile {
    fn mac(&self) -> String {
        if let Some(macs) = &self.identity.mac
            && let Some(mac) = macs.values().next()
        {
            return mac.clone();
        }
        random_mac(&mut self.rng.lock().unwrap())
    }

    fn uuid(&self) -> String {
        let mut buf = [0u8; 16];
        self.rng.lock().unwrap().fill(&mut buf);
        if let Some(id) = &self.identity.machine_id {
            return id.clone();
        }
        buf[6] = (buf[6] & 0x0F) | 0x40;
        buf[8] = (buf[8] & 0x3F) | 0x80;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            buf[0],
            buf[1],
            buf[2],
            buf[3],
            buf[4],
            buf[5],
            buf[6],
            buf[7],
            buf[8],
            buf[9],
            buf[10],
            buf[11],
            buf[12],
            buf[13],
            buf[14],
            buf[15]
        )
    }

    fn hostname(&self) -> String {
        self.identity
            .hostname
            .clone()
            .unwrap_or_else(|| super::random::random_hostname(&mut self.rng.lock().unwrap()))
    }

    fn serial(&self, len: usize) -> String {
        super::random::random_serial(&mut self.rng.lock().unwrap(), len)
    }

    fn dmi_sys_vendor(&self) -> Option<&str> {
        self.identity
            .dmi
            .as_ref()
            .and_then(|d| d.sys_vendor.as_deref())
    }

    fn dmi_product_name(&self) -> Option<&str> {
        self.identity
            .dmi
            .as_ref()
            .and_then(|d| d.product_name.as_deref())
    }

    fn dmi_version(&self) -> Option<&str> {
        self.identity
            .dmi
            .as_ref()
            .and_then(|d| d.version.as_deref())
    }

    fn dmi_board_vendor(&self) -> Option<&str> {
        self.identity
            .dmi
            .as_ref()
            .and_then(|d| d.board_vendor.as_deref())
    }

    fn dmi_board_name(&self) -> Option<&str> {
        self.identity
            .dmi
            .as_ref()
            .and_then(|d| d.board_name.as_deref())
    }

    fn dmi_bios_vendor(&self) -> Option<&str> {
        self.identity
            .dmi
            .as_ref()
            .and_then(|d| d.bios_vendor.as_deref())
    }

    fn dmi_bios_version(&self) -> Option<&str> {
        self.identity
            .dmi
            .as_ref()
            .and_then(|d| d.bios_version.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.toml");

        let identity = PinnedIdentity {
            hostname: Some("test-host".into()),
            machine_id: Some("abc123".into()),
            mac: Some(HashMap::from([("eth0".into(), "AA:BB:CC:DD:EE:FF".into())])),
            dmi: Some(PinnedDmi {
                sys_vendor: Some("TestVendor".into()),
                product_name: Some("TestProduct".into()),
                version: Some("1.0".into()),
                board_vendor: None,
                board_name: None,
                bios_vendor: None,
                bios_version: None,
            }),
        };

        identity.save(&path).unwrap();
        let loaded = PinnedIdentity::load(&path).unwrap();
        assert_eq!(loaded.hostname, Some("test-host".into()));
        assert_eq!(loaded.machine_id, Some("abc123".into()));
        assert_eq!(
            loaded.mac.unwrap().get("eth0").unwrap(),
            "AA:BB:CC:DD:EE:FF"
        );
    }

    #[test]
    fn pinned_profile_returns_loaded_values() {
        let identity = PinnedIdentity {
            hostname: Some("fixed-host".into()),
            machine_id: None,
            mac: None,
            dmi: Some(PinnedDmi {
                sys_vendor: Some("FixedVendor".into()),
                product_name: Some("ModelX".into()),
                version: None,
                board_vendor: None,
                board_name: None,
                bios_vendor: None,
                bios_version: None,
            }),
        };
        let p = PinnedProfile::from_identity(identity, 42);
        assert_eq!(p.hostname(), "fixed-host");
        assert_eq!(p.dmi_sys_vendor(), Some("FixedVendor"));
        assert_eq!(p.dmi_product_name(), Some("ModelX"));
    }

    #[test]
    fn pinned_profile_fallback_for_missing() {
        let p = PinnedProfile::new(42);
        let mac = p.mac();
        assert_eq!(mac.len(), 17);
    }
}
