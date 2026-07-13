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
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::{Result, SmokeError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedIdentity {
    pub hostname: Option<String>,
    pub machine_id: Option<String>,
    pub mac: Option<HashMap<String, String>>,
    pub dmi: Option<PinnedDmi>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedDmi {
    pub sys_vendor: Option<String>,
    pub product_name: Option<String>,
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
}
