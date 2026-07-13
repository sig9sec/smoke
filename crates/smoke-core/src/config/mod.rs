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

pub mod io;

use crate::identifier::IdentifierId;
use crate::rng::{Profile, ValueOverride};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmokeConfig {
    pub version: u32,
    #[serde(default = "default_profile")]
    pub profile: Profile,
    #[serde(default)]
    pub modules: HashMap<String, ModuleConfig>,
    #[serde(default)]
    pub rotation: RotationConfig,
    #[serde(default)]
    pub log_scrub: LogScrubConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub overrides: HashMap<IdentifierId, ValueOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    #[serde(default = "default_rotation_period")]
    pub default_period: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogScrubConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub targets: Vec<String>,
}

fn default_profile() -> Profile {
    Profile::Consistent
}

fn default_true() -> bool {
    true
}

fn default_rotation_period() -> String {
    "boot".into()
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            default_period: default_rotation_period(),
        }
    }
}

impl Default for SmokeConfig {
    fn default() -> Self {
        Self {
            version: 1,
            profile: default_profile(),
            modules: HashMap::new(),
            rotation: RotationConfig::default(),
            log_scrub: LogScrubConfig::default(),
        }
    }
}

impl SmokeConfig {
    pub fn module(&self, id: &str) -> ModuleConfig {
        self.modules
            .get(id)
            .cloned()
            .unwrap_or_else(|| ModuleConfig {
                enabled: true,
                overrides: HashMap::new(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = SmokeConfig::default();
        assert_eq!(cfg.version, 1);
        assert_eq!(cfg.profile, Profile::Consistent);
        assert!(cfg.modules.is_empty());
    }

    #[test]
    fn serde_roundtrip() {
        let mut modules = HashMap::new();
        modules.insert(
            "machine-id".into(),
            ModuleConfig {
                enabled: true,
                overrides: HashMap::from([(
                    IdentifierId::new("machine-id"),
                    ValueOverride::Fixed("abc123".into()),
                )]),
            },
        );

        let cfg = SmokeConfig {
            version: 1,
            profile: Profile::Random,
            modules,
            rotation: RotationConfig {
                default_period: "daily".into(),
            },
            log_scrub: LogScrubConfig::default(),
        };

        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        let restored: SmokeConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.version, 1);
        assert_eq!(restored.profile, Profile::Random);
        assert!(restored.modules.contains_key("machine-id"));
        assert_eq!(restored.rotation.default_period, "daily");
    }

    #[test]
    fn missing_module_returns_default() {
        let cfg = SmokeConfig::default();
        let mc = cfg.module("nonexistent");
        assert!(mc.enabled);
    }
}
