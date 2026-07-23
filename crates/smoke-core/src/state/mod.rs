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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Persisted runtime state, stored as JSON at `/var/lib/smoke/state.json`.
///
/// Tracks which modules have been applied, their current spoofed values,
/// and rotation counters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub version: u32,
    #[serde(default)]
    pub modules: HashMap<String, ModuleState>,
}

/// Per-module state entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleState {
    #[serde(default)]
    pub last_applied: Option<String>,
    #[serde(default)]
    pub last_rotated: Option<String>,
    #[serde(default)]
    pub rotation_count: u64,
    #[serde(default)]
    pub current_values: HashMap<String, String>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: 1,
            modules: HashMap::new(),
        }
    }
}

impl State {
    pub fn module_mut(&mut self, id: &str) -> &mut ModuleState {
        self.modules.entry(id.into()).or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state() {
        let state = State::default();
        assert_eq!(state.version, 1);
        assert!(state.modules.is_empty());
    }

    #[test]
    fn serde_roundtrip() {
        let mut modules = HashMap::new();
        modules.insert(
            "machine-id".into(),
            ModuleState {
                last_applied: Some("2026-01-01T00:00:00Z".into()),
                last_rotated: None,
                rotation_count: 3,
                current_values: HashMap::from([("machine-id".into(), "abc123".into())]),
            },
        );
        let state = State {
            version: 1,
            modules,
        };

        let json = serde_json::to_string(&state).unwrap();
        let restored: State = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.version, 1);
        let ms = restored.modules.get("machine-id").unwrap();
        assert_eq!(ms.rotation_count, 3);
        assert_eq!(ms.current_values.get("machine-id").unwrap(), "abc123");
    }
}
