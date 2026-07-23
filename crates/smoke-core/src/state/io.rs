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

use super::State;
use crate::{Result, SmokeError};
use std::fs;
use std::path::{Path, PathBuf};

const SYSTEM_STATE_PATH: &str = "/var/lib/smoke/state.json";

/// Default state file path: `/var/lib/smoke/state.json`.
pub fn default_state_path() -> PathBuf {
    PathBuf::from(SYSTEM_STATE_PATH)
}

/// Load and parse state JSON. Accepts empty files (returns default).
/// Rejects `version != 1`.
pub fn load(path: &Path) -> Result<State> {
    let content = fs::read_to_string(path).map_err(|e| SmokeError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    if content.trim().is_empty() {
        return Ok(State::default());
    }
    let state: State = serde_json::from_str(&content)
        .map_err(|e| SmokeError::State(format!("parse error: {e}")))?;
    if state.version != 1 {
        return Err(SmokeError::State(format!(
            "unsupported state version: {}",
            state.version
        )));
    }
    Ok(state)
}

/// Serialize state to JSON and write atomically via temp-file rename.
pub fn save(path: &Path, state: &State) -> Result<()> {
    let content = serde_json::to_string_pretty(state)
        .map_err(|e| SmokeError::State(format!("serialize error: {e}")))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| SmokeError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, &content).map_err(|e| SmokeError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    fs::rename(&tmp, path).map_err(|e| SmokeError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_save_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");

        let state = State::default();
        save(&path, &state).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.version, 1);
    }

    #[test]
    fn load_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        fs::write(&path, "").unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.version, 1);
    }

    #[test]
    fn load_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        fs::write(&path, "not json").unwrap();
        let err = load(&path).unwrap_err();
        assert!(err.to_string().contains("parse error"));
    }

    #[test]
    fn load_bad_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        fs::write(&path, r#"{"version": 99}"#).unwrap();
        let err = load(&path).unwrap_err();
        assert!(err.to_string().contains("unsupported state version"));
    }
}
