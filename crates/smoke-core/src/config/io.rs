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

use super::SmokeConfig;
use crate::{Result, SmokeError};
use std::fs;
use std::path::{Path, PathBuf};

const SYSTEM_CONFIG_PATH: &str = "/etc/smoke/smoke.toml";
const XDG_CONFIG_DIR: &str = ".config/smoke";

pub fn default_config_path() -> PathBuf {
    if Path::new(SYSTEM_CONFIG_PATH).exists() {
        PathBuf::from(SYSTEM_CONFIG_PATH)
    } else if let Some(home) = dirs_home() {
        home.join(XDG_CONFIG_DIR).join("smoke.toml")
    } else {
        PathBuf::from(SYSTEM_CONFIG_PATH)
    }
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

pub fn load(path: &Path) -> Result<SmokeConfig> {
    let content = fs::read_to_string(path).map_err(|e| SmokeError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let cfg: SmokeConfig =
        toml::from_str(&content).map_err(|e| SmokeError::Config(format!("parse error: {e}")))?;
    if cfg.version != 1 {
        return Err(SmokeError::Config(format!(
            "unsupported config version: {}",
            cfg.version
        )));
    }
    Ok(cfg)
}

pub fn save(path: &Path, cfg: &SmokeConfig) -> Result<()> {
    let content = toml::to_string_pretty(cfg)
        .map_err(|e| SmokeError::Config(format!("serialize error: {e}")))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| SmokeError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    let tmp = path.with_extension("toml.tmp");
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
        let path = dir.path().join("smoke.toml");

        let cfg = SmokeConfig::default();
        save(&path, &cfg).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.profile, cfg.profile);
    }

    #[test]
    fn load_bad_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("smoke.toml");
        fs::write(&path, "version = 99\n").unwrap();
        let err = load(&path).unwrap_err();
        assert!(err.to_string().contains("unsupported config version"));
    }

    #[test]
    fn load_missing_file() {
        let err = load(Path::new("/nonexistent/path.toml")).unwrap_err();
        assert!(err.to_string().contains("io error"));
    }
}
