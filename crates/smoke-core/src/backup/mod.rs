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

pub mod manifest;

use crate::{Result, SmokeError};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const SYSTEM_BACKUP_DIR: &str = "/var/lib/smoke/backup";

pub fn default_backup_dir() -> PathBuf {
    PathBuf::from(SYSTEM_BACKUP_DIR)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEntry {
    pub module_id: String,
    pub identifier: String,
    pub original_value: String,
    pub backed_up_at: String,
}

pub struct BackupStore {
    dir: PathBuf,
}

impl BackupStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn init(&self) -> Result<()> {
        fs::create_dir_all(&self.dir).map_err(|e| SmokeError::Io {
            path: self.dir.clone(),
            source: e,
        })
    }

    pub fn store(&self, entry: &BackupEntry) -> Result<()> {
        let module_dir = self.dir.join(&entry.module_id);
        fs::create_dir_all(&module_dir).map_err(|e| SmokeError::Io {
            path: module_dir.clone(),
            source: e,
        })?;
        let path = module_dir.join(format!("{}.json", entry.identifier));
        let content = serde_json::to_string_pretty(entry)
            .map_err(|e| SmokeError::State(format!("serialize error: {e}")))?;
        fs::write(&path, content).map_err(|e| SmokeError::Io { path, source: e })
    }

    pub fn load(&self, module_id: &str, identifier: &str) -> Result<BackupEntry> {
        let path = self.dir.join(module_id).join(format!("{identifier}.json"));
        let content = fs::read_to_string(&path).map_err(|e| SmokeError::Io {
            path: path.clone(),
            source: e,
        })?;
        serde_json::from_str(&content).map_err(|e| SmokeError::State(format!("parse error: {e}")))
    }

    pub fn list_module(&self, module_id: &str) -> Result<Vec<BackupEntry>> {
        let module_dir = self.dir.join(module_id);
        if !module_dir.exists() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        for entry in fs::read_dir(&module_dir).map_err(|e| SmokeError::Io {
            path: module_dir.clone(),
            source: e,
        })? {
            let entry = entry.map_err(|e| SmokeError::Io {
                path: module_dir.clone(),
                source: e,
            })?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "json") {
                let content = fs::read_to_string(&path).map_err(|e| SmokeError::Io {
                    path: path.clone(),
                    source: e,
                })?;
                let be: BackupEntry = serde_json::from_str(&content)
                    .map_err(|e| SmokeError::State(format!("parse error: {e}")))?;
                entries.push(be);
            }
        }
        Ok(entries)
    }

    pub fn remove(&self, module_id: &str, identifier: &str) -> Result<()> {
        let path = self.dir.join(module_id).join(format!("{identifier}.json"));
        if path.exists() {
            fs::remove_file(&path).map_err(|e| SmokeError::Io { path, source: e })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = BackupStore::new(dir.path().to_path_buf());
        store.init().unwrap();

        let entry = BackupEntry {
            module_id: "machine-id".into(),
            identifier: "machine-id".into(),
            original_value: "abc123".into(),
            backed_up_at: "2026-01-01T00:00:00Z".into(),
        };
        store.store(&entry).unwrap();

        let loaded = store.load("machine-id", "machine-id").unwrap();
        assert_eq!(loaded.original_value, "abc123");
    }

    #[test]
    fn list_module() {
        let dir = tempfile::tempdir().unwrap();
        let store = BackupStore::new(dir.path().to_path_buf());
        store.init().unwrap();

        for i in 0..3 {
            store
                .store(&BackupEntry {
                    module_id: "test".into(),
                    identifier: format!("id-{i}"),
                    original_value: format!("val-{i}"),
                    backed_up_at: "2026-01-01T00:00:00Z".into(),
                })
                .unwrap();
        }

        let entries = store.list_module("test").unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn remove() {
        let dir = tempfile::tempdir().unwrap();
        let store = BackupStore::new(dir.path().to_path_buf());
        store.init().unwrap();

        store
            .store(&BackupEntry {
                module_id: "m".into(),
                identifier: "id".into(),
                original_value: "val".into(),
                backed_up_at: "2026-01-01T00:00:00Z".into(),
            })
            .unwrap();

        store.remove("m", "id").unwrap();
        assert!(store.load("m", "id").is_err());
    }

    #[test]
    fn list_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = BackupStore::new(dir.path().to_path_buf());
        store.init().unwrap();
        assert!(store.list_module("nonexistent").unwrap().is_empty());
    }
}
