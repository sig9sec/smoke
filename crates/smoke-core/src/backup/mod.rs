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
use manifest::Manifest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

const SYSTEM_BACKUP_DIR: &str = "/var/lib/smoke/backup";
const MANIFEST_FILE: &str = "manifest.json";

/// Default backup directory: `/var/lib/smoke/backup`.
pub fn default_backup_dir() -> PathBuf {
    PathBuf::from(SYSTEM_BACKUP_DIR)
}

/// One captured value backup. Stored as a timestamped JSON file so
/// that repeated applies never lose the original hardware value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEntry {
    pub module_id: String,
    pub identifier: String,
    pub original_value: String,
    pub backed_up_at: String,
}

/// Persistent backup store. Every `store()` call creates a new
/// timestamped snapshot; originals are never clobbered. A SHA-256
/// manifest is maintained alongside the blobs for tamper detection.
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

    fn module_dir(&self, module_id: &str) -> PathBuf {
        self.dir.join(module_id)
    }

    fn identifier_dir(&self, module_id: &str, identifier: &str) -> PathBuf {
        self.module_dir(module_id).join(identifier)
    }

    fn manifest_path(&self, module_id: &str) -> PathBuf {
        self.module_dir(module_id).join(MANIFEST_FILE)
    }

    /// Store a backup entry. Creates a timestamped file so repeated
    /// applies never overwrite the original.
    pub fn store(&self, entry: &BackupEntry) -> Result<()> {
        let id_dir = self.identifier_dir(&entry.module_id, &entry.identifier);
        fs::create_dir_all(&id_dir).map_err(|e| SmokeError::Io {
            path: id_dir.clone(),
            source: e,
        })?;

        let content = serde_json::to_string_pretty(entry)
            .map_err(|e| SmokeError::State(format!("serialize error: {e}")))?;

        let hash = sha256_hex(content.as_bytes());
        let timestamp = sanitize_timestamp(&entry.backed_up_at);
        let path = id_dir.join(format!("{timestamp}.json"));

        if path.exists() {
            return Err(SmokeError::State(format!(
                "backup snapshot already exists: {}",
                path.display()
            )));
        }

        fs::write(&path, &content).map_err(|e| SmokeError::Io {
            path: path.clone(),
            source: e,
        })?;

        let mut manifest = self.load_manifest(&entry.module_id);
        manifest.insert(path.to_string_lossy().to_string(), hash);
        self.save_manifest(&entry.module_id, &manifest)
    }

    /// Load the original (oldest) backup for a module+identifier.
    /// This is the value `revert` restores.
    pub fn load_original(&self, module_id: &str, identifier: &str) -> Result<BackupEntry> {
        let snapshots = self.list_snapshots(module_id, identifier)?;
        snapshots
            .into_iter()
            .next()
            .ok_or_else(|| SmokeError::State(format!("no backup for {module_id}/{identifier}")))
    }

    /// Load the most recent backup for a module+identifier.
    pub fn load_latest(&self, module_id: &str, identifier: &str) -> Result<BackupEntry> {
        let snapshots = self.list_snapshots(module_id, identifier)?;
        snapshots
            .into_iter()
            .last()
            .ok_or_else(|| SmokeError::State(format!("no backup for {module_id}/{identifier}")))
    }

    /// Compatibility alias for `load_original`.
    pub fn load(&self, module_id: &str, identifier: &str) -> Result<BackupEntry> {
        self.load_original(module_id, identifier)
    }

    /// List all backup entries for a module, sorted oldest-first.
    pub fn list_module(&self, module_id: &str) -> Result<Vec<BackupEntry>> {
        let mod_dir = self.module_dir(module_id);
        if !mod_dir.exists() {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        for id_entry in fs::read_dir(&mod_dir).map_err(|e| SmokeError::Io {
            path: mod_dir.clone(),
            source: e,
        })? {
            let id_entry = id_entry.map_err(|e| SmokeError::Io {
                path: mod_dir.clone(),
                source: e,
            })?;
            let id_path = id_entry.path();
            if !id_path.is_dir() {
                continue;
            }
            for snap_entry in fs::read_dir(&id_path).map_err(|e| SmokeError::Io {
                path: id_path.clone(),
                source: e,
            })? {
                let snap_entry = snap_entry.map_err(|e| SmokeError::Io {
                    path: id_path.clone(),
                    source: e,
                })?;
                let snap_path = snap_entry.path();
                if snap_path.extension().is_some_and(|e| e == "json") {
                    let content = fs::read_to_string(&snap_path).map_err(|e| SmokeError::Io {
                        path: snap_path.clone(),
                        source: e,
                    })?;
                    let be: BackupEntry = serde_json::from_str(&content)
                        .map_err(|e| SmokeError::State(format!("parse error: {e}")))?;
                    entries.push(be);
                }
            }
        }

        entries.sort_by(|a, b| a.backed_up_at.cmp(&b.backed_up_at));
        Ok(entries)
    }

    /// Remove all backups for a module+identifier.
    pub fn remove(&self, module_id: &str, identifier: &str) -> Result<()> {
        let id_dir = self.identifier_dir(module_id, identifier);
        if id_dir.exists() {
            fs::remove_dir_all(&id_dir).map_err(|e| SmokeError::Io {
                path: id_dir,
                source: e,
            })?;
        }
        Ok(())
    }

    /// Verify the integrity manifest for a module. Returns the number
    /// of entries that failed verification (0 = all good).
    pub fn verify_module(&self, module_id: &str) -> Result<usize> {
        let manifest = self.load_manifest(module_id);
        let mod_dir = self.module_dir(module_id);
        if !mod_dir.exists() {
            return Ok(0);
        }

        let mut failures = 0;
        for (path_str, expected_hash) in &manifest.entries {
            let path = PathBuf::from(path_str);
            match fs::read_to_string(&path) {
                Ok(content) => {
                    let actual = sha256_hex(content.as_bytes());
                    if &actual != expected_hash {
                        failures += 1;
                    }
                }
                Err(_) => {
                    failures += 1;
                }
            }
        }
        Ok(failures)
    }

    fn list_snapshots(&self, module_id: &str, identifier: &str) -> Result<Vec<BackupEntry>> {
        let id_dir = self.identifier_dir(module_id, identifier);
        if !id_dir.exists() {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        for snap_entry in fs::read_dir(&id_dir).map_err(|e| SmokeError::Io {
            path: id_dir.clone(),
            source: e,
        })? {
            let snap_entry = snap_entry.map_err(|e| SmokeError::Io {
                path: id_dir.clone(),
                source: e,
            })?;
            let snap_path = snap_entry.path();
            if snap_path.extension().is_some_and(|e| e == "json") {
                let content = fs::read_to_string(&snap_path).map_err(|e| SmokeError::Io {
                    path: snap_path.clone(),
                    source: e,
                })?;
                let be: BackupEntry = serde_json::from_str(&content)
                    .map_err(|e| SmokeError::State(format!("parse error: {e}")))?;
                entries.push(be);
            }
        }

        entries.sort_by(|a, b| a.backed_up_at.cmp(&b.backed_up_at));
        Ok(entries)
    }

    fn load_manifest(&self, module_id: &str) -> Manifest {
        let path = self.manifest_path(module_id);
        match fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Manifest::new(),
        }
    }

    fn save_manifest(&self, module_id: &str, manifest: &Manifest) -> Result<()> {
        let path = self.manifest_path(module_id);
        let content = serde_json::to_string_pretty(manifest)
            .map_err(|e| SmokeError::State(format!("serialize error: {e}")))?;
        fs::write(&path, content).map_err(|e| SmokeError::Io { path, source: e })
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.iter().map(|b| format!("{b:02x}")).collect()
}

fn sanitize_timestamp(ts: &str) -> String {
    ts.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(module: &str, id: &str, value: &str, ts: &str) -> BackupEntry {
        BackupEntry {
            module_id: module.into(),
            identifier: id.into(),
            original_value: value.into(),
            backed_up_at: ts.into(),
        }
    }

    #[test]
    fn store_and_load_original() {
        let dir = tempfile::tempdir().unwrap();
        let store = BackupStore::new(dir.path().to_path_buf());
        store.init().unwrap();

        store
            .store(&make_entry("m", "id", "original", "2026-01-01T00:00:00Z"))
            .unwrap();

        let loaded = store.load_original("m", "id").unwrap();
        assert_eq!(loaded.original_value, "original");
    }

    #[test]
    fn store_preserves_history() {
        let dir = tempfile::tempdir().unwrap();
        let store = BackupStore::new(dir.path().to_path_buf());
        store.init().unwrap();

        store
            .store(&make_entry("m", "id", "original", "2026-01-01T00:00:00Z"))
            .unwrap();
        store
            .store(&make_entry("m", "id", "second", "2026-01-02T00:00:00Z"))
            .unwrap();

        let original = store.load_original("m", "id").unwrap();
        assert_eq!(original.original_value, "original");

        let latest = store.load_latest("m", "id").unwrap();
        assert_eq!(latest.original_value, "second");

        let all = store.list_snapshots("m", "id").unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn list_module_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let store = BackupStore::new(dir.path().to_path_buf());
        store.init().unwrap();

        store
            .store(&make_entry("test", "id-b", "val-b", "2026-01-02T00:00:00Z"))
            .unwrap();
        store
            .store(&make_entry("test", "id-a", "val-a", "2026-01-01T00:00:00Z"))
            .unwrap();

        let entries = store.list_module("test").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].identifier, "id-a");
    }

    #[test]
    fn remove() {
        let dir = tempfile::tempdir().unwrap();
        let store = BackupStore::new(dir.path().to_path_buf());
        store.init().unwrap();

        store
            .store(&make_entry("m", "id", "val", "2026-01-01T00:00:00Z"))
            .unwrap();
        store.remove("m", "id").unwrap();
        assert!(store.load_original("m", "id").is_err());
    }

    #[test]
    fn list_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = BackupStore::new(dir.path().to_path_buf());
        store.init().unwrap();
        assert!(store.list_module("nonexistent").unwrap().is_empty());
    }

    #[test]
    fn manifest_verify_clean() {
        let dir = tempfile::tempdir().unwrap();
        let store = BackupStore::new(dir.path().to_path_buf());
        store.init().unwrap();

        store
            .store(&make_entry("m", "id", "val", "2026-01-01T00:00:00Z"))
            .unwrap();

        assert_eq!(store.verify_module("m").unwrap(), 0);
    }

    #[test]
    fn manifest_detects_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let store = BackupStore::new(dir.path().to_path_buf());
        store.init().unwrap();

        store
            .store(&make_entry("m", "id", "val", "2026-01-01T00:00:00Z"))
            .unwrap();

        let snap_path = dir
            .path()
            .join("m")
            .join("id")
            .join("2026_01_01T00_00_00Z.json");
        fs::write(&snap_path, "tampered").unwrap();

        assert_eq!(store.verify_module("m").unwrap(), 1);
    }
}
