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
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    pub entries: BTreeMap<String, String>,
}

impl Manifest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, path: String, sha256: String) {
        self.entries.insert(path, sha256);
    }

    pub fn verify(&self, path: &str, sha256: &str) -> bool {
        self.entries.get(path).is_some_and(|h| h == sha256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_verify() {
        let mut m = Manifest::new();
        m.insert("/test/path".into(), "abc123".into());
        assert!(m.verify("/test/path", "abc123"));
        assert!(!m.verify("/test/path", "wrong"));
        assert!(!m.verify("/other", "abc123"));
    }
}
