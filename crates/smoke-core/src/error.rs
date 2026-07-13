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

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum SmokeError {
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("config error: {0}")]
    Config(String),

    #[error("state error: {0}")]
    State(String),

    #[error("permission denied: {0}")]
    Permission(String),

    #[error("module error: {0}")]
    Module(String),

    #[error("root required: {0}")]
    NotRoot(String),

    #[error("verification failed: {0}")]
    Verify(String),

    #[error("unsupported: {0}")]
    Unsupported(String),
}

pub type Result<T> = std::result::Result<T, SmokeError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let err = SmokeError::Config("bad key".into());
        assert_eq!(err.to_string(), "config error: bad key");

        let err = SmokeError::NotRoot("bind-mount".into());
        assert_eq!(err.to_string(), "root required: bind-mount");
    }
}
