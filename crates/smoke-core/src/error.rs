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

/// Errors returned by smoke-core operations.
#[derive(Debug, thiserror::Error)]
pub enum SmokeError {
    /// Filesystem I/O failure, with the path that was accessed.
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    /// Configuration parse or validation error.
    #[error("config error: {0}")]
    Config(String),

    /// State file parse or version mismatch error.
    #[error("state error: {0}")]
    State(String),

    /// Insufficient permissions (not root, missing capability, etc.).
    #[error("permission denied: {0}")]
    Permission(String),

    /// Module-specific logic error.
    #[error("module error: {0}")]
    Module(String),

    /// Operation requires root privileges.
    #[error("root required: {0}")]
    NotRoot(String),

    /// Backup integrity verification failed.
    #[error("verification failed: {0}")]
    Verify(String),

    /// Feature or operation is not supported in this build or environment.
    #[error("unsupported: {0}")]
    Unsupported(String),
}

/// Convenience alias used throughout smoke-core.
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
