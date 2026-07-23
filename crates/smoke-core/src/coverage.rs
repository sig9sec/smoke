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

/// Spoofing coverage tier for a single identifier.
///
/// Ordered from worst to best. See SPEC section 3 for the full table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Tier {
    None,
    PartialUserspace,
    PartialUdev,
    FullKernel,
    FullBoot,
}

impl Tier {
    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "T0",
            Self::PartialUserspace => "T1",
            Self::PartialUdev => "T2",
            Self::FullKernel => "T3",
            Self::FullBoot => "T4",
        }
    }
}

/// Technique used to spoof an identifier.
///
/// A module may combine multiple strategies (e.g. `FileOverwrite` +
/// `PeriodicRotation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Strategy {
    FileOverwrite,
    BindMount,
    UdevRule,
    KernelBpf,
    Disable,
    PeriodicRotation,
    BootPatch,
}

/// What a module achieves and how.
///
/// Reported by `SmokeModule::coverage` and surfaced in `doctor` output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coverage {
    pub achieved_tier: Tier,
    pub strategies: Vec<Strategy>,
}

/// Risk severity used by the executor to gate `--force`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Risk assessment for a module's operations.
///
/// `High` and `Critical` require `--force` in the executor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Risk {
    pub level: RiskLevel,
    pub summary: String,
    pub mitigations: Vec<String>,
}

/// Runtime prerequisites a module needs to apply successfully.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Requirements {
    pub root: bool,
    pub kmod: bool,
    pub bpf: bool,
    pub reboot: bool,
    pub degraded_mode: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_ordering() {
        assert!(Tier::None < Tier::FullBoot);
        assert!(Tier::PartialUserspace < Tier::FullKernel);
    }

    #[test]
    fn tier_labels() {
        assert_eq!(Tier::None.label(), "T0");
        assert_eq!(Tier::PartialUserspace.label(), "T1");
        assert_eq!(Tier::PartialUdev.label(), "T2");
        assert_eq!(Tier::FullKernel.label(), "T3");
        assert_eq!(Tier::FullBoot.label(), "T4");
    }

    #[test]
    fn requirements_default() {
        let req = Requirements::default();
        assert!(!req.root);
        assert!(!req.kmod);
        assert!(!req.bpf);
        assert!(!req.reboot);
        assert!(!req.degraded_mode);
    }
}
