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

pub mod consistent;
pub mod lam;
pub mod pinned;
pub mod random;

use serde::{Deserialize, Serialize};

/// Which randomization profile to use.
///
/// See SPEC section 6.4 for details on each profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Profile {
    Random,
    Consistent,
    LocallyAdministered,
    Pinned,
}

/// Per-identifier override. Applied before consulting the profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueOverride {
    UseProfile,
    Fixed(String),
    Random,
    Keep,
}

/// Generates spoofed identifier values.
///
/// Each randomization profile implements this trait. Modules receive a
/// `Box<dyn ValueGenerator>` via [`ApplyCtx`](crate::ApplyCtx) and call
/// the appropriate method for their identifier kind.
///
/// Methods returning `Option<&str>` are `None` when the profile does not
/// produce values for that identifier kind. In that case the module
/// should leave the identifier unchanged (equivalent to `Keep`).
pub trait ValueGenerator: Send {
    fn mac(&self) -> String;
    fn uuid(&self) -> String;
    fn hostname(&self) -> String;
    fn serial(&self, len: usize) -> String;

    fn dmi_sys_vendor(&self) -> Option<&str> {
        None
    }
    fn dmi_product_name(&self) -> Option<&str> {
        None
    }
    fn dmi_version(&self) -> Option<&str> {
        None
    }
    fn dmi_board_vendor(&self) -> Option<&str> {
        None
    }
    fn dmi_board_name(&self) -> Option<&str> {
        None
    }
    fn dmi_bios_vendor(&self) -> Option<&str> {
        None
    }
    fn dmi_bios_version(&self) -> Option<&str> {
        None
    }

    fn disk_vendor(&self) -> Option<&str> {
        None
    }
    fn disk_model(&self) -> Option<&str> {
        None
    }
}

/// Create a profile-specific generator from a [`Profile`] and a seed.
pub fn create_generator(profile: Profile, seed: u64) -> Box<dyn ValueGenerator> {
    match profile {
        Profile::Random => Box::new(random::RandomProfile::new(seed)),
        Profile::Consistent => Box::new(consistent::ConsistentProfile::new(seed)),
        Profile::LocallyAdministered => Box::new(lam::LamProfile::new(seed)),
        Profile::Pinned => Box::new(pinned::PinnedProfile::new(seed)),
    }
}
