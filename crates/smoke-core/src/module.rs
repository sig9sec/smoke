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

use crate::Result;
use crate::coverage::{Coverage, Requirements, Risk};
use crate::identifier::{Findings, IdentifierId};
use crate::rng::{Profile, ValueGenerator, ValueOverride};
use std::collections::HashMap;

/// Every identifier group implements this trait.
///
/// See SPEC section 6.2 for the full contract.
pub trait SmokeModule: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn category(&self) -> crate::Category;
    fn requires(&self) -> Requirements;
    fn enumerate(&self) -> Result<Findings>;
    fn apply(&self, ctx: &ApplyCtx) -> Result<ApplyReport>;
    fn rotate(&self, ctx: &RotateCtx) -> Result<RotateReport>;
    fn status(&self) -> Result<ModuleStatus>;
    fn revert(&self) -> Result<RevertReport>;
    fn coverage(&self) -> Coverage;
    fn risks(&self) -> Risk;
}

/// Context passed to `SmokeModule::apply`.
pub struct ApplyCtx {
    pub dry_run: bool,
    pub force: bool,
    pub profile: Profile,
    pub overrides: HashMap<IdentifierId, ValueOverride>,
    pub generator: Box<dyn ValueGenerator>,
}

/// Context passed to `SmokeModule::rotate`.
pub struct RotateCtx {
    pub dry_run: bool,
    pub period: Option<String>,
    pub profile: Profile,
    pub overrides: HashMap<IdentifierId, ValueOverride>,
    pub generator: Box<dyn ValueGenerator>,
}

/// Report returned by `SmokeModule::apply`. Lists every value changed
/// and any non-fatal warnings.
#[derive(Debug, Clone, Default)]
pub struct ApplyReport {
    pub changed: Vec<Change>,
    pub warnings: Vec<String>,
}

/// One value modification recorded in an [`ApplyReport`].
#[derive(Debug, Clone)]
pub struct Change {
    pub identifier: String,
    pub old_value: String,
    pub new_value: String,
}

/// Report returned by `SmokeModule::rotate`.
#[derive(Debug, Clone, Default)]
pub struct RotateReport {
    pub rotated: Vec<String>,
    pub warnings: Vec<String>,
}

/// Report returned by `SmokeModule::revert`.
#[derive(Debug, Clone, Default)]
pub struct RevertReport {
    pub reverted: Vec<String>,
    pub warnings: Vec<String>,
}

/// Snapshot of a module's current state, surfaced by `smoke status`.
#[derive(Debug, Clone, Default)]
pub struct ModuleStatus {
    pub enabled: bool,
    pub applied: bool,
    pub last_applied: Option<String>,
    pub current_values: HashMap<String, String>,
}
