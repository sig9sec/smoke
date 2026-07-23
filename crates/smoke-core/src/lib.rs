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

//! Core types, config, state, and module trait for the `smoke` privacy suite.
//!
//! This crate provides the shared infrastructure that CLI commands and
//! identifier modules build on:
//!
//! - [`module::SmokeModule`] - the trait every identifier group implements.
//! - [`registry::Registry`] - collects registered modules for dispatch.
//! - [`executor::Executor`] - orchestrates apply / rotate / revert with
//!   prerequisite checks, backup writes, and state updates.
//! - [`config::SmokeConfig`] - user-facing TOML configuration.
//! - [`state::State`] - persisted runtime state (current values, rotation
//!   counters).
//! - [`backup::BackupStore`] - timestamped original-value snapshots with
//!   SHA-256 tamper detection.
//! - [`rng`] - randomization profiles (random, consistent, LAM, pinned)
//!   that produce spoofed identifier values.

pub mod backup;
pub mod config;
pub mod coverage;
pub mod error;
pub mod executor;
pub mod identifier;
pub mod module;
pub mod registry;
pub mod rng;
pub mod state;
pub mod vendors;

pub use coverage::{Coverage, Requirements, Risk, RiskLevel, Strategy, Tier};
pub use error::{Result, SmokeError};
pub use identifier::{Category, Finding, Findings, IdentifierId};
pub use module::{
    ApplyCtx, ApplyReport, Change, ModuleStatus, RevertCtx, RevertReport, RotateCtx, RotateReport,
    SmokeModule,
};
pub use rng::{Profile, ValueGenerator, ValueOverride};
