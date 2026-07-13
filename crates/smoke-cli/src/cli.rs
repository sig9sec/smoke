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

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "smoke",
    version,
    about = "Linux privacy / anti-fingerprinting suite"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Apply {
        #[arg(long)]
        module: Vec<String>,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        force: bool,
    },
    Rotate {
        #[arg(long)]
        module: Vec<String>,
        #[arg(long)]
        period: Option<String>,
    },
    Status {
        #[arg(long)]
        module: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Doctor {
        #[arg(long)]
        fix: bool,
    },
    Revert {
        #[arg(long)]
        module: Vec<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        force: bool,
    },
    Enable {
        module: String,
    },
    Disable {
        module: String,
    },
    List {
        #[arg(long)]
        category: Option<String>,
        #[arg(long)]
        status: Option<String>,
    },
    Dump {
        #[arg(long)]
        out: Option<String>,
        #[arg(long)]
        r#real: bool,
        #[arg(long)]
        spoofed: bool,
    },
    Fingerprint,
    Diff,
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    Selftest,
}

#[derive(Subcommand)]
pub enum ConfigAction {
    Edit,
    Show,
    Validate,
}

#[derive(Subcommand)]
pub enum ServiceAction {
    Install,
    EnableRotateTimer,
    Status,
}
