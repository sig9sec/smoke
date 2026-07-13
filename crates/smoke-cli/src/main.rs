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

mod cli;

use clap::Parser;
use cli::{Cli, Commands, ConfigAction, ServiceAction};

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Apply {
            module,
            profile,
            dry_run,
            force,
        } => cmd_apply(module, profile, dry_run, force),
        Commands::Rotate { module, period } => cmd_rotate(module, period),
        Commands::Status { module, json } => cmd_status(module, json),
        Commands::Doctor { fix } => cmd_doctor(fix),
        Commands::Revert { module, all, force } => cmd_revert(module, all, force),
        Commands::Enable { module } => cmd_enable(module),
        Commands::Disable { module } => cmd_disable(module),
        Commands::List { category, status } => cmd_list(category, status),
        Commands::Dump {
            out,
            r#real,
            spoofed,
        } => cmd_dump(out, real, spoofed),
        Commands::Fingerprint => cmd_fingerprint(),
        Commands::Diff => cmd_diff(),
        Commands::Config { action } => match action {
            ConfigAction::Edit => cmd_config_edit(),
            ConfigAction::Show => cmd_config_show(),
            ConfigAction::Validate => cmd_config_validate(),
        },
        Commands::Service { action } => match action {
            ServiceAction::Install => cmd_service_install(),
            ServiceAction::EnableRotateTimer => cmd_service_enable_rotate(),
            ServiceAction::Status => cmd_service_status(),
        },
        Commands::Selftest => cmd_selftest(),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(2);
    }
}

fn cmd_apply(
    _module: Vec<String>,
    _profile: Option<String>,
    _dry_run: bool,
    _force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke apply")
}

fn cmd_rotate(
    _module: Vec<String>,
    _period: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke rotate")
}

fn cmd_status(_module: Option<String>, _json: bool) -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke status")
}

fn cmd_doctor(_fix: bool) -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke doctor")
}

fn cmd_revert(
    _module: Vec<String>,
    _all: bool,
    _force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke revert")
}

fn cmd_enable(_module: String) -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke enable")
}

fn cmd_disable(_module: String) -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke disable")
}

fn cmd_list(
    _category: Option<String>,
    _status: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke list")
}

fn cmd_dump(
    _out: Option<String>,
    _real: bool,
    _spoofed: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke dump")
}

fn cmd_fingerprint() -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke fingerprint")
}

fn cmd_diff() -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke diff")
}

fn cmd_config_edit() -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke config edit")
}

fn cmd_config_show() -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke config show")
}

fn cmd_config_validate() -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke config validate")
}

fn cmd_service_install() -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke service install")
}

fn cmd_service_enable_rotate() -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke service enable-rotate-timer")
}

fn cmd_service_status() -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke service status")
}

fn cmd_selftest() -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke selftest")
}
