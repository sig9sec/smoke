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
mod output;

use clap::Parser;
use cli::{Cli, Commands, ConfigAction, ServiceAction};
use smoke_core::config::{self, SmokeConfig};
use smoke_core::registry::Registry;
use smoke_core::state::{self, State};
use std::path::PathBuf;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

fn main() {
    let cli = Cli::parse();

    let default_level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("smoke={default_level}")));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_target(false))
        .init();

    let config_path = cli
        .config
        .as_ref()
        .map(PathBuf::from)
        .or_else(config::io::default_config_path_if_exists);

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
        Commands::List { category, status } => cmd_list(category, status, &config_path),
        Commands::Dump { out, real, spoofed } => cmd_dump(out, real, spoofed),
        Commands::Fingerprint => cmd_fingerprint(),
        Commands::Diff => cmd_diff(),
        Commands::Config { action } => match action {
            ConfigAction::Edit => cmd_config_edit(),
            ConfigAction::Show => cmd_config_show(&config_path),
            ConfigAction::Validate => cmd_config_validate(&config_path),
        },
        Commands::Service { action } => match action {
            ServiceAction::Install => cmd_service_install(),
            ServiceAction::EnableRotateTimer => cmd_service_enable_rotate(),
            ServiceAction::Status => cmd_service_status(),
        },
        Commands::Selftest => cmd_selftest(&config_path),
        Commands::Scan {
            pattern,
            yara,
            pid,
            all,
        } => cmd_scan(pattern, yara, pid, all),
        Commands::Watch {
            pattern,
            yara,
            pid,
            poll,
        } => cmd_watch(pattern, yara, pid, poll),
    };

    if let Err(e) = result {
        tracing::error!("{e}");
        eprintln!("error: {e}");
        std::process::exit(2);
    }
}

fn load_config_from(path: &Option<PathBuf>) -> Result<SmokeConfig, Box<dyn std::error::Error>> {
    match path {
        Some(p) => {
            tracing::debug!(path = %p.display(), "loading config");
            Ok(config::io::load(p)?)
        }
        None => {
            tracing::debug!("no config file, using defaults");
            Ok(SmokeConfig::default())
        }
    }
}

fn load_state() -> Result<State, Box<dyn std::error::Error>> {
    let path = state::io::default_state_path();
    if path.exists() {
        tracing::debug!(path = %path.display(), "loading state");
        Ok(state::io::load(&path)?)
    } else {
        tracing::debug!("no state file, using defaults");
        Ok(State::default())
    }
}

fn cmd_apply(
    _module: Vec<String>,
    _profile: Option<String>,
    _dry_run: bool,
    _force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("apply requested");
    unimplemented!("smoke apply")
}

fn cmd_rotate(
    _module: Vec<String>,
    _period: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("rotate requested");
    unimplemented!("smoke rotate")
}

fn cmd_status(module: Option<String>, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let state = load_state()?;

    if let Some(mod_name) = module {
        if let Some(ms) = state.modules.get(&mod_name) {
            if json {
                output::print_json(ms)?;
            } else {
                println!("module: {mod_name}");
                println!(
                    "  applied: {}",
                    ms.last_applied.as_deref().unwrap_or("never")
                );
                println!(
                    "  rotated: {}",
                    ms.last_rotated.as_deref().unwrap_or("never")
                );
                println!("  rotation count: {}", ms.rotation_count);
                if !ms.current_values.is_empty() {
                    println!("  current values:");
                    for (k, v) in &ms.current_values {
                        println!("    {k}: {v}");
                    }
                }
            }
        } else {
            println!("module '{mod_name}' has no recorded state");
        }
        return Ok(());
    }

    if json {
        output::print_json(&state)?;
        return Ok(());
    }

    let mut rows = Vec::new();
    for (id, ms) in &state.modules {
        rows.push(vec![
            id.clone(),
            ms.last_applied.as_deref().unwrap_or("never").to_string(),
            ms.rotation_count.to_string(),
        ]);
    }
    if rows.is_empty() {
        println!("no modules have been applied yet");
    } else {
        output::print_table(&["module", "last applied", "rotations"], &rows);
    }

    Ok(())
}

fn cmd_doctor(_fix: bool) -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke doctor")
}

fn cmd_revert(
    _module: Vec<String>,
    _all: bool,
    _force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("revert requested");
    unimplemented!("smoke revert")
}

fn cmd_enable(_module: String) -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke enable")
}

fn cmd_disable(_module: String) -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("smoke disable")
}

fn cmd_list(
    category: Option<String>,
    status: Option<String>,
    config_path: &Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config_from(config_path)?;
    let registry = Registry::new();

    let mut rows = Vec::new();
    for module in registry.all() {
        let mc = config.module(module.id());

        if let Some(ref cat) = category
            && format!("{:?}", module.category()).to_lowercase() != cat.to_lowercase()
        {
            continue;
        }

        let module_status = if mc.enabled { "enabled" } else { "disabled" };
        if let Some(ref st) = status
            && module_status != st
        {
            continue;
        }

        rows.push(vec![
            module.id().to_string(),
            format!("{:?}", module.category()),
            module_status.to_string(),
            module.coverage().achieved_tier.label().to_string(),
        ]);
    }

    if rows.is_empty() {
        println!("no modules registered");
    } else {
        output::print_table(&["id", "category", "status", "tier"], &rows);
    }

    Ok(())
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

fn cmd_config_show(config_path: &Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = load_config_from(config_path)?;
    let toml = toml::to_string_pretty(&cfg)?;
    println!("{toml}");
    Ok(())
}

fn cmd_config_validate(config_path: &Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let resolved = match config_path {
        Some(p) => Some(p.clone()),
        None => {
            let default = config::io::default_config_path();
            if default.exists() {
                Some(default)
            } else {
                None
            }
        }
    };
    match resolved {
        Some(path) => match config::io::load(&path) {
            Ok(_) => {
                println!("config is valid");
                Ok(())
            }
            Err(e) => {
                eprintln!("config validation failed: {e}");
                std::process::exit(2);
            }
        },
        None => {
            eprintln!("no config file found");
            std::process::exit(2);
        }
    }
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

fn cmd_selftest(config_path: &Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    println!("smoke selftest");

    if let Some(path) = config_path {
        match config::io::load(path) {
            Ok(_) => println!("  [ok] config parses"),
            Err(e) => {
                println!("  [FAIL] config: {e}");
                std::process::exit(1);
            }
        }
    } else {
        println!("  [skip] no config file");
    }

    let state_path = state::io::default_state_path();
    if state_path.exists() {
        match state::io::load(&state_path) {
            Ok(_) => println!("  [ok] state parses"),
            Err(e) => {
                println!("  [FAIL] state: {e}");
                std::process::exit(1);
            }
        }
    } else {
        println!("  [skip] no state file");
    }

    let registry = Registry::new();
    if registry.is_empty() {
        println!("  [warn] no modules registered");
    } else {
        println!("  [ok] {} modules registered", registry.len());
    }

    println!("selftest complete");
    Ok(())
}

fn cmd_scan(
    pattern: Option<String>,
    yara: Option<String>,
    pid: Option<u32>,
    all: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let rule_source = match (&pattern, &yara) {
        (_, Some(file)) => std::fs::read_to_string(file)?,
        (Some(p), _) => format!(
            r#"rule smoke_scan {{
    strings:
        $s = "{p}"
    condition:
        $s
}}"#
        ),
        (None, None) => {
            eprintln!("error: provide --yara FILE or a pattern argument");
            std::process::exit(2);
        }
    };

    let scanner = smoke_scan::yara_probe::compile_rule(&rule_source)
        .map_err(|e| format!("YARA compile error: {e}"))?;

    let self_pid = std::process::id();
    let pids: Vec<u32> = if all {
        smoke_scan::walker::list_pids()?
    } else if let Some(p) = pid {
        vec![p]
    } else {
        vec![self_pid]
    };

    let mut total_hits = 0;
    for pid in &pids {
        match smoke_scan::walker::parse_maps(*pid) {
            Ok(regions) => {
                for region in &regions {
                    if !region.permissions.contains('r') {
                        continue;
                    }
                    let size = (region.end - region.start) as usize;
                    if size == 0 || size > 256 * 1024 * 1024 {
                        continue;
                    }
                    let mut buf = vec![0u8; size];
                    if let Ok(n) =
                        smoke_scan::walker::read_remote_slice(*pid, region.start, &mut buf)
                    {
                        let hits = smoke_scan::yara_probe::scan_bytes(&scanner, &buf[..n])
                            .unwrap_or_default();
                        if !hits.is_empty() {
                            for rule_name in &hits {
                                println!(
                                    "pid {pid}: rule '{rule_name}' matched at {:#x} ({})",
                                    region.start,
                                    region.pathname.as_deref().unwrap_or("?")
                                );
                                total_hits += 1;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("warn: cannot read maps for pid {pid}: {e}");
            }
        }
    }

    println!("scan complete: {total_hits} hit(s)");
    Ok(())
}

fn cmd_watch(
    pattern: Option<String>,
    yara: Option<String>,
    pid: Option<u32>,
    poll: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let rule_source = match (&pattern, &yara) {
        (_, Some(file)) => std::fs::read_to_string(file)?,
        (Some(p), _) => format!(
            r#"rule smoke_watch {{
    strings:
        $s = "{p}"
    condition:
        $s
}}"#
        ),
        (None, None) => {
            eprintln!("error: provide --yara FILE or a pattern argument");
            std::process::exit(2);
        }
    };

    let scanner = smoke_scan::yara_probe::compile_rule(&rule_source)
        .map_err(|e| format!("YARA compile error: {e}"))?;
    let target_pid = pid.unwrap_or_else(std::process::id);
    let interval = std::time::Duration::from_secs(poll);

    println!("watching pid {target_pid} every {}s (Ctrl-C to stop)", poll);

    loop {
        let mut found = false;
        if let Ok(regions) = smoke_scan::walker::parse_maps(target_pid) {
            for region in &regions {
                if !region.permissions.contains('r') {
                    continue;
                }
                let size = (region.end - region.start) as usize;
                if size == 0 || size > 256 * 1024 * 1024 {
                    continue;
                }
                let mut buf = vec![0u8; size];
                if let Ok(n) =
                    smoke_scan::walker::read_remote_slice(target_pid, region.start, &mut buf)
                {
                    let hits =
                        smoke_scan::yara_probe::scan_bytes(&scanner, &buf[..n]).unwrap_or_default();
                    if !hits.is_empty() {
                        let ts = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        for rule_name in &hits {
                            println!(
                                "[{ts}] pid {target_pid}: rule '{rule_name}' matched at {:#x}",
                                region.start
                            );
                            found = true;
                        }
                    }
                }
            }
        }

        if !found {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            println!("[{ts}] no hits");
        }

        std::thread::sleep(interval);
    }
}
