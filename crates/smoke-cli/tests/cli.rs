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

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn config_show_default() {
    let mut cmd = Command::cargo_bin("smoke").unwrap();
    cmd.args(["config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("version = 1"));
}

#[test]
fn config_show_custom_path() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("smoke.toml");
    fs::write(
        &path,
        r#"version = 1
profile = "Random"

[rotation]
default_period = "daily"
"#,
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("smoke").unwrap();
    cmd.args(["--config", path.to_str().unwrap(), "config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("profile = \"Random\""));
}

#[test]
fn config_validate_valid() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("smoke.toml");
    fs::write(&path, "version = 1\nprofile = \"Consistent\"\n").unwrap();

    let mut cmd = Command::cargo_bin("smoke").unwrap();
    cmd.args(["--config", path.to_str().unwrap(), "config", "validate"])
        .assert()
        .success()
        .stdout(predicate::str::contains("config is valid"));
}

#[test]
fn config_validate_bad_version() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("smoke.toml");
    fs::write(&path, "version = 99\n").unwrap();

    let mut cmd = Command::cargo_bin("smoke").unwrap();
    cmd.args(["--config", path.to_str().unwrap(), "config", "validate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported config version"));
}

#[test]
fn config_validate_missing_file() {
    let mut cmd = Command::cargo_bin("smoke").unwrap();
    cmd.args(["--config", "/nonexistent/smoke.toml", "config", "validate"])
        .assert()
        .code(2);
}

#[test]
fn list_no_modules() {
    let mut cmd = Command::cargo_bin("smoke").unwrap();
    cmd.args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("no modules registered"));
}

#[test]
fn status_no_state() {
    let mut cmd = Command::cargo_bin("smoke").unwrap();
    cmd.args(["status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("no modules have been applied yet"));
}

#[test]
fn selftest_no_config() {
    let mut cmd = Command::cargo_bin("smoke").unwrap();
    cmd.args(["selftest"])
        .assert()
        .success()
        .stdout(predicate::str::contains("selftest complete"));
}

#[test]
fn config_show_with_overrides() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("smoke.toml");
    fs::write(
        &path,
        r#"version = 1

[modules.machine-id.overrides."machine-id"]
Fixed = "abc123"
"#,
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("smoke").unwrap();
    cmd.args(["--config", path.to_str().unwrap(), "config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("abc123"));
}
