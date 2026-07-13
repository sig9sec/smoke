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

#![allow(dead_code)]

pub fn print_json<T: serde::Serialize>(value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing JSON: {e}"),
    }
}

pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }

    for (i, header) in headers.iter().enumerate() {
        if i > 0 {
            print!("  ");
        }
        print!("{:<width$}", header, width = widths[i]);
    }
    println!();

    for (i, _) in headers.iter().enumerate() {
        if i > 0 {
            print!("  ");
        }
        print!("{}", "-".repeat(widths[i]));
    }
    println!();

    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i > 0 {
                print!("  ");
            }
            print!("{:<width$}", cell, width = widths[i]);
        }
        println!();
    }
}

pub fn verbose_enabled() -> bool {
    std::env::var("SMOKE_VERBOSE").is_ok()
}

pub fn log_verbose(msg: &str) {
    if verbose_enabled() {
        eprintln!("[verbose] {msg}");
    }
}
