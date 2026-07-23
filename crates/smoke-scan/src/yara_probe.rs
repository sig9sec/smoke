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

use boreal::Scanner;

pub fn compile_rule(rule_source: &str) -> Result<Scanner, String> {
    let mut compiler = boreal::Compiler::new();
    compiler
        .add_rules_str(rule_source)
        .map_err(|e| format!("YARA compile error: {e}"))?;
    Ok(compiler.finalize())
}

pub fn scan_bytes(scanner: &Scanner, data: &[u8]) -> Result<Vec<String>, String> {
    scanner
        .scan_mem(data)
        .map(|result| result.rules.iter().map(|r| r.name.to_string()).collect())
        .map_err(|e| format!("YARA scan error: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_and_scan() {
        let rule = r#"
            rule test_string {
                strings:
                    $s = "hello_world_test"
                condition:
                    $s
            }
        "#;

        let scanner = compile_rule(rule).unwrap();
        let hits = scan_bytes(&scanner, b"some data with hello_world_test embedded").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0], "test_string");
    }

    #[test]
    fn no_match() {
        let rule = r#"
            rule test_no_match {
                strings:
                    $s = "WILL_NOT_MATCH"
                condition:
                    $s
            }
        "#;

        let scanner = compile_rule(rule).unwrap();
        let hits = scan_bytes(&scanner, b"clean data").unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn multiple_rules() {
        let rule = r#"
            rule rule_a {
                strings:
                    $s = "alpha"
                condition:
                    $s
            }
            rule rule_b {
                strings:
                    $s = "bravo"
                condition:
                    $s
            }
        "#;

        let scanner = compile_rule(rule).unwrap();
        let hits = scan_bytes(&scanner, b"alpha and bravo").unwrap();
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn scan_self_memory_with_yara() {
        let rule = r#"
            rule self_scan {
                strings:
                    $s = "scan_self_memory_with_yara"
                condition:
                    $s
            }
        "#;

        let scanner = compile_rule(rule).unwrap();
        let pid = std::process::id();
        let regions = super::super::walker::parse_maps(pid).unwrap();

        let mut found = false;
        for region in &regions {
            if !region.permissions.contains('r') {
                continue;
            }
            let size = (region.end - region.start) as usize;
            if size == 0 || size > 1024 * 1024 * 256 {
                continue;
            }
            let mut buf = vec![0u8; size];
            if let Ok(n) = super::super::walker::read_remote_slice(pid, region.start, &mut buf) {
                let hits = scan_bytes(&scanner, &buf[..n]).unwrap();
                if !hits.is_empty() {
                    found = true;
                    break;
                }
            }
        }
        assert!(
            found,
            "should find own test function name via YARA in process memory"
        );
    }
}
