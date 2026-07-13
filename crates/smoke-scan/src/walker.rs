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

use std::fs;
use std::io;

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub permissions: String,
    pub offset: u64,
    pub pathname: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScanHit {
    pub region: MemoryRegion,
    pub offset_in_region: usize,
    pub matched_bytes: Vec<u8>,
}

pub fn parse_maps(pid: u32) -> io::Result<Vec<MemoryRegion>> {
    let maps_path = format!("/proc/{pid}/maps");
    let content = fs::read_to_string(&maps_path)?;
    let mut regions = Vec::new();

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let addr_parts: Vec<&str> = parts[0].split('-').collect();
        if addr_parts.len() != 2 {
            continue;
        }

        let start = match u64::from_str_radix(addr_parts[0], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let end = match u64::from_str_radix(addr_parts[1], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let permissions = parts[1].to_string();
        let offset = parts
            .get(2)
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .unwrap_or(0);
        let pathname = parts.get(5).map(|s| s.to_string());

        regions.push(MemoryRegion {
            start,
            end,
            permissions,
            offset,
            pathname,
        });
    }

    Ok(regions)
}

fn read_remote(pid: u32, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
    let local_iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let remote_iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let ret =
        unsafe { libc::process_vm_readv(pid as libc::pid_t, &local_iov, 1, &remote_iov, 1, 0) };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

pub fn scan_process(pid: u32, needle: &[u8]) -> io::Result<Vec<ScanHit>> {
    if needle.is_empty() {
        return Ok(Vec::new());
    }

    let regions = parse_maps(pid)?;
    let mut hits = Vec::new();

    for region in &regions {
        if !region.permissions.contains('r') {
            continue;
        }

        let size = (region.end - region.start) as usize;
        if size == 0 || size > 1024 * 1024 * 1024 {
            continue;
        }

        let mut buf = vec![0u8; size];
        match read_remote(pid, region.start, &mut buf) {
            Ok(n) => {
                let search_buf = &buf[..n];
                let mut offset = 0;
                while let Some(pos) = find_in_slice(search_buf, needle, offset) {
                    hits.push(ScanHit {
                        region: region.clone(),
                        offset_in_region: pos,
                        matched_bytes: search_buf[pos..pos + needle.len()].to_vec(),
                    });
                    offset = pos + 1;
                }
            }
            Err(_) => continue,
        }
    }

    Ok(hits)
}

fn find_in_slice(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.len() > haystack.len() || start > haystack.len() - needle.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + start)
}

pub fn list_pids() -> io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        if let Ok(pid) = name.to_string_lossy().parse::<u32>() {
            pids.push(pid);
        }
    }
    Ok(pids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_maps_current_process() {
        let pid = std::process::id();
        let regions = parse_maps(pid).unwrap();
        assert!(!regions.is_empty());
        assert!(regions.iter().any(|r| r.permissions.contains('r')));
    }

    #[test]
    fn find_in_slice_works() {
        let haystack = b"hello world foo bar";
        assert_eq!(find_in_slice(haystack, b"world", 0), Some(6));
        assert_eq!(find_in_slice(haystack, b"world", 7), None);
        assert_eq!(find_in_slice(haystack, b"missing", 0), None);
    }

    #[test]
    fn scan_self_for_known_string() {
        let pid = std::process::id();
        let needle = b"scan_self_for_known_string";
        let hits = scan_process(pid, needle).unwrap();
        assert!(
            !hits.is_empty(),
            "should find own test function name in memory"
        );
    }

    #[test]
    fn list_pids_works() {
        let pids = list_pids().unwrap();
        let self_pid = std::process::id();
        assert!(pids.contains(&self_pid));
    }
}
