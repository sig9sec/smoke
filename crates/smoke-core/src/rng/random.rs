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

use super::ValueGenerator;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::sync::Mutex;

/// Generate a locally-administered unicast MAC (LAM bit set, multicast
/// bit clear).
pub fn random_mac(rng: &mut ChaCha20Rng) -> String {
    let mut buf = [0u8; 6];
    rng.fill(&mut buf);
    buf[0] = (buf[0] & 0xFE) | 0x02;
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]
    )
}

/// Generate a RFC 4122 version 4 (random) UUID.
pub fn random_uuid_v4(rng: &mut ChaCha20Rng) -> String {
    let mut buf = [0u8; 16];
    rng.fill(&mut buf);
    buf[6] = (buf[6] & 0x0F) | 0x40;
    buf[8] = (buf[8] & 0x3F) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        buf[0],
        buf[1],
        buf[2],
        buf[3],
        buf[4],
        buf[5],
        buf[6],
        buf[7],
        buf[8],
        buf[9],
        buf[10],
        buf[11],
        buf[12],
        buf[13],
        buf[14],
        buf[15]
    )
}

/// Generate a random alphanumeric serial of the given length.
pub fn random_serial(rng: &mut ChaCha20Rng, len: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..len)
        .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
        .collect()
}

/// Generate a plausible hostname in `adjective-noun-number` form.
pub fn random_hostname(rng: &mut ChaCha20Rng) -> String {
    const ADJ: &[&str] = &[
        "swift", "calm", "dark", "bright", "warm", "cool", "soft", "hard", "fast", "slow", "deep",
        "high", "wide", "thin", "rich", "pure",
    ];
    const NOUN: &[&str] = &[
        "oak", "pine", "lake", "hill", "moon", "star", "wind", "rain", "fox", "wolf", "bear",
        "hawk", "fish", "fern", "moss", "sage",
    ];
    let adj = ADJ[rng.random_range(0..ADJ.len())];
    let noun = NOUN[rng.random_range(0..NOUN.len())];
    let num: u16 = rng.random_range(100..999);
    format!("{adj}-{noun}-{num}")
}

/// [`ValueGenerator`] that produces fully random values with no
/// cross-identifier coherence. See SPEC section 6.4.
pub struct RandomProfile {
    rng: Mutex<ChaCha20Rng>,
}

impl RandomProfile {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: Mutex::new(ChaCha20Rng::seed_from_u64(seed)),
        }
    }
}

impl ValueGenerator for RandomProfile {
    fn mac(&self) -> String {
        random_mac(&mut self.rng.lock().unwrap())
    }

    fn uuid(&self) -> String {
        random_uuid_v4(&mut self.rng.lock().unwrap())
    }

    fn hostname(&self) -> String {
        random_hostname(&mut self.rng.lock().unwrap())
    }

    fn serial(&self, len: usize) -> String {
        random_serial(&mut self.rng.lock().unwrap(), len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn test_rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(42)
    }

    #[test]
    fn mac_format() {
        let mut rng = test_rng();
        let mac = random_mac(&mut rng);
        assert_eq!(mac.len(), 17);
        let first = u8::from_str_radix(&mac[..2], 16).unwrap();
        assert_eq!(first & 0x01, 0, "multicast bit must be clear");
        assert_eq!(first & 0x02, 0x02, "locally administered bit must be set");
    }

    #[test]
    fn uuid_v4_format() {
        let mut rng = test_rng();
        let uuid = random_uuid_v4(&mut rng);
        let parts: Vec<&str> = uuid.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
        assert!(parts[2].starts_with('4'));
        let byte8 = u8::from_str_radix(&parts[3][..2], 16).unwrap();
        assert_eq!(byte8 & 0xC0, 0x80);
    }

    #[test]
    fn serial_length() {
        let mut rng = test_rng();
        let s = random_serial(&mut rng, 20);
        assert_eq!(s.len(), 20);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn hostname_format() {
        let mut rng = test_rng();
        let h = random_hostname(&mut rng);
        assert!(h.contains('-'));
        let parts: Vec<&str> = h.split('-').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn profile_deterministic() {
        let p1 = RandomProfile::new(42);
        let p2 = RandomProfile::new(42);
        assert_eq!(p1.mac(), p2.mac());
        assert_eq!(p1.uuid(), p2.uuid());
    }
}
