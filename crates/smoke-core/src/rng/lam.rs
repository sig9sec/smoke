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
use super::random;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Mutex;

/// MAC-only profile: sets the locally-administered bit on every MAC.
///
/// All non-MAC identifiers are left untouched (methods return defaults
/// that modules treat as "keep the current value"). This mimics the
/// behaviour of iOS/Android MAC randomization.
pub struct LamProfile {
    rng: Mutex<ChaCha20Rng>,
}

impl LamProfile {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: Mutex::new(ChaCha20Rng::seed_from_u64(seed)),
        }
    }
}

impl ValueGenerator for LamProfile {
    fn mac(&self) -> String {
        random::random_mac(&mut self.rng.lock().unwrap())
    }

    fn uuid(&self) -> String {
        random::random_uuid_v4(&mut self.rng.lock().unwrap())
    }

    fn hostname(&self) -> String {
        random::random_hostname(&mut self.rng.lock().unwrap())
    }

    fn serial(&self, len: usize) -> String {
        random::random_serial(&mut self.rng.lock().unwrap(), len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lam_bit_set() {
        let p = LamProfile::new(42);
        let mac = p.mac();
        let first = u8::from_str_radix(&mac[..2], 16).unwrap();
        assert_eq!(first & 0x02, 0x02);
    }

    #[test]
    fn no_dmi_values() {
        let p = LamProfile::new(42);
        assert!(p.dmi_sys_vendor().is_none());
        assert!(p.dmi_product_name().is_none());
        assert!(p.disk_vendor().is_none());
    }
}
