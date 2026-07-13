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

use super::random;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub struct LamProfile {
    rng: ChaCha20Rng,
}

impl LamProfile {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: ChaCha20Rng::seed_from_u64(seed),
        }
    }

    pub fn mac(&mut self) -> String {
        random::random_mac(&mut self.rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lam_bit_set() {
        let mut p = LamProfile::new(42);
        let mac = p.mac();
        let first = u8::from_str_radix(&mac[..2], 16).unwrap();
        assert_eq!(first & 0x02, 0x02);
    }
}
