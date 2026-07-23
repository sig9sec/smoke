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

use crate::Category;
use crate::config::SmokeConfig;
use crate::module::SmokeModule;

/// Collection of registered [`SmokeModule`]s.
///
/// The CLI builds one `Registry` at startup, registers every available
/// module, then passes it to the [`Executor`](crate::executor::Executor)
/// or queries it for `list` / `status` commands.
pub struct Registry {
    modules: Vec<Box<dyn SmokeModule>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
        }
    }

    pub fn register(&mut self, module: Box<dyn SmokeModule>) {
        self.modules.push(module);
    }

    pub fn by_id(&self, id: &str) -> Option<&dyn SmokeModule> {
        self.modules.iter().find(|m| m.id() == id).map(|m| &**m)
    }

    pub fn by_category(&self, cat: Category) -> Vec<&dyn SmokeModule> {
        self.modules
            .iter()
            .filter(|m| m.category() == cat)
            .map(|m| &**m)
            .collect()
    }

    pub fn iter_enabled<'a>(
        &'a self,
        config: &'a SmokeConfig,
    ) -> impl Iterator<Item = &'a dyn SmokeModule> + 'a {
        self.modules
            .iter()
            .filter(move |m| config.module(m.id()).enabled)
            .map(|m| &**m)
    }

    pub fn all(&self) -> &[Box<dyn SmokeModule>] {
        &self.modules
    }

    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.modules.len()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Result;
    use crate::coverage::{Coverage, Requirements, Risk, RiskLevel, Strategy, Tier};
    use crate::identifier::Findings;
    use crate::module::*;

    struct FakeModule {
        id: &'static str,
        cat: Category,
    }

    impl SmokeModule for FakeModule {
        fn id(&self) -> &'static str {
            self.id
        }
        fn name(&self) -> &'static str {
            self.id
        }
        fn category(&self) -> Category {
            self.cat
        }
        fn requires(&self) -> Requirements {
            Requirements::default()
        }
        fn enumerate(&self) -> Result<Findings> {
            Ok(Findings::new())
        }
        fn apply(&self, _: &ApplyCtx) -> Result<ApplyReport> {
            Ok(ApplyReport::default())
        }
        fn rotate(&self, _: &RotateCtx) -> Result<RotateReport> {
            Ok(RotateReport::default())
        }
        fn status(&self) -> Result<ModuleStatus> {
            Ok(ModuleStatus::default())
        }
        fn revert(&self) -> Result<RevertReport> {
            Ok(RevertReport::default())
        }
        fn coverage(&self) -> Coverage {
            Coverage {
                achieved_tier: Tier::PartialUserspace,
                strategies: vec![Strategy::FileOverwrite],
            }
        }
        fn risks(&self) -> Risk {
            Risk {
                level: RiskLevel::Low,
                summary: "test".into(),
                mitigations: vec![],
            }
        }
    }

    #[test]
    fn register_and_lookup() {
        let mut reg = Registry::new();
        reg.register(Box::new(FakeModule {
            id: "test-mod",
            cat: Category::Misc,
        }));

        assert!(reg.by_id("test-mod").is_some());
        assert!(reg.by_id("other").is_none());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn by_category() {
        let mut reg = Registry::new();
        reg.register(Box::new(FakeModule {
            id: "a",
            cat: Category::Dmi,
        }));
        reg.register(Box::new(FakeModule {
            id: "b",
            cat: Category::Misc,
        }));
        reg.register(Box::new(FakeModule {
            id: "c",
            cat: Category::Dmi,
        }));

        let dmi = reg.by_category(Category::Dmi);
        assert_eq!(dmi.len(), 2);
    }

    #[test]
    fn iter_enabled() {
        let mut reg = Registry::new();
        reg.register(Box::new(FakeModule {
            id: "a",
            cat: Category::Misc,
        }));
        reg.register(Box::new(FakeModule {
            id: "b",
            cat: Category::Misc,
        }));

        let mut config = SmokeConfig::default();
        config.modules.insert(
            "b".into(),
            crate::config::ModuleConfig {
                enabled: false,
                overrides: Default::default(),
            },
        );

        let enabled: Vec<_> = reg.iter_enabled(&config).collect();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].id(), "a");
    }
}
