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

use crate::Result;
use crate::backup::BackupStore;
use crate::config::SmokeConfig;
use crate::module::{ApplyCtx, ApplyReport, RotateCtx, RotateReport};
use crate::registry::Registry;
use crate::state::State;
use std::collections::HashMap;

pub struct Executor<'a> {
    registry: &'a Registry,
    config: &'a SmokeConfig,
    state: &'a mut State,
    #[allow(dead_code)]
    backup: &'a BackupStore,
}

impl<'a> Executor<'a> {
    pub fn new(
        registry: &'a Registry,
        config: &'a SmokeConfig,
        state: &'a mut State,
        backup: &'a BackupStore,
    ) -> Self {
        Self {
            registry,
            config,
            state,
            backup,
        }
    }

    pub fn apply(
        &mut self,
        module_ids: &[&str],
        dry_run: bool,
        force: bool,
    ) -> Result<Vec<ApplyReport>> {
        let mut reports = Vec::new();
        for module in self.registry.iter_enabled(self.config) {
            if !module_ids.is_empty() && !module_ids.contains(&module.id()) {
                continue;
            }
            let ctx = ApplyCtx {
                dry_run,
                force,
                profile_overrides: HashMap::new(),
            };
            let report = module.apply(&ctx)?;
            if !dry_run {
                let ms = self.state.module_mut(module.id());
                ms.last_applied = Some(chrono_now());
            }
            reports.push(report);
        }
        Ok(reports)
    }

    pub fn rotate(&mut self, module_ids: &[&str]) -> Result<Vec<RotateReport>> {
        let mut reports = Vec::new();
        for module in self.registry.iter_enabled(self.config) {
            if !module_ids.is_empty() && !module_ids.contains(&module.id()) {
                continue;
            }
            let ctx = RotateCtx {
                dry_run: false,
                period: None,
            };
            let report = module.rotate(&ctx)?;
            let ms = self.state.module_mut(module.id());
            ms.last_rotated = Some(chrono_now());
            ms.rotation_count += 1;
            reports.push(report);
        }
        Ok(reports)
    }

    pub fn revert(&mut self, module_ids: &[&str]) -> Result<Vec<crate::module::RevertReport>> {
        let mut reports = Vec::new();
        for module in self.registry.iter_enabled(self.config) {
            if !module_ids.is_empty() && !module_ids.contains(&module.id()) {
                continue;
            }
            let report = module.revert()?;
            reports.push(report);
        }
        Ok(reports)
    }
}

fn chrono_now() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Category;
    use crate::coverage::{Coverage, Requirements, Risk, RiskLevel, Strategy, Tier};
    use crate::identifier::Findings;
    use crate::module::*;

    struct FakeModule {
        id: &'static str,
    }

    impl SmokeModule for FakeModule {
        fn id(&self) -> &'static str {
            self.id
        }
        fn name(&self) -> &'static str {
            self.id
        }
        fn category(&self) -> Category {
            Category::Misc
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

    fn setup() -> (Registry, SmokeConfig, State, BackupStore) {
        let mut reg = Registry::new();
        reg.register(Box::new(FakeModule { id: "mod-a" }));
        reg.register(Box::new(FakeModule { id: "mod-b" }));
        let config = SmokeConfig::default();
        let state = State::default();
        let dir = tempfile::tempdir().unwrap();
        let backup = BackupStore::new(dir.path().to_path_buf());
        backup.init().unwrap();
        (reg, config, state, backup)
    }

    #[test]
    fn apply_all() {
        let (reg, config, mut state, backup) = setup();
        let mut exec = Executor::new(&reg, &config, &mut state, &backup);
        let reports = exec.apply(&[], false, false).unwrap();
        assert_eq!(reports.len(), 2);
    }

    #[test]
    fn apply_filtered() {
        let (reg, config, mut state, backup) = setup();
        let mut exec = Executor::new(&reg, &config, &mut state, &backup);
        let reports = exec.apply(&["mod-a"], false, false).unwrap();
        assert_eq!(reports.len(), 1);
    }

    #[test]
    fn apply_dry_run() {
        let (reg, config, mut state, backup) = setup();
        let mut exec = Executor::new(&reg, &config, &mut state, &backup);
        exec.apply(&[], true, false).unwrap();
        assert!(state.modules.is_empty());
    }

    #[test]
    fn rotate_updates_state() {
        let (reg, config, mut state, backup) = setup();
        let mut exec = Executor::new(&reg, &config, &mut state, &backup);
        exec.rotate(&["mod-a"]).unwrap();
        let ms = state.modules.get("mod-a").unwrap();
        assert_eq!(ms.rotation_count, 1);
        assert!(ms.last_rotated.is_some());
    }
}
