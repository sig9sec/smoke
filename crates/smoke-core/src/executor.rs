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
use crate::SmokeError;
use crate::backup::{BackupEntry, BackupStore};
use crate::config::SmokeConfig;
use crate::coverage::RiskLevel;
use crate::module::{ApplyCtx, ApplyReport, Change, RotateCtx, RotateReport};
use crate::registry::Registry;
use crate::rng;
use crate::state::State;

use std::time::{SystemTime, UNIX_EPOCH};

pub struct Executor<'a> {
    registry: &'a Registry,
    config: &'a SmokeConfig,
    state: &'a mut State,
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
        let seed = system_seed();

        for module in self.registry.iter_enabled(self.config) {
            if !module_ids.is_empty() && !module_ids.contains(&module.id()) {
                continue;
            }

            self.check_prerequisites(module.id(), module.requires(), module.risks(), force)?;

            let mod_config = self.config.module(module.id());
            let ctx = ApplyCtx {
                dry_run,
                force,
                profile: self.config.profile,
                overrides: mod_config.overrides,
                generator: rng::create_generator(self.config.profile, seed),
            };

            let report = module.apply(&ctx)?;

            if !dry_run {
                for change in &report.changed {
                    self.write_backup(module.id(), change)?;
                }

                let ms = self.state.module_mut(module.id());
                ms.last_applied = Some(iso_now());
                for change in &report.changed {
                    ms.current_values
                        .insert(change.identifier.clone(), change.new_value.clone());
                }
            }

            reports.push(report);
        }
        Ok(reports)
    }

    pub fn rotate(&mut self, module_ids: &[&str], dry_run: bool) -> Result<Vec<RotateReport>> {
        let mut reports = Vec::new();
        let seed = system_seed();

        for module in self.registry.iter_enabled(self.config) {
            if !module_ids.is_empty() && !module_ids.contains(&module.id()) {
                continue;
            }

            self.check_prerequisites(module.id(), module.requires(), module.risks(), false)?;

            let mod_config = self.config.module(module.id());
            let ctx = RotateCtx {
                dry_run,
                period: Some(self.config.rotation.default_period.clone()),
                profile: self.config.profile,
                overrides: mod_config.overrides,
                generator: rng::create_generator(self.config.profile, seed),
            };

            let report = module.rotate(&ctx)?;

            if !dry_run {
                let ms = self.state.module_mut(module.id());
                ms.last_rotated = Some(iso_now());
                ms.rotation_count += 1;
            }

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

            self.state.modules.remove(module.id());

            reports.push(report);
        }
        Ok(reports)
    }

    fn check_prerequisites(
        &self,
        module_id: &str,
        reqs: crate::coverage::Requirements,
        risk: crate::coverage::Risk,
        force: bool,
    ) -> Result<()> {
        if reqs.root && !is_root() {
            return Err(SmokeError::NotRoot(format!(
                "module '{module_id}' requires root"
            )));
        }
        if (risk.level == RiskLevel::High || risk.level == RiskLevel::Critical) && !force {
            return Err(SmokeError::Module(format!(
                "module '{module_id}' is high-risk ({}) and requires --force",
                risk.summary
            )));
        }
        Ok(())
    }

    fn write_backup(&self, module_id: &str, change: &Change) -> Result<()> {
        let entry = BackupEntry {
            module_id: module_id.to_string(),
            identifier: change.identifier.clone(),
            original_value: change.old_value.clone(),
            backed_up_at: iso_now(),
        };
        self.backup.store(&entry)
    }
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn system_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn iso_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{secs}")
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
        risk_level: RiskLevel,
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
        fn apply(&self, ctx: &ApplyCtx) -> Result<ApplyReport> {
            if ctx.dry_run {
                return Ok(ApplyReport::default());
            }
            Ok(ApplyReport {
                changed: vec![Change {
                    identifier: "test-id".into(),
                    old_value: "old".into(),
                    new_value: "new".into(),
                }],
                warnings: vec![],
            })
        }
        fn rotate(&self, ctx: &RotateCtx) -> Result<RotateReport> {
            if ctx.dry_run {
                return Ok(RotateReport::default());
            }
            Ok(RotateReport {
                rotated: vec!["test-id".into()],
                warnings: vec![],
            })
        }
        fn status(&self) -> Result<ModuleStatus> {
            Ok(ModuleStatus::default())
        }
        fn revert(&self) -> Result<RevertReport> {
            Ok(RevertReport {
                reverted: vec!["test-id".into()],
                warnings: vec![],
            })
        }
        fn coverage(&self) -> Coverage {
            Coverage {
                achieved_tier: Tier::PartialUserspace,
                strategies: vec![Strategy::FileOverwrite],
            }
        }
        fn risks(&self) -> Risk {
            Risk {
                level: self.risk_level,
                summary: "test".into(),
                mitigations: vec![],
            }
        }
    }

    fn setup() -> (Registry, SmokeConfig, State, BackupStore) {
        let mut reg = Registry::new();
        reg.register(Box::new(FakeModule {
            id: "mod-a",
            risk_level: RiskLevel::Low,
        }));
        reg.register(Box::new(FakeModule {
            id: "mod-b",
            risk_level: RiskLevel::Low,
        }));
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
    fn apply_dry_run_no_state_change() {
        let (reg, config, mut state, backup) = setup();
        let mut exec = Executor::new(&reg, &config, &mut state, &backup);
        exec.apply(&[], true, false).unwrap();
        assert!(state.modules.is_empty());
    }

    #[test]
    fn apply_writes_backup() {
        let (reg, config, mut state, backup) = setup();
        {
            let mut exec = Executor::new(&reg, &config, &mut state, &backup);
            exec.apply(&["mod-a"], false, false).unwrap();
        }
        let entries = backup.list_module("mod-a").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].original_value, "old");
    }

    #[test]
    fn apply_updates_current_values() {
        let (reg, config, mut state, backup) = setup();
        let mut exec = Executor::new(&reg, &config, &mut state, &backup);
        exec.apply(&["mod-a"], false, false).unwrap();
        let ms = state.modules.get("mod-a").unwrap();
        assert_eq!(ms.current_values.get("test-id").unwrap(), "new");
        assert!(ms.last_applied.is_some());
    }

    #[test]
    fn apply_preserves_backup_history() {
        let (reg, config, mut state, backup) = setup();
        {
            let mut exec = Executor::new(&reg, &config, &mut state, &backup);
            exec.apply(&["mod-a"], false, false).unwrap();
        }
        let original = backup.load_original("mod-a", "test-id").unwrap();
        assert_eq!(original.original_value, "old");
    }

    #[test]
    fn rotate_updates_state() {
        let (reg, config, mut state, backup) = setup();
        let mut exec = Executor::new(&reg, &config, &mut state, &backup);
        exec.rotate(&["mod-a"], false).unwrap();
        let ms = state.modules.get("mod-a").unwrap();
        assert_eq!(ms.rotation_count, 1);
        assert!(ms.last_rotated.is_some());
    }

    #[test]
    fn rotate_dry_run_no_state_change() {
        let (reg, config, mut state, backup) = setup();
        let mut exec = Executor::new(&reg, &config, &mut state, &backup);
        exec.rotate(&["mod-a"], true).unwrap();
        assert!(state.modules.is_empty());
    }

    #[test]
    fn revert_clears_state() {
        let (reg, config, mut state, backup) = setup();
        let applied = {
            let mut exec = Executor::new(&reg, &config, &mut state, &backup);
            exec.apply(&["mod-a"], false, false).unwrap();
            state.modules.contains_key("mod-a")
        };
        assert!(applied);
        {
            let mut exec = Executor::new(&reg, &config, &mut state, &backup);
            exec.revert(&["mod-a"]).unwrap();
        }
        assert!(!state.modules.contains_key("mod-a"));
    }

    #[test]
    fn high_risk_requires_force() {
        let mut reg = Registry::new();
        reg.register(Box::new(FakeModule {
            id: "dangerous",
            risk_level: RiskLevel::High,
        }));
        let config = SmokeConfig::default();
        let mut state = State::default();
        let dir = tempfile::tempdir().unwrap();
        let backup = BackupStore::new(dir.path().to_path_buf());
        backup.init().unwrap();

        let mut exec = Executor::new(&reg, &config, &mut state, &backup);
        let err = exec.apply(&["dangerous"], false, false);
        assert!(err.is_err());
    }
}
