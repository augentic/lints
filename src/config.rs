//! Cargo.toml configuration discovery and parsing for `qwasr-lint`.
//!
//! Reads the `[lints.qwasr]` or `[workspace.lints.qwasr]` table from the
//! nearest `Cargo.toml` and produces a [`CargoLintConfig`] that the linter
//! uses to override default rule severities.
//!
//! # Cargo.toml format
//!
//! ```toml
//! [workspace.lints.qwasr]
//! # Set the default level for every qwasr category:
//! all = "warn"
//!
//! # Override individual categories:
//! handler  = "deny"
//! wasm     = "deny"
//! security = "forbid"
//! error    = "warn"
//!
//! # Override individual rules:
//! error_generic_unwrap = "allow"
//! perf_clone_in_loop   = "allow"
//! ```
//!
//! Crate-level `[lints.qwasr]` tables are merged on top of
//! `[workspace.lints.qwasr]` when both exist (crate wins).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::rules::{LintLevel, RuleCategory};

/// Configuration extracted from a `Cargo.toml` `[lints.qwasr]` table.
#[derive(Debug, Clone, Default)]
pub struct CargoLintConfig {
    /// The `Cargo.toml` this config was loaded from (for diagnostics).
    pub source: Option<PathBuf>,

    /// Supercategory level – applies to *all* categories when set.
    /// Corresponds to `all = "warn"` in the toml table.
    pub all: Option<LintLevel>,

    /// Per-category severity overrides.
    pub categories: HashMap<RuleCategory, LintLevel>,

    /// Per-rule severity overrides (rule ID → level).
    pub rules: HashMap<String, LintLevel>,
}

impl CargoLintConfig {
    /// Resolve the effective [`LintLevel`] for a given rule.
    ///
    /// Precedence (highest → lowest):
    /// 1. Per-rule override (`error_generic_unwrap = "allow"`)
    /// 2. Per-category override (`error = "deny"`)
    /// 3. Supercategory (`all = "warn"`)
    /// 4. `None` – use the rule's built-in default severity.
    pub fn effective_level(&self, rule_id: &str, category: RuleCategory) -> Option<LintLevel> {
        if let Some(&level) = self.rules.get(rule_id) {
            return Some(level);
        }
        if let Some(&level) = self.categories.get(&category) {
            return Some(level);
        }
        self.all
    }

    /// Merge another config on top of this one (other wins on conflicts).
    pub fn merge(&mut self, other: &CargoLintConfig) {
        if other.all.is_some() {
            self.all = other.all;
        }
        for (&cat, &level) in &other.categories {
            self.categories.insert(cat, level);
        }
        for (rule, &level) in &other.rules {
            self.rules.insert(rule.clone(), level);
        }
    }

    /// Returns `true` when no overrides are configured.
    pub fn is_empty(&self) -> bool {
        self.all.is_none() && self.categories.is_empty() && self.rules.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Cargo.toml discovery
// ---------------------------------------------------------------------------

/// Walk up from `start_dir` and return the first `Cargo.toml` found.
pub fn find_cargo_toml(start_dir: &Path) -> Option<PathBuf> {
    let mut dir = if start_dir.is_file() {
        start_dir.parent()?.to_path_buf()
    } else {
        start_dir.to_path_buf()
    };

    loop {
        let candidate = dir.join("Cargo.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Load a [`CargoLintConfig`] from a `Cargo.toml` file.
///
/// Reads both `[workspace.lints.qwasr]` and `[lints.qwasr]`, merging
/// workspace first, then crate-level on top.
pub fn load_cargo_lint_config(cargo_toml: &Path) -> Result<CargoLintConfig> {
    let content = std::fs::read_to_string(cargo_toml)
        .with_context(|| format!("reading {}", cargo_toml.display()))?;

    let doc: toml::Value =
        toml::from_str(&content).with_context(|| format!("parsing {}", cargo_toml.display()))?;

    let mut config = CargoLintConfig {
        source: Some(cargo_toml.to_path_buf()),
        ..Default::default()
    };

    // 1. workspace.lints.qwasr
    if let Some(table) = doc
        .get("workspace")
        .and_then(|w| w.get("lints"))
        .and_then(|l| l.get("qwasr"))
        .and_then(|q| q.as_table())
    {
        merge_toml_table(&mut config, table);
    }

    // 2. lints.qwasr (crate-level, wins over workspace)
    if let Some(table) = doc
        .get("lints")
        .and_then(|l| l.get("qwasr"))
        .and_then(|q| q.as_table())
    {
        merge_toml_table(&mut config, table);
    }

    Ok(config)
}

/// Discover and load the qwasr lint config for a given path.
///
/// Walks up from `path` looking for the nearest `Cargo.toml` with a
/// `[lints.qwasr]` or `[workspace.lints.qwasr]` section.
pub fn discover_config(path: &Path) -> Result<CargoLintConfig> {
    match find_cargo_toml(path) {
        Some(cargo_toml) => load_cargo_lint_config(&cargo_toml),
        None => Ok(CargoLintConfig::default()),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a single TOML value into a [`LintLevel`].
///
/// Supports both:
///   - `"warn"` (plain string)
///   - `{ level = "warn", priority = 0 }` (table form – priority is ignored
///     for now but accepted for Cargo compatibility)
fn parse_lint_level(value: &toml::Value) -> Option<LintLevel> {
    match value {
        toml::Value::String(s) => LintLevel::from_str(s),
        toml::Value::Table(t) => t
            .get("level")
            .and_then(|v| v.as_str())
            .and_then(LintLevel::from_str),
        _ => None,
    }
}

/// Merge a TOML table of lint entries into a [`CargoLintConfig`].
fn merge_toml_table(config: &mut CargoLintConfig, table: &toml::value::Table) {
    for (key, value) in table {
        let Some(level) = parse_lint_level(value) else {
            continue;
        };

        if key == "all" {
            // Supercategory
            config.all = Some(level);
        } else if let Some(cat) = RuleCategory::from_key(key) {
            // Category override
            config.categories.insert(cat, level);
        } else {
            // Assume it's a rule ID
            config.rules.insert(key.clone(), level);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_levels() {
        let toml_str = r#"
[workspace.lints.qwasr]
all = "warn"
handler = "deny"
wasm = "forbid"
error_generic_unwrap = "allow"
"#;
        let doc: toml::Value = toml::from_str(toml_str).unwrap();
        let table = doc
            .get("workspace")
            .unwrap()
            .get("lints")
            .unwrap()
            .get("qwasr")
            .unwrap()
            .as_table()
            .unwrap();

        let mut config = CargoLintConfig::default();
        merge_toml_table(&mut config, table);

        assert_eq!(config.all, Some(LintLevel::Warn));
        assert_eq!(
            config.categories.get(&RuleCategory::Handler),
            Some(&LintLevel::Deny)
        );
        assert_eq!(
            config.categories.get(&RuleCategory::Wasm),
            Some(&LintLevel::Forbid)
        );
        assert_eq!(
            config.rules.get("error_generic_unwrap"),
            Some(&LintLevel::Allow)
        );
    }

    #[test]
    fn test_parse_table_form() {
        let toml_str = r#"
[workspace.lints.qwasr]
all = "warn"
handler = { level = "deny", priority = 1 }
"#;
        let doc: toml::Value = toml::from_str(toml_str).unwrap();
        let table = doc
            .get("workspace")
            .unwrap()
            .get("lints")
            .unwrap()
            .get("qwasr")
            .unwrap()
            .as_table()
            .unwrap();

        let mut config = CargoLintConfig::default();
        merge_toml_table(&mut config, table);

        assert_eq!(config.all, Some(LintLevel::Warn));
        assert_eq!(
            config.categories.get(&RuleCategory::Handler),
            Some(&LintLevel::Deny)
        );
    }

    #[test]
    fn test_effective_level_precedence() {
        let mut config = CargoLintConfig::default();
        config.all = Some(LintLevel::Warn);
        config
            .categories
            .insert(RuleCategory::Error, LintLevel::Deny);
        config
            .rules
            .insert("error_generic_unwrap".to_string(), LintLevel::Allow);

        // Rule override wins
        assert_eq!(
            config.effective_level("error_generic_unwrap", RuleCategory::Error),
            Some(LintLevel::Allow)
        );
        // Category wins over all
        assert_eq!(
            config.effective_level("error_panic_macro", RuleCategory::Error),
            Some(LintLevel::Deny)
        );
        // Falls back to all
        assert_eq!(
            config.effective_level("handler_generic_p", RuleCategory::Handler),
            Some(LintLevel::Warn)
        );
    }

    #[test]
    fn test_effective_level_none_when_empty() {
        let config = CargoLintConfig::default();
        assert_eq!(
            config.effective_level("handler_generic_p", RuleCategory::Handler),
            None
        );
    }

    #[test]
    fn test_merge_crate_wins() {
        let mut workspace = CargoLintConfig::default();
        workspace.all = Some(LintLevel::Warn);
        workspace
            .categories
            .insert(RuleCategory::Handler, LintLevel::Deny);

        let mut crate_level = CargoLintConfig::default();
        crate_level
            .categories
            .insert(RuleCategory::Handler, LintLevel::Allow);

        workspace.merge(&crate_level);

        assert_eq!(workspace.all, Some(LintLevel::Warn));
        assert_eq!(
            workspace.categories.get(&RuleCategory::Handler),
            Some(&LintLevel::Allow)
        );
    }
}
