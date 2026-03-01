//! Omnia Lint - A custom Rust linter for Omnia guest development.
//!
//! This crate provides linting rules and analysis for Rust code targeting
//! WASM32 handlers with the Omnia framework. It enforces best practices,
//! detects forbidden patterns, and validates Handler implementations.
//!
//! # Usage
//!
//! ```rust,no_run
//! use omnia_lint::{LintConfig, Linter};
//!
//! let linter = Linter::new(LintConfig::default());
//! let diagnostics = linter.lint_file("src/handler.rs").unwrap();
//!
//! for diag in diagnostics {
//!     println!("{}", diag);
//! }
//! ```

pub mod config;
pub mod constraints;
pub mod diagnostics;
pub mod output;
pub mod rules;
pub mod semantic;

use std::path::Path;

use anyhow::Result;
pub use config::CargoLintConfig;
pub use diagnostics::{Diagnostic, DiagnosticsEngine, IgnoreDirective, parse_ignore_directives};
pub use rules::{LintLevel, Rule, RuleCategory, RuleSet, RuleSeverity};

/// Configuration for the linter.
#[derive(Debug, Clone)]
pub struct LintConfig {
    /// Enable all rules.
    pub all_rules: bool,

    /// Rule categories to enable.
    pub categories: Vec<RuleCategory>,

    /// Specific rule IDs to disable.
    pub disabled_rules: Vec<String>,

    /// Minimum severity to report.
    pub min_severity: RuleSeverity,

    /// Whether to include fix suggestions in output.
    pub show_fixes: bool,

    /// Cargo.toml-based severity overrides (populated from `[lints.omnia]`).
    pub cargo_overrides: CargoLintConfig,
}

impl Default for LintConfig {
    fn default() -> Self {
        Self {
            all_rules: true,
            categories: vec![],
            disabled_rules: vec![],
            min_severity: RuleSeverity::Hint,
            show_fixes: true,
            cargo_overrides: CargoLintConfig::default(),
        }
    }
}

/// The main linter struct.
pub struct Linter {
    engine: DiagnosticsEngine,
    config: LintConfig,
}

impl Linter {
    /// Create a new linter with the given configuration.
    pub fn new(config: LintConfig) -> Self {
        Self {
            engine: DiagnosticsEngine::new(),
            config,
        }
    }

    /// Lint a single file and return diagnostics.
    pub fn lint_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<Diagnostic>> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        let diagnostics = self.engine.analyze(&content, path);

        Ok(self.filter_diagnostics(diagnostics))
    }

    /// Lint a string of content.
    pub fn lint_str(&self, content: &str, filename: &str) -> Vec<Diagnostic> {
        let path = Path::new(filename);
        let diagnostics = self.engine.analyze(content, path);
        self.filter_diagnostics(diagnostics)
    }

    /// Filter diagnostics based on configuration.
    fn filter_diagnostics(&self, diagnostics: Vec<Diagnostic>) -> Vec<Diagnostic> {
        diagnostics
            .into_iter()
            .filter_map(|mut d| {
                if !self.config.cargo_overrides.is_empty()
                    && let Some(level) =
                        self.config.cargo_overrides.effective_level(&d.rule_id, d.category)
                {
                    match level.to_severity() {
                        None => return None,
                        Some(sev) => d.severity = sev,
                    }
                }

                // Filter by minimum severity (CLI --severity flag)
                if d.severity < self.config.min_severity {
                    return None;
                }

                // Filter by disabled rules (CLI --disable flag)
                if self.config.disabled_rules.contains(&d.rule_id) {
                    return None;
                }

                // Filter by categories if specified (CLI --categories flag)
                if !self.config.categories.is_empty()
                    && !self.config.categories.contains(&d.category)
                {
                    return None;
                }

                Some(d)
            })
            .collect()
    }
}
