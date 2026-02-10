//! QWASR Lint - A custom Rust linter for QWASR WASM32 handler development.
//!
//! This crate provides linting rules and analysis for Rust code targeting
//! WASM32 handlers with the QWASR framework. It enforces best practices,
//! detects forbidden patterns, and validates Handler implementations.
//!
//! # Usage
//!
//! ```rust,no_run
//! use qwasr_lint::{Linter, LintConfig};
//!
//! let linter = Linter::new(LintConfig::default());
//! let diagnostics = linter.lint_file("src/handler.rs").unwrap();
//!
//! for diag in diagnostics {
//!     println!("{}", diag);
//! }
//! ```

pub mod constraints;
pub mod diagnostics;
pub mod output;
pub mod rules;
pub mod semantic;

pub use diagnostics::{
    parse_ignore_directives, Diagnostic, DiagnosticsEngine, IgnoreDirective, Severity,
};
pub use rules::{Rule, RuleCategory, RuleSet, RuleSeverity};

use anyhow::Result;
use std::path::Path;

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
}

impl Default for LintConfig {
    fn default() -> Self {
        Self {
            all_rules: true,
            categories: vec![],
            disabled_rules: vec![],
            min_severity: RuleSeverity::Hint,
            show_fixes: true,
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
            .filter(|d| {
                // Filter by severity
                if d.severity < self.config.min_severity {
                    return false;
                }

                // Filter by disabled rules
                if self.config.disabled_rules.contains(&d.rule_id) {
                    return false;
                }

                // Filter by categories if specified
                if !self.config.categories.is_empty()
                    && !self.config.categories.contains(&d.category)
                {
                    return false;
                }

                true
            })
            .collect()
    }
}
