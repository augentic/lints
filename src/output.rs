//! Output formatters for diagnostics.
//!
//! This module provides different output formats for linter diagnostics,
//! including human-readable, JSON, compact, and GitHub Actions format.

use std::path::Path;

use colored::Colorize;

use crate::diagnostics::Diagnostic;
use crate::rules::RuleSeverity;

/// Output format for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable colored output.
    Pretty,
    /// JSON output for tooling integration.
    Json,
    /// Compact one-line-per-diagnostic.
    Compact,
    /// GitHub Actions format.
    Github,
}

/// Format diagnostics according to the specified output format.
pub fn format_diagnostics(
    file: &Path,
    diagnostics: &[Diagnostic],
    format: OutputFormat,
    show_fixes: bool,
) -> String {
    match format {
        OutputFormat::Pretty => format_pretty(file, diagnostics, show_fixes),
        OutputFormat::Json => format_json(file, diagnostics),
        OutputFormat::Compact => format_compact(file, diagnostics),
        OutputFormat::Github => format_github(file, diagnostics),
    }
}

/// Format diagnostics in human-readable colored output.
fn format_pretty(file: &Path, diagnostics: &[Diagnostic], show_fixes: bool) -> String {
    if diagnostics.is_empty() {
        return String::new();
    }

    let mut output = String::new();

    // File header
    output.push_str(&format!(
        "\n{}\n",
        file.display().to_string().bold().underline()
    ));

    for diag in diagnostics {
        let severity_str = match diag.severity {
            RuleSeverity::Error => "error".red().bold(),
            RuleSeverity::Warning => "warning".yellow().bold(),
            RuleSeverity::Info => "info".blue().bold(),
            RuleSeverity::Hint => "hint".dimmed(),
        };

        let severity_marker = match diag.severity {
            RuleSeverity::Error => "✖".red(),
            RuleSeverity::Warning => "⚠".yellow(),
            RuleSeverity::Info => "ℹ".blue(),
            RuleSeverity::Hint => "💡".dimmed(),
        };

        // Main diagnostic line
        output.push_str(&format!(
            "\n  {} {} {} [{}]\n",
            severity_marker,
            format!("{}:{}", diag.line, diag.column).dimmed(),
            severity_str,
            diag.rule_id.cyan()
        ));

        // Rule name
        output.push_str(&format!("    {} {}\n", "→".dimmed(), diag.rule_name.bold()));

        // Message (handle multiline)
        for line in diag.message.lines().take(3) {
            output.push_str(&format!("    {}\n", line));
        }

        // Source snippet with highlighting
        if let Some(ref snippet) = diag.source_snippet {
            output.push_str(&format!("\n    {} │ {}\n", diag.line, snippet.dimmed()));

            // Underline the problematic section
            let start = diag.column;
            let end = diag.end_column;
            if end > start {
                let underline = format!(
                    "    {} │ {}{}",
                    " ".repeat(diag.line.to_string().len()),
                    " ".repeat(start),
                    match diag.severity {
                        RuleSeverity::Error => "^".repeat(end - start).red().to_string(),
                        RuleSeverity::Warning => "^".repeat(end - start).yellow().to_string(),
                        _ => "^".repeat(end - start).blue().to_string(),
                    }
                );
                output.push_str(&format!("{}\n", underline));
            }
        }

        // Fix suggestion
        if show_fixes {
            if let Some(ref fix) = diag.fix_template {
                output.push_str(&format!(
                    "\n    {} {}\n",
                    "Fix:".green().bold(),
                    fix.green()
                ));
            }
        }
    }

    output.push('\n');
    output
}

/// Format diagnostics as JSON.
fn format_json(file: &Path, diagnostics: &[Diagnostic]) -> String {
    let json_diagnostics: Vec<serde_json::Value> = diagnostics
        .iter()
        .map(|diag| {
            serde_json::json!({
                "file": file.display().to_string(),
                "line": diag.line,
                "column": diag.column,
                "end_column": diag.end_column,
                "severity": format!("{:?}", diag.severity).to_lowercase(),
                "rule_id": diag.rule_id,
                "rule_name": diag.rule_name,
                "category": format!("{:?}", diag.category),
                "message": diag.message,
                "fix": diag.fix_template,
                "source": diag.source_snippet,
            })
        })
        .collect();

    serde_json::to_string_pretty(&json_diagnostics).unwrap_or_default()
}

/// Format diagnostics in compact one-line format.
fn format_compact(file: &Path, diagnostics: &[Diagnostic]) -> String {
    let mut output = String::new();

    for diag in diagnostics {
        let severity = match diag.severity {
            RuleSeverity::Error => "E",
            RuleSeverity::Warning => "W",
            RuleSeverity::Info => "I",
            RuleSeverity::Hint => "H",
        };

        output.push_str(&format!(
            "{}:{}:{}: {} [{}] {}\n",
            file.display(),
            diag.line,
            diag.column,
            severity,
            diag.rule_id,
            diag.message.lines().next().unwrap_or("")
        ));
    }

    output
}

/// Format diagnostics for GitHub Actions.
fn format_github(file: &Path, diagnostics: &[Diagnostic]) -> String {
    let mut output = String::new();

    for diag in diagnostics {
        let level = match diag.severity {
            RuleSeverity::Error => "error",
            RuleSeverity::Warning => "warning",
            RuleSeverity::Info => "notice",
            RuleSeverity::Hint => "notice",
        };

        // GitHub Actions format: ::level file=file,line=line,col=col,endColumn=endColumn::message
        output.push_str(&format!(
            "::{}file={},line={},col={},endColumn={},title={}::{}\\n",
            level,
            file.display(),
            diag.line,
            diag.column,
            diag.end_column,
            diag.rule_id,
            diag.message
                .lines()
                .next()
                .unwrap_or("")
                .replace('\n', "\\n")
        ));
    }

    output
}

/// Summary statistics for diagnostics.
#[derive(Debug, Default)]
pub struct DiagnosticSummary {
    pub total: usize,
    pub errors: usize,
    pub warnings: usize,
    pub info: usize,
    pub hints: usize,
    pub files_with_issues: usize,
    pub total_files: usize,
}

impl DiagnosticSummary {
    /// Create a summary from diagnostics.
    pub fn from_diagnostics(diagnostics: &[Diagnostic]) -> Self {
        let mut summary = Self::default();
        summary.total = diagnostics.len();

        for diag in diagnostics {
            match diag.severity {
                RuleSeverity::Error => summary.errors += 1,
                RuleSeverity::Warning => summary.warnings += 1,
                RuleSeverity::Info => summary.info += 1,
                RuleSeverity::Hint => summary.hints += 1,
            }
        }

        summary
    }

    /// Format the summary as a human-readable string.
    pub fn format_pretty(&self) -> String {
        format!(
            "{} ({} {}, {} {}, {} info, {} hints)",
            format!("{} issues", self.total).bold(),
            self.errors.to_string().red().bold(),
            if self.errors == 1 { "error" } else { "errors" },
            self.warnings.to_string().yellow().bold(),
            if self.warnings == 1 {
                "warning"
            } else {
                "warnings"
            },
            self.info,
            self.hints
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleCategory;

    fn create_test_diagnostic() -> Diagnostic {
        Diagnostic {
            line: 10,
            column: 5,
            end_column: 15,
            severity: RuleSeverity::Error,
            rule_id: "test_rule".to_string(),
            rule_name: "Test Rule".to_string(),
            category: RuleCategory::Error,
            message: "This is a test message".to_string(),
            fix_template: Some("Fix suggestion".to_string()),
            source_snippet: Some("let x = some_code();".to_string()),
        }
    }

    #[test]
    fn test_format_compact() {
        let diag = create_test_diagnostic();
        let output = format_compact(Path::new("test.rs"), &[diag]);
        assert!(output.contains("test.rs:10:5: E [test_rule]"));
    }

    #[test]
    fn test_format_github() {
        let diag = create_test_diagnostic();
        let output = format_github(Path::new("test.rs"), &[diag]);
        assert!(output.contains("::error"));
        assert!(output.contains("test.rs"));
        assert!(output.contains("line=10"));
    }

    #[test]
    fn test_summary() {
        let diagnostics = vec![
            create_test_diagnostic(),
            Diagnostic {
                severity: RuleSeverity::Warning,
                ..create_test_diagnostic()
            },
            Diagnostic {
                severity: RuleSeverity::Info,
                ..create_test_diagnostic()
            },
        ];

        let summary = DiagnosticSummary::from_diagnostics(&diagnostics);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.errors, 1);
        assert_eq!(summary.warnings, 1);
        assert_eq!(summary.info, 1);
    }
}
