//! Diagnostics engine for analyzing Omnia code.

use std::collections::HashSet;
use std::path::Path;

use regex::Regex;

use crate::constraints::{ForbiddenPattern, OmniaContext};
use crate::rules::{RuleCategory, RuleSet, RuleSeverity};
use crate::semantic::SemanticAnalyzer;

/// Parsed ignore directive from source code.
#[derive(Debug, Clone)]
pub struct IgnoreDirective {
    /// Line number where the directive appears (1-indexed).
    pub line: usize,
    /// Whether this is a file-level directive (#![...]).
    pub is_file_level: bool,
    /// Rule IDs to ignore, or None for all rules.
    pub rules: Option<HashSet<String>>,
}

impl IgnoreDirective {
    /// Check if this directive allows (ignores) a specific rule.
    pub fn allows(&self, rule_id: &str) -> bool {
        match &self.rules {
            None => true, // "all" - ignore everything
            Some(rules) => rules.contains(rule_id) || rules.contains(&rule_id.to_lowercase()),
        }
    }
}

/// Parse ignore directives from source code.
///
/// Supports:
/// - `#[omnia::allow(all)]` - ignore all rules for the next item
/// - `#[omnia::allow(rule_id)]` - ignore specific rule for the next item
/// - `#[omnia::allow(rule1, rule2)]` - ignore multiple rules for the next item
/// - `#![omnia::allow(...)]` - file-level ignore (inner attribute)
pub fn parse_ignore_directives(content: &str) -> Vec<IgnoreDirective> {
    let mut directives = Vec::new();

    // Pattern for #[omnia::allow(...)] or #![omnia::allow(...)]
    let attr_pattern = Regex::new(r#"#(!?)\[omnia::allow\(([^)]+)\)\]"#).unwrap();

    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        if let Some(caps) = attr_pattern.captures(trimmed) {
            let is_file_level = caps.get(1).is_some_and(|m| m.as_str() == "!");
            let rules_str = caps.get(2).map_or("", |m| m.as_str());

            let rules = if rules_str.trim().to_lowercase() == "all" {
                None
            } else {
                let rule_set: HashSet<String> = rules_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                Some(rule_set)
            };

            directives.push(IgnoreDirective {
                line: line_idx + 1,
                is_file_level,
                rules,
            });
        }
    }

    directives
}

/// Check if a diagnostic should be ignored based on directives.
fn should_ignore_diagnostic(
    diagnostic_line: usize, rule_id: &str, directives: &[IgnoreDirective],
) -> bool {
    for directive in directives {
        // File-level directives apply to everything
        if directive.is_file_level && directive.allows(rule_id) {
            return true;
        }

        // Line-level directives apply to the next non-attribute line
        // We check if the directive is on the line immediately before the diagnostic
        // or within a few lines before (to handle multiple stacked attributes)
        if !directive.is_file_level
            && directive.line < diagnostic_line
            && diagnostic_line <= directive.line + 10  // Allow up to 10 lines of attributes
            && directive.allows(rule_id)
        {
            return true;
        }
    }
    false
}

/// A diagnostic message produced by the linter.
#[derive(Debug, Clone)]
pub struct Diagnostic {
    /// Line number (1-indexed).
    pub line: usize,

    /// Column start (0-indexed).
    pub column: usize,

    /// Column end (0-indexed).
    pub end_column: usize,

    /// Severity of the diagnostic.
    pub severity: RuleSeverity,

    /// Rule ID that triggered this diagnostic.
    pub rule_id: String,

    /// Human-readable rule name.
    pub rule_name: String,

    /// Category of the rule.
    pub category: RuleCategory,

    /// The diagnostic message.
    pub message: String,

    /// Optional fix template.
    pub fix_template: Option<String>,

    /// The source code snippet that triggered the diagnostic.
    pub source_snippet: Option<String>,
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}: {:?} [{}] {}",
            self.line, self.column, self.severity, self.rule_id, self.message
        )
    }
}

/// Diagnostics engine for Omnia code analysis.
pub struct DiagnosticsEngine {
    /// Omnia context with patterns and rules.
    context: OmniaContext,

    /// Comprehensive rule set for Omnia validation.
    rule_set: RuleSet,

    /// Compiled regex patterns for forbidden patterns.
    compiled_patterns: Vec<(ForbiddenPattern, Vec<Regex>)>,

    /// Compiled regex for forbidden crate detection in use statements.
    crate_use_pattern: Regex,

    /// Compiled regex for forbidden crate detection in extern crate.
    crate_extern_pattern: Regex,

    /// Semantic analyzer for deeper code analysis.
    semantic_analyzer: SemanticAnalyzer,
}

/// Check if a position (byte offset from start of content) falls inside a string literal.
fn is_inside_string_literal_at_offset(content: &str, byte_offset: usize) -> bool {
    let bytes = content.as_bytes();
    let mut i = 0;

    while i < byte_offset && i < bytes.len() {
        // Skip comments
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        // Check for raw string: r"..." or r#"..."# etc.
        if bytes[i] == b'r' && i + 1 < bytes.len() {
            let mut hash_count = 0;
            let mut j = i + 1;

            while j < bytes.len() && bytes[j] == b'#' {
                hash_count += 1;
                j += 1;
            }

            if j < bytes.len() && bytes[j] == b'"' {
                j += 1;

                while j < bytes.len() {
                    if bytes[j] == b'"' {
                        let mut closing_hashes = 0;
                        let mut k = j + 1;
                        while k < bytes.len() && bytes[k] == b'#' && closing_hashes < hash_count {
                            closing_hashes += 1;
                            k += 1;
                        }
                        if closing_hashes == hash_count {
                            if byte_offset > i && byte_offset < k {
                                return true;
                            }
                            i = k;
                            break;
                        }
                    }
                    j += 1;
                }
                continue;
            }
        }

        // Check for regular string
        if bytes[i] == b'"' {
            let start = i;
            i += 1;

            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'"' {
                    if byte_offset > start && byte_offset <= i {
                        return true;
                    }
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }

        i += 1;
    }

    false
}

/// Calculate byte offset for a line and column position.
fn calculate_byte_offset(content: &str, line_idx: usize, col: usize) -> usize {
    let mut offset = 0;
    for (idx, line) in content.lines().enumerate() {
        if idx == line_idx {
            return offset + col.min(line.len());
        }
        offset += line.len() + 1;
    }
    offset
}

impl DiagnosticsEngine {
    /// Create a new diagnostics engine.
    pub fn new() -> Self {
        let context = OmniaContext::new();

        let compiled_patterns: Vec<(ForbiddenPattern, Vec<Regex>)> = context
            .forbidden_patterns
            .iter()
            .map(|fp| {
                let regexes = fp.patterns.iter().filter_map(|p| Regex::new(p).ok()).collect();
                (fp.clone(), regexes)
            })
            .collect();

        let semantic_analyzer = SemanticAnalyzer::new();

        Self {
            context,
            rule_set: RuleSet::new(),
            compiled_patterns,
            crate_use_pattern: Regex::new(r"use\s+(\w+)(?:::|;)").unwrap(),
            crate_extern_pattern: Regex::new(r"extern\s+crate\s+(\w+)").unwrap(),
            semantic_analyzer,
        }
    }

    /// Analyze document content and return diagnostics.
    pub fn analyze(&self, content: &str, path: &Path) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        // Only analyze Rust files
        if path.extension().is_none_or(|ext| ext != "rs") {
            return diagnostics;
        }

        // Parse ignore directives first
        let ignore_directives = parse_ignore_directives(content);

        // Check for forbidden patterns
        for (line_idx, line) in content.lines().enumerate() {
            // Skip comments
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
                continue;
            }

            // Check forbidden patterns from constraints
            for (pattern, regexes) in &self.compiled_patterns {
                for regex in regexes {
                    if let Some(mat) = regex.find(line) {
                        let byte_offset = calculate_byte_offset(content, line_idx, mat.start());
                        if is_inside_string_literal_at_offset(content, byte_offset) {
                            continue;
                        }
                        diagnostics.push(self.create_forbidden_pattern_diagnostic(
                            line_idx,
                            mat.start(),
                            mat.end(),
                            pattern,
                            line,
                        ));
                    }
                }
            }

            // Check for forbidden crates in use statements
            for cap in self.crate_use_pattern.captures_iter(line) {
                if let Some(crate_match) = cap.get(1) {
                    let crate_name = crate_match.as_str();
                    if self.context.is_forbidden_crate(crate_name) {
                        diagnostics.push(self.create_forbidden_crate_diagnostic(
                            line_idx,
                            crate_match.start(),
                            crate_match.end(),
                            crate_name,
                            line,
                        ));
                    }
                }
            }

            // Check for forbidden crates in extern crate
            for cap in self.crate_extern_pattern.captures_iter(line) {
                if let Some(crate_match) = cap.get(1) {
                    let crate_name = crate_match.as_str();
                    if self.context.is_forbidden_crate(crate_name) {
                        diagnostics.push(self.create_forbidden_crate_diagnostic(
                            line_idx,
                            crate_match.start(),
                            crate_match.end(),
                            crate_name,
                            line,
                        ));
                    }
                }
            }

            // Check against comprehensive rule set
            diagnostics.extend(self.check_rules(content, line, line_idx));
        }

        // Perform semantic analysis (includes handler implementation checks)
        let semantic_result = self.semantic_analyzer.analyze(content);
        diagnostics.extend(semantic_result.diagnostics);

        // Filter out ignored diagnostics
        diagnostics.retain(|d| !should_ignore_diagnostic(d.line, &d.rule_id, &ignore_directives));

        diagnostics
    }

    /// Check a line against the comprehensive rule set.
    fn check_rules(&self, content: &str, line: &str, line_idx: usize) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        for rule in &self.rule_set.rules {
            if rule.is_anti_pattern
                && let Some(mat) = rule.pattern.find(line)
            {
                let byte_offset = calculate_byte_offset(content, line_idx, mat.start());
                if is_inside_string_literal_at_offset(content, byte_offset) {
                    continue;
                }

                let message = if let Some(fix) = rule.fix_template {
                    format!("{}\n\nSuggested fix: {}", rule.description, fix)
                } else {
                    rule.description.to_string()
                };

                diagnostics.push(Diagnostic {
                    line: line_idx + 1,
                    column: mat.start(),
                    end_column: mat.end(),
                    severity: rule.severity,
                    rule_id: rule.id.to_string(),
                    rule_name: rule.name.to_string(),
                    category: rule.category,
                    message,
                    fix_template: rule.fix_template.map(String::from),
                    source_snippet: Some(line.to_string()),
                });
            }
        }

        diagnostics
    }

    /// Create a diagnostic for a forbidden pattern.
    fn create_forbidden_pattern_diagnostic(
        &self, line_idx: usize, start: usize, end: usize, pattern: &ForbiddenPattern, line: &str,
    ) -> Diagnostic {
        Diagnostic {
            line: line_idx + 1,
            column: start,
            end_column: end,
            severity: pattern.severity,
            rule_id: pattern.id.to_string(),
            rule_name: pattern.name.to_string(),
            category: RuleCategory::Wasm,
            message: format!("{}\n\nAlternative: {}", pattern.reason, pattern.alternative),
            fix_template: Some(pattern.alternative.to_string()),
            source_snippet: Some(line.to_string()),
        }
    }

    /// Create a diagnostic for a forbidden crate.
    fn create_forbidden_crate_diagnostic(
        &self, line_idx: usize, start: usize, end: usize, crate_name: &str, line: &str,
    ) -> Diagnostic {
        let alternative = get_crate_alternative(crate_name);

        Diagnostic {
            line: line_idx + 1,
            column: start,
            end_column: end,
            severity: RuleSeverity::Error,
            rule_id: format!("forbidden_crate_{}", crate_name),
            rule_name: format!("Forbidden Crate: {}", crate_name),
            category: RuleCategory::Wasm,
            message: format!(
                "Crate '{}' is not available in WASM32.\n\nAlternative: {}",
                crate_name, alternative
            ),
            fix_template: Some(alternative.to_string()),
            source_snippet: Some(line.to_string()),
        }
    }

}

impl Default for DiagnosticsEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the recommended alternative for a forbidden crate.
fn get_crate_alternative(crate_name: &str) -> &'static str {
    match crate_name {
        // HTTP clients
        "reqwest" | "hyper" | "surf" | "ureq" | "isahc" | "attohttpc" => {
            "Use the HttpRequest provider trait (ctx.provider.fetch())"
        }
        // Redis
        "redis" | "fred" => "Use the StateStore provider trait for caching",
        // Kafka/messaging
        "rdkafka" | "kafka" | "lapin" | "amqp" => "Use the Publisher provider trait for messaging",
        // Async runtimes
        "tokio" | "async-std" | "smol" | "actix-rt" | "futures-executor" => {
            "Use async/await without explicit runtime - WASI provides the executor"
        }
        // Parallelism
        "rayon" => "Use sequential iterators - WASM is single-threaded",
        // Concurrency primitives
        "crossbeam" | "parking_lot" => "WASM is single-threaded; use async/await for concurrency",
        // Global state
        "once_cell" | "lazy_static" => "Use the Config provider trait for configuration values",
        // Collections
        "dashmap" | "evmap" => "Use the StateStore provider trait for shared state",
        // Database
        "sqlx" | "diesel" | "rusqlite" | "postgres" | "mysql" | "mongodb" => {
            "Use the TableStore provider trait for database operations"
        }
        // Filesystem
        "tempfile" | "directories" => {
            "Filesystem is not available in WASM32; use StateStore or TableStore"
        }
        // Network
        "socket2" | "mio" | "quinn" => "Use the HttpRequest provider trait for network operations",
        _ => "This crate is not compatible with WASM32",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_unwrap() {
        let engine = DiagnosticsEngine::new();
        let content = r#"
fn main() {
    let x = Some(5).unwrap();
}
"#;
        let diagnostics = engine.analyze(content, Path::new("test.rs"));
        assert!(!diagnostics.is_empty());
        assert!(diagnostics.iter().any(|d| d.rule_id == "error_generic_unwrap"));
    }

    #[test]
    fn test_detects_tokio() {
        let engine = DiagnosticsEngine::new();
        let content = r#"
use tokio::runtime::Runtime;
"#;
        let diagnostics = engine.analyze(content, Path::new("test.rs"));
        assert!(!diagnostics.is_empty());
        assert!(diagnostics.iter().any(|d| d.rule_id.contains("tokio")));
    }

    #[test]
    fn test_detects_static_mut() {
        let engine = DiagnosticsEngine::new();
        let content = r#"
static mut COUNTER: u32 = 0;
"#;
        let diagnostics = engine.analyze(content, Path::new("test.rs"));
        assert!(!diagnostics.is_empty());
        assert!(diagnostics.iter().any(|d| d.rule_id.contains("static")));
    }

    #[test]
    fn test_ignores_non_rust_files() {
        let engine = DiagnosticsEngine::new();
        let content = "let x = Some(5).unwrap();";
        let diagnostics = engine.analyze(content, Path::new("test.txt"));
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn test_ignore_directive_all() {
        let engine = DiagnosticsEngine::new();
        let content = r#"
#[omnia::allow(all)]
fn main() {
    let x = Some(5).unwrap();
}
"#;
        let diagnostics = engine.analyze(content, Path::new("test.rs"));
        // The unwrap should be ignored
        assert!(!diagnostics.iter().any(|d| d.line == 4));
    }

    #[test]
    fn test_ignore_directive_specific_rule() {
        let engine = DiagnosticsEngine::new();

        // First verify the diagnostic fires without the ignore directive
        let content_without_ignore = r#"
fn main() {
    let x = Some(5).unwrap();
}
"#;
        let diags = engine.analyze(content_without_ignore, Path::new("test.rs"));
        assert!(
            diags.iter().any(|d| d.rule_id == "error_generic_unwrap" && d.line == 3),
            "error_generic_unwrap should fire on .unwrap() without an ignore directive"
        );

        // Now verify the directive suppresses it
        let content = r#"
#[omnia::allow(error_generic_unwrap)]
fn main() {
    let x = Some(5).unwrap();
}
"#;
        let diagnostics = engine.analyze(content, Path::new("test.rs"));
        assert!(
            !diagnostics.iter().any(|d| d.rule_id == "error_generic_unwrap" && d.line == 4),
            "error_generic_unwrap should be suppressed by #[omnia::allow(error_generic_unwrap)]"
        );
    }

    #[test]
    fn test_ignore_directive_file_level() {
        let engine = DiagnosticsEngine::new();
        let content = r#"#![omnia::allow(all)]

fn main() {
    let x = Some(5).unwrap();
    static mut COUNTER: u32 = 0;
}
"#;
        let diagnostics = engine.analyze(content, Path::new("test.rs"));
        // All diagnostics should be ignored
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn test_ignore_directive_multiple_rules() {
        let engine = DiagnosticsEngine::new();

        // Verify rule fires without the directive
        let content_without_ignore = r#"
fn main() {
    let x = Some(5).unwrap();
    let y = Some(6).expect("msg");
}
"#;
        let diags = engine.analyze(content_without_ignore, Path::new("test.rs"));
        assert!(
            diags.iter().any(|d| d.rule_id == "error_generic_unwrap" && d.line == 3),
            "error_generic_unwrap should fire on .unwrap()"
        );
        assert!(
            diags.iter().any(|d| d.rule_id == "error_generic_unwrap" && d.line == 4),
            "error_generic_unwrap should fire on .expect()"
        );

        // Now verify the directive suppresses both
        let content = r#"
#[omnia::allow(error_generic_unwrap)]
fn main() {
    let x = Some(5).unwrap();
    let y = Some(6).expect("msg");
}
"#;
        let diagnostics = engine.analyze(content, Path::new("test.rs"));
        assert!(
            !diagnostics
                .iter()
                .any(|d| d.rule_id == "error_generic_unwrap" && (d.line == 4 || d.line == 5)),
            "error_generic_unwrap should be suppressed for both unwrap and expect"
        );
    }

    #[test]
    fn test_parse_ignore_directives() {
        let content = r#"
#![omnia::allow(all)]
#[omnia::allow(unwrap_used)]
fn foo() {}
#[omnia::allow(rule1, rule2)]
fn bar() {}
"#;
        let directives = parse_ignore_directives(content);
        assert_eq!(directives.len(), 3);

        // First directive is file-level, ignores all
        assert!(directives[0].is_file_level);
        assert!(directives[0].rules.is_none());

        // Second directive is line-level, ignores specific rule
        assert!(!directives[1].is_file_level);
        assert!(directives[1].rules.as_ref().unwrap().contains("unwrap_used"));

        // Third directive ignores multiple rules
        assert!(!directives[2].is_file_level);
        let rules = directives[2].rules.as_ref().unwrap();
        assert!(rules.contains("rule1"));
        assert!(rules.contains("rule2"));
    }

    #[test]
    fn test_is_inside_string_literal_regular() {
        let content = r#"let x = "hello.unwrap()"; let y = foo.unwrap();"#;
        // offset inside the string literal
        let offset_in_str = content.find("hello").unwrap();
        assert!(is_inside_string_literal_at_offset(content, offset_in_str));

        // offset outside the string literal (the second unwrap)
        let second_unwrap = content.rfind("unwrap").unwrap();
        assert!(!is_inside_string_literal_at_offset(content, second_unwrap));
    }

    #[test]
    fn test_is_inside_string_literal_raw_string() {
        let content = r##"let x = r#"hello.unwrap()"#; let y = foo.unwrap();"##;
        let in_raw = content.find("hello").unwrap();
        assert!(is_inside_string_literal_at_offset(content, in_raw));
    }

    #[test]
    fn test_is_inside_string_literal_comment() {
        let content = "// let x = foo.unwrap();\nlet y = bar.unwrap();";
        // Inside a comment line - the function skips comments
        let in_comment = content.find("foo").unwrap();
        assert!(!is_inside_string_literal_at_offset(content, in_comment));
    }

    #[test]
    fn test_calculate_byte_offset() {
        let content = "line0\nline1\nline2";
        assert_eq!(calculate_byte_offset(content, 0, 0), 0);
        assert_eq!(calculate_byte_offset(content, 1, 0), 6);
        assert_eq!(calculate_byte_offset(content, 2, 3), 15);
    }
}
