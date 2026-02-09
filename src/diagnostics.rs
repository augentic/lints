//! Diagnostics engine for analyzing QWASR code.

use std::sync::Arc;

use regex::Regex;
use tower_lsp::lsp_types::*;
use tracing::debug;

use crate::qwasr::{ForbiddenPattern, QwasrContext, RuleSet, RuleSeverity, Severity};

/// Diagnostics engine for QWASR code analysis.
pub struct DiagnosticsEngine {
    /// QWASR context with patterns and rules.
    context: Arc<QwasrContext>,

    /// Comprehensive rule set for QWASR validation.
    rule_set: RuleSet,

    /// Compiled regex patterns for forbidden patterns.
    compiled_patterns: Vec<(ForbiddenPattern, Vec<Regex>)>,

    /// Compiled regex for forbidden crate detection in use statements.
    crate_use_pattern: Regex,

    /// Compiled regex for forbidden crate detection in extern crate.
    crate_extern_pattern: Regex,
}

/// Check if a position (byte offset from start of content) falls inside a string literal.
/// This handles regular strings, raw strings (r"..."), and raw strings with # delimiters (r#"..."#).
fn is_inside_string_literal_at_offset(content: &str, byte_offset: usize) -> bool {
    let bytes = content.as_bytes();
    let mut i = 0;

    while i < byte_offset && i < bytes.len() {
        // Skip comments
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            // Line comment - skip to end of line
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        // Check for raw string: r"..." or r#"..."# or r##"..."## etc.
        if bytes[i] == b'r' && i + 1 < bytes.len() {
            let mut hash_count = 0;
            let mut j = i + 1;

            // Count # symbols
            while j < bytes.len() && bytes[j] == b'#' {
                hash_count += 1;
                j += 1;
            }

            // Check for opening quote
            if j < bytes.len() && bytes[j] == b'"' {
                // This is a raw string - find the closing
                j += 1; // Skip opening quote

                // Find closing: "# repeated hash_count times
                while j < bytes.len() {
                    if bytes[j] == b'"' {
                        // Check if followed by correct number of #
                        let mut closing_hashes = 0;
                        let mut k = j + 1;
                        while k < bytes.len() && bytes[k] == b'#' && closing_hashes < hash_count {
                            closing_hashes += 1;
                            k += 1;
                        }
                        if closing_hashes == hash_count {
                            // Found closing - check if target is inside
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

            // Find closing quote, handling escapes
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2; // Skip escaped character
                    continue;
                }
                if bytes[i] == b'"' {
                    // Found closing quote
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

/// Calculate byte offset for a line and column position
fn calculate_byte_offset(content: &str, line_idx: usize, col: usize) -> usize {
    let mut offset = 0;
    for (idx, line) in content.lines().enumerate() {
        if idx == line_idx {
            return offset + col.min(line.len());
        }
        offset += line.len() + 1; // +1 for newline
    }
    offset
}

impl DiagnosticsEngine {
    /// Create a new diagnostics engine.
    pub fn new(context: Arc<QwasrContext>) -> Self {
        // Pre-compile regex patterns for performance
        let compiled_patterns: Vec<(ForbiddenPattern, Vec<Regex>)> = context
            .forbidden_patterns
            .iter()
            .map(|fp| {
                let regexes = fp
                    .patterns
                    .iter()
                    .filter_map(|p| Regex::new(p).ok())
                    .collect();
                (fp.clone(), regexes)
            })
            .collect();

        Self {
            context,
            rule_set: RuleSet::new(),
            compiled_patterns,
            crate_use_pattern: Regex::new(r"use\s+(\w+)(?:::|;)").unwrap(),
            crate_extern_pattern: Regex::new(r"extern\s+crate\s+(\w+)").unwrap(),
        }
    }

    /// Analyze document content and return diagnostics.
    pub fn analyze(&self, content: &str, uri: &Url) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        // Only analyze Rust files
        if !uri.path().ends_with(".rs") {
            return diagnostics;
        }

        debug!("Analyzing document: {}", uri);

        // Check for forbidden patterns
        for (line_idx, line) in content.lines().enumerate() {
            // Skip comments
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
                continue;
            }

            // Check forbidden patterns
            for (pattern, regexes) in &self.compiled_patterns {
                for regex in regexes {
                    if let Some(mat) = regex.find(line) {
                        // Skip matches inside string literals (handles multi-line raw strings)
                        let byte_offset = calculate_byte_offset(content, line_idx, mat.start());
                        if is_inside_string_literal_at_offset(content, byte_offset) {
                            continue;
                        }
                        diagnostics.push(self.create_diagnostic(
                            line_idx,
                            mat.start(),
                            mat.end(),
                            pattern.name,
                            &format!("{}\n\nAlternative: {}", pattern.reason, pattern.alternative),
                            pattern.severity,
                            Some(pattern.id.to_string()),
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
                        ));
                    }
                }
            }

            // Check against comprehensive rule set
            diagnostics.extend(self.check_rules(content, line, line_idx));
        }

        // Check for Handler implementation issues
        diagnostics.extend(self.check_handler_implementations(content));

        // Check for missing provider trait bounds
        diagnostics.extend(self.check_provider_bounds(content));

        debug!("Found {} diagnostics", diagnostics.len());
        diagnostics
    }

    /// Check a line against the comprehensive rule set.
    fn check_rules(&self, content: &str, line: &str, line_idx: usize) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        for rule in &self.rule_set.rules {
            // Only check anti-patterns (violations)
            if rule.is_anti_pattern {
                if let Some(mat) = rule.pattern.find(line) {
                    // Skip matches inside string literals (handles multi-line raw strings)
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
                        range: Range {
                            start: Position {
                                line: line_idx as u32,
                                character: mat.start() as u32,
                            },
                            end: Position {
                                line: line_idx as u32,
                                character: mat.end() as u32,
                            },
                        },
                        severity: Some(match rule.severity {
                            RuleSeverity::Error => DiagnosticSeverity::ERROR,
                            RuleSeverity::Warning => DiagnosticSeverity::WARNING,
                            RuleSeverity::Info => DiagnosticSeverity::INFORMATION,
                            RuleSeverity::Hint => DiagnosticSeverity::HINT,
                        }),
                        code: Some(NumberOrString::String(rule.id.to_string())),
                        source: Some("qwasr".to_string()),
                        message: format!("{}: {}", rule.name, message),
                        ..Default::default()
                    });
                }
            }
        }

        diagnostics
    }

    /// Create a diagnostic for a forbidden pattern.
    fn create_diagnostic(
        &self,
        line: usize,
        start_col: usize,
        end_col: usize,
        title: &str,
        message: &str,
        severity: Severity,
        code: Option<String>,
    ) -> Diagnostic {
        Diagnostic {
            range: Range {
                start: Position {
                    line: line as u32,
                    character: start_col as u32,
                },
                end: Position {
                    line: line as u32,
                    character: end_col as u32,
                },
            },
            severity: Some(match severity {
                Severity::Error => DiagnosticSeverity::ERROR,
                Severity::Warning => DiagnosticSeverity::WARNING,
                Severity::Hint => DiagnosticSeverity::HINT,
            }),
            code: code.map(NumberOrString::String),
            code_description: None,
            source: Some("qwasr".to_string()),
            message: format!("{}: {}", title, message),
            related_information: None,
            tags: None,
            data: None,
        }
    }

    /// Create a diagnostic for a forbidden crate.
    fn create_forbidden_crate_diagnostic(
        &self,
        line: usize,
        start_col: usize,
        end_col: usize,
        crate_name: &str,
    ) -> Diagnostic {
        let alternative = self.get_crate_alternative(crate_name);

        Diagnostic {
            range: Range {
                start: Position {
                    line: line as u32,
                    character: start_col as u32,
                },
                end: Position {
                    line: line as u32,
                    character: end_col as u32,
                },
            },
            severity: Some(DiagnosticSeverity::ERROR),
            code: Some(NumberOrString::String("forbidden_crate".to_string())),
            code_description: None,
            source: Some("qwasr".to_string()),
            message: format!(
                "Forbidden crate '{}': This crate is not compatible with WASM32.\n\nAlternative: {}",
                crate_name, alternative
            ),
            related_information: None,
            tags: None,
            data: None,
        }
    }

    /// Get the recommended alternative for a forbidden crate.
    fn get_crate_alternative(&self, crate_name: &str) -> &'static str {
        match crate_name {
            "reqwest" | "hyper" | "surf" | "ureq" => "Use the HttpRequest provider trait",
            "redis" => "Use the StateStore provider trait",
            "rdkafka" | "lapin" => "Use the Publisher provider trait",
            "tokio" | "async-std" | "smol" => "WASI runtime provides the async executor",
            "rayon" | "crossbeam" | "parking_lot" => "WASM is single-threaded, use async/await",
            "once_cell" | "lazy_static" => "Use the Config provider trait for configuration",
            "dashmap" => "Use the StateStore provider trait for shared state",
            "sqlx" | "diesel" | "postgres" | "mysql" | "rusqlite" => {
                "Use the TableStore provider trait"
            }
            "tempfile" => "Filesystem operations are not available in WASM32",
            "socket2" | "mio" => "Use the HttpRequest provider trait for network operations",
            _ => "Check QWASR documentation for the appropriate provider trait",
        }
    }

    /// Check for Handler implementation issues.
    fn check_handler_implementations(&self, content: &str) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        // Look for impl Handler blocks
        let handler_impl_re =
            Regex::new(r"impl\s*<[^>]*>\s*Handler\s*<[^>]*>\s*for\s+(\w+)").unwrap();

        for (line_idx, line) in content.lines().enumerate() {
            if let Some(caps) = handler_impl_re.captures(line) {
                // Check if from_input and handle are properly defined
                // This is a simplified check - a full AST analysis would be more accurate
                let type_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");

                // Look for common issues in subsequent lines
                let remaining_content: String = content
                    .lines()
                    .skip(line_idx)
                    .take(50)
                    .collect::<Vec<_>>()
                    .join("\n");

                // Check if returning wrong error type
                if remaining_content.contains("anyhow::Error")
                    && !remaining_content.contains("qwasr_sdk::Error")
                {
                    diagnostics.push(Diagnostic {
                        range: Range {
                            start: Position {
                                line: line_idx as u32,
                                character: 0,
                            },
                            end: Position {
                                line: line_idx as u32,
                                character: line.len() as u32,
                            },
                        },
                        severity: Some(DiagnosticSeverity::WARNING),
                        code: Some(NumberOrString::String("handler_error_type".to_string())),
                        source: Some("qwasr".to_string()),
                        message: format!(
                            "Handler for '{}' should use qwasr_sdk::Error, not anyhow::Error.\n\n\
                            The Handler trait's Error type should be qwasr_sdk::Error for proper HTTP status mapping.",
                            type_name
                        ),
                        ..Default::default()
                    });
                }
            }
        }

        diagnostics
    }

    /// Check for missing provider trait bounds.
    fn check_provider_bounds(&self, content: &str) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        // Look for async fn with provider parameter but missing trait bounds
        let provider_fn_re =
            Regex::new(r"async\s+fn\s+(\w+)\s*<\s*P\s*>\s*\([^)]*provider\s*:\s*&P").unwrap();
        let where_clause_re = Regex::new(r"where\s+P\s*:").unwrap();

        for (line_idx, line) in content.lines().enumerate() {
            if provider_fn_re.is_match(line) {
                // Look for where clause in the next few lines
                let context: String = content
                    .lines()
                    .skip(line_idx)
                    .take(5)
                    .collect::<Vec<_>>()
                    .join("\n");

                if !where_clause_re.is_match(&context)
                    && !line.contains(": Config")
                    && !line.contains(": HttpRequest")
                {
                    diagnostics.push(Diagnostic {
                        range: Range {
                            start: Position {
                                line: line_idx as u32,
                                character: 0,
                            },
                            end: Position {
                                line: line_idx as u32,
                                character: line.len() as u32,
                            },
                        },
                        severity: Some(DiagnosticSeverity::HINT),
                        code: Some(NumberOrString::String(
                            "missing_provider_bounds".to_string(),
                        )),
                        source: Some("qwasr".to_string()),
                        message: "Provider parameter 'P' should have trait bounds.\n\n\
                            Add a where clause with the required provider traits, e.g.:\n\
                            where P: Config + HttpRequest"
                            .to_string(),
                        ..Default::default()
                    });
                }
            }
        }

        diagnostics
    }
}
