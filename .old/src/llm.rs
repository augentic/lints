//! LLM-friendly analysis and context extraction for QWASR code.
//!
//! This module provides structured analysis results optimized for consumption
//! by Large Language Models (LLMs) like Claude when used as a coding assistant.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Structured analysis result for LLM consumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QwasrAnalysis {
    /// Summary of the file's QWASR components.
    pub summary: FileSummary,

    /// Handler implementations found in the file.
    pub handlers: Vec<HandlerAnalysis>,

    /// Provider trait implementations found.
    pub provider_impls: Vec<ProviderImplAnalysis>,

    /// Issues and violations detected.
    pub issues: Vec<Issue>,

    /// Suggestions for improvements.
    pub suggestions: Vec<Suggestion>,

    /// Missing implementations or TODOs.
    pub missing: Vec<MissingItem>,

    /// Context about the file for LLM understanding.
    pub context: FileContext,
}

/// High-level summary of the file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSummary {
    /// Whether this appears to be a QWASR business logic crate.
    pub is_qwasr_crate: bool,

    /// Number of Handler implementations.
    pub handler_count: usize,

    /// Provider traits used.
    pub provider_traits_used: Vec<String>,

    /// Request types defined.
    pub request_types: Vec<String>,

    /// Response types defined.
    pub response_types: Vec<String>,

    /// Overall health score (0-100).
    pub health_score: u8,
}

/// Detailed analysis of a Handler implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerAnalysis {
    /// The request type implementing Handler.
    pub request_type: String,

    /// The response type (Output).
    pub response_type: String,

    /// Provider trait bounds required.
    pub provider_bounds: Vec<String>,

    /// Provider traits actually used in the implementation.
    pub provider_traits_used: Vec<String>,

    /// Line number where the impl starts.
    pub line_start: usize,

    /// Line number where the impl ends.
    pub line_end: usize,

    /// Issues specific to this handler.
    pub issues: Vec<HandlerIssue>,

    /// Whether from_input is properly implemented.
    pub has_from_input: bool,

    /// Whether handle is properly implemented.
    pub has_handle: bool,

    /// Whether the handler follows best practices.
    pub follows_best_practices: bool,
}

/// Issues specific to Handler implementations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerIssue {
    /// Issue code.
    pub code: String,

    /// Severity level.
    pub severity: IssueSeverity,

    /// Human-readable message.
    pub message: String,

    /// Line number.
    pub line: usize,

    /// Suggested fix.
    pub fix: Option<String>,

    /// Explanation for LLM.
    pub explanation: String,
}

/// Provider trait implementation analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderImplAnalysis {
    /// The trait being implemented.
    pub trait_name: String,

    /// The type implementing the trait.
    pub impl_type: String,

    /// Line number.
    pub line: usize,

    /// Whether implementation is complete.
    pub is_complete: bool,

    /// Missing methods.
    pub missing_methods: Vec<String>,
}

/// General issue detected in the code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    /// Unique issue code.
    pub code: String,

    /// Severity level.
    pub severity: IssueSeverity,

    /// Category of the issue.
    pub category: IssueCategory,

    /// Human-readable message.
    pub message: String,

    /// Line number.
    pub line: usize,

    /// Column start.
    pub column_start: usize,

    /// Column end.
    pub column_end: usize,

    /// The problematic code snippet.
    pub snippet: String,

    /// Suggested fix code.
    pub fix: Option<String>,

    /// Detailed explanation for LLM understanding.
    pub explanation: String,

    /// Related QWASR documentation reference.
    pub doc_reference: Option<String>,
}

/// Severity levels for issues.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IssueSeverity {
    Error,
    Warning,
    Info,
    Hint,
}

/// Categories of issues.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IssueCategory {
    /// WASM32 compatibility issues.
    Wasm32Compatibility,
    /// Handler pattern violations.
    HandlerPattern,
    /// Provider trait usage issues.
    ProviderUsage,
    /// Error handling issues.
    ErrorHandling,
    /// Statelessness violations.
    Statelessness,
    /// Best practice violations.
    BestPractice,
    /// Missing implementations.
    MissingImplementation,
}

/// Improvement suggestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suggestion {
    /// Suggestion type.
    pub kind: SuggestionKind,

    /// Human-readable title.
    pub title: String,

    /// Detailed description.
    pub description: String,

    /// Code before (if applicable).
    pub before: Option<String>,

    /// Suggested code after.
    pub after: Option<String>,

    /// Priority (1-5, 1 being highest).
    pub priority: u8,
}

/// Types of suggestions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionKind {
    /// Add missing implementation.
    AddImplementation,
    /// Refactor existing code.
    Refactor,
    /// Add error handling.
    AddErrorHandling,
    /// Add validation.
    AddValidation,
    /// Optimize code.
    Optimize,
    /// Add documentation.
    AddDocumentation,
}

/// Missing item that should be implemented.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingItem {
    /// What is missing.
    pub kind: MissingKind,

    /// Name of the missing item.
    pub name: String,

    /// Where it should be added.
    pub location: String,

    /// Template code to add.
    pub template: String,

    /// Explanation.
    pub reason: String,
}

/// Types of missing items.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MissingKind {
    /// Missing Handler implementation.
    HandlerImpl,
    /// Missing trait method.
    TraitMethod,
    /// Missing validation.
    Validation,
    /// Missing error handling.
    ErrorHandling,
    /// Missing type definition.
    TypeDefinition,
}

/// Context about the file for LLM understanding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileContext {
    /// Detected imports from qwasr_sdk.
    pub qwasr_imports: Vec<String>,

    /// External crates used.
    pub external_crates: Vec<String>,

    /// Async functions defined.
    pub async_functions: Vec<FunctionInfo>,

    /// Structs defined.
    pub structs: Vec<StructInfo>,

    /// Trait implementations.
    pub trait_impls: Vec<TraitImplInfo>,

    /// Provider trait bounds used across the file.
    pub provider_bounds_summary: HashMap<String, usize>,
}

/// Information about a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    /// Function name.
    pub name: String,

    /// Whether it's async.
    pub is_async: bool,

    /// Whether it's public.
    pub is_public: bool,

    /// Generic parameters.
    pub generics: Vec<String>,

    /// Provider trait bounds if any.
    pub provider_bounds: Vec<String>,

    /// Line number.
    pub line: usize,
}

/// Information about a struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructInfo {
    /// Struct name.
    pub name: String,

    /// Whether it's a Request type.
    pub is_request: bool,

    /// Whether it's a Response type.
    pub is_response: bool,

    /// Derive macros used.
    pub derives: Vec<String>,

    /// Line number.
    pub line: usize,
}

/// Information about a trait implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraitImplInfo {
    /// Trait name.
    pub trait_name: String,

    /// Type implementing the trait.
    pub impl_type: String,

    /// Generic parameters.
    pub generics: Vec<String>,

    /// Line number.
    pub line: usize,
}

/// LLM-oriented analyzer for QWASR code.
pub struct LlmAnalyzer {
    /// Compiled regex patterns.
    patterns: AnalyzerPatterns,
}

#[allow(dead_code)]
struct AnalyzerPatterns {
    handler_impl: regex::Regex,
    provider_impl: regex::Regex,
    struct_def: regex::Regex,
    async_fn: regex::Regex,
    use_qwasr: regex::Regex,
    provider_bounds: regex::Regex,
    from_input: regex::Regex,
    handle_fn: regex::Regex,
    config_get: regex::Regex,
    http_fetch: regex::Regex,
    publisher_send: regex::Regex,
    state_store: regex::Regex,
    bad_request: regex::Regex,
    server_error: regex::Regex,
    bad_gateway: regex::Regex,
    reply_ok: regex::Regex,
    context_usage: regex::Regex,
    derive_attr: regex::Regex,
}

impl LlmAnalyzer {
    /// Create a new LLM analyzer.
    pub fn new() -> Self {
        Self {
            patterns: AnalyzerPatterns {
                handler_impl: regex::Regex::new(
                    r"impl\s*<([^>]*)>\s*Handler\s*<([^>]*)>\s*for\s+(\w+)",
                )
                .unwrap(),
                provider_impl: regex::Regex::new(r"impl\s+(?:qwasr_sdk::)?(\w+)\s+for\s+(\w+)")
                    .unwrap(),
                struct_def: regex::Regex::new(r"(?:pub\s+)?struct\s+(\w+)").unwrap(),
                async_fn: regex::Regex::new(r"(?:(pub)\s+)?async\s+fn\s+(\w+)\s*<([^>]*)>")
                    .unwrap(),
                use_qwasr: regex::Regex::new(r"use\s+qwasr_sdk::(?:\{([^}]+)\}|(\w+))").unwrap(),
                provider_bounds: regex::Regex::new(r"P\s*:\s*((?:\w+\s*\+\s*)*\w+)").unwrap(),
                from_input: regex::Regex::new(r"fn\s+from_input").unwrap(),
                handle_fn: regex::Regex::new(r"async\s+fn\s+handle").unwrap(),
                config_get: regex::Regex::new(r"Config::get|provider\.get\(").unwrap(),
                http_fetch: regex::Regex::new(r"HttpRequest::fetch|provider\.fetch\(").unwrap(),
                publisher_send: regex::Regex::new(r"Publisher::send|provider\.send\(").unwrap(),
                state_store: regex::Regex::new(
                    r"StateStore::(get|set|delete)|provider\.(get|set|delete)\(",
                )
                .unwrap(),
                bad_request: regex::Regex::new(r"bad_request!").unwrap(),
                server_error: regex::Regex::new(r"server_error!").unwrap(),
                bad_gateway: regex::Regex::new(r"bad_gateway!").unwrap(),
                reply_ok: regex::Regex::new(r"Reply::(ok|created|accepted)|\.into\(\)").unwrap(),
                context_usage: regex::Regex::new(r"ctx\.(owner|provider|headers)").unwrap(),
                derive_attr: regex::Regex::new(r"#\[derive\(([^)]+)\)\]").unwrap(),
            },
        }
    }

    /// Perform full analysis of a QWASR source file.
    pub fn analyze(&self, content: &str) -> QwasrAnalysis {
        let lines: Vec<&str> = content.lines().collect();

        let handlers = self.extract_handlers(content, &lines);
        let provider_impls = self.extract_provider_impls(content, &lines);
        let context = self.extract_context(content, &lines);
        let issues = self.detect_issues(content, &lines, &handlers);
        let suggestions = self.generate_suggestions(&handlers, &context, &issues);
        let missing = self.detect_missing(&handlers, &context);

        let summary = FileSummary {
            is_qwasr_crate: !context.qwasr_imports.is_empty() || !handlers.is_empty(),
            handler_count: handlers.len(),
            provider_traits_used: context.provider_bounds_summary.keys().cloned().collect(),
            request_types: context
                .structs
                .iter()
                .filter(|s| s.is_request)
                .map(|s| s.name.clone())
                .collect(),
            response_types: context
                .structs
                .iter()
                .filter(|s| s.is_response)
                .map(|s| s.name.clone())
                .collect(),
            health_score: self.calculate_health_score(&issues, &handlers),
        };

        QwasrAnalysis {
            summary,
            handlers,
            provider_impls,
            issues,
            suggestions,
            missing,
            context,
        }
    }

    /// Extract Handler implementations from the code.
    fn extract_handlers(&self, content: &str, lines: &[&str]) -> Vec<HandlerAnalysis> {
        let mut handlers = Vec::new();

        for (line_idx, line) in lines.iter().enumerate() {
            if let Some(caps) = self.patterns.handler_impl.captures(line) {
                let generics = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let _provider_type = caps.get(2).map(|m| m.as_str()).unwrap_or("P");
                let request_type = caps.get(3).map(|m| m.as_str()).unwrap_or("").to_string();

                // Extract provider bounds
                let provider_bounds: Vec<String> =
                    if let Some(bounds_match) = self.patterns.provider_bounds.captures(generics) {
                        bounds_match
                            .get(1)
                            .map(|m| m.as_str())
                            .unwrap_or("")
                            .split('+')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect()
                    } else {
                        Vec::new()
                    };

                // Find the end of the impl block (simplified)
                let impl_content = self.extract_impl_block(content, line_idx);
                let line_end = line_idx + impl_content.lines().count();

                // Check for from_input and handle
                let has_from_input = self.patterns.from_input.is_match(&impl_content);
                let has_handle = self.patterns.handle_fn.is_match(&impl_content);

                // Detect which provider traits are actually used
                let provider_traits_used = self.detect_provider_usage(&impl_content);

                // Check for issues in this handler
                let issues = self.check_handler_issues(&impl_content, &provider_bounds, line_idx);

                // Check best practices
                let follows_best_practices =
                    issues.iter().all(|i| i.severity != IssueSeverity::Error);

                // Extract response type from impl
                let response_type = self.extract_output_type(&impl_content);

                handlers.push(HandlerAnalysis {
                    request_type,
                    response_type,
                    provider_bounds,
                    provider_traits_used,
                    line_start: line_idx + 1,
                    line_end: line_end + 1,
                    issues,
                    has_from_input,
                    has_handle,
                    follows_best_practices,
                });
            }
        }

        handlers
    }

    /// Extract an impl block starting from a line.
    fn extract_impl_block(&self, content: &str, start_line: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let mut brace_count = 0;
        let mut started = false;
        let mut result = Vec::new();

        for line in lines.iter().skip(start_line) {
            result.push(*line);

            for ch in line.chars() {
                if ch == '{' {
                    brace_count += 1;
                    started = true;
                } else if ch == '}' {
                    brace_count -= 1;
                }
            }

            if started && brace_count == 0 {
                break;
            }
        }

        result.join("\n")
    }

    /// Extract the Output type from a Handler impl.
    fn extract_output_type(&self, impl_content: &str) -> String {
        let output_re = regex::Regex::new(r"type\s+Output\s*=\s*(\w+)").unwrap();
        output_re
            .captures(impl_content)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "Unknown".to_string())
    }

    /// Detect which provider traits are actually used in code.
    fn detect_provider_usage(&self, content: &str) -> Vec<String> {
        let mut used = Vec::new();

        if self.patterns.config_get.is_match(content) {
            used.push("Config".to_string());
        }
        if self.patterns.http_fetch.is_match(content) {
            used.push("HttpRequest".to_string());
        }
        if self.patterns.publisher_send.is_match(content) {
            used.push("Publisher".to_string());
        }
        if self.patterns.state_store.is_match(content) {
            used.push("StateStore".to_string());
        }

        used
    }

    /// Check for handler-specific issues.
    fn check_handler_issues(
        &self,
        impl_content: &str,
        declared_bounds: &[String],
        start_line: usize,
    ) -> Vec<HandlerIssue> {
        let mut issues = Vec::new();

        // Check for missing from_input
        if !self.patterns.from_input.is_match(impl_content) {
            issues.push(HandlerIssue {
                code: "handler_missing_from_input".to_string(),
                severity: IssueSeverity::Error,
                message: "Handler is missing from_input method".to_string(),
                line: start_line,
                fix: Some(r#"fn from_input(input: Self::Input) -> Result<Self> {
    serde_json::from_slice(&input)
        .context("deserializing request")
        .map_err(Into::into)
}"#.to_string()),
                explanation: "The from_input method is required by the Handler trait to parse raw input bytes into the request type.".to_string(),
            });
        }

        // Check for missing handle
        if !self.patterns.handle_fn.is_match(impl_content) {
            issues.push(HandlerIssue {
                code: "handler_missing_handle".to_string(),
                severity: IssueSeverity::Error,
                message: "Handler is missing handle method".to_string(),
                line: start_line,
                fix: Some(r#"async fn handle(self, ctx: Context<'_, P>) -> Result<Reply<Self::Output>> {
    // Process request
    Ok(Reply::ok(Self::Output { /* fields */ }))
}"#.to_string()),
                explanation: "The handle method is required by the Handler trait to process the request and return a response.".to_string(),
            });
        }

        // Check for unused provider bounds
        let used = self.detect_provider_usage(impl_content);
        for bound in declared_bounds {
            if !used.contains(bound) && bound != "P" {
                issues.push(HandlerIssue {
                    code: "handler_unused_provider_bound".to_string(),
                    severity: IssueSeverity::Warning,
                    message: format!("Provider trait '{}' is declared but not used", bound),
                    line: start_line,
                    fix: None,
                    explanation: format!(
                        "The trait bound '{}' is declared in the impl but no methods from this trait are called. \
                        Remove unused bounds to keep the interface minimal.", bound
                    ),
                });
            }
        }

        // Check for missing provider bounds
        for used_trait in &used {
            if !declared_bounds.contains(used_trait) {
                issues.push(HandlerIssue {
                    code: "handler_missing_provider_bound".to_string(),
                    severity: IssueSeverity::Error,
                    message: format!("Provider trait '{}' is used but not declared in bounds", used_trait),
                    line: start_line,
                    fix: Some(format!("Add '{}' to the provider bounds: P: {} + {}", 
                        used_trait,
                        declared_bounds.join(" + "),
                        used_trait
                    )),
                    explanation: format!(
                        "The code uses methods from '{}' but this trait is not in the generic bounds. \
                        Add it to ensure the provider implements the required trait.", used_trait
                    ),
                });
            }
        }

        // Check for proper error handling
        if !self.patterns.bad_request.is_match(impl_content)
            && !self.patterns.server_error.is_match(impl_content)
            && !self.patterns.bad_gateway.is_match(impl_content)
        {
            if impl_content.contains("Err(") {
                issues.push(HandlerIssue {
                    code: "handler_non_sdk_error".to_string(),
                    severity: IssueSeverity::Warning,
                    message: "Handler returns errors but doesn't use qwasr_sdk error macros".to_string(),
                    line: start_line,
                    fix: Some("Use bad_request!(), server_error!(), or bad_gateway!() macros".to_string()),
                    explanation: "QWASR error macros provide proper HTTP status code mapping and structured error responses.".to_string(),
                });
            }
        }

        // Check for Reply usage
        if !self.patterns.reply_ok.is_match(impl_content) {
            issues.push(HandlerIssue {
                code: "handler_no_reply".to_string(),
                severity: IssueSeverity::Hint,
                message: "Handler doesn't use Reply constructors explicitly".to_string(),
                line: start_line,
                fix: Some("Use Reply::ok(response) or response.into()".to_string()),
                explanation: "Using Reply::ok(), Reply::created(), or .into() makes the response construction explicit.".to_string(),
            });
        }

        // Check for business logic separation
        let impl_lines = impl_content.lines().count();
        if impl_lines > 50 && !impl_content.contains("async fn ") {
            issues.push(HandlerIssue {
                code: "handler_large_impl".to_string(),
                severity: IssueSeverity::Hint,
                message: "Handler implementation is large - consider extracting business logic".to_string(),
                line: start_line,
                fix: None,
                explanation: "Large handler implementations should extract business logic into separate async functions for better testability and readability.".to_string(),
            });
        }

        issues
    }

    /// Extract provider implementations.
    fn extract_provider_impls(&self, _content: &str, lines: &[&str]) -> Vec<ProviderImplAnalysis> {
        let mut impls = Vec::new();
        let provider_traits = [
            "Config",
            "HttpRequest",
            "Publisher",
            "StateStore",
            "Identity",
            "TableStore",
        ];

        for (line_idx, line) in lines.iter().enumerate() {
            if let Some(caps) = self.patterns.provider_impl.captures(line) {
                let trait_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let impl_type = caps.get(2).map(|m| m.as_str()).unwrap_or("");

                if provider_traits.contains(&trait_name) {
                    impls.push(ProviderImplAnalysis {
                        trait_name: trait_name.to_string(),
                        impl_type: impl_type.to_string(),
                        line: line_idx + 1,
                        is_complete: true, // Simplified - would need deeper analysis
                        missing_methods: Vec::new(),
                    });
                }
            }
        }

        impls
    }

    /// Extract file context.
    fn extract_context(&self, content: &str, lines: &[&str]) -> FileContext {
        let mut qwasr_imports = Vec::new();
        let mut structs = Vec::new();
        let mut async_functions = Vec::new();
        let mut trait_impls = Vec::new();
        let mut provider_bounds_summary: HashMap<String, usize> = HashMap::new();

        // Track derives for the next struct
        let mut pending_derives: Vec<String> = Vec::new();

        for (line_idx, line) in lines.iter().enumerate() {
            // Extract derives
            if let Some(caps) = self.patterns.derive_attr.captures(line) {
                if let Some(derives) = caps.get(1) {
                    pending_derives = derives
                        .as_str()
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect();
                }
            }

            // Extract qwasr imports
            if let Some(caps) = self.patterns.use_qwasr.captures(line) {
                if let Some(items) = caps.get(1) {
                    qwasr_imports.extend(items.as_str().split(',').map(|s| s.trim().to_string()));
                } else if let Some(item) = caps.get(2) {
                    qwasr_imports.push(item.as_str().to_string());
                }
            }

            // Extract structs
            if let Some(caps) = self.patterns.struct_def.captures(line) {
                if let Some(name) = caps.get(1) {
                    let name_str = name.as_str().to_string();
                    structs.push(StructInfo {
                        name: name_str.clone(),
                        is_request: name_str.ends_with("Request"),
                        is_response: name_str.ends_with("Response"),
                        derives: std::mem::take(&mut pending_derives),
                        line: line_idx + 1,
                    });
                }
            }

            // Extract async functions
            if let Some(caps) = self.patterns.async_fn.captures(line) {
                let is_public = caps.get(1).is_some();
                let name = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                let generics_str = caps.get(3).map(|m| m.as_str()).unwrap_or("");

                let generics: Vec<String> = generics_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();

                let provider_bounds: Vec<String> = if let Some(bounds_caps) =
                    self.patterns.provider_bounds.captures(generics_str)
                {
                    let bounds = bounds_caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    bounds
                        .split('+')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                } else {
                    Vec::new()
                };

                // Update provider bounds summary
                for bound in &provider_bounds {
                    *provider_bounds_summary.entry(bound.clone()).or_insert(0) += 1;
                }

                async_functions.push(FunctionInfo {
                    name: name.to_string(),
                    is_async: true,
                    is_public,
                    generics,
                    provider_bounds,
                    line: line_idx + 1,
                });
            }

            // Extract trait impls
            if line.contains("impl") && line.contains("for") {
                if let Some(caps) = self.patterns.handler_impl.captures(line) {
                    let generics: Vec<String> = caps
                        .get(1)
                        .map(|m| m.as_str())
                        .unwrap_or("")
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();

                    trait_impls.push(TraitImplInfo {
                        trait_name: "Handler".to_string(),
                        impl_type: caps.get(3).map(|m| m.as_str()).unwrap_or("").to_string(),
                        generics,
                        line: line_idx + 1,
                    });
                }
            }
        }

        // Detect external crates from use statements
        let external_crate_re = regex::Regex::new(r"use\s+(\w+)::").unwrap();
        let external_crates: Vec<String> = external_crate_re
            .captures_iter(content)
            .filter_map(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .filter(|c| {
                ![
                    "std",
                    "core",
                    "alloc",
                    "qwasr_sdk",
                    "self",
                    "super",
                    "crate",
                ]
                .contains(&c.as_str())
            })
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        FileContext {
            qwasr_imports,
            external_crates,
            async_functions,
            structs,
            trait_impls,
            provider_bounds_summary,
        }
    }

    /// Detect issues in the code.
    fn detect_issues(
        &self,
        _content: &str,
        lines: &[&str],
        handlers: &[HandlerAnalysis],
    ) -> Vec<Issue> {
        let mut issues = Vec::new();

        // Convert handler issues to general issues
        for handler in handlers {
            for hi in &handler.issues {
                issues.push(Issue {
                    code: hi.code.clone(),
                    severity: hi.severity,
                    category: IssueCategory::HandlerPattern,
                    message: hi.message.clone(),
                    line: hi.line,
                    column_start: 0,
                    column_end: 0,
                    snippet: String::new(),
                    fix: hi.fix.clone(),
                    explanation: hi.explanation.clone(),
                    doc_reference: Some("handler-trait.md".to_string()),
                });
            }
        }

        // Check for common anti-patterns
        for (line_idx, line) in lines.iter().enumerate() {
            // Check for unwrap/expect
            if line.contains(".unwrap()") || line.contains(".expect(") {
                issues.push(Issue {
                    code: "panic_unwrap".to_string(),
                    severity: IssueSeverity::Warning,
                    category: IssueCategory::ErrorHandling,
                    message: "Avoid unwrap()/expect() in WASM handlers - use ? operator".to_string(),
                    line: line_idx + 1,
                    column_start: 0,
                    column_end: line.len(),
                    snippet: line.to_string(),
                    fix: Some("Use the ? operator with .context() for error handling".to_string()),
                    explanation: "Panics in WASM handlers cause the entire component to abort. Use proper error handling with Result types.".to_string(),
                    doc_reference: Some("error-handling.md".to_string()),
                });
            }

            // Check for anyhow::Error in public API
            if line.contains("anyhow::Error") && (line.contains("pub ") || line.contains("Result<"))
            {
                issues.push(Issue {
                    code: "anyhow_public_api".to_string(),
                    severity: IssueSeverity::Warning,
                    category: IssueCategory::ErrorHandling,
                    message: "Use qwasr_sdk::Error instead of anyhow::Error in public APIs".to_string(),
                    line: line_idx + 1,
                    column_start: 0,
                    column_end: line.len(),
                    snippet: line.to_string(),
                    fix: Some("Use qwasr_sdk::Error or qwasr_sdk::Result<T>".to_string()),
                    explanation: "qwasr_sdk::Error provides proper HTTP status code mapping. anyhow::Error should only be used internally.".to_string(),
                    doc_reference: Some("error-handling.md".to_string()),
                });
            }
        }

        issues
    }

    /// Generate suggestions based on analysis.
    fn generate_suggestions(
        &self,
        handlers: &[HandlerAnalysis],
        context: &FileContext,
        _issues: &[Issue],
    ) -> Vec<Suggestion> {
        let mut suggestions = Vec::new();

        // Suggest validation for request types without validation
        for handler in handlers {
            if !handler.issues.iter().any(|i| i.code.contains("validation")) {
                suggestions.push(Suggestion {
                    kind: SuggestionKind::AddValidation,
                    title: format!("Add input validation to {}", handler.request_type),
                    description:
                        "Consider adding validation in from_input to catch invalid input early"
                            .to_string(),
                    before: None,
                    after: Some(format!(
                        r#"fn from_input(input: Self::Input) -> Result<Self> {{
    let req: Self = serde_json::from_slice(&input)
        .context("deserializing {}")?;
    
    // Add validation
    if req.field.is_empty() {{
        return Err(bad_request!("field is required"));
    }}
    
    Ok(req)
}}"#,
                        handler.request_type
                    )),
                    priority: 3,
                });
            }
        }

        // Suggest extracting business logic for large handlers
        for handler in handlers {
            if handler.line_end - handler.line_start > 40 {
                suggestions.push(Suggestion {
                    kind: SuggestionKind::Refactor,
                    title: format!(
                        "Extract business logic from {} handler",
                        handler.request_type
                    ),
                    description: "Large handlers should delegate to separate async functions"
                        .to_string(),
                    before: None,
                    after: Some(format!(
                        r#"async fn process_{}(provider: &impl {}, req: &{}) -> Result<{}> {{
    // Business logic here
}}

// In handle():
let result = process_{}(ctx.provider, &self).await?;
Ok(Reply::ok(result))"#,
                        handler.request_type.to_lowercase(),
                        handler.provider_bounds.join(" + "),
                        handler.request_type,
                        handler.response_type,
                        handler.request_type.to_lowercase()
                    )),
                    priority: 2,
                });
            }
        }

        // Suggest adding tracing if not present
        if !context.qwasr_imports.iter().any(|i| i.contains("tracing")) {
            suggestions.push(Suggestion {
                kind: SuggestionKind::AddImplementation,
                title: "Add tracing for observability".to_string(),
                description: "Use tracing macros for logging and observability".to_string(),
                before: None,
                after: Some("use tracing::{info, warn, error, debug};".to_string()),
                priority: 4,
            });
        }

        // Suggest documentation for public types
        for s in &context.structs {
            if s.is_request || s.is_response {
                suggestions.push(Suggestion {
                    kind: SuggestionKind::AddDocumentation,
                    title: format!("Add documentation to {}", s.name),
                    description: "Public request/response types should be documented".to_string(),
                    before: None,
                    after: Some(format!(
                        r#"/// Description of {}.
/// 
/// # Fields
/// 
/// * `field` - Description of field
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct {} {{"#,
                        s.name, s.name
                    )),
                    priority: 5,
                });
            }
        }

        suggestions
    }

    /// Detect missing implementations.
    fn detect_missing(
        &self,
        handlers: &[HandlerAnalysis],
        context: &FileContext,
    ) -> Vec<MissingItem> {
        let mut missing = Vec::new();

        // Check for request types without Handler implementations
        for s in &context.structs {
            if s.is_request {
                let has_handler = handlers.iter().any(|h| h.request_type == s.name);
                if !has_handler {
                    missing.push(MissingItem {
                        kind: MissingKind::HandlerImpl,
                        name: format!("Handler for {}", s.name),
                        location: format!("After struct {} definition", s.name),
                        template: format!(
                            r#"impl<P: Config> Handler<P> for {} {{
    type Error = Error;
    type Input = Vec<u8>;
    type Output = {}Response;

    fn from_input(input: Self::Input) -> Result<Self> {{
        serde_json::from_slice(&input)
            .context("deserializing {}")
            .map_err(Into::into)
    }}

    async fn handle(self, ctx: Context<'_, P>) -> Result<Reply<Self::Output>> {{
        // TODO: Implement handler logic
        Ok(Reply::ok({}Response {{ /* fields */ }}))
    }}
}}"#,
                            s.name,
                            s.name.trim_end_matches("Request"),
                            s.name,
                            s.name.trim_end_matches("Request")
                        ),
                        reason: "Request types should implement Handler<P> for request processing"
                            .to_string(),
                    });
                }
            }
        }

        // Check for request types without corresponding response types
        for s in &context.structs {
            if s.is_request {
                let response_name = format!("{}Response", s.name.trim_end_matches("Request"));
                let has_response = context.structs.iter().any(|r| r.name == response_name);
                if !has_response {
                    missing.push(MissingItem {
                        kind: MissingKind::TypeDefinition,
                        name: response_name.clone(),
                        location: format!("Near {} definition", s.name),
                        template: format!(
                            r#"#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct {} {{
    // Add response fields
}}"#,
                            response_name
                        ),
                        reason: format!(
                            "Request type {} needs a corresponding response type",
                            s.name
                        ),
                    });
                }
            }
        }

        missing
    }

    /// Calculate a health score based on issues.
    fn calculate_health_score(&self, issues: &[Issue], handlers: &[HandlerAnalysis]) -> u8 {
        let mut score: i32 = 100;

        // Deduct for errors
        let error_count = issues
            .iter()
            .filter(|i| i.severity == IssueSeverity::Error)
            .count();
        score -= (error_count as i32) * 15;

        // Deduct for warnings
        let warning_count = issues
            .iter()
            .filter(|i| i.severity == IssueSeverity::Warning)
            .count();
        score -= (warning_count as i32) * 5;

        // Deduct for handlers without best practices
        let bad_handlers = handlers
            .iter()
            .filter(|h| !h.follows_best_practices)
            .count();
        score -= (bad_handlers as i32) * 10;

        // Bonus for complete handlers
        let complete_handlers = handlers
            .iter()
            .filter(|h| h.has_from_input && h.has_handle)
            .count();
        if complete_handlers == handlers.len() && !handlers.is_empty() {
            score += 5;
        }

        score.clamp(0, 100) as u8
    }

    /// Generate a structured JSON report for LLM consumption.
    pub fn to_json(&self, analysis: &QwasrAnalysis) -> String {
        serde_json::to_string_pretty(analysis).unwrap_or_else(|_| "{}".to_string())
    }

    /// Generate a human-readable summary for the LLM.
    pub fn to_summary(&self, analysis: &QwasrAnalysis) -> String {
        let mut summary = String::new();

        summary.push_str(&format!(
            "## QWASR Analysis Summary\n\n\
            **Health Score:** {}/100\n\
            **Is QWASR Crate:** {}\n\
            **Handlers:** {}\n\n",
            analysis.summary.health_score,
            analysis.summary.is_qwasr_crate,
            analysis.summary.handler_count
        ));

        if !analysis.handlers.is_empty() {
            summary.push_str("### Handlers\n\n");
            for h in &analysis.handlers {
                summary.push_str(&format!(
                    "- **{}** → {} (lines {}-{})\n  Bounds: {}\n  Issues: {}\n\n",
                    h.request_type,
                    h.response_type,
                    h.line_start,
                    h.line_end,
                    h.provider_bounds.join(" + "),
                    h.issues.len()
                ));
            }
        }

        if !analysis.issues.is_empty() {
            summary.push_str("### Issues\n\n");
            for issue in &analysis.issues {
                summary.push_str(&format!(
                    "- **[{:?}]** {} (line {})\n  {}\n\n",
                    issue.severity, issue.message, issue.line, issue.explanation
                ));
            }
        }

        if !analysis.suggestions.is_empty() {
            summary.push_str("### Suggestions\n\n");
            for s in &analysis.suggestions {
                summary.push_str(&format!(
                    "- **{}** (priority {})\n  {}\n\n",
                    s.title, s.priority, s.description
                ));
            }
        }

        if !analysis.missing.is_empty() {
            summary.push_str("### Missing Implementations\n\n");
            for m in &analysis.missing {
                summary.push_str(&format!("- **{}**\n  {}\n\n", m.name, m.reason));
            }
        }

        summary
    }
}

impl Default for LlmAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
