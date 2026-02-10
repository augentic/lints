//! Comprehensive QWASR pattern rules for validation.
//!
//! This module contains detailed rules for validating Handler implementations,
//! Provider trait usage, and other QWASR patterns.

use regex::Regex;
use serde::{Deserialize, Serialize};

/// A validation rule with associated metadata.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Unique identifier for the rule.
    pub id: &'static str,

    /// Human-readable name.
    pub name: &'static str,

    /// Category of the rule.
    pub category: RuleCategory,

    /// Severity of violations.
    pub severity: RuleSeverity,

    /// Detailed description.
    pub description: &'static str,

    /// Regex pattern to detect violations.
    pub pattern: Regex,

    /// Whether this is an anti-pattern (match = violation).
    pub is_anti_pattern: bool,

    /// Suggested fix template.
    pub fix_template: Option<&'static str>,

    /// Reference to documentation.
    pub doc_reference: &'static str,
}

/// Categories of rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum RuleCategory {
    /// Handler trait implementation rules.
    Handler,
    /// Provider trait usage rules.
    Provider,
    /// Context usage rules.
    Context,
    /// Error handling rules.
    Error,
    /// Reply/Response rules.
    Response,
    /// WASM compatibility rules.
    Wasm,
    /// Statelessness rules.
    Stateless,
    /// Performance rules.
    Performance,
    /// Security rules.
    Security,
    /// Strong typing rules (newtypes, enums over strings).
    StrongTyping,
    /// Caching and StateStore usage rules.
    Caching,
    /// Time handling rules.
    Time,
    /// Authentication and authorization rules.
    Auth,
}

/// Severity of rule violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RuleSeverity {
    /// Hint - suggestions for improvement.
    Hint = 0,
    /// Info - informational guidance.
    Info = 1,
    /// Warning - code may have issues.
    Warning = 2,
    /// Error - code will not work or violates critical constraints.
    Error = 3,
}

/// Collection of all QWASR rules.
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// Create a new RuleSet with all QWASR rules.
    pub fn new() -> Self {
        Self {
            rules: create_all_rules(),
        }
    }

    /// Get rules by category.
    pub fn by_category(&self, category: RuleCategory) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|r| r.category == category)
            .collect()
    }

    /// Get rules by severity.
    pub fn by_severity(&self, severity: RuleSeverity) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|r| r.severity == severity)
            .collect()
    }

    /// Get anti-pattern rules only.
    pub fn anti_patterns(&self) -> Vec<&Rule> {
        self.rules.iter().filter(|r| r.is_anti_pattern).collect()
    }

    /// Get a rule by ID.
    pub fn get(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }
}

impl Default for RuleSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Create all QWASR validation rules.
fn create_all_rules() -> Vec<Rule> {
    vec![
        // ==================== HANDLER RULES ====================
        Rule {
            id: "handler_generic_p",
            name: "Handler Generic Parameter",
            category: RuleCategory::Handler,
            severity: RuleSeverity::Error,
            description: "Handler implementations must use a generic parameter P for the provider type, enabling runtime to inject implementations.",
            pattern: Regex::new(r"impl\s+Handler<(\w+)>\s+for").unwrap(),
            is_anti_pattern: false,
            fix_template: Some("impl<P: TraitBounds> Handler<P> for RequestType"),
            doc_reference: "handler-trait.md",
        },
        Rule {
            id: "handler_async_handle",
            name: "Handle Method is Async",
            category: RuleCategory::Handler,
            severity: RuleSeverity::Error,
            description: "The handle method must be async to support asynchronous provider operations.",
            pattern: Regex::new(r"fn\s+handle\s*\(").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("async fn handle(self, ctx: Context<'_, P>) -> Result<Reply<Self::Output>>"),
            doc_reference: "handler-trait.md",
        },
        Rule {
            id: "handler_context_lifetime",
            name: "Context Lifetime Parameter",
            category: RuleCategory::Handler,
            severity: RuleSeverity::Warning,
            description: "Context should use the elided lifetime Context<'_, P> for clarity.",
            pattern: Regex::new(r"Context<P>").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Context<'_, P>"),
            doc_reference: "handler-trait.md",
        },
        
        // ==================== PROVIDER RULES ====================
        Rule {
            id: "provider_config_hardcode",
            name: "Avoid Hardcoded Config",
            category: RuleCategory::Provider,
            severity: RuleSeverity::Warning,
            description: "Configuration values should come from the Config provider, not hardcoded strings.",
            pattern: Regex::new(r#"(?:api_key|secret|password|token)\s*=\s*"[^"]+""#).unwrap(),
            is_anti_pattern: true,
            fix_template: Some(r#"let api_key = ctx.provider.get("API_KEY").ok_or_else(|| bad_request!("missing API_KEY"))?;"#),
            doc_reference: "provider-traits.md#config",
        },
        Rule {
            id: "provider_direct_http",
            name: "Avoid Direct HTTP",
            category: RuleCategory::Provider,
            severity: RuleSeverity::Error,
            description: "HTTP requests must go through HttpRequest provider, not direct clients.",
            pattern: Regex::new(r"(?:reqwest|hyper|surf|ureq)::").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use ctx.provider.fetch() from HttpRequest trait"),
            doc_reference: "wasm32.md#forbidden-crates",
        },
        Rule {
            id: "provider_bounds_minimal",
            name: "Minimal Provider Bounds",
            category: RuleCategory::Provider,
            severity: RuleSeverity::Warning,
            description: "Declare only the provider traits that are actually used in the handler.",
            pattern: Regex::new(r"P:\s*(\w+(?:\s*\+\s*\w+){4,})").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Only include traits that are actually used: P: Config + HttpRequest"),
            doc_reference: "handler-trait.md#provider-bounds",
        },
        
        // ==================== ERROR RULES ====================
        Rule {
            id: "error_generic_unwrap",
            name: "Avoid unwrap/expect",
            category: RuleCategory::Error,
            severity: RuleSeverity::Warning,
            description: "Avoid .unwrap() and .expect() as they cause panics. Use ? operator instead.",
            pattern: Regex::new(r"\.(unwrap|expect)\s*\(").unwrap(),
            is_anti_pattern: true,
            fix_template: Some(".ok_or_else(|| bad_request!(\"error message\"))?"),
            doc_reference: "error-handling.md#no-panics",
        },
        Rule {
            id: "error_panic_macro",
            name: "Avoid panic! Macro",
            category: RuleCategory::Error,
            severity: RuleSeverity::Error,
            description: "Never use panic! in WASM handlers - it aborts the entire component.",
            pattern: Regex::new(r"panic!\s*\(").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Return Err(server_error!(\"reason\")) instead"),
            doc_reference: "error-handling.md#no-panics",
        },
        Rule {
            id: "error_unreachable",
            name: "Avoid unreachable! Macro",
            category: RuleCategory::Error,
            severity: RuleSeverity::Error,
            description: "Never use unreachable! in WASM handlers.",
            pattern: Regex::new(r"unreachable!\s*\(").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use an explicit error return instead"),
            doc_reference: "error-handling.md#no-panics",
        },
        Rule {
            id: "error_todo",
            name: "Avoid todo! Macro",
            category: RuleCategory::Error,
            severity: RuleSeverity::Warning,
            description: "todo! causes panics - replace with proper error handling or implementation.",
            pattern: Regex::new(r"todo!\s*\(").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Implement the missing functionality or return an error"),
            doc_reference: "error-handling.md#no-panics",
        },
        Rule {
            id: "error_assert",
            name: "No assert! in Handlers",
            category: RuleCategory::Error,
            severity: RuleSeverity::Error,
            description: "assert! causes panics which abort WASM execution. Return errors instead.",
            pattern: Regex::new(r"assert!\s*\(").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("if !condition { return Err(bad_request!(\"validation failed\")); }"),
            doc_reference: "error-handling.md#no-panics",
        },
        Rule {
            id: "error_assert_eq",
            name: "No assert_eq! in Handlers",
            category: RuleCategory::Error,
            severity: RuleSeverity::Error,
            description: "assert_eq! causes panics which abort WASM execution. Return errors instead.",
            pattern: Regex::new(r"assert_eq!\s*\(").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("if a != b { return Err(bad_request!(\"mismatch\")); }"),
            doc_reference: "error-handling.md#no-panics",
        },
        Rule {
            id: "error_debug_assert",
            name: "No debug_assert! in Handlers",
            category: RuleCategory::Error,
            severity: RuleSeverity::Warning,
            description: "debug_assert! can cause panics in debug builds. Prefer explicit error handling.",
            pattern: Regex::new(r"debug_assert!?\s*\(").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Remove or convert to explicit error check"),
            doc_reference: "error-handling.md#no-panics",
        },
        Rule {
            id: "error_missing_context_serde",
            name: "Serde Deserialize Without Context",
            category: RuleCategory::Error,
            severity: RuleSeverity::Warning,
            description: "serde_json::from_* should use .context() for meaningful error messages.",
            pattern: Regex::new(r"serde_json::from_\w+\([^)]+\)\?").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("serde_json::from_slice(&data).context(\"deserializing MyType\").map_err(Into::into)?"),
            doc_reference: "error-handling.md#context",
        },
        Rule {
            id: "error_missing_context_parse",
            name: "Parse Without Context",
            category: RuleCategory::Error,
            severity: RuleSeverity::Warning,
            description: "Parsing operations should use .context() for meaningful error messages.",
            pattern: Regex::new(r"\.parse\(\)\?").unwrap(),
            is_anti_pattern: true,
            fix_template: Some(".parse().context(\"parsing field_name\")?"),
            doc_reference: "error-handling.md#context",
        },
        Rule {
            id: "error_dynamic_code",
            name: "Error Code Should Be Static",
            category: RuleCategory::Error,
            severity: RuleSeverity::Warning,
            description: "Error codes should be stable static strings, not dynamically generated with format!.",
            pattern: Regex::new(r"code:\s*format!\(").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("code: \"error_code\".to_string()"),
            doc_reference: "error-handling.md#error-codes",
        },
        Rule {
            id: "error_anyhow_in_handler",
            name: "Use qwasr_sdk::Error Not anyhow::Error",
            category: RuleCategory::Error,
            severity: RuleSeverity::Warning,
            description: "Handler Error type should be qwasr_sdk::Error for proper HTTP status mapping, not anyhow::Error.",
            pattern: Regex::new(r"type\s+Error\s*=\s*anyhow::Error").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("type Error = qwasr_sdk::Error;"),
            doc_reference: "error-handling.md#error-type",
        },
        
        // ==================== WASM RULES ====================
        Rule {
            id: "wasm_std_fs",
            name: "No std::fs",
            category: RuleCategory::Wasm,
            severity: RuleSeverity::Error,
            description: "std::fs is not available in WASM32. Use provider abstractions.",
            pattern: Regex::new(r"std::fs::").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use StateStore or TableStore provider"),
            doc_reference: "wasm32.md#forbidden-apis",
        },
        Rule {
            id: "wasm_std_net",
            name: "No std::net",
            category: RuleCategory::Wasm,
            severity: RuleSeverity::Error,
            description: "std::net is not available in WASM32. Use HttpRequest provider.",
            pattern: Regex::new(r"std::net::").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use HttpRequest provider for network access"),
            doc_reference: "wasm32.md#forbidden-apis",
        },
        Rule {
            id: "wasm_std_thread",
            name: "No std::thread",
            category: RuleCategory::Wasm,
            severity: RuleSeverity::Error,
            description: "std::thread is not available in WASM32. Use async/await.",
            pattern: Regex::new(r"std::thread::").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use async/await for concurrency"),
            doc_reference: "wasm32.md#forbidden-apis",
        },
        Rule {
            id: "wasm_std_env",
            name: "No std::env",
            category: RuleCategory::Wasm,
            severity: RuleSeverity::Error,
            description: "std::env is not available in WASM32. Use Config provider.",
            pattern: Regex::new(r"std::env::").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use Config provider for environment variables"),
            doc_reference: "wasm32.md#forbidden-apis",
        },
        Rule {
            id: "wasm_std_process",
            name: "No std::process",
            category: RuleCategory::Wasm,
            severity: RuleSeverity::Error,
            description: "std::process is not available in WASM32.",
            pattern: Regex::new(r"std::process::").unwrap(),
            is_anti_pattern: true,
            fix_template: None,
            doc_reference: "wasm32.md#forbidden-apis",
        },
        Rule {
            id: "wasm_std_time_instant",
            name: "No std::time::Instant",
            category: RuleCategory::Wasm,
            severity: RuleSeverity::Error,
            description: "std::time::Instant is not available in WASM32.",
            pattern: Regex::new(r"std::time::Instant").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use chrono::Utc::now() for time"),
            doc_reference: "wasm32.md#forbidden-apis",
        },
        Rule {
            id: "wasm_64bit_integer",
            name: "Prefer 32-bit Integers",
            category: RuleCategory::Wasm,
            severity: RuleSeverity::Warning,
            description: "WASM32 is a 32-bit environment. i64/u64 operations are emulated and slower.",
            pattern: Regex::new(r":\s*[iu]64\b").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use i32/u32 if the value range allows"),
            doc_reference: "wasm32.md#performance",
        },
        Rule {
            id: "wasm_128bit_integer",
            name: "Avoid 128-bit Integers",
            category: RuleCategory::Wasm,
            severity: RuleSeverity::Warning,
            description: "WASM32 does not natively support 128-bit integers. i128/u128 are heavily emulated and slow.",
            pattern: Regex::new(r":\s*[iu]128\b").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use smaller integer types"),
            doc_reference: "wasm32.md#performance",
        },
        Rule {
            id: "wasm_isize_usize",
            name: "Avoid isize/usize for Data",
            category: RuleCategory::Wasm,
            severity: RuleSeverity::Hint,
            description: "isize/usize vary by platform. Use explicit i32/u32 for data that crosses API boundaries.",
            pattern: Regex::new(r":\s*[iu]size\b").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use i32/u32 for API data, keep usize only for indexing"),
            doc_reference: "wasm32.md#portability",
        },
        
        // ==================== STATELESS RULES ====================
        Rule {
            id: "stateless_static_mut",
            name: "No static mut",
            category: RuleCategory::Stateless,
            severity: RuleSeverity::Error,
            description: "static mut creates global mutable state. QWASR handlers must be stateless.",
            pattern: Regex::new(r"static\s+mut\s+").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use StateStore provider for state persistence"),
            doc_reference: "guardrails.md#statelessness",
        },
        Rule {
            id: "stateless_lazy_static",
            name: "No lazy_static",
            category: RuleCategory::Stateless,
            severity: RuleSeverity::Error,
            description: "lazy_static creates global state. Not allowed in QWASR.",
            pattern: Regex::new(r"lazy_static!\s*\{").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Pass state through Context or use StateStore"),
            doc_reference: "guardrails.md#forbidden-crates",
        },
        Rule {
            id: "stateless_once_cell",
            name: "No OnceCell/OnceLock",
            category: RuleCategory::Stateless,
            severity: RuleSeverity::Error,
            description: "OnceCell/OnceLock create global state. Not allowed in QWASR.",
            pattern: Regex::new(r"(?:OnceCell|OnceLock)").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use StateStore provider"),
            doc_reference: "guardrails.md#forbidden-crates",
        },
        Rule {
            id: "stateless_lazy_lock",
            name: "No LazyLock",
            category: RuleCategory::Stateless,
            severity: RuleSeverity::Error,
            description: "LazyLock (std 1.80+) creates global state which is forbidden in QWASR WASM.",
            pattern: Regex::new(r"LazyLock\s*<").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use Config provider trait instead"),
            doc_reference: "guardrails.md#forbidden-crates",
        },
        Rule {
            id: "stateless_arc_mutex",
            name: "Avoid Arc<Mutex>",
            category: RuleCategory::Stateless,
            severity: RuleSeverity::Warning,
            description: "Arc<Mutex<T>> suggests shared mutable state. Use StateStore instead.",
            pattern: Regex::new(r"Arc\s*<\s*(?:Mutex|RwLock)").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use StateStore provider for shared state"),
            doc_reference: "guardrails.md#statelessness",
        },
        Rule {
            id: "stateless_mutex",
            name: "Avoid Mutex/RwLock",
            category: RuleCategory::Stateless,
            severity: RuleSeverity::Warning,
            description: "Mutex and RwLock create shared mutable state. WASM is single-threaded.",
            pattern: Regex::new(r"(?:std::sync::)?(?:Mutex|RwLock)\s*<").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use StateStore provider for shared state"),
            doc_reference: "guardrails.md#statelessness",
        },
        
        // ==================== PERFORMANCE RULES ====================
        Rule {
            id: "perf_clone_in_loop",
            name: "Avoid Clone in Loop",
            category: RuleCategory::Performance,
            severity: RuleSeverity::Hint,
            description: "Cloning inside loops may be inefficient. Consider borrowing.",
            pattern: Regex::new(r"for\s+[^{]+\{[^}]*\.clone\s*\(").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use references or move ownership"),
            doc_reference: "ms-pragmatic-rust.md",
        },
        Rule {
            id: "perf_string_add",
            name: "Prefer format! Over String Concatenation",
            category: RuleCategory::Performance,
            severity: RuleSeverity::Hint,
            description: "String concatenation with + is inefficient. Use format! or push_str.",
            pattern: Regex::new(r"String::new\s*\(\s*\)\s*\+").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("format!(\"{}{}\", a, b)"),
            doc_reference: "ms-pragmatic-rust.md",
        },
        Rule {
            id: "perf_unbounded_query",
            name: "Query Without Limit",
            category: RuleCategory::Performance,
            severity: RuleSeverity::Warning,
            description: "Database queries should have a limit to prevent unbounded result sets.",
            pattern: Regex::new(r"ctx\.provider\.query\([^)]+\)\.await").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Add LIMIT clause or use .limit() method"),
            doc_reference: "tablestore-handler.md#limits",
        },
        Rule {
            id: "perf_format_in_loop",
            name: "Avoid format! in Loops",
            category: RuleCategory::Performance,
            severity: RuleSeverity::Hint,
            description: "format! allocates - consider preallocating strings outside loops.",
            pattern: Regex::new(r"for\s+\w+\s+in[^{]*\{[^}]*format!\(").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Preallocate String and use push_str"),
            doc_reference: "ms-pragmatic-rust.md#allocations",
        },
        Rule {
            id: "perf_collect_count",
            name: "Use Iterator::count Instead of collect().len()",
            category: RuleCategory::Performance,
            severity: RuleSeverity::Hint,
            description: "Use .count() instead of .collect::<Vec<_>>().len() to avoid allocation.",
            pattern: Regex::new(r"\.collect\(\)\.len\(\)").unwrap(),
            is_anti_pattern: true,
            fix_template: Some(".count()"),
            doc_reference: "ms-pragmatic-rust.md#iterators",
        },
        
        // ==================== SECURITY RULES ====================
        Rule {
            id: "security_hardcoded_secret",
            name: "No Hardcoded Secrets",
            category: RuleCategory::Security,
            severity: RuleSeverity::Error,
            description: "Secrets must come from Config provider, never hardcoded.",
            pattern: Regex::new(r#"(?:password|secret|api_key|token)\s*:\s*"[a-zA-Z0-9]+"#).unwrap(),
            is_anti_pattern: true,
            fix_template: Some("let secret = ctx.provider.get(\"SECRET_KEY\")?;"),
            doc_reference: "guardrails.md#security",
        },
        Rule {
            id: "security_sql_concat",
            name: "Avoid SQL String Concatenation",
            category: RuleCategory::Security,
            severity: RuleSeverity::Error,
            description: "Never concatenate SQL strings - use parameterized queries.",
            pattern: Regex::new(r#"format!\s*\(\s*"(?:SELECT|INSERT|UPDATE|DELETE)[^"]*\{\}"#).unwrap(),
            is_anti_pattern: true,
            fix_template: Some(r#"ctx.provider.query("SELECT * FROM t WHERE id = $1", &[("$1", id)])"#),
            doc_reference: "guardrails.md#security",
        },
        
        // ==================== STRONG TYPING RULES ====================
        Rule {
            id: "type_primitive_string_id",
            name: "Use Newtypes for IDs",
            category: RuleCategory::StrongTyping,
            severity: RuleSeverity::Warning,
            description: "Use newtype wrappers for identifiers instead of raw String.",
            pattern: Regex::new(r"pub\s+(?:id|\w+_id)\s*:\s*String").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("pub struct VehicleId(pub String);"),
            doc_reference: "ms-pragmatic-rust.md#newtypes",
        },
        Rule {
            id: "type_string_match",
            name: "Use Enums Instead of String Matching",
            category: RuleCategory::StrongTyping,
            severity: RuleSeverity::Hint,
            description: "Replace string literal matching with typed enums for compile-time safety.",
            pattern: Regex::new(r#"match\s+\w+\.as_str\(\)\s*\{[^}]*"[^"]+"\s*=>"#).unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Define an enum with #[derive(Deserialize)]"),
            doc_reference: "ms-pragmatic-rust.md#enums",
        },
        Rule {
            id: "type_raw_coordinates",
            name: "Use Newtypes for Coordinates",
            category: RuleCategory::StrongTyping,
            severity: RuleSeverity::Info,
            description: "Use newtype wrappers for latitude/longitude instead of raw f64.",
            pattern: Regex::new(r"pub\s+(?:lat(?:itude)?|lon(?:gitude)?)\s*:\s*f(?:32|64)").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("pub struct Latitude(pub f64);"),
            doc_reference: "ms-pragmatic-rust.md#newtypes",
        },
        
        // ==================== TIME RULES ====================
        Rule {
            id: "time_system_time_now",
            name: "No SystemTime::now()",
            category: RuleCategory::Time,
            severity: RuleSeverity::Error,
            description: "SystemTime::now() is unreliable in WASM32. Use chrono::Utc::now() instead.",
            pattern: Regex::new(r"SystemTime::now\(\)").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("chrono::Utc::now()"),
            doc_reference: "wasm32.md#time",
        },
        Rule {
            id: "time_instant_duration",
            name: "No Instant for Elapsed Time",
            category: RuleCategory::Time,
            severity: RuleSeverity::Error,
            description: "Instant::now() and elapsed() are not available in WASM32.",
            pattern: Regex::new(r"Instant::now\(\)\.elapsed\(\)").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use chrono timestamps for elapsed time calculations"),
            doc_reference: "wasm32.md#time",
        },
        
        // ==================== AUTH RULES ====================
        Rule {
            id: "auth_hardcoded_bearer",
            name: "No Hardcoded Bearer Tokens",
            category: RuleCategory::Auth,
            severity: RuleSeverity::Error,
            description: "Bearer tokens must come from Identity::access_token(), not hardcoded strings.",
            pattern: Regex::new(r#"Bearer\s+[A-Za-z0-9._-]{20,}"#).unwrap(),
            is_anti_pattern: true,
            fix_template: Some("let token = ctx.provider.access_token(\"service\").await?;"),
            doc_reference: "provider-traits.md#identity",
        },
        Rule {
            id: "auth_authorization_without_identity",
            name: "Authorization Header Requires Identity Trait",
            category: RuleCategory::Auth,
            severity: RuleSeverity::Warning,
            description: "If using Authorization header, the handler should include Identity trait bound.",
            pattern: Regex::new(r#"\("Authorization"\s*,"#).unwrap(),
            is_anti_pattern: false,
            fix_template: Some("Add Identity to handler bounds: P: Config + HttpRequest + Identity"),
            doc_reference: "provider-traits.md#identity",
        },
        
        // ==================== CACHING RULES ====================
        Rule {
            id: "cache_missing_ttl",
            name: "Cache Set Without TTL",
            category: RuleCategory::Caching,
            severity: RuleSeverity::Warning,
            description: "StateStore::set should include a TTL to prevent unbounded cache growth.",
            pattern: Regex::new(r"ctx\.provider\.set\([^)]*,\s*None\s*\)\.await").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("ctx.provider.set(key, value, Some(Duration::from_secs(3600))).await?"),
            doc_reference: "cache-handler.md#ttl",
        },
        
        // ==================== FORBIDDEN IMPORTS ====================
        Rule {
            id: "forbidden_tokio",
            name: "No Tokio Runtime",
            category: RuleCategory::Wasm,
            severity: RuleSeverity::Error,
            description: "Tokio runtime is not available in WASM32. WASI provides the executor.",
            pattern: Regex::new(r"use\s+tokio\b").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use async/await without explicit runtime"),
            doc_reference: "wasm32.md#forbidden-crates",
        },
        Rule {
            id: "forbidden_async_std",
            name: "No async-std Runtime",
            category: RuleCategory::Wasm,
            severity: RuleSeverity::Error,
            description: "async-std runtime is not available in WASM32. WASI provides the executor.",
            pattern: Regex::new(r"use\s+async_std\b").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use async/await without explicit runtime"),
            doc_reference: "wasm32.md#forbidden-crates",
        },
        Rule {
            id: "forbidden_rayon",
            name: "No Rayon Parallelism",
            category: RuleCategory::Wasm,
            severity: RuleSeverity::Error,
            description: "Rayon is not available in WASM32. WASM is single-threaded.",
            pattern: Regex::new(r"use\s+rayon\b").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use sequential iterators"),
            doc_reference: "wasm32.md#forbidden-crates",
        },
        
        // ==================== PRINT STATEMENTS ====================
        Rule {
            id: "println_debug",
            name: "Avoid println!/eprintln!",
            category: RuleCategory::Performance,
            severity: RuleSeverity::Hint,
            description: "println!/eprintln! may not be visible in WASM32. Use tracing macros.",
            pattern: Regex::new(r"(?:println|eprintln|dbg)!\s*\(").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use tracing macros: info!, warn!, error!, debug!"),
            doc_reference: "observability.md#tracing",
        },
        
        // ==================== ADDITIONAL HANDLER RULES ====================
        Rule {
            id: "handler_from_input_result",
            name: "from_input Returns Result",
            category: RuleCategory::Handler,
            severity: RuleSeverity::Error,
            description: "The from_input method must return Result<Self> to properly handle deserialization errors.",
            pattern: Regex::new(r"fn\s+from_input\([^)]*\)\s*->").unwrap(),
            is_anti_pattern: false,
            fix_template: Some("fn from_input(input: Self::Input) -> Result<Self>"),
            doc_reference: "handler-trait.md",
        },
        Rule {
            id: "handler_serde_deserialize",
            name: "Request Derives Deserialize",
            category: RuleCategory::Handler,
            severity: RuleSeverity::Error,
            description: "Request types must derive Deserialize for from_input parsing.",
            pattern: Regex::new(r"#\[derive\([^)]*Deserialize[^)]*\)\]\s*(?:pub\s+)?struct\s+\w+Request").unwrap(),
            is_anti_pattern: false,
            fix_template: Some("#[derive(Clone, Debug, Deserialize, Serialize)]"),
            doc_reference: "handler-trait.md",
        },
        Rule {
            id: "handler_output_type",
            name: "Handler Output Type Definition",
            category: RuleCategory::Handler,
            severity: RuleSeverity::Error,
            description: "Handler must define type Output = ResponseType; to specify the response type.",
            pattern: Regex::new(r"impl.*Handler.*for").unwrap(),
            is_anti_pattern: false,
            fix_template: Some("type Output = ResponseType;"),
            doc_reference: "handler-trait.md",
        },
        Rule {
            id: "handler_error_type",
            name: "Handler Error Type",
            category: RuleCategory::Handler,
            severity: RuleSeverity::Warning,
            description: "Handler should use type Error = qwasr_sdk::Error for proper HTTP status mapping.",
            pattern: Regex::new(r"type\s+Error\s*=").unwrap(),
            is_anti_pattern: false,
            fix_template: Some("type Error = Error;"),
            doc_reference: "error-handling.md",
        },
        Rule {
            id: "handler_input_vec_u8",
            name: "Handler Input Type",
            category: RuleCategory::Handler,
            severity: RuleSeverity::Info,
            description: "Handler Input is typically Vec<u8> for raw bytes from HTTP body.",
            pattern: Regex::new(r"type\s+Input\s*=\s*Vec<u8>").unwrap(),
            is_anti_pattern: false,
            fix_template: Some("type Input = Vec<u8>;"),
            doc_reference: "handler-trait.md",
        },
        
        // ==================== ADDITIONAL PROVIDER RULES ====================
        Rule {
            id: "provider_config_get",
            name: "Config::get Usage",
            category: RuleCategory::Provider,
            severity: RuleSeverity::Info,
            description: "Use Config trait to retrieve configuration values. Returns Option<String>.",
            pattern: Regex::new(r#"ctx\.provider\.get\s*\(\s*"[^"]+"\s*\)"#).unwrap(),
            is_anti_pattern: false,
            fix_template: Some("let value = ctx.provider.get(\"KEY\").ok_or_else(|| bad_request!(\"missing config\"))?;"),
            doc_reference: "provider-traits.md#config",
        },
        Rule {
            id: "provider_http_request_fetch",
            name: "HttpRequest::fetch Usage",
            category: RuleCategory::Provider,
            severity: RuleSeverity::Info,
            description: "Use HttpRequest trait for external HTTP calls with proper request building.",
            pattern: Regex::new(r"ctx\.provider\.fetch\s*\([^)]*\)\.await").unwrap(),
            is_anti_pattern: false,
            fix_template: Some(r#"let response = ctx.provider.fetch(Request { method: "GET", url: &url, headers: &[], body: None }).await?;"#),
            doc_reference: "provider-traits.md#httprequest",
        },
        Rule {
            id: "provider_publisher_send",
            name: "Publisher::send Usage",
            category: RuleCategory::Provider,
            severity: RuleSeverity::Info,
            description: "Use Publisher trait to send events/messages to external systems.",
            pattern: Regex::new(r"ctx\.provider\.send\s*\([^)]*\)\.await").unwrap(),
            is_anti_pattern: false,
            fix_template: Some(r#"ctx.provider.send("topic", serde_json::to_vec(&event)?.as_slice()).await?;"#),
            doc_reference: "provider-traits.md#publisher",
        },
        Rule {
            id: "provider_statestore_get",
            name: "StateStore::get Usage",
            category: RuleCategory::Provider,
            severity: RuleSeverity::Info,
            description: "Use StateStore trait for key-value state access.",
            pattern: Regex::new(r#"ctx\.provider\.get\s*\(\s*(?:&?\w+|"[^"]+")\s*\)\.await"#).unwrap(),
            is_anti_pattern: false,
            fix_template: Some("let value = ctx.provider.get(key).await?;"),
            doc_reference: "provider-traits.md#statestore",
        },
        Rule {
            id: "provider_statestore_set",
            name: "StateStore::set Usage",
            category: RuleCategory::Provider,
            severity: RuleSeverity::Info,
            description: "Use StateStore::set for storing state with optional TTL.",
            pattern: Regex::new(r"ctx\.provider\.set\s*\([^)]*\)\.await").unwrap(),
            is_anti_pattern: false,
            fix_template: Some("ctx.provider.set(key, value.as_bytes(), Some(ttl)).await?;"),
            doc_reference: "provider-traits.md#statestore",
        },
        Rule {
            id: "provider_tablestore_query",
            name: "TableStore::query Usage",
            category: RuleCategory::Provider,
            severity: RuleSeverity::Info,
            description: "Use TableStore for structured data queries.",
            pattern: Regex::new(r"ctx\.provider\.query\s*\([^)]*\)\.await").unwrap(),
            is_anti_pattern: false,
            fix_template: Some(r#"let rows = ctx.provider.query("SELECT * FROM table WHERE id = $1", &[("$1", id)]).await?;"#),
            doc_reference: "provider-traits.md#tablestore",
        },
        Rule {
            id: "provider_tablestore_exec",
            name: "TableStore::exec Usage",
            category: RuleCategory::Provider,
            severity: RuleSeverity::Info,
            description: "Use TableStore::exec for data mutations.",
            pattern: Regex::new(r"ctx\.provider\.exec\s*\([^)]*\)\.await").unwrap(),
            is_anti_pattern: false,
            fix_template: Some(r#"ctx.provider.exec("INSERT INTO table (id, data) VALUES ($1, $2)", &[("$1", id), ("$2", data)]).await?;"#),
            doc_reference: "provider-traits.md#tablestore",
        },
        Rule {
            id: "provider_identity_token",
            name: "Identity::access_token Usage",
            category: RuleCategory::Provider,
            severity: RuleSeverity::Info,
            description: "Use Identity trait to get OAuth/auth tokens for external services.",
            pattern: Regex::new(r"ctx\.provider\.access_token\s*\([^)]*\)\.await").unwrap(),
            is_anti_pattern: false,
            fix_template: Some(r#"let token = ctx.provider.access_token("service-name").await?;"#),
            doc_reference: "provider-traits.md#identity",
        },
        
        // ==================== ADDITIONAL CONTEXT RULES ====================
        Rule {
            id: "context_owner",
            name: "Context Owner Access",
            category: RuleCategory::Context,
            severity: RuleSeverity::Info,
            description: "ctx.owner provides the authenticated user/tenant identifier.",
            pattern: Regex::new(r"ctx\.owner").unwrap(),
            is_anti_pattern: false,
            fix_template: None,
            doc_reference: "handler-trait.md#context",
        },
        Rule {
            id: "context_headers",
            name: "Context Headers Access",
            category: RuleCategory::Context,
            severity: RuleSeverity::Info,
            description: "ctx.headers provides access to HTTP request headers.",
            pattern: Regex::new(r"ctx\.headers").unwrap(),
            is_anti_pattern: false,
            fix_template: Some("ctx.headers.get(\"X-Custom-Header\")"),
            doc_reference: "handler-trait.md#context",
        },
        
        // ==================== ADDITIONAL ERROR RULES ====================
        Rule {
            id: "error_bad_request",
            name: "bad_request! Macro",
            category: RuleCategory::Error,
            severity: RuleSeverity::Info,
            description: "Use bad_request!() for client errors (400). Takes format string.",
            pattern: Regex::new(r"bad_request!\s*\(").unwrap(),
            is_anti_pattern: false,
            fix_template: Some(r#"bad_request!("validation failed: {}", reason)"#),
            doc_reference: "error-handling.md#error-macros",
        },
        Rule {
            id: "error_server_error",
            name: "server_error! Macro",
            category: RuleCategory::Error,
            severity: RuleSeverity::Info,
            description: "Use server_error!() for internal errors (500). Takes format string.",
            pattern: Regex::new(r"server_error!\s*\(").unwrap(),
            is_anti_pattern: false,
            fix_template: Some(r#"server_error!("internal error: {}", err)"#),
            doc_reference: "error-handling.md#error-macros",
        },
        Rule {
            id: "error_bad_gateway",
            name: "bad_gateway! Macro",
            category: RuleCategory::Error,
            severity: RuleSeverity::Info,
            description: "Use bad_gateway!() for upstream service errors (502). Takes format string.",
            pattern: Regex::new(r"bad_gateway!\s*\(").unwrap(),
            is_anti_pattern: false,
            fix_template: Some(r#"bad_gateway!("upstream error: {}", err)"#),
            doc_reference: "error-handling.md#error-macros",
        },
        Rule {
            id: "error_anyhow_context",
            name: "anyhow::Context Usage",
            category: RuleCategory::Error,
            severity: RuleSeverity::Info,
            description: "Use .context() to add context to errors before propagating with ?.",
            pattern: Regex::new(r#"\.context\s*\(\s*"[^"]+"\s*\)"#).unwrap(),
            is_anti_pattern: false,
            fix_template: Some(".context(\"descriptive error message\")"),
            doc_reference: "error-handling.md#context",
        },
        Rule {
            id: "error_impl_from_required",
            name: "Domain Error Missing From impl",
            category: RuleCategory::Error,
            severity: RuleSeverity::Info,
            description: "Domain error enums should implement From<DomainError> for qwasr_sdk::Error.",
            pattern: Regex::new(r"#\[derive\([^)]*Error[^)]*\)\]\s*pub\s+enum\s+(\w+Error)").unwrap(),
            is_anti_pattern: false,
            fix_template: Some("impl From<DomainError> for qwasr_sdk::Error { ... }"),
            doc_reference: "error-handling.md#domain-errors",
        },
        Rule {
            id: "error_map_to_bad_request",
            name: "Map Parsing Errors to BadRequest",
            category: RuleCategory::Error,
            severity: RuleSeverity::Info,
            description: "Parsing/validation errors should map to bad_request! (400), not server_error! (500).",
            pattern: Regex::new(r"(?:parse|deserialize|validate).*server_error!").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use bad_request!(\"invalid input: {}\", err) for client errors"),
            doc_reference: "error-handling.md#status-codes",
        },
        Rule {
            id: "error_map_to_bad_gateway",
            name: "Map Upstream Errors to BadGateway",
            category: RuleCategory::Error,
            severity: RuleSeverity::Info,
            description: "External service/API errors should map to bad_gateway! (502), not server_error! (500).",
            pattern: Regex::new(r"(?:fetch|http|api|upstream).*server_error!").unwrap(),
            is_anti_pattern: true,
            fix_template: Some("Use bad_gateway!(\"upstream failed: {}\", err) for external service errors"),
            doc_reference: "error-handling.md#status-codes",
        },
        Rule {
            id: "error_result_map_err",
            name: "Use map_err for Error Conversion",
            category: RuleCategory::Error,
            severity: RuleSeverity::Info,
            description: "Use .map_err(Into::into) or .map_err(|e| bad_request!(...)) for explicit error conversion.",
            pattern: Regex::new(r"\.map_err\((?:Into::into|\|\w+\|)").unwrap(),
            is_anti_pattern: false,
            fix_template: None,
            doc_reference: "error-handling.md#conversion",
        },
        
        // ==================== ADDITIONAL RESPONSE RULES ====================
        Rule {
            id: "response_reply_ok",
            name: "Reply::ok Usage",
            category: RuleCategory::Response,
            severity: RuleSeverity::Info,
            description: "Use Reply::ok(response) for successful responses (200 OK).",
            pattern: Regex::new(r"Reply::ok\s*\(").unwrap(),
            is_anti_pattern: false,
            fix_template: Some("Reply::ok(ResponseType { /* fields */ })"),
            doc_reference: "handler-trait.md#reply",
        },
        Rule {
            id: "response_reply_created",
            name: "Reply::created Usage",
            category: RuleCategory::Response,
            severity: RuleSeverity::Info,
            description: "Use Reply::created(response) for resource creation (201 Created).",
            pattern: Regex::new(r"Reply::created\s*\(").unwrap(),
            is_anti_pattern: false,
            fix_template: Some("Reply::created(ResponseType { id })"),
            doc_reference: "handler-trait.md#reply",
        },
        Rule {
            id: "response_reply_accepted",
            name: "Reply::accepted Usage",
            category: RuleCategory::Response,
            severity: RuleSeverity::Info,
            description: "Use Reply::accepted(response) for async processing (202 Accepted).",
            pattern: Regex::new(r"Reply::accepted\s*\(").unwrap(),
            is_anti_pattern: false,
            fix_template: Some("Reply::accepted(ResponseType { job_id })"),
            doc_reference: "handler-trait.md#reply",
        },
        Rule {
            id: "response_into",
            name: "Response Into Reply",
            category: RuleCategory::Response,
            severity: RuleSeverity::Info,
            description: "Response types can use .into() to convert to Reply.",
            pattern: Regex::new(r"Ok\s*\([^)]+\.into\s*\(\s*\)\s*\)").unwrap(),
            is_anti_pattern: false,
            fix_template: Some("Ok(response.into())"),
            doc_reference: "handler-trait.md#reply",
        },
        
        // ==================== ADDITIONAL CACHING RULES ====================
        Rule {
            id: "cache_key_format",
            name: "Cache Key Consistent Format",
            category: RuleCategory::Caching,
            severity: RuleSeverity::Info,
            description: "Cache keys should follow entity-{id} pattern for consistency and debuggability.",
            pattern: Regex::new(r#"StateStore::get\(provider,\s*&format!\("[^{]+\{\}""#).unwrap(),
            is_anti_pattern: false,
            fix_template: Some("format!(\"entity-{}\", id)"),
            doc_reference: "cache-handler.md#keys",
        },
    ]
}
