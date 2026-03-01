//! Comprehensive Omnia pattern rules for validation.
//!
//! This module contains detailed rules for validating Handler implementations,
//! Provider trait usage, and other Omnia patterns.

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

impl RuleCategory {
    /// All rule categories.
    pub const ALL: &[RuleCategory] = &[
        RuleCategory::Handler,
        RuleCategory::Provider,
        RuleCategory::Context,
        RuleCategory::Error,
        RuleCategory::Response,
        RuleCategory::Wasm,
        RuleCategory::Stateless,
        RuleCategory::Performance,
        RuleCategory::Security,
        RuleCategory::StrongTyping,
        RuleCategory::Caching,
        RuleCategory::Time,
        RuleCategory::Auth,
    ];

    /// Convert a snake_case string key to a `RuleCategory`.
    ///
    /// This is used when parsing `[lints.omnia]` tables from `Cargo.toml`.
    pub fn from_key(s: &str) -> Option<RuleCategory> {
        match s {
            "handler" => Some(RuleCategory::Handler),
            "provider" => Some(RuleCategory::Provider),
            "context" => Some(RuleCategory::Context),
            "error" => Some(RuleCategory::Error),
            "response" => Some(RuleCategory::Response),
            "wasm" => Some(RuleCategory::Wasm),
            "stateless" => Some(RuleCategory::Stateless),
            "performance" => Some(RuleCategory::Performance),
            "security" => Some(RuleCategory::Security),
            "strong_typing" => Some(RuleCategory::StrongTyping),
            "caching" => Some(RuleCategory::Caching),
            "time" => Some(RuleCategory::Time),
            "auth" => Some(RuleCategory::Auth),
            _ => None,
        }
    }

    /// Return the snake_case key for this category, as used in `Cargo.toml`.
    pub fn as_key(&self) -> &'static str {
        match self {
            RuleCategory::Handler => "handler",
            RuleCategory::Provider => "provider",
            RuleCategory::Context => "context",
            RuleCategory::Error => "error",
            RuleCategory::Response => "response",
            RuleCategory::Wasm => "wasm",
            RuleCategory::Stateless => "stateless",
            RuleCategory::Performance => "performance",
            RuleCategory::Security => "security",
            RuleCategory::StrongTyping => "strong_typing",
            RuleCategory::Caching => "caching",
            RuleCategory::Time => "time",
            RuleCategory::Auth => "auth",
        }
    }
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

/// The configured lint level from a `Cargo.toml` `[lints.omnia]` table.
///
/// These mirror the standard Cargo lint levels:
/// `"allow"`, `"warn"`, `"deny"`, and `"forbid"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LintLevel {
    /// Suppress the lint entirely.
    Allow,
    /// Report as a warning.
    Warn,
    /// Report as an error.
    Deny,
    /// Report as an error (cannot be overridden downstream).
    Forbid,
}

impl LintLevel {
    /// Parse a Cargo.toml lint level string.
    ///
    /// Accepts both plain strings (`"warn"`) and the table form will be handled
    /// by the config parser.
    pub fn parse(s: &str) -> Option<LintLevel> {
        match s {
            "allow" => Some(LintLevel::Allow),
            "warn" => Some(LintLevel::Warn),
            "deny" => Some(LintLevel::Deny),
            "forbid" => Some(LintLevel::Forbid),
            _ => None,
        }
    }

    /// Convert to the closest `RuleSeverity` for filtering.
    ///
    /// `Allow` maps to `None` (suppressed), the rest map to a severity.
    pub fn to_severity(self) -> Option<RuleSeverity> {
        match self {
            LintLevel::Allow => None,
            LintLevel::Warn => Some(RuleSeverity::Warning),
            LintLevel::Deny | LintLevel::Forbid => Some(RuleSeverity::Error),
        }
    }
}

/// Collection of all Omnia rules.
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// Create a new RuleSet with all Omnia rules.
    pub fn new() -> Self {
        Self {
            rules: create_all_rules(),
        }
    }

    /// Get rules by category.
    pub fn by_category(&self, category: RuleCategory) -> Vec<&Rule> {
        self.rules.iter().filter(|r| r.category == category).collect()
    }

    /// Get rules by severity.
    pub fn by_severity(&self, severity: RuleSeverity) -> Vec<&Rule> {
        self.rules.iter().filter(|r| r.severity == severity).collect()
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

/// Construct a [`Rule`] with reduced boilerplate.
///
/// `anti` defaults to `true`, `fix` and `doc` are optional.
macro_rules! rule {
    (
        id: $id:expr,
        name: $name:expr,
        category: $cat:ident,
        severity: $sev:ident,
        description: $desc:expr,
        pattern: $pat:expr
        $(, anti: $anti:expr)?
        $(, fix: $fix:expr)?
        $(, doc: $doc:expr)?
        $(,)?
    ) => {
        Rule {
            id: $id,
            name: $name,
            category: RuleCategory::$cat,
            severity: RuleSeverity::$sev,
            description: $desc,
            pattern: Regex::new($pat).expect(concat!("valid regex for rule ", $id)),
            is_anti_pattern: rule!(@anti $($anti)?),
            fix_template: rule!(@opt $($fix)?),
            doc_reference: rule!(@doc $($doc)?),
        }
    };
    // Default: anti-pattern is true
    (@anti) => { true };
    (@anti $val:expr) => { $val };
    // Default: no fix
    (@opt) => { None };
    (@opt $val:expr) => { Some($val) };
    // Default doc reference
    (@doc) => { "" };
    (@doc $val:expr) => { $val };
}

/// Create all Omnia validation rules.
fn create_all_rules() -> Vec<Rule> {
    vec![
        // ==================== HANDLER RULES ====================
        rule! {
            id: "handler_async_handle",
            name: "Handle Method is Async",
            category: Handler,
            severity: Error,
            description: "The handle method must be async to support asynchronous provider operations.",
            pattern: r"^\s*fn\s+handle\s*\(",
            fix: "async fn handle(self, ctx: Context<'_, P>) -> Result<Reply<Self::Output>>",
            doc: "handler-trait.md",
        },
        rule! {
            id: "handler_context_lifetime",
            name: "Context Lifetime Parameter",
            category: Handler,
            severity: Warning,
            description: "Context should use the elided lifetime Context<'_, P> for clarity.",
            pattern: r"Context<P>",
            fix: "Context<'_, P>",
            doc: "handler-trait.md",
        },
        // ==================== PROVIDER RULES ====================
        rule! {
            id: "provider_config_hardcode",
            name: "Avoid Hardcoded Config",
            category: Provider,
            severity: Warning,
            description: "Configuration values should come from the Config provider, not hardcoded strings.",
            pattern: r#"(?:api_key|secret|password|token)\s*=\s*"[^"]+""#,
            fix: r#"let api_key = ctx.provider.get("API_KEY").ok_or_else(|| bad_request!("missing API_KEY"))?;"#,
            doc: "provider-traits.md#config",
        },
        rule! {
            id: "provider_direct_http",
            name: "Avoid Direct HTTP",
            category: Provider,
            severity: Error,
            description: "HTTP requests must go through HttpRequest provider, not direct clients.",
            pattern: r"(?:reqwest|hyper|surf|ureq)::",
            fix: "Use ctx.provider.fetch() from HttpRequest trait",
            doc: "wasm32.md#forbidden-crates",
        },
        rule! {
            id: "provider_bounds_minimal",
            name: "Minimal Provider Bounds",
            category: Provider,
            severity: Warning,
            description: "Declare only the provider traits that are actually used in the handler.",
            pattern: r"P:\s*(\w+(?:\s*\+\s*\w+){4,})",
            fix: "Only include traits that are actually used: P: Config + HttpRequest",
            doc: "handler-trait.md#provider-bounds",
        },
        // ==================== ERROR RULES ====================
        rule! {
            id: "error_generic_unwrap",
            name: "Avoid unwrap/expect",
            category: Error,
            severity: Warning,
            description: "Avoid .unwrap() and .expect() as they cause panics. Use ? operator instead.",
            pattern: r"\.(unwrap|expect)\s*\(",
            fix: r#".ok_or_else(|| bad_request!("error message"))?"#,
            doc: "error-handling.md#no-panics",
        },
        rule! {
            id: "error_panic_macro",
            name: "Avoid panic! Macro",
            category: Error,
            severity: Error,
            description: "Never use panic! in WASM handlers - it aborts the entire component.",
            pattern: r"panic!\s*\(",
            fix: r#"Return Err(server_error!("reason")) instead"#,
            doc: "error-handling.md#no-panics",
        },
        rule! {
            id: "error_unreachable",
            name: "Avoid unreachable! Macro",
            category: Error,
            severity: Error,
            description: "Never use unreachable! in WASM handlers.",
            pattern: r"unreachable!\s*\(",
            fix: "Use an explicit error return instead",
            doc: "error-handling.md#no-panics",
        },
        rule! {
            id: "error_todo",
            name: "Avoid todo! Macro",
            category: Error,
            severity: Warning,
            description: "todo! causes panics - replace with proper error handling or implementation.",
            pattern: r"todo!\s*\(",
            fix: "Implement the missing functionality or return an error",
            doc: "error-handling.md#no-panics",
        },
        rule! {
            id: "error_assert",
            name: "No assert! in Handlers",
            category: Error,
            severity: Error,
            description: "assert! causes panics which abort WASM execution. Return errors instead.",
            pattern: r"assert!\s*\(",
            fix: r#"if !condition { return Err(bad_request!("validation failed")); }"#,
            doc: "error-handling.md#no-panics",
        },
        rule! {
            id: "error_assert_eq",
            name: "No assert_eq! in Handlers",
            category: Error,
            severity: Error,
            description: "assert_eq! causes panics which abort WASM execution. Return errors instead.",
            pattern: r"assert_eq!\s*\(",
            fix: r#"if a != b { return Err(bad_request!("mismatch")); }"#,
            doc: "error-handling.md#no-panics",
        },
        rule! {
            id: "error_debug_assert",
            name: "No debug_assert! in Handlers",
            category: Error,
            severity: Warning,
            description: "debug_assert! can cause panics in debug builds. Prefer explicit error handling.",
            pattern: r"debug_assert!?\s*\(",
            fix: "Remove or convert to explicit error check",
            doc: "error-handling.md#no-panics",
        },
        rule! {
            id: "error_missing_context_serde",
            name: "Serde Deserialize Without Context",
            category: Error,
            severity: Warning,
            description: "serde_json::from_* should use .context() for meaningful error messages.",
            pattern: r"serde_json::from_\w+\([^)]+\)\?",
            fix: r#"serde_json::from_slice(&data).context("deserializing MyType").map_err(Into::into)?"#,
            doc: "error-handling.md#context",
        },
        rule! {
            id: "error_missing_context_parse",
            name: "Parse Without Context",
            category: Error,
            severity: Warning,
            description: "Parsing operations should use .context() for meaningful error messages.",
            pattern: r"\.parse\(\)\?",
            fix: r#".parse().context("parsing field_name")?"#,
            doc: "error-handling.md#context",
        },
        rule! {
            id: "error_dynamic_code",
            name: "Error Code Should Be Static",
            category: Error,
            severity: Warning,
            description: "Error codes should be stable static strings, not dynamically generated with format!.",
            pattern: r"code:\s*format!\(",
            fix: r#"code: "error_code".to_string()"#,
            doc: "error-handling.md#error-codes",
        },
        rule! {
            id: "error_anyhow_in_handler",
            name: "Use omnia_sdk::Error Not anyhow::Error",
            category: Error,
            severity: Warning,
            description: "Handler Error type should be omnia_sdk::Error for proper HTTP status mapping, not anyhow::Error.",
            pattern: r"type\s+Error\s*=\s*anyhow::Error",
            fix: "type Error = omnia_sdk::Error;",
            doc: "error-handling.md#error-type",
        },
        // ==================== WASM RULES ====================
        rule! {
            id: "wasm_std_fs",
            name: "No std::fs",
            category: Wasm,
            severity: Error,
            description: "std::fs is not available in WASM32. Use provider abstractions.",
            pattern: r"std::fs::",
            fix: "Use StateStore or TableStore provider",
            doc: "wasm32.md#forbidden-apis",
        },
        rule! {
            id: "wasm_std_net",
            name: "No std::net",
            category: Wasm,
            severity: Error,
            description: "std::net is not available in WASM32. Use HttpRequest provider.",
            pattern: r"std::net::",
            fix: "Use HttpRequest provider for network access",
            doc: "wasm32.md#forbidden-apis",
        },
        rule! {
            id: "wasm_std_thread",
            name: "No std::thread",
            category: Wasm,
            severity: Error,
            description: "std::thread is not available in WASM32. Use async/await.",
            pattern: r"std::thread::",
            fix: "Use async/await for concurrency",
            doc: "wasm32.md#forbidden-apis",
        },
        rule! {
            id: "wasm_std_env",
            name: "No std::env",
            category: Wasm,
            severity: Error,
            description: "std::env is not available in WASM32. Use Config provider.",
            pattern: r"std::env::",
            fix: "Use Config provider for environment variables",
            doc: "wasm32.md#forbidden-apis",
        },
        rule! {
            id: "wasm_std_process",
            name: "No std::process",
            category: Wasm,
            severity: Error,
            description: "std::process is not available in WASM32.",
            pattern: r"std::process::",
            doc: "wasm32.md#forbidden-apis",
        },
        rule! {
            id: "wasm_std_time_instant",
            name: "No std::time::Instant",
            category: Wasm,
            severity: Error,
            description: "std::time::Instant is not available in WASM32.",
            pattern: r"std::time::Instant",
            fix: "Use chrono::Utc::now() for time",
            doc: "wasm32.md#forbidden-apis",
        },
        rule! {
            id: "wasm_64bit_integer",
            name: "Prefer 32-bit Integers",
            category: Wasm,
            severity: Warning,
            description: "WASM32 is a 32-bit environment. i64/u64 operations are emulated and slower.",
            pattern: r":\s*[iu]64\b",
            fix: "Use i32/u32 if the value range allows",
            doc: "wasm32.md#performance",
        },
        rule! {
            id: "wasm_128bit_integer",
            name: "Avoid 128-bit Integers",
            category: Wasm,
            severity: Warning,
            description: "WASM32 does not natively support 128-bit integers. i128/u128 are heavily emulated and slow.",
            pattern: r":\s*[iu]128\b",
            fix: "Use smaller integer types",
            doc: "wasm32.md#performance",
        },
        rule! {
            id: "wasm_isize_usize",
            name: "Avoid isize/usize for Data",
            category: Wasm,
            severity: Hint,
            description: "isize/usize vary by platform. Use explicit i32/u32 for data that crosses API boundaries.",
            pattern: r":\s*[iu]size\b",
            fix: "Use i32/u32 for API data, keep usize only for indexing",
            doc: "wasm32.md#portability",
        },
        // ==================== STATELESS RULES ====================
        rule! {
            id: "stateless_static_mut",
            name: "No static mut",
            category: Stateless,
            severity: Error,
            description: "static mut creates global mutable state. Omnia handlers must be stateless.",
            pattern: r"static\s+mut\s+",
            fix: "Use StateStore provider for state persistence",
            doc: "guardrails.md#statelessness",
        },
        rule! {
            id: "stateless_lazy_static",
            name: "No lazy_static",
            category: Stateless,
            severity: Error,
            description: "lazy_static creates global state. Not allowed in Omnia.",
            pattern: r"lazy_static!\s*\{",
            fix: "Pass state through Context or use StateStore",
            doc: "guardrails.md#forbidden-crates",
        },
        rule! {
            id: "stateless_once_cell",
            name: "No OnceCell/OnceLock",
            category: Stateless,
            severity: Error,
            description: "OnceCell/OnceLock create global state. Not allowed in Omnia.",
            pattern: r"(?:OnceCell|OnceLock)",
            fix: "Use StateStore provider",
            doc: "guardrails.md#forbidden-crates",
        },
        rule! {
            id: "stateless_lazy_lock",
            name: "No LazyLock",
            category: Stateless,
            severity: Error,
            description: "LazyLock (std 1.80+) creates global state which is forbidden in Omnia WASM.",
            pattern: r"LazyLock\s*<",
            fix: "Use Config provider trait instead",
            doc: "guardrails.md#forbidden-crates",
        },
        rule! {
            id: "stateless_arc_mutex",
            name: "Avoid Arc<Mutex>",
            category: Stateless,
            severity: Warning,
            description: "Arc<Mutex<T>> suggests shared mutable state. Use StateStore instead.",
            pattern: r"Arc\s*<\s*(?:Mutex|RwLock)",
            fix: "Use StateStore provider for shared state",
            doc: "guardrails.md#statelessness",
        },
        rule! {
            id: "stateless_mutex",
            name: "Avoid Mutex/RwLock",
            category: Stateless,
            severity: Warning,
            description: "Mutex and RwLock create shared mutable state. WASM is single-threaded.",
            pattern: r"(?:std::sync::)?(?:Mutex|RwLock)\s*<",
            fix: "Use StateStore provider for shared state",
            doc: "guardrails.md#statelessness",
        },
        // ==================== PERFORMANCE RULES ====================
        rule! {
            id: "perf_clone_in_loop",
            name: "Avoid Clone in Loop",
            category: Performance,
            severity: Hint,
            description: "Cloning inside loops may be inefficient. Consider borrowing.",
            pattern: r"for\s+[^{]+\{[^}]*\.clone\s*\(",
            fix: "Use references or move ownership",
            doc: "ms-pragmatic-rust.md",
        },
        rule! {
            id: "perf_string_add",
            name: "Prefer format! Over String Concatenation",
            category: Performance,
            severity: Hint,
            description: "String concatenation with + is inefficient. Use format! or push_str.",
            pattern: r"String::new\s*\(\s*\)\s*\+",
            fix: "format!(\"{}{}\", a, b)",
            doc: "ms-pragmatic-rust.md",
        },
        rule! {
            id: "perf_unbounded_query",
            name: "Query Without Limit",
            category: Performance,
            severity: Warning,
            description: "Database queries should have a limit to prevent unbounded result sets.",
            pattern: r"ctx\.provider\.query\([^)]+\)\.await",
            fix: "Add LIMIT clause or use .limit() method",
            doc: "tablestore-handler.md#limits",
        },
        rule! {
            id: "perf_format_in_loop",
            name: "Avoid format! in Loops",
            category: Performance,
            severity: Hint,
            description: "format! allocates - consider preallocating strings outside loops.",
            pattern: r"for\s+\w+\s+in[^{]*\{[^}]*format!\(",
            fix: "Preallocate String and use push_str",
            doc: "ms-pragmatic-rust.md#allocations",
        },
        rule! {
            id: "perf_collect_count",
            name: "Use Iterator::count Instead of collect().len()",
            category: Performance,
            severity: Hint,
            description: "Use .count() instead of .collect::<Vec<_>>().len() to avoid allocation.",
            pattern: r"\.collect\(\)\.len\(\)",
            fix: ".count()",
            doc: "ms-pragmatic-rust.md#iterators",
        },
        // ==================== SECURITY RULES ====================
        rule! {
            id: "security_hardcoded_secret",
            name: "No Hardcoded Secrets",
            category: Security,
            severity: Error,
            description: "Secrets must come from Config provider, never hardcoded.",
            pattern: r#"(?:password|secret|api_key|token)\s*:\s*"[a-zA-Z0-9]+"#,
            fix: "let secret = ctx.provider.get(\"SECRET_KEY\")?;",
            doc: "guardrails.md#security",
        },
        rule! {
            id: "security_sql_concat",
            name: "Avoid SQL String Concatenation",
            category: Security,
            severity: Error,
            description: "Never concatenate SQL strings - use parameterized queries.",
            pattern: r#"format!\s*\(\s*"(?:SELECT|INSERT|UPDATE|DELETE)[^"]*\{\}"#,
            fix: r#"ctx.provider.query("SELECT * FROM t WHERE id = $1", &[("$1", id)])"#,
            doc: "guardrails.md#security",
        },
        // ==================== STRONG TYPING RULES ====================
        rule! {
            id: "type_primitive_string_id",
            name: "Use Newtypes for IDs",
            category: StrongTyping,
            severity: Warning,
            description: "Use newtype wrappers for identifiers instead of raw String.",
            pattern: r"pub\s+(?:id|\w+_id)\s*:\s*String",
            fix: "pub struct VehicleId(pub String);",
            doc: "ms-pragmatic-rust.md#newtypes",
        },
        rule! {
            id: "type_string_match",
            name: "Use Enums Instead of String Matching",
            category: StrongTyping,
            severity: Hint,
            description: "Replace string literal matching with typed enums for compile-time safety.",
            pattern: r#"match\s+\w+\.as_str\(\)\s*\{[^}]*"[^"]+"\s*=>"#,
            fix: "Define an enum with #[derive(Deserialize)]",
            doc: "ms-pragmatic-rust.md#enums",
        },
        rule! {
            id: "type_raw_coordinates",
            name: "Use Newtypes for Coordinates",
            category: StrongTyping,
            severity: Info,
            description: "Use newtype wrappers for latitude/longitude instead of raw f64.",
            pattern: r"pub\s+(?:lat(?:itude)?|lon(?:gitude)?)\s*:\s*f(?:32|64)",
            fix: "pub struct Latitude(pub f64);",
            doc: "ms-pragmatic-rust.md#newtypes",
        },
        // ==================== TIME RULES ====================
        rule! {
            id: "time_system_time_now",
            name: "No SystemTime::now()",
            category: Time,
            severity: Error,
            description: "SystemTime::now() is unreliable in WASM32. Use chrono::Utc::now() instead.",
            pattern: r"SystemTime::now\(\)",
            fix: "chrono::Utc::now()",
            doc: "wasm32.md#time",
        },
        rule! {
            id: "time_instant_duration",
            name: "No Instant for Elapsed Time",
            category: Time,
            severity: Error,
            description: "Instant::now() and elapsed() are not available in WASM32.",
            pattern: r"Instant::now\(\)\.elapsed\(\)",
            fix: "Use chrono timestamps for elapsed time calculations",
            doc: "wasm32.md#time",
        },
        // ==================== AUTH RULES ====================
        rule! {
            id: "auth_hardcoded_bearer",
            name: "No Hardcoded Bearer Tokens",
            category: Auth,
            severity: Error,
            description: "Bearer tokens must come from Identity::access_token(), not hardcoded strings.",
            pattern: r#"Bearer\s+[A-Za-z0-9._-]{20,}"#,
            fix: "let token = ctx.provider.access_token(\"service\").await?;",
            doc: "provider-traits.md#identity",
        },
        // ==================== CACHING RULES ====================
        rule! {
            id: "cache_missing_ttl",
            name: "Cache Set Without TTL",
            category: Caching,
            severity: Warning,
            description: "StateStore::set should include a TTL to prevent unbounded cache growth.",
            pattern: r"ctx\.provider\.set\([^)]*,\s*None\s*\)\.await",
            fix: "ctx.provider.set(key, value, Some(Duration::from_secs(3600))).await?",
            doc: "cache-handler.md#ttl",
        },
        // ==================== FORBIDDEN IMPORTS ====================
        rule! {
            id: "forbidden_tokio",
            name: "No Tokio Runtime",
            category: Wasm,
            severity: Error,
            description: "Tokio runtime is not available in WASM32. WASI provides the executor.",
            pattern: r"use\s+tokio\b",
            fix: "Use async/await without explicit runtime",
            doc: "wasm32.md#forbidden-crates",
        },
        rule! {
            id: "forbidden_async_std",
            name: "No async-std Runtime",
            category: Wasm,
            severity: Error,
            description: "async-std runtime is not available in WASM32. WASI provides the executor.",
            pattern: r"use\s+async_std\b",
            fix: "Use async/await without explicit runtime",
            doc: "wasm32.md#forbidden-crates",
        },
        rule! {
            id: "forbidden_rayon",
            name: "No Rayon Parallelism",
            category: Wasm,
            severity: Error,
            description: "Rayon is not available in WASM32. WASM is single-threaded.",
            pattern: r"use\s+rayon\b",
            fix: "Use sequential iterators",
            doc: "wasm32.md#forbidden-crates",
        },
        // ==================== PRINT STATEMENTS ====================
        rule! {
            id: "println_debug",
            name: "Avoid println!/eprintln!",
            category: Performance,
            severity: Hint,
            description: "println!/eprintln! may not be visible in WASM32. Use tracing macros.",
            pattern: r"(?:println|eprintln|dbg)!\s*\(",
            fix: "Use tracing macros: info!, warn!, error!, debug!",
            doc: "observability.md#tracing",
        },
        // ==================== ADDITIONAL ERROR RULES ====================
        rule! {
            id: "error_map_to_bad_request",
            name: "Map Parsing Errors to BadRequest",
            category: Error,
            severity: Info,
            description: "Parsing/validation errors should map to bad_request! (400), not server_error! (500).",
            pattern: r"(?:parse|deserialize|validate).*server_error!",
            fix: "Use bad_request!(\"invalid input: {}\", err) for client errors",
            doc: "error-handling.md#status-codes",
        },
        rule! {
            id: "error_map_to_bad_gateway",
            name: "Map Upstream Errors to BadGateway",
            category: Error,
            severity: Info,
            description: "External service/API errors should map to bad_gateway! (502), not server_error! (500).",
            pattern: r"(?:fetch|http|api|upstream).*server_error!",
            fix: "Use bad_gateway!(\"upstream failed: {}\", err) for external service errors",
            doc: "error-handling.md#status-codes",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_set_creation() {
        let rule_set = RuleSet::new();
        assert!(rule_set.rules.len() > 50, "Should have many rules defined");
    }

    #[test]
    fn test_all_anti_pattern_rules_have_descriptions() {
        let rule_set = RuleSet::new();
        for rule in &rule_set.rules {
            assert!(!rule.description.is_empty(), "Rule {} has empty description", rule.id);
            assert!(!rule.id.is_empty(), "Found rule with empty id");
            assert!(!rule.name.is_empty(), "Rule {} has empty name", rule.id);
        }
    }

    #[test]
    fn test_by_category() {
        let rule_set = RuleSet::new();
        let handler_rules = rule_set.by_category(RuleCategory::Handler);
        assert!(!handler_rules.is_empty(), "Should have handler rules");
        for rule in &handler_rules {
            assert_eq!(rule.category, RuleCategory::Handler);
        }
    }

    #[test]
    fn test_by_severity() {
        let rule_set = RuleSet::new();
        let errors = rule_set.by_severity(RuleSeverity::Error);
        assert!(!errors.is_empty(), "Should have error-severity rules");
    }

    #[test]
    fn test_get_rule_by_id() {
        let rule_set = RuleSet::new();
        let rule = rule_set.get("error_generic_unwrap");
        assert!(rule.is_some(), "Should find error_generic_unwrap");
        let rule = rule.unwrap();
        assert_eq!(rule.severity, RuleSeverity::Warning);
        assert!(rule.is_anti_pattern);
    }

    #[test]
    fn test_anti_patterns_filter() {
        let rule_set = RuleSet::new();
        let anti = rule_set.anti_patterns();
        assert!(!anti.is_empty());
        for rule in &anti {
            assert!(rule.is_anti_pattern, "Rule {} should be anti-pattern", rule.id);
        }
    }

    #[test]
    fn test_category_from_key_roundtrip() {
        for cat in RuleCategory::ALL {
            let key = cat.as_key();
            let parsed = RuleCategory::from_key(key);
            assert_eq!(parsed, Some(*cat), "Roundtrip failed for {:?}", cat);
        }
    }

    #[test]
    fn test_category_from_key_unknown() {
        assert_eq!(RuleCategory::from_key("nonexistent"), None);
    }

    #[test]
    fn test_lint_level_from_str() {
        assert_eq!(LintLevel::parse("allow"), Some(LintLevel::Allow));
        assert_eq!(LintLevel::parse("warn"), Some(LintLevel::Warn));
        assert_eq!(LintLevel::parse("deny"), Some(LintLevel::Deny));
        assert_eq!(LintLevel::parse("forbid"), Some(LintLevel::Forbid));
        assert_eq!(LintLevel::parse("invalid"), None);
    }

    #[test]
    fn test_lint_level_to_severity() {
        assert_eq!(LintLevel::Allow.to_severity(), None);
        assert_eq!(LintLevel::Warn.to_severity(), Some(RuleSeverity::Warning));
        assert_eq!(LintLevel::Deny.to_severity(), Some(RuleSeverity::Error));
        assert_eq!(LintLevel::Forbid.to_severity(), Some(RuleSeverity::Error));
    }

    #[test]
    fn test_unwrap_rule_matches() {
        let rule_set = RuleSet::new();
        let rule = rule_set.get("error_generic_unwrap").unwrap();
        assert!(rule.pattern.is_match("let x = foo.unwrap()"));
        assert!(rule.pattern.is_match("let x = foo.expect(\"msg\")"));
        assert!(!rule.pattern.is_match("let x = foo.unwrap_or(0)"));
    }

    #[test]
    fn test_static_mut_rule_matches() {
        let rule_set = RuleSet::new();
        let rule = rule_set.get("stateless_static_mut").unwrap();
        assert!(rule.pattern.is_match("static mut COUNTER: u32 = 0;"));
        assert!(!rule.pattern.is_match("static COUNTER: u32 = 0;"));
    }

    #[test]
    fn test_no_duplicate_rule_ids() {
        let rule_set = RuleSet::new();
        let mut seen = std::collections::HashSet::new();
        for rule in &rule_set.rules {
            assert!(seen.insert(rule.id), "Duplicate rule id: {}", rule.id);
        }
    }
}
