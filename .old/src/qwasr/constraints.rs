//! QWASR constraints and forbidden patterns.

use std::collections::HashSet;

/// A pattern that is forbidden in QWASR WASM32 code.
#[derive(Debug, Clone)]
pub struct ForbiddenPattern {
    /// Pattern identifier.
    pub id: &'static str,

    /// Human-readable name.
    pub name: &'static str,

    /// Description of why this pattern is forbidden.
    pub reason: &'static str,

    /// Regex patterns to detect this issue.
    pub patterns: Vec<&'static str>,

    /// Suggested alternative.
    pub alternative: &'static str,

    /// Severity level.
    pub severity: Severity,
}

/// Severity level for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Error - code will not work.
    Error,
    /// Warning - code may have issues.
    Warning,
    /// Hint - suggestion for improvement.
    Hint,
}

/// Returns the set of forbidden crates in WASM32 code.
pub fn forbidden_crates() -> HashSet<String> {
    [
        // HTTP clients - use HttpRequest trait
        "reqwest",
        "hyper",
        "surf",
        "ureq",
        // Redis clients - use StateStore trait
        "redis",
        // Kafka clients - use Publisher trait
        "rdkafka",
        // RabbitMQ - use Publisher trait
        "lapin",
        // Async runtimes - WASI provides executor
        "tokio",
        "async-std",
        "smol",
        // Parallel processing - WASM is single-threaded
        "rayon",
        // Concurrency primitives - WASM is single-threaded
        "crossbeam",
        "parking_lot",
        // Global state - WASM must be stateless
        "once_cell",
        "lazy_static",
        // Concurrent collections - use StateStore trait
        "dashmap",
        // Direct database clients
        "sqlx",
        "diesel",
        "rusqlite",
        "postgres",
        "mysql",
        // Filesystem operations
        "tempfile",
        // Network operations
        "socket2",
        "mio",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// Returns forbidden patterns for QWASR WASM32 code.
pub fn forbidden_patterns() -> Vec<ForbiddenPattern> {
    vec![
        ForbiddenPattern {
            id: "global_state_static_mut",
            name: "Static Mutable State",
            reason: "WASM components must be stateless. Static mutable state persists across invocations.",
            patterns: vec![r"static\s+mut\s+\w+"],
            alternative: "Use function parameters or the StateStore provider trait for state management.",
            severity: Severity::Error,
        },
        ForbiddenPattern {
            id: "global_state_once_cell",
            name: "OnceCell Global State",
            reason: "WASM components must be stateless. OnceCell creates global state.",
            patterns: vec![r"OnceCell\s*<", r"OnceLock\s*<"],
            alternative: "Use the Config provider trait for configuration values.",
            severity: Severity::Error,
        },
        ForbiddenPattern {
            id: "global_state_lazy",
            name: "Lazy Static Global State",
            reason: "WASM components must be stateless. lazy_static!/LazyLock create global state.",
            patterns: vec![r"lazy_static!", r"LazyLock\s*<", r"Lazy\s*<"],
            alternative: "Use the Config provider trait for configuration values.",
            severity: Severity::Error,
        },
        ForbiddenPattern {
            id: "std_fs",
            name: "Filesystem Access",
            reason: "std::fs is not available in WASM32. No filesystem access in sandboxed environment.",
            patterns: vec![r"std::fs::", r"use\s+std::fs"],
            alternative: "Use wasi_blobstore provider if blob storage is available.",
            severity: Severity::Error,
        },
        ForbiddenPattern {
            id: "std_net",
            name: "Network Access",
            reason: "std::net is not available in WASM32. Use provider traits for network access.",
            patterns: vec![r"std::net::", r"use\s+std::net"],
            alternative: "Use the HttpRequest provider trait for HTTP requests.",
            severity: Severity::Error,
        },
        ForbiddenPattern {
            id: "std_thread",
            name: "Threading",
            reason: "std::thread is not available in WASM32. WASM is single-threaded.",
            patterns: vec![r"std::thread::", r"use\s+std::thread"],
            alternative: "Use async/await for concurrent operations.",
            severity: Severity::Error,
        },
        ForbiddenPattern {
            id: "std_process",
            name: "Process Spawning",
            reason: "std::process is not available in WASM32. Cannot spawn subprocesses.",
            patterns: vec![r"std::process::", r"use\s+std::process"],
            alternative: "Not applicable in WASM - restructure logic to avoid subprocess spawning.",
            severity: Severity::Error,
        },
        ForbiddenPattern {
            id: "std_env",
            name: "Environment Variables",
            reason: "std::env is not available in WASM32. Use Config provider for configuration.",
            patterns: vec![r"std::env::", r"use\s+std::env", r"env::var\("],
            alternative: "Use Config::get(provider, \"KEY\").await? for configuration values.",
            severity: Severity::Error,
        },
        ForbiddenPattern {
            id: "std_time_system",
            name: "System Time",
            reason: "std::time::SystemTime may not work correctly in WASM32.",
            patterns: vec![r"SystemTime::", r"use\s+std::time::SystemTime"],
            alternative: "Use chrono::Utc::now() for wall-clock time.",
            severity: Severity::Warning,
        },
        ForbiddenPattern {
            id: "thread_sleep",
            name: "Thread Sleep",
            reason: "std::thread::sleep is not available in WASM32.",
            patterns: vec![r"thread::sleep", r"std::thread::sleep"],
            alternative: "Async delays are not directly available in WASI. Consider restructuring logic.",
            severity: Severity::Error,
        },
        ForbiddenPattern {
            id: "panic_unwrap",
            name: "Unwrap/Expect Usage",
            reason: "Panics should be avoided in WASM handlers. Prefer returning errors.",
            patterns: vec![r"\.unwrap\(\)", r"\.expect\("],
            alternative: "Use the ? operator or match/if-let for error handling.",
            severity: Severity::Warning,
        },
        ForbiddenPattern {
            id: "println_debug",
            name: "Println/Eprintln",
            reason: "println!/eprintln! may not be visible in WASM32. Use tracing.",
            patterns: vec![r"println!", r"eprintln!", r"dbg!"],
            alternative: "Use tracing macros: info!, warn!, error!, debug!",
            severity: Severity::Hint,
        },
    ]
}
