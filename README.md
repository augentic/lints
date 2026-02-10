# QWASR Lint

A custom Rust linter for QWASR WASM32 handler development. This linter enforces best practices, detects forbidden patterns, and validates Handler implementations for WASM32 targets.

## Features

- **80+ Validation Rules** across 13 categories
- **Semantic Analysis** for provider trait bound checking
- **Multiple Output Formats**: Pretty, JSON, Compact, GitHub Actions
- **Parallel Processing** for fast linting of large codebases
- **Configurable Severity Levels**
- **Rule Category Filtering**
- **Inline Ignore Directives** using `#[qwasr::allow(...)]` attributes

## Installation

### From Source

```bash
cd custom-linter
cargo install --path .
```

### As a Dependency

Add to your `Cargo.toml`:

```toml
[dev-dependencies]
qwasr-lint = { path = "../custom-linter" }
```

## Usage

### Command Line

```bash
# Lint a single file
qwasr-lint src/handler.rs

# Lint a directory recursively
qwasr-lint src/

# Lint multiple paths
qwasr-lint src/ tests/

# Output as JSON
qwasr-lint src/ --format json

# Only show errors and warnings
qwasr-lint src/ --severity warning

# Filter by category
qwasr-lint src/ --categories handler,wasm,error

# Disable specific rules
qwasr-lint src/ --disable error_generic_unwrap,println_debug

# GitHub Actions output
qwasr-lint src/ --format github

# Show statistics
qwasr-lint src/ --stats
```

### As a Library

```rust
use qwasr_lint::{Linter, LintConfig, RuleSeverity};

fn main() {
    let config = LintConfig {
        min_severity: RuleSeverity::Warning,
        show_fixes: true,
        ..Default::default()
    };

    let linter = Linter::new(config);
    
    let diagnostics = linter.lint_file("src/handler.rs").unwrap();
    
    for diag in diagnostics {
        println!("{}", diag);
    }
}
```

## Rule Categories

| Category | Description | Count |
|----------|-------------|-------|
| **Handler** | Handler trait implementation rules | 8 |
| **Provider** | Provider trait usage rules | 11 |
| **Error** | Error handling rules | 19 |
| **Wasm** | WASM32 compatibility rules | 12 |
| **Stateless** | Statelessness enforcement | 6 |
| **Performance** | Performance optimization hints | 5 |
| **Security** | Security-critical rules | 2 |
| **StrongTyping** | Type safety recommendations | 3 |
| **Time** | Time handling rules | 2 |
| **Auth** | Authentication rules | 2 |
| **Caching** | Cache usage rules | 2 |

## Key Rules

### Critical Errors (Must Fix)

| Rule ID | Description |
|---------|-------------|
| `error_panic_macro` | No `panic!` in WASM handlers |
| `error_unreachable` | No `unreachable!` macro |
| `error_assert` | No `assert!` in handlers |
| `wasm_std_fs` | No `std::fs` access |
| `wasm_std_net` | No `std::net` access |
| `wasm_std_thread` | No `std::thread` usage |
| `stateless_static_mut` | No `static mut` state |
| `security_sql_concat` | No SQL string concatenation |
| `forbidden_tokio` | No Tokio runtime |

### Warnings (Should Fix)

| Rule ID | Description |
|---------|-------------|
| `error_generic_unwrap` | Avoid `.unwrap()` and `.expect()` |
| `handler_context_lifetime` | Use `Context<'_, P>` lifetime |
| `provider_bounds_minimal` | Declare only used provider traits |
| `cache_missing_ttl` | StateStore::set should have TTL |

### Semantic Analysis

The linter performs deep semantic analysis to detect:

- **Unused Provider Bounds**: Traits declared but never used
- **Missing Provider Bounds**: Traits used but not declared
- **StateStore TTL Issues**: Cache operations without expiration

## Forbidden Crates

The following crates are not compatible with WASM32:

| Category | Crates |
|----------|--------|
| HTTP Clients | `reqwest`, `hyper`, `surf`, `ureq` |
| Async Runtimes | `tokio`, `async-std`, `smol` |
| Databases | `sqlx`, `diesel`, `postgres`, `mysql` |
| Parallelism | `rayon`, `crossbeam` |
| Global State | `once_cell`, `lazy_static` |
| Messaging | `rdkafka`, `lapin` |

## Output Formats

### Pretty (Default)

Human-readable colored output with source snippets and fix suggestions.

### JSON

Structured output for tooling integration:

```json
[
  {
    "file": "src/handler.rs",
    "line": 10,
    "column": 5,
    "severity": "error",
    "rule_id": "error_panic_macro",
    "message": "Never use panic! in WASM handlers",
    "fix": "Return Err(server_error!(\"reason\")) instead"
  }
]
```

### Compact

One diagnostic per line:

```
src/handler.rs:10:5: E [error_panic_macro] Never use panic! in WASM handlers
```

### GitHub Actions

Native GitHub Actions annotation format for CI integration.

## CI Integration

### GitHub Actions

```yaml
- name: Run QWASR Lint
  run: |
    cargo install --path custom-linter
    qwasr-lint src/ --format github --error-on-warnings
```

### Pre-commit Hook

```bash
#!/bin/bash
qwasr-lint src/ --severity warning --quiet
if [ $? -ne 0 ]; then
    echo "Linting failed. Please fix the issues above."
    exit 1
fi
```

## Configuration

### Inline Ignore Directives

You can suppress specific lint warnings using `#[qwasr::allow(...)]` attributes, similar to Clippy's `#[allow(...)]`.

#### Ignore all rules for the next item

```rust
#[qwasr::allow(all)]
fn my_function() {
    let x = Some(5).unwrap();  // No warning
}
```

#### Ignore specific rule(s)

```rust
#[qwasr::allow(unwrap_used)]
fn my_function() {
    let x = Some(5).unwrap();  // No warning for unwrap_used
}

// Multiple rules can be specified
#[qwasr::allow(unwrap_used, expect_used)]
fn my_function() {
    let x = Some(5).unwrap();
    let y = Some(6).expect("msg");  // Both ignored
}
```

#### File-level ignore (inner attribute)

Use `#!` for file-wide suppression:

```rust
#![qwasr::allow(all)]  // Ignore all rules in this file

fn my_function() {
    let x = Some(5).unwrap();  // No warning
}
```

```rust
#![qwasr::allow(forbidden_crate_tokio)]  // Only ignore tokio warnings file-wide

use tokio::runtime::Runtime;  // No warning
```

### LintConfig Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `all_rules` | bool | true | Enable all rules |
| `categories` | Vec | [] | Filter by categories |
| `disabled_rules` | Vec | [] | Rules to disable |
| `min_severity` | Severity | Hint | Minimum severity to report |
| `show_fixes` | bool | true | Show fix suggestions |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No errors (warnings may be present) |
| 1 | One or more errors found |
| 1 | Warnings found (with `--error-on-warnings`) |

## Contributing

1. Add new rules in `src/rules.rs`
2. Add forbidden patterns in `src/constraints.rs`
3. Extend semantic analysis in `src/semantic.rs`
4. Run tests: `cargo test`
5. Build: `cargo build --release`

## License

MIT
