# Omnia Lint

A custom Rust linter for [Omnia](https://github.com/augentic/omnia) WASM32 handler development. It enforces WASI component constraints, validates `Handler` trait implementations, detects forbidden crates/APIs, and checks provider trait bounds -- including transitive usage through function delegation.

## Why

Omnia handlers compile to `wasm32-wasip2` and run inside a sandboxed runtime. Standard Rust patterns that work on native targets (filesystem access, threading, direct HTTP clients, global mutable state) will either fail to compile or panic at runtime in this environment. This linter catches those issues at development time, before they reach CI or production.

## Install

```bash
cargo install --path .
```

Or add as a dev-dependency for programmatic use:

```toml
[dev-dependencies]
omnia-lint = { path = "../lints" }
```

## Quick Start

```bash
# Lint a directory
omnia-lint src/

# Lint specific files
omnia-lint src/handler.rs src/routes.rs

# Show only errors and warnings (skip info/hint)
omnia-lint src/ --severity warning

# JSON output for tooling
omnia-lint src/ --format json

# GitHub Actions annotations
omnia-lint src/ --format github --error-on-warnings
```

## What It Checks

### Forbidden Crates (~35 crates)

Crates that are incompatible with WASM32 are flagged on `use` or `extern crate`:

| Category | Crates | Alternative |
|----------|--------|-------------|
| HTTP clients | `reqwest`, `hyper`, `surf`, `ureq` | `HttpRequest` provider trait |
| Async runtimes | `tokio`, `async-std`, `smol` | WASI provides the executor |
| Databases | `sqlx`, `diesel`, `postgres`, `mysql` | `TableStore` provider trait |
| Redis/caching | `redis`, `fred` | `StateStore` provider trait |
| Messaging | `rdkafka`, `lapin` | `Publish` provider trait |
| Parallelism | `rayon`, `crossbeam` | Sequential iterators (WASM is single-threaded) |
| Global state | `once_cell`, `lazy_static` | `Config` provider trait |

### Forbidden Patterns (11 patterns)

Source patterns that won't work or are dangerous in WASM32:

- `static mut`, `OnceCell`, `LazyLock` -- global mutable state
- `std::fs`, `std::net`, `std::thread`, `std::process`, `std::env` -- unavailable APIs
- `SystemTime::now()`, `thread::sleep` -- unreliable or unavailable
- `println!`, `eprintln!`, `dbg!` -- use `tracing` instead

### Regex-Based Rules (51 rules across 13 categories)

| Category | What it checks |
|----------|---------------|
| Handler | Generic parameter `P`, async `handle`, `Context<'_, P>` lifetime |
| Provider | Hardcoded config, direct HTTP clients, too many bounds |
| Error | `unwrap`/`expect`/`panic!`/`assert!`, missing `.context()`, wrong error mapping |
| Wasm | `std::fs`/`net`/`thread`/`env`/`process`, 64/128-bit integers, `isize`/`usize` in APIs |
| Stateless | `static mut`, `lazy_static`, `OnceCell`, `Arc<Mutex>` |
| Performance | Clone in loop, string concatenation, `collect().len()`, unbounded queries |
| Security | Hardcoded secrets, SQL string concatenation |
| Strong Typing | Raw `String` IDs, string matching instead of enums, raw `f64` coordinates |
| Time | `SystemTime::now()`, `Instant::now().elapsed()` |
| Auth | Hardcoded bearer tokens |
| Caching | `StateStore::set` without TTL |

### Semantic Analysis (syn-based AST parsing)

The linter parses source files with `syn` to perform deep structural analysis:

- **Unused provider bounds** -- traits declared on `impl<P: Config + HttpRequest>` but never called in the handler body
- **Missing provider bounds** -- traits used (e.g. `ctx.provider.fetch(...)`) but not declared in bounds
- **Transitive trait detection** -- if a handler calls `fetch_data(provider)` which requires `HttpRequest`, the bound is traced through the call chain
- **Handler missing bounds** -- `impl<P> Handler<P>` with no provider traits specified
- **Helper function bounds** -- the same unused/missing analysis applied to standalone `async fn` helpers

The analyzer also runs regex-based checks for:
- `Config::get` without `?` or error handling
- `StateStore::set` with `None` TTL
- `HttpRequest::fetch` without `.context()`

## Configuration

### Cargo.toml

Configure severity overrides in `[lints.omnia]` or `[workspace.lints.omnia]`, following the same convention as `clippy`:

```toml
[workspace.lints.omnia]
all = "warn"

handler  = "deny"
wasm     = "deny"
security = "forbid"

error_generic_unwrap = "allow"
perf_clone_in_loop   = "allow"
```

Levels: `allow` (suppress), `warn`, `deny` (error), `forbid` (error, cannot be overridden).

### Inline Suppression

Suppress diagnostics with `#[omnia::allow(...)]`, similar to `#[allow(clippy::...)]`:

```rust
// Suppress a specific rule for the next item
#[omnia::allow(error_generic_unwrap)]
fn parse_config(input: &str) -> Config {
    serde_json::from_str(input).unwrap() // no warning
}

// Suppress all omnia rules for the next item
#[omnia::allow(all)]
fn legacy_handler() { /* ... */ }

// File-level suppression (inner attribute)
#![omnia::allow(println_debug)]
```

### CLI Options

```
omnia-lint [OPTIONS] <PATHS>...

Options:
  -f, --format <FORMAT>        pretty | json | compact | github [default: pretty]
  -s, --severity <SEVERITY>    error | warning | info | hint [default: hint]
  -c, --categories <CATS>      Comma-separated category filter
      --disable <RULES>        Comma-separated rule IDs to disable
      --show-fixes             Show fix suggestions [default: true]
      --error-on-warnings      Exit 1 on warnings (for CI)
  -q, --quiet                  Only show files with diagnostics
      --stats                  Show per-rule hit counts
      --max-diagnostics <N>    Limit output (0 = unlimited) [default: 0]
```

## Output Formats

**Pretty** (default) -- colored output with source snippets and fix suggestions.

**JSON** -- structured array for tooling integration:

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

**Compact** -- one line per diagnostic: `src/handler.rs:10:5: E [error_panic_macro] Never use panic!...`

**GitHub** -- native GitHub Actions annotation format (`::error file=...`).

## CI Integration

### GitHub Actions

```yaml
- name: Omnia Lint
  run: |
    cargo install --path lints
    omnia-lint src/ --format github --error-on-warnings
```

### Pre-commit Hook

```bash
#!/bin/bash
omnia-lint src/ --severity warning --quiet
```

## Library API

```rust
use omnia_lint::{Linter, LintConfig, RuleSeverity};

let config = LintConfig {
    min_severity: RuleSeverity::Warning,
    ..Default::default()
};

let linter = Linter::new(config);
let diagnostics = linter.lint_file("src/handler.rs").unwrap();

for diag in &diagnostics {
    println!("{}", diag);
}
```

Or lint a string directly:

```rust
let diagnostics = linter.lint_str(source_code, "handler.rs");
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No errors found |
| 1 | Errors found, or warnings found with `--error-on-warnings` |

## Architecture

```
src/
  main.rs          CLI entry point (clap, rayon parallel linting)
  lib.rs           Linter API, LintConfig, filtering
  diagnostics.rs   DiagnosticsEngine: orchestrates rules, constraints, semantic analysis
  rules.rs         51 regex-based rules defined via rule! macro
  constraints.rs   Forbidden crates and patterns
  semantic.rs      syn-based AST analysis (Handler bounds, transitive traits)
  config.rs        Cargo.toml [lints.omnia] discovery and parsing
  output.rs        Pretty, JSON, Compact, GitHub formatters
```

## Contributing

1. **Add a rule**: use the `rule!` macro in `src/rules.rs`
2. **Add a forbidden pattern**: add to `forbidden_patterns()` in `src/constraints.rs`
3. **Extend semantic analysis**: modify the `syn` visitors in `src/semantic.rs`
4. **Run tests**: `cargo test` (56 tests across all modules)
5. **Check style**: `cargo clippy`

## License

MIT
