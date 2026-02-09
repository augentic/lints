# QWASR LSP Server

A QWASR-aware Language Server Protocol (LSP) implementation for Rust, providing intelligent assistance for developing WASM components using the [QWASR](https://github.com/augentic/qwasr) (Quick WebAssembly Secure Runtime) platform.

## Features

### Diagnostics

The LSP provides real-time diagnostics for common QWASR issues:

- **Forbidden Crates**: Detects usage of crates incompatible with WASM32 (e.g., `reqwest`, `tokio`, `redis`)
- **Forbidden Patterns**: Identifies patterns that violate WASM32 constraints:
  - Global mutable state (`static mut`, `OnceCell`, `lazy_static!`)
  - OS-specific APIs (`std::fs`, `std::net`, `std::thread`, `std::env`)
  - Blocking operations (`thread::sleep`)
- **Handler Issues**: Checks Handler trait implementations for common mistakes
- **Best Practices**: Warns about `unwrap()`/`expect()` usage and `println!` in WASM code

### Completions

Context-aware completions for QWASR patterns:

- Provider trait methods (`Config::get`, `HttpRequest::fetch`, etc.)
- Error macros (`bad_request!`, `server_error!`, `bad_gateway!`)
- Import suggestions for `qwasr_sdk` types
- Code snippets for common patterns:
  - Handler implementation boilerplate
  - Request/Response struct definitions
  - HTTP fetch patterns
  - Cache operations with StateStore

### Hover Documentation

Rich documentation on hover for QWASR concepts:

- **Provider Traits**: `Config`, `HttpRequest`, `Publisher`, `StateStore`, `Identity`, `TableStore`
- **Handler Trait**: Definition, associated types, and methods
- **Error Macros**: Usage examples and HTTP status mappings
- **SDK Types**: `Context`, `Reply`, `Message`

### Code Actions

Quick fixes and refactoring suggestions:

- Replace `std::env::var()` with `Config::get()`
- Replace `SystemTime` with `chrono::Utc::now()`
- Replace `println!` with `tracing::info!`
- Replace `.unwrap()` with `?` operator
- Remove forbidden crate imports

### Document Symbols

Navigate QWASR code with symbol outlines:

- Handler implementations
- Request/Response structs
- Provider trait implementations
- Async handler functions

## Installation

### Building from Source

```bash
cd qwasr-lsp
cargo build --release
```

The binary will be available at `target/release/qwasr-lsp`.

### VS Code Integration

Create a VS Code extension or add to your settings:

```json
{
  "rust-analyzer.server.extraEnv": {},
  "[rust]": {
    "editor.formatOnSave": true
  }
}
```

For custom LSP client configuration, point to the `qwasr-lsp` binary.

## Usage

The LSP server communicates over stdin/stdout using the Language Server Protocol.

### Command Line

```bash
qwasr-lsp
```

### Environment Variables

- `RUST_LOG`: Set logging level (e.g., `RUST_LOG=debug`)

## QWASR Patterns Enforced

### Provider Traits

All external I/O must go through provider traits:

| Trait | Purpose | WASI Module |
|-------|---------|-------------|
| `Config` | Configuration values | `qwasr_wasi_config` |
| `HttpRequest` | HTTP requests | `qwasr_wasi_http` |
| `Publisher` | Message publishing | `qwasr_wasi_messaging` |
| `StateStore` | Cache/KV operations | `qwasr_wasi_keyvalue` |
| `Identity` | Authentication tokens | `qwasr_wasi_identity` |
| `TableStore` | SQL database ops | `qwasr_wasi_sql` |

### Handler Pattern

```rust
impl<P: Config + HttpRequest> Handler<P> for MyRequest {
    type Error = Error;
    type Input = Vec<u8>;
    type Output = MyResponse;

    fn from_input(input: Self::Input) -> Result<Self> {
        serde_json::from_slice(&input)
            .context("deserializing MyRequest")
            .map_err(Into::into)
    }

    async fn handle(self, ctx: Context<'_, P>) -> Result<Reply<MyResponse>> {
        let result = process_request(ctx.provider, &self).await?;
        Ok(Reply::ok(result))
    }
}
```

### Error Handling

Use QWASR error macros for proper HTTP status mapping:

```rust
// 400 Bad Request
Err(bad_request!("invalid input"))

// 500 Internal Server Error  
Err(server_error!("unexpected state"))

// 502 Bad Gateway
Err(bad_gateway!("upstream failed"))
```

## LLM Integration (Claude Code Skill)

This LSP is designed to work as a **Claude Code skill** for LLM-assisted QWASR development.

### LLM Analysis Module

The `llm` module provides structured analysis output optimized for LLM consumption:

```rust
use qwasr_lsp::llm::LlmAnalyzer;

let analyzer = LlmAnalyzer::new();
let analysis = analyzer.analyze(source_code);

// Get JSON output for LLM processing
let json = analyzer.to_json(&analysis);

// Get markdown summary
let summary = analyzer.to_summary(&analysis);
```

### Analysis Output Structure

The analysis provides:

- **FileSummary**: Overview including health score, handler count, provider traits used
- **HandlerAnalysis**: Detailed analysis of each Handler implementation
  - Request/response types
  - Provider trait bounds (declared vs. actually used)
  - Issue detection (missing methods, unused bounds, etc.)
- **Issues**: Categorized violations with explanations and suggested fixes
- **Suggestions**: Improvement recommendations with code templates
- **MissingItems**: Required implementations that are absent

### Comprehensive Rule Set

50+ validation rules covering:

| Category | Rules |
|----------|-------|
| Handler | from_input signature, handle async, Output type, Error type, bounds validation |
| Provider | Config usage, HttpRequest patterns, Publisher usage, StateStore operations, TableStore queries |
| Error | Error macro usage, unwrap/expect detection, panic detection, anyhow context |
| WASM | std::fs/net/thread/env detection, forbidden crate detection |
| Stateless | static mut, lazy_static, OnceCell, Arc<Mutex> detection |
| Security | Hardcoded secrets, SQL injection patterns |

### Example LLM Workflow

1. **Analyze code**: Run `LlmAnalyzer::analyze()` on source file
2. **Check health score**: If below threshold, review issues
3. **Fix violations**: Apply suggested fixes for anti-patterns
4. **Generate missing**: Use templates for missing Handler/Response types
5. **Validate bounds**: Ensure provider bounds match actual usage

## Development

### Project Structure

```
qwasr-lsp/
├── src/
│   ├── main.rs              # Entry point
│   ├── backend.rs           # LSP backend implementation
│   ├── capabilities.rs      # Server capabilities
│   ├── diagnostics.rs       # Diagnostics engine
│   ├── llm.rs               # LLM-oriented analysis module
│   ├── handlers/            # LSP feature handlers
│   │   ├── mod.rs
│   │   ├── hover.rs
│   │   ├── completion.rs
│   │   ├── code_action.rs
│   │   └── document_symbol.rs
│   └── qwasr/               # QWASR knowledge base
│       ├── mod.rs
│       ├── traits.rs        # Provider trait definitions
│       ├── constraints.rs   # Forbidden patterns/crates
│       ├── patterns.rs      # Code snippets and templates
│       └── rules.rs         # Comprehensive validation rules
└── Cargo.toml
```

### Running Tests

```bash
cargo test
```

### Debugging

Set the log level for verbose output:

```bash
RUST_LOG=debug qwasr-lsp
```

## License

MIT OR Apache-2.0

## References

- [QWASR Repository](https://github.com/augentic/qwasr)
- [Language Server Protocol](https://microsoft.github.io/language-server-protocol/)
- [tower-lsp](https://github.com/ebkalderon/tower-lsp)
