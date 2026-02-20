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

### Semantic Analysis

Deep code analysis beyond pattern matching:

- **Provider Trait Bounds**: Detects unused or missing trait bounds on Handler implementations
- **Trait Usage Tracking**: Identifies which provider traits are actually used vs. declared
- **Handler Validation**: Validates Handler impl structure and associated types

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

You must build the LSP server from source. Pre-built binaries are not currently distributed.

### Building from Source

**Prerequisites:**
- Rust 1.70+
- Cargo

```bash
cd lsp
cargo build --release
```

The compiled binary will be available at `target/release/qwasr-lsp`.

### VS Code Extension

**Using the Pre-built VSIX File**

1. Build the LSP server as described above
2. Install the VS Code extension from the `.vsix` file:
   ```bash
   code --install-extension qwasr-lsp-extension.vsix
   ```
   Or manually:
   - Open VS Code
   - Go to Extensions (Cmd+Shift+X)
   - Click "Install from VSIX..."
   - Select the `qwasr-lsp-extension.vsix` file

3. The extension will automatically use the `qwasr-lsp` binary from your `target/release` directory


### Claude Code Integration

> **TODO**: Integration with Claude Code skill for LLM-assisted QWASR development. The `llm` module is already designed to work with Claude Code for structured analysis output.

## Usage

The LSP server communicates over stdin/stdout using the Language Server Protocol.

### Environment Variables

- `RUST_LOG`: Set logging level (e.g., `RUST_LOG=debug`)

## Project Structure

```
lsp/
├── src/
│   ├── main.rs                 # Entry point and LSP server initialization
│   ├── backend.rs              # LSP backend implementation and message routing
│   ├── capabilities.rs         # Server capabilities definition
│   ├── diagnostics.rs          # Diagnostics engine for QWASR issue detection
│   ├── llm.rs                  # LLM-oriented analysis module for Claude Code integration
│   ├── semantic.rs             # Semantic analysis utilities
│   ├── lib.rs                  # Library exports
│   ├── handlers/               # LSP feature handlers
│   │   ├── mod.rs
│   │   ├── completion.rs       # Completion provider implementation
│   │   ├── hover.rs            # Hover documentation provider
│   │   ├── code_action.rs      # Quick fixes and refactoring suggestions
│   │   └── document_symbol.rs  # Document symbol/outline provider
│   └── qwasr/                  # QWASR domain knowledge
│       ├── mod.rs
│       ├── traits.rs           # Provider trait definitions and documentation
│       ├── constraints.rs      # Forbidden patterns and crates database
│       ├── patterns.rs         # Code snippets and templates for common patterns
│       ├── rules.rs            # 50+ comprehensive validation rules
│       └── rules/              # Detailed rule implementations
├── examples/
│   └── semantic_tests.rs       # Example semantic analysis tests
├── Cargo.toml                  # Rust dependencies and project metadata
├── QWASR_RULES_REFERENCE.md   # Detailed reference for all validation rules
└── README.md
```

### Key Modules

- **Backend**: Core LSP message handling and dispatch
- **Diagnostics**: Real-time issue detection for WASM32 and QWASR patterns
- **Handlers**: Implements LSP features (completion, hover, code actions, etc.)
- **QWASR Knowledge Base**: Domain-specific rules, patterns, and validation logic
- **LLM Module**: Structured analysis output for AI-assisted development

## Development

### Running Tests

```bash
cargo test
```

### Debugging

Set the log level for verbose output:

```bash
RUST_LOG=debug cargo run
```

Or when using the compiled binary directly:

```bash
RUST_LOG=debug ./target/release/qwasr-lsp
```

## References

### QWASR Ecosystem

- [QWASR Repository](https://github.com/augentic/qwasr) - Quick WebAssembly Secure Runtime platform
- [QWASR SDK](https://github.com/augentic/qwasr-sdk) - Rust SDK for QWASR component development
- [QWASR Rules Reference](./QWASR_RULES_REFERENCE.md) - Comprehensive validation rules documentation

### Standards and Specifications

- [Language Server Protocol (LSP)](https://microsoft.github.io/language-server-protocol/) - Official LSP specification
- [WebAssembly (WASM)](https://webassembly.org/) - WebAssembly documentation
- [WASI](https://wasi.dev/) - WebAssembly System Interface

### Rust Libraries

- [tower-lsp](https://github.com/ebkalderon/tower-lsp) - Async LSP server framework
- [tower](https://github.com/tower-rs/tower) - Modular and reusable components for building robust clients and servers
- [tokio](https://tokio.rs/) - Async runtime for Rust
- [serde](https://serde.rs/) - Serialization/deserialization framework

### Related Tools

- [rust-analyzer](https://rust-analyzer.github.io/) - Official Rust language server (inspiration)
- [Clippy](https://github.com/rust-lang/rust-clippy) - Official Rust linter (rule patterns)

