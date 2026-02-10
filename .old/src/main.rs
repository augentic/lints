//! QWASR-aware Language Server Protocol implementation.
//!
//! This LSP server provides intelligent assistance for Rust code targeting the QWASR
//! (Quick WebAssembly Secure Runtime) platform.

use anyhow::Result;
use tower_lsp::{LspService, Server};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

mod backend;
mod capabilities;
mod diagnostics;
mod handlers;
pub mod llm;
mod qwasr;
mod semantic;

// Re-export linter from the library
pub use qwasr_lsp::linter;

use crate::backend::QwasrBackend;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();

    info!("Starting QWASR LSP Server");

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::build(QwasrBackend::new).finish();

    Server::new(stdin, stdout, socket).serve(service).await;

    Ok(())
}
