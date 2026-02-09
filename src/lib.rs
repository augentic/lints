//! QWASR Language Server Protocol library.
//!
//! This crate provides the core LSP functionality for QWASR-aware
//! language support in Rust code targeting WebAssembly.

pub mod linter {
    //! Re-exports of linter functionality.
    //!
    //! This module provides access to the QWASR linter rules and analysis
    //! for use in the LSP and other tools.

    pub use crate::qwasr::rules::{Rule, RuleCategory, RuleSet, RuleSeverity};
}

mod qwasr;
mod semantic;

// Re-export semantic analysis types
pub use semantic::{HandlerInfo, SemanticAnalysisResult, SemanticAnalyzer, TraitUsage};
