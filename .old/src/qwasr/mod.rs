//! QWASR context and knowledge base.
//!
//! This module contains the core knowledge about QWASR patterns, traits,
//! constraints, and rules that the LSP uses for analysis.

mod constraints;
mod patterns;
pub mod rules;
mod traits;

pub use constraints::*;
pub use patterns::*;
#[allow(unused_imports)]
pub use rules::{provider_trait_docs, HandlerRules, ProviderTraitDoc, Rule, RuleCategory, RuleSet, RuleSeverity};
pub use traits::*;

use std::collections::HashSet;

/// The central QWASR context containing all knowledge needed for analysis.
#[derive(Debug)]
pub struct QwasrContext {
    /// Provider traits available in QWASR SDK.
    pub provider_traits: Vec<ProviderTrait>,

    /// Error macros available in QWASR SDK.
    pub error_macros: Vec<ErrorMacro>,

    /// Forbidden crates that cannot be used in WASM32 code.
    pub forbidden_crates: HashSet<String>,

    /// Forbidden patterns (global state, OS APIs, etc.).
    pub forbidden_patterns: Vec<ForbiddenPattern>,

    /// Handler trait information.
    pub handler_trait: HandlerTraitInfo,
}

impl QwasrContext {
    /// Create a new QWASR context with all known patterns and rules.
    pub fn new() -> Self {
        Self {
            provider_traits: provider_traits(),
            error_macros: error_macros(),
            forbidden_crates: forbidden_crates(),
            forbidden_patterns: forbidden_patterns(),
            handler_trait: handler_trait_info(),
        }
    }

    /// Check if a crate name is forbidden in WASM32 code.
    pub fn is_forbidden_crate(&self, crate_name: &str) -> bool {
        self.forbidden_crates.contains(crate_name)
    }

    /// Get the provider trait by name.
    pub fn get_provider_trait(&self, name: &str) -> Option<&ProviderTrait> {
        self.provider_traits.iter().find(|t| t.name == name)
    }

    /// Get the error macro by name.
    pub fn get_error_macro(&self, name: &str) -> Option<&ErrorMacro> {
        self.error_macros.iter().find(|m| m.name == name)
    }
}

impl Default for QwasrContext {
    fn default() -> Self {
        Self::new()
    }
}
