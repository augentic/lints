//! Document symbol provider for QWASR code.

use std::sync::Arc;

use regex::Regex;
use tower_lsp::lsp_types::*;

use crate::qwasr::QwasrContext;

/// Handler for document symbol requests.
pub struct DocumentSymbolHandler {
    #[allow(dead_code)]
    context: Arc<QwasrContext>,
}

impl DocumentSymbolHandler {
    /// Create a new document symbol handler.
    pub fn new(context: Arc<QwasrContext>) -> Self {
        Self { context }
    }

    /// Extract document symbols from the content.
    pub fn symbols(&self, content: &str) -> Vec<SymbolInformation> {
        self.symbols_with_uri(content, None)
    }

    /// Extract document symbols from the content with a specific URI.
    pub fn symbols_with_uri(&self, content: &str, uri: Option<Url>) -> Vec<SymbolInformation> {
        let mut symbols = Vec::new();

        // Use a default URI if none provided
        let document_uri = uri.unwrap_or_else(|| Url::parse("file:///unknown").unwrap());

        // Regex patterns for finding QWASR-relevant symbols
        let handler_impl_re =
            Regex::new(r"impl\s*<[^>]*>\s*Handler\s*<[^>]*>\s*for\s+(\w+)").unwrap();
        let struct_re = Regex::new(r"pub\s+struct\s+(\w+)").unwrap();
        let provider_impl_re = Regex::new(r"impl\s+(?:qwasr_sdk::)?(\w+)\s+for\s+(\w+)").unwrap();
        let async_fn_re = Regex::new(r"(?:pub\s+)?async\s+fn\s+(\w+)").unwrap();

        for (line_idx, line) in content.lines().enumerate() {
            let char_count = line.len().max(1) as u32;
            let location = Location {
                uri: document_uri.clone(),
                range: Range {
                    start: Position {
                        line: line_idx as u32,
                        character: 0,
                    },
                    end: Position {
                        line: line_idx as u32,
                        character: char_count,
                    },
                },
            };

            // Handler implementations
            if let Some(caps) = handler_impl_re.captures(line) {
                if let Some(type_match) = caps.get(1) {
                    #[allow(deprecated)]
                    symbols.push(SymbolInformation {
                        name: format!("Handler<P> for {}", type_match.as_str()),
                        kind: SymbolKind::INTERFACE,
                        tags: None,
                        deprecated: None,
                        location: location.clone(),
                        container_name: None,
                    });
                }
            }

            // Request/Response structs
            if let Some(caps) = struct_re.captures(line) {
                if let Some(name_match) = caps.get(1) {
                    let name = name_match.as_str();
                    if name.ends_with("Request") || name.ends_with("Response") {
                        let kind = if name.ends_with("Request") {
                            SymbolKind::STRUCT
                        } else {
                            SymbolKind::STRUCT
                        };

                        #[allow(deprecated)]
                        symbols.push(SymbolInformation {
                            name: name.to_string(),
                            kind,
                            tags: None,
                            deprecated: None,
                            location: location.clone(),
                            container_name: None,
                        });
                    }
                }
            }

            // Provider trait implementations
            if let Some(caps) = provider_impl_re.captures(line) {
                let trait_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let type_name = caps.get(2).map(|m| m.as_str()).unwrap_or("");

                // Check if it's a known provider trait
                let is_provider_trait = matches!(
                    trait_name,
                    "Config"
                        | "HttpRequest"
                        | "Publisher"
                        | "StateStore"
                        | "Identity"
                        | "TableStore"
                );

                if is_provider_trait {
                    #[allow(deprecated)]
                    symbols.push(SymbolInformation {
                        name: format!("{} for {}", trait_name, type_name),
                        kind: SymbolKind::INTERFACE,
                        tags: None,
                        deprecated: None,
                        location: location.clone(),
                        container_name: Some("Provider Traits".to_string()),
                    });
                }
            }

            // Async handler functions
            if let Some(caps) = async_fn_re.captures(line) {
                if let Some(name_match) = caps.get(1) {
                    let name = name_match.as_str();
                    // Skip common non-handler functions
                    if name != "main" && name != "new" && name != "default" {
                        #[allow(deprecated)]
                        symbols.push(SymbolInformation {
                            name: format!("async fn {}", name),
                            kind: SymbolKind::FUNCTION,
                            tags: None,
                            deprecated: None,
                            location: location.clone(),
                            container_name: None,
                        });
                    }
                }
            }
        }

        symbols
    }
}
