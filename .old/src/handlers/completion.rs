//! Completion provider for QWASR patterns.

use std::sync::Arc;

use tower_lsp::lsp_types::*;

use crate::qwasr::{code_snippets, QwasrContext};

/// Handler for completion requests.
pub struct CompletionHandler {
    context: Arc<QwasrContext>,
}

impl CompletionHandler {
    /// Create a new completion handler.
    pub fn new(context: Arc<QwasrContext>) -> Self {
        Self { context }
    }

    /// Provide completions at the given position.
    pub fn complete(&self, content: &str, position: Position) -> Vec<CompletionItem> {
        let mut items = Vec::new();

        let line = match content.lines().nth(position.line as usize) {
            Some(l) => l,
            None => return items,
        };

        let prefix = &line[..position.character as usize];

        // Provider trait completions
        if prefix.contains("impl") && prefix.contains("Handler") {
            items.extend(self.provider_trait_bounds_completions());
        }

        // Error macro completions
        if prefix.trim_end().ends_with("Err(") || prefix.contains("return Err") {
            items.extend(self.error_macro_completions());
        }

        // Provider method completions
        if prefix.contains("::") {
            let parts: Vec<&str> = prefix.split("::").collect();
            if let Some(trait_name) = parts.iter().rev().nth(1) {
                let trait_name = trait_name.split_whitespace().last().unwrap_or(*trait_name);
                if let Some(provider_trait) = self.context.get_provider_trait(trait_name) {
                    items.extend(self.provider_method_completions(provider_trait));
                }
            }
        }

        // Snippet completions (always available)
        if prefix.trim().is_empty() || prefix.ends_with(' ') || prefix.ends_with('\t') {
            items.extend(self.snippet_completions());
        }

        // Import completions
        if prefix.starts_with("use qwasr_sdk") || prefix.contains("use qwasr_sdk") {
            items.extend(self.qwasr_import_completions());
        }

        items
    }

    /// Provide completions for provider trait bounds.
    fn provider_trait_bounds_completions(&self) -> Vec<CompletionItem> {
        self.context
            .provider_traits
            .iter()
            .map(|t| CompletionItem {
                label: t.name.to_string(),
                kind: Some(CompletionItemKind::INTERFACE),
                detail: Some(t.description.to_string()),
                documentation: Some(Documentation::MarkupContent(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: format!(
                        "**{}**\n\n{}\n\n*WASI Module:* `{}`",
                        t.name, t.description, t.wasi_module
                    ),
                })),
                insert_text: Some(t.name.to_string()),
                insert_text_format: Some(InsertTextFormat::PLAIN_TEXT),
                ..Default::default()
            })
            .collect()
    }

    /// Provide completions for error macros.
    fn error_macro_completions(&self) -> Vec<CompletionItem> {
        self.context
            .error_macros
            .iter()
            .map(|m| {
                let macro_name = m.name.trim_end_matches('!');
                CompletionItem {
                    label: m.name.to_string(),
                    kind: Some(CompletionItemKind::SNIPPET),
                    detail: Some(format!("HTTP {}", m.status_code)),
                    documentation: Some(Documentation::MarkupContent(MarkupContent {
                        kind: MarkupKind::Markdown,
                        value: format!(
                            "**{}** (HTTP {})\n\n**Use for:** {}\n\n**Example:**\n```rust\n{}\n```",
                            m.name, m.status_code, m.use_for, m.example
                        ),
                    })),
                    insert_text: Some(format!("{}!(\"${{1:message}}\")", macro_name)),
                    insert_text_format: Some(InsertTextFormat::SNIPPET),
                    ..Default::default()
                }
            })
            .collect()
    }

    /// Provide completions for provider methods.
    fn provider_method_completions(
        &self,
        provider_trait: &crate::qwasr::ProviderTrait,
    ) -> Vec<CompletionItem> {
        provider_trait
            .methods
            .iter()
            .map(|m| CompletionItem {
                label: m.name.to_string(),
                kind: Some(CompletionItemKind::METHOD),
                detail: Some(m.signature.to_string()),
                documentation: Some(Documentation::MarkupContent(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: format!(
                        "**{}**\n\n```rust\n{}\n```\n\n{}\n\n**Example:**\n```rust\n{}\n```",
                        m.name, m.signature, m.description, m.example
                    ),
                })),
                insert_text: Some(self.method_snippet(m)),
                insert_text_format: Some(InsertTextFormat::SNIPPET),
                ..Default::default()
            })
            .collect()
    }

    /// Generate a snippet for a method call.
    fn method_snippet(&self, method: &crate::qwasr::TraitMethod) -> String {
        match method.name {
            "get" if method.signature.contains("key: &str") && method.signature.contains("Option<Vec<u8>>") => {
                "get(provider, \"${1:key}\").await?".to_string()
            }
            "get" if method.signature.contains("key: &str") && method.signature.contains("Result<String>") => {
                "get(provider, \"${1:KEY}\").await?".to_string()
            }
            "set" => "set(provider, \"${1:key}\", &${2:value}, ${3:Some(3600)}).await?".to_string(),
            "delete" => "delete(provider, \"${1:key}\").await?".to_string(),
            "fetch" => "fetch(provider, ${1:request}).await?".to_string(),
            "send" => "send(provider, \"${1:topic}\", &${2:message}).await?".to_string(),
            "access_token" => "access_token(provider, ${1:identity}).await?".to_string(),
            "query" => "query(provider, \"${1:db}\".to_string(), \"${2:SELECT * FROM}\".to_string(), vec![]).await?".to_string(),
            "exec" => "exec(provider, \"${1:db}\".to_string(), \"${2:INSERT INTO}\".to_string(), vec![]).await?".to_string(),
            _ => format!("{}(${{1:}})", method.name),
        }
    }

    /// Provide snippet completions for common QWASR patterns.
    fn snippet_completions(&self) -> Vec<CompletionItem> {
        code_snippets()
            .into_iter()
            .map(|s| CompletionItem {
                label: s.label.to_string(),
                kind: Some(CompletionItemKind::SNIPPET),
                detail: Some(s.description.to_string()),
                documentation: Some(Documentation::MarkupContent(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: format!("**{}**\n\n{}", s.label, s.description),
                })),
                insert_text: Some(s.template.to_string()),
                insert_text_format: Some(InsertTextFormat::SNIPPET),
                filter_text: Some(s.id.to_string()),
                sort_text: Some(format!("0_{}", s.id)), // Sort snippets first
                ..Default::default()
            })
            .collect()
    }

    /// Provide import completions for qwasr_sdk.
    fn qwasr_import_completions(&self) -> Vec<CompletionItem> {
        let imports = vec![
            ("Config", "Provider trait for configuration"),
            ("HttpRequest", "Provider trait for HTTP requests"),
            ("Publisher", "Provider trait for message publishing"),
            ("StateStore", "Provider trait for caching/KV"),
            ("Identity", "Provider trait for authentication"),
            ("TableStore", "Provider trait for SQL operations"),
            ("Handler", "Core handler trait"),
            ("Context", "Request context type"),
            ("Reply", "Response wrapper type"),
            ("Error", "SDK error type"),
            ("Result", "SDK result type alias"),
            ("Message", "Message type for Publisher"),
            ("bad_request", "Error macro for 400 responses"),
            ("server_error", "Error macro for 500 responses"),
            ("bad_gateway", "Error macro for 502 responses"),
        ];

        imports
            .into_iter()
            .map(|(name, desc)| CompletionItem {
                label: name.to_string(),
                kind: Some(if name.chars().next().unwrap().is_uppercase() {
                    CompletionItemKind::STRUCT
                } else {
                    CompletionItemKind::FUNCTION
                }),
                detail: Some(desc.to_string()),
                insert_text: Some(name.to_string()),
                ..Default::default()
            })
            .collect()
    }
}
