//! Code action provider for QWASR fixes.

use std::sync::Arc;

use tower_lsp::lsp_types::*;

use crate::qwasr::QwasrContext;

/// Handler for code action requests.
pub struct CodeActionHandler {
    #[allow(dead_code)]
    context: Arc<QwasrContext>,
}

impl CodeActionHandler {
    /// Create a new code action handler.
    pub fn new(context: Arc<QwasrContext>) -> Self {
        Self { context }
    }

    /// Provide code actions for the given range and diagnostics.
    pub fn actions(
        &self,
        content: &str,
        uri: &Url,
        range: &Range,
        diagnostics: &[Diagnostic],
    ) -> CodeActionResponse {
        let mut actions = Vec::new();

        // Generate fixes for each diagnostic
        for diagnostic in diagnostics {
            if diagnostic.source.as_deref() != Some("qwasr") {
                continue;
            }

            if let Some(code) = &diagnostic.code {
                let code_str = match code {
                    NumberOrString::String(s) => s.as_str(),
                    NumberOrString::Number(_) => {
                        // Skip numeric codes
                        continue;
                    }
                };

                if let Some(action) = self.fix_for_diagnostic(content, uri, diagnostic, code_str) {
                    actions.push(action);
                }
            }
        }

        // Add refactoring actions based on context
        actions.extend(self.refactoring_actions(content, uri, range));

        actions
    }

    /// Generate a fix for a specific diagnostic.
    fn fix_for_diagnostic(
        &self,
        content: &str,
        uri: &Url,
        diagnostic: &Diagnostic,
        code: &str,
    ) -> Option<CodeActionOrCommand> {
        match code {
            "std_env" => Some(self.fix_std_env(uri, diagnostic)),
            "std_time_system" => Some(self.fix_system_time(uri, diagnostic)),
            "println_debug" => Some(self.fix_println(content, uri, diagnostic)),
            "panic_unwrap" => Some(self.fix_unwrap(content, uri, diagnostic)),
            "forbidden_crate" => self.fix_forbidden_crate(content, uri, diagnostic),
            _ => None,
        }
    }

    /// Fix std::env usage by suggesting Config provider.
    fn fix_std_env(&self, uri: &Url, diagnostic: &Diagnostic) -> CodeActionOrCommand {
        CodeActionOrCommand::CodeAction(CodeAction {
            title: "Replace with Config::get()".to_string(),
            kind: Some(CodeActionKind::QUICKFIX),
            diagnostics: Some(vec![diagnostic.clone()]),
            edit: Some(WorkspaceEdit {
                changes: Some(
                    [(
                        uri.clone(),
                        vec![TextEdit {
                            range: diagnostic.range,
                            new_text: "Config::get(provider, \"KEY\").await?".to_string(),
                        }],
                    )]
                    .into_iter()
                    .collect(),
                ),
                ..Default::default()
            }),
            is_preferred: Some(true),
            ..Default::default()
        })
    }

    /// Fix SystemTime usage by suggesting chrono.
    fn fix_system_time(&self, uri: &Url, diagnostic: &Diagnostic) -> CodeActionOrCommand {
        CodeActionOrCommand::CodeAction(CodeAction {
            title: "Replace with chrono::Utc::now()".to_string(),
            kind: Some(CodeActionKind::QUICKFIX),
            diagnostics: Some(vec![diagnostic.clone()]),
            edit: Some(WorkspaceEdit {
                changes: Some(
                    [(
                        uri.clone(),
                        vec![TextEdit {
                            range: diagnostic.range,
                            new_text: "chrono::Utc::now()".to_string(),
                        }],
                    )]
                    .into_iter()
                    .collect(),
                ),
                ..Default::default()
            }),
            is_preferred: Some(true),
            ..Default::default()
        })
    }

    /// Fix println/eprintln by suggesting tracing macros.
    fn fix_println(
        &self,
        content: &str,
        uri: &Url,
        diagnostic: &Diagnostic,
    ) -> CodeActionOrCommand {
        let line = content
            .lines()
            .nth(diagnostic.range.start.line as usize)
            .unwrap_or("");

        let new_macro = if line.contains("eprintln!") || line.contains("error") {
            "error!"
        } else if line.contains("dbg!") {
            "debug!"
        } else {
            "info!"
        };

        // Extract the content inside the macro
        let new_text = if line.contains("println!(") {
            line.replace("println!(", &format!("{}(", new_macro))
        } else if line.contains("eprintln!(") {
            line.replace("eprintln!(", &format!("{}(", new_macro))
        } else if line.contains("dbg!(") {
            // dbg! has different semantics, just suggest replacing
            format!("{}(\"value: {{:?}}\", value);", new_macro)
        } else {
            return CodeActionOrCommand::CodeAction(CodeAction {
                title: format!("Replace with {}(...)", new_macro),
                kind: Some(CodeActionKind::QUICKFIX),
                diagnostics: Some(vec![diagnostic.clone()]),
                ..Default::default()
            });
        };

        CodeActionOrCommand::CodeAction(CodeAction {
            title: format!("Replace with {}", new_macro),
            kind: Some(CodeActionKind::QUICKFIX),
            diagnostics: Some(vec![diagnostic.clone()]),
            edit: Some(WorkspaceEdit {
                changes: Some(
                    [(
                        uri.clone(),
                        vec![TextEdit {
                            range: Range {
                                start: Position {
                                    line: diagnostic.range.start.line,
                                    character: 0,
                                },
                                end: Position {
                                    line: diagnostic.range.start.line,
                                    character: line.len() as u32,
                                },
                            },
                            new_text,
                        }],
                    )]
                    .into_iter()
                    .collect(),
                ),
                ..Default::default()
            }),
            is_preferred: Some(true),
            ..Default::default()
        })
    }

    /// Fix unwrap/expect by suggesting ? operator.
    fn fix_unwrap(&self, content: &str, uri: &Url, diagnostic: &Diagnostic) -> CodeActionOrCommand {
        let line = content
            .lines()
            .nth(diagnostic.range.start.line as usize)
            .unwrap_or("");

        // Simple heuristic replacement
        let new_text = line
            .replace(".unwrap()", "?")
            .replace(".expect(\"", ".context(\"")
            .replace("\")", "\")?");

        CodeActionOrCommand::CodeAction(CodeAction {
            title: "Replace with ? operator".to_string(),
            kind: Some(CodeActionKind::QUICKFIX),
            diagnostics: Some(vec![diagnostic.clone()]),
            edit: Some(WorkspaceEdit {
                changes: Some(
                    [(
                        uri.clone(),
                        vec![TextEdit {
                            range: Range {
                                start: Position {
                                    line: diagnostic.range.start.line,
                                    character: 0,
                                },
                                end: Position {
                                    line: diagnostic.range.start.line,
                                    character: line.len() as u32,
                                },
                            },
                            new_text,
                        }],
                    )]
                    .into_iter()
                    .collect(),
                ),
                ..Default::default()
            }),
            is_preferred: Some(true),
            ..Default::default()
        })
    }

    /// Fix forbidden crate usage.
    fn fix_forbidden_crate(
        &self,
        _content: &str,
        uri: &Url,
        diagnostic: &Diagnostic,
    ) -> Option<CodeActionOrCommand> {
        // Extract the crate name from the diagnostic message
        let crate_name = if diagnostic.message.contains("'") {
            diagnostic.message.split('\'').nth(1).map(|s| s.to_string())
        } else {
            None
        }?;

        // Suggest removing the use statement
        Some(CodeActionOrCommand::CodeAction(CodeAction {
            title: format!("Remove forbidden '{}' import", crate_name),
            kind: Some(CodeActionKind::QUICKFIX),
            diagnostics: Some(vec![diagnostic.clone()]),
            edit: Some(WorkspaceEdit {
                changes: Some(
                    [(
                        uri.clone(),
                        vec![TextEdit {
                            range: Range {
                                start: Position {
                                    line: diagnostic.range.start.line,
                                    character: 0,
                                },
                                end: Position {
                                    line: diagnostic.range.start.line + 1,
                                    character: 0,
                                },
                            },
                            new_text: String::new(), // Remove the line
                        }],
                    )]
                    .into_iter()
                    .collect(),
                ),
                ..Default::default()
            }),
            ..Default::default()
        }))
    }

    /// Provide refactoring actions based on context.
    fn refactoring_actions(
        &self,
        content: &str,
        _uri: &Url,
        range: &Range,
    ) -> Vec<CodeActionOrCommand> {
        let mut actions = Vec::new();

        let line = match content.lines().nth(range.start.line as usize) {
            Some(l) => l,
            None => return actions,
        };

        // Suggest extracting business logic from handler
        if line.contains("async fn handle") {
            actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                title: "Extract business logic to separate function".to_string(),
                kind: Some(CodeActionKind::REFACTOR_EXTRACT),
                ..Default::default()
            }));
        }

        // Suggest adding provider trait bounds
        if line.contains("fn ") && line.contains("<P>") && !line.contains("where") {
            actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                title: "Add provider trait bounds".to_string(),
                kind: Some(CodeActionKind::REFACTOR),
                ..Default::default()
            }));
        }

        // Suggest implementing Handler trait for a struct
        if line.contains("pub struct") && line.contains("Request") {
            actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                title: "Implement Handler trait".to_string(),
                kind: Some(CodeActionKind::REFACTOR),
                ..Default::default()
            }));
        }

        actions
    }
}
