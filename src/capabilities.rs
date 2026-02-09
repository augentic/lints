//! LSP Server capabilities configuration.

use tower_lsp::lsp_types::*;

/// Returns the server capabilities for the QWASR LSP.
pub fn server_capabilities() -> ServerCapabilities {
    ServerCapabilities {
        // Full text document sync
        text_document_sync: Some(TextDocumentSyncCapability::Options(
            TextDocumentSyncOptions {
                open_close: Some(true),
                change: Some(TextDocumentSyncKind::FULL),
                will_save: Some(false),
                will_save_wait_until: Some(false),
                save: Some(TextDocumentSyncSaveOptions::SaveOptions(SaveOptions {
                    include_text: Some(true),
                })),
            },
        )),

        // Hover support for QWASR traits and patterns
        hover_provider: Some(HoverProviderCapability::Simple(true)),

        // Completion support for QWASR patterns
        completion_provider: Some(CompletionOptions {
            resolve_provider: Some(false),
            trigger_characters: Some(vec![
                ":".to_string(),
                ".".to_string(),
                "<".to_string(),
                "!".to_string(),
            ]),
            work_done_progress_options: WorkDoneProgressOptions::default(),
            all_commit_characters: None,
            completion_item: None,
        }),

        // Code actions for QWASR fixes
        code_action_provider: Some(CodeActionProviderCapability::Options(CodeActionOptions {
            code_action_kinds: Some(vec![
                CodeActionKind::QUICKFIX,
                CodeActionKind::REFACTOR,
                CodeActionKind::SOURCE,
            ]),
            work_done_progress_options: WorkDoneProgressOptions::default(),
            resolve_provider: Some(false),
        })),

        // Document symbols for Handler implementations
        document_symbol_provider: Some(OneOf::Left(true)),

        // Diagnostics are published asynchronously via didOpen/didChange handlers
        // We use push-based diagnostics only, not pull-based
        diagnostic_provider: None,

        ..Default::default()
    }
}
