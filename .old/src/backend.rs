//! LSP Backend implementation for QWASR-aware language server.

use std::sync::Arc;

use dashmap::DashMap;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer};
use tracing::{debug, info};

use crate::capabilities::server_capabilities;
use crate::diagnostics::DiagnosticsEngine;
use crate::handlers::{CodeActionHandler, CompletionHandler, DocumentSymbolHandler, HoverHandler};
use crate::qwasr::QwasrContext;

/// Document state stored for each open file.
#[derive(Debug)]
pub struct DocumentState {
    pub content: String,
    pub version: i32,
}

/// The main LSP backend for QWASR-aware language support.
pub struct QwasrBackend {
    /// LSP client for sending notifications/requests back to the editor.
    client: Client,

    /// Open documents tracked by the server.
    documents: DashMap<Url, DocumentState>,

    /// QWASR context containing patterns, traits, and rules.
    #[allow(dead_code)]
    qwasr_context: Arc<QwasrContext>,

    /// Diagnostics engine for analyzing code.
    diagnostics_engine: DiagnosticsEngine,

    /// Completion handler.
    completion_handler: CompletionHandler,

    /// Hover handler.
    hover_handler: HoverHandler,

    /// Code action handler.
    code_action_handler: CodeActionHandler,

    /// Document symbol handler.
    document_symbol_handler: DocumentSymbolHandler,
}

impl QwasrBackend {
    /// Create a new QWASR LSP backend.
    pub fn new(client: Client) -> Self {
        let qwasr_context = Arc::new(QwasrContext::new());

        Self {
            client,
            documents: DashMap::new(),
            qwasr_context: Arc::clone(&qwasr_context),
            diagnostics_engine: DiagnosticsEngine::new(Arc::clone(&qwasr_context)),
            completion_handler: CompletionHandler::new(Arc::clone(&qwasr_context)),
            hover_handler: HoverHandler::new(Arc::clone(&qwasr_context)),
            code_action_handler: CodeActionHandler::new(Arc::clone(&qwasr_context)),
            document_symbol_handler: DocumentSymbolHandler::new(Arc::clone(&qwasr_context)),
        }
    }

    /// Analyze a document and publish diagnostics.
    async fn analyze_document(&self, uri: &Url) {
        if let Some(doc) = self.documents.get(uri) {
            let diagnostics = self.diagnostics_engine.analyze(&doc.content, uri);

            self.client
                .publish_diagnostics(uri.clone(), diagnostics, Some(doc.version))
                .await;
        }
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for QwasrBackend {
    async fn initialize(&self, _params: InitializeParams) -> Result<InitializeResult> {
        info!("QWASR LSP Server initializing");

        Ok(InitializeResult {
            capabilities: server_capabilities(),
            server_info: Some(ServerInfo {
                name: "qwasr-lsp".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
        })
    }

    async fn initialized(&self, _params: InitializedParams) {
        info!("QWASR LSP Server initialized");

        self.client
            .log_message(MessageType::INFO, "QWASR LSP Server ready")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        info!("QWASR LSP Server shutting down");
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        debug!("Document opened: {}", params.text_document.uri);

        self.documents.insert(
            params.text_document.uri.clone(),
            DocumentState {
                content: params.text_document.text,
                version: params.text_document.version,
            },
        );

        self.analyze_document(&params.text_document.uri).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        debug!("Document changed: {}", params.text_document.uri);

        if let Some(mut doc) = self.documents.get_mut(&params.text_document.uri) {
            // Apply changes (we use full sync, so take the last change)
            if let Some(change) = params.content_changes.into_iter().last() {
                doc.content = change.text;
                doc.version = params.text_document.version;
            }
        }

        self.analyze_document(&params.text_document.uri).await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        debug!("Document closed: {}", params.text_document.uri);

        self.documents.remove(&params.text_document.uri);

        // Clear diagnostics for closed document
        self.client
            .publish_diagnostics(params.text_document.uri, vec![], None)
            .await;
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        debug!("Document saved: {}", params.text_document.uri);

        // Re-analyze on save
        self.analyze_document(&params.text_document.uri).await;
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;

        if let Some(doc) = self.documents.get(uri) {
            return Ok(self.hover_handler.hover(&doc.content, position));
        }

        Ok(None)
    }

    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        let uri = &params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;

        if let Some(doc) = self.documents.get(uri) {
            let items = self.completion_handler.complete(&doc.content, position);
            if !items.is_empty() {
                return Ok(Some(CompletionResponse::Array(items)));
            }
        }

        Ok(None)
    }

    async fn code_action(&self, params: CodeActionParams) -> Result<Option<CodeActionResponse>> {
        let uri = &params.text_document.uri;

        if let Some(doc) = self.documents.get(uri) {
            let actions = self.code_action_handler.actions(
                &doc.content,
                uri,
                &params.range,
                &params.context.diagnostics,
            );
            if !actions.is_empty() {
                return Ok(Some(actions));
            }
        }

        Ok(None)
    }

    async fn document_symbol(
        &self,
        params: DocumentSymbolParams,
    ) -> Result<Option<DocumentSymbolResponse>> {
        let uri = &params.text_document.uri;

        if let Some(doc) = self.documents.get(uri) {
            let symbols = self
                .document_symbol_handler
                .symbols_with_uri(&doc.content, Some(uri.clone()));
            if !symbols.is_empty() {
                return Ok(Some(DocumentSymbolResponse::Flat(symbols)));
            }
        }

        Ok(None)
    }
}
