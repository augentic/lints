//! LSP handlers for various features.

mod code_action;
mod completion;
mod document_symbol;
mod hover;

pub use code_action::CodeActionHandler;
pub use completion::CompletionHandler;
pub use document_symbol::DocumentSymbolHandler;
pub use hover::HoverHandler;
