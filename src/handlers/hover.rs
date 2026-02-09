//! Hover provider for QWASR documentation.

use std::sync::Arc;

use tower_lsp::lsp_types::*;

use crate::qwasr::{provider_trait_docs, QwasrContext};

/// Handler for hover requests.
pub struct HoverHandler {
    context: Arc<QwasrContext>,
}

impl HoverHandler {
    /// Create a new hover handler.
    pub fn new(context: Arc<QwasrContext>) -> Self {
        Self { context }
    }

    /// Provide hover information at the given position.
    pub fn hover(&self, content: &str, position: Position) -> Option<Hover> {
        let line = content.lines().nth(position.line as usize)?;
        let word = self.get_word_at_position(line, position.character as usize)?;

        // Check if hovering over a provider trait using enhanced documentation
        for trait_doc in provider_trait_docs() {
            if word == trait_doc.name {
                return Some(self.create_enhanced_provider_trait_hover(&trait_doc));
            }
        }

        // Check if hovering over a provider trait (fallback to context)
        if let Some(provider_trait) = self.context.get_provider_trait(&word) {
            return Some(self.create_provider_trait_hover(provider_trait));
        }

        // Check if hovering over an error macro
        if word.ends_with('!') {
            let macro_name = word.trim_end_matches('!');
            if let Some(error_macro) = self.context.get_error_macro(&format!("{}!", macro_name)) {
                return Some(self.create_error_macro_hover(error_macro));
            }
        }

        // Check for known QWASR types and keywords
        match word.as_str() {
            "Handler" => Some(self.create_handler_trait_hover()),
            "Context" => Some(self.create_context_hover()),
            "Reply" => Some(self.create_reply_hover()),
            "Message" => Some(self.create_message_hover()),
            "Result" => Some(self.create_result_hover()),
            "Error" => Some(self.create_error_hover()),
            "from_input" => Some(self.create_from_input_hover()),
            "handle" => Some(self.create_handle_hover()),
            "bad_request" => {
                Some(self.create_error_macro_hover(self.context.get_error_macro("bad_request!")?))
            }
            "server_error" => {
                Some(self.create_error_macro_hover(self.context.get_error_macro("server_error!")?))
            }
            "bad_gateway" => {
                Some(self.create_error_macro_hover(self.context.get_error_macro("bad_gateway!")?))
            }
            _ => None,
        }
    }

    /// Extract the word at the given position in a line.
    fn get_word_at_position(&self, line: &str, char_pos: usize) -> Option<String> {
        if char_pos >= line.len() {
            return None;
        }

        let chars: Vec<char> = line.chars().collect();

        // Find word boundaries
        let mut start = char_pos;
        while start > 0 && (chars[start - 1].is_alphanumeric() || chars[start - 1] == '_') {
            start -= 1;
        }

        let mut end = char_pos;
        while end < chars.len()
            && (chars[end].is_alphanumeric() || chars[end] == '_' || chars[end] == '!')
        {
            end += 1;
        }

        if start == end {
            return None;
        }

        Some(chars[start..end].iter().collect())
    }

    /// Create enhanced hover content for a provider trait using the rules module.
    fn create_enhanced_provider_trait_hover(
        &self,
        trait_doc: &crate::qwasr::ProviderTraitDoc,
    ) -> Hover {
        let mut content = format!(
            "## {}\n\n{}\n\n### Methods\n\n",
            trait_doc.name, trait_doc.description
        );

        for method in &trait_doc.methods {
            content.push_str(&format!(
                "#### `{}`\n\n```rust\n{}\n```\n\n{}\n\n**Example:**\n```rust\n{}\n```\n\n---\n\n",
                method.name, method.signature, method.description, method.example
            ));
        }

        content.push_str("### Full Example\n\n```rust\n");
        content.push_str(trait_doc.example);
        content.push_str("\n```\n");

        Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: content,
            }),
            range: None,
        }
    }

    /// Create hover content for a provider trait.
    fn create_provider_trait_hover(&self, trait_info: &crate::qwasr::ProviderTrait) -> Hover {
        let mut content = format!(
            "## {}\n\n{}\n\n**WASI Module:** `{}`\n\n### Methods\n\n",
            trait_info.name, trait_info.description, trait_info.wasi_module
        );

        for method in &trait_info.methods {
            content.push_str(&format!(
                "#### `{}`\n\n```rust\n{}\n```\n\n{}\n\n**Example:**\n```rust\n{}\n```\n\n",
                method.name, method.signature, method.description, method.example
            ));
        }

        Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: content,
            }),
            range: None,
        }
    }

    /// Create hover content for an error macro.
    fn create_error_macro_hover(&self, macro_info: &crate::qwasr::ErrorMacro) -> Hover {
        let content = format!(
            "## `{}`\n\n**HTTP Status:** {}\n\n### When to Use\n\n{}\n\n### Example\n\n```rust\n{}\n```\n",
            macro_info.name, macro_info.status_code, macro_info.use_for, macro_info.example
        );

        Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: content,
            }),
            range: None,
        }
    }

    /// Create hover content for the Handler trait.
    fn create_handler_trait_hover(&self) -> Hover {
        let info = &self.context.handler_trait;

        let mut content = String::from("## Handler Trait\n\n");
        content.push_str("The core trait for implementing request handlers in QWASR.\n\n");
        content.push_str("### Definition\n\n```rust\n");
        content.push_str(info.definition);
        content.push_str("\n```\n\n### Associated Types\n\n");

        for (name, desc) in &info.associated_types {
            content.push_str(&format!("- **`{}`**: {}\n", name, desc));
        }

        content.push_str("\n### Methods\n\n");
        for (name, sig, desc) in &info.methods {
            content.push_str(&format!(
                "#### `{}`\n\n```rust\n{}\n```\n\n{}\n\n",
                name, sig, desc
            ));
        }

        content.push_str("### Best Practices\n\n");
        content.push_str(
            "1. **Validate in `from_input`**: Parse and validate input early to fail fast\n",
        );
        content
            .push_str("2. **Keep `handle` focused**: Delegate complex logic to helper functions\n");
        content.push_str(
            "3. **Minimal bounds**: Only declare provider traits that are actually used\n",
        );
        content.push_str("4. **Semantic Reply**: Use `Reply::ok`, `Reply::created`, or `Reply::accepted` appropriately\n\n");

        content.push_str("### Example\n\n```rust\n");
        content.push_str(info.example);
        content.push_str("\n```\n");

        Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: content,
            }),
            range: None,
        }
    }

    /// Create hover content for from_input method.
    fn create_from_input_hover(&self) -> Hover {
        let content = r#"## `from_input`

The first method called in the Handler lifecycle. Parses raw input into the request type.

### Signature

```rust
fn from_input(input: Self::Input) -> Result<Self>
```

### Purpose

- Deserialize raw bytes (`Vec<u8>`) into the request struct
- Perform validation on input data
- Return errors early for malformed requests

### Best Practices

```rust
fn from_input(input: Self::Input) -> Result<Self> {
    // Parse JSON
    let req: Self = serde_json::from_slice(&input)
        .context("deserializing request")?;
    
    // Validate required fields
    if req.name.is_empty() {
        return Err(bad_request!("name is required"));
    }
    
    // Validate business rules
    if req.quantity < 1 {
        return Err(bad_request!("quantity must be at least 1"));
    }
    
    Ok(req)
}
```

### Note

This method is **synchronous** - it cannot access providers or perform async operations.
All validation should be based on the input data alone.
"#;

        Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: content.to_string(),
            }),
            range: None,
        }
    }

    /// Create hover content for handle method.
    fn create_handle_hover(&self) -> Hover {
        let content = r#"## `handle`

The main business logic method in the Handler trait. Processes the request and returns a response.

### Signature

```rust
async fn handle(self, ctx: Context<'_, P>) -> Result<Reply<Self::Output>>
```

### Purpose

- Execute business logic
- Access external services via provider traits
- Return appropriate responses

### Parameters

- `self` - The validated request (from `from_input`)
- `ctx` - Request context containing:
  - `ctx.owner` - Tenant/namespace identifier
  - `ctx.provider` - Provider implementation (P)
  - `ctx.headers` - HTTP request headers

### Best Practices

```rust
async fn handle(self, ctx: Context<'_, P>) -> Result<Reply<Self::Output>> {
    // Use ctx.provider for external operations
    let config = ctx.provider.get("API_KEY")
        .ok_or_else(|| server_error!("API_KEY not configured"))?;
    
    // Delegate complex logic
    let result = process_request(&self, ctx.provider).await?;
    
    // Return appropriate response
    Ok(Reply::ok(MyResponse { result }))
}
```

### Note

- Always use provider traits for external I/O
- Prefer returning proper error types over panicking
- Keep the handler focused; extract business logic to helper functions
"#;

        Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: content.to_string(),
            }),
            range: None,
        }
    }

    /// Create hover content for Context.
    fn create_context_hover(&self) -> Hover {
        let content = r#"## Context<'a, P>

Request-scoped context passed to Handler::handle().

### Fields

- **`owner`**: `&'a str` - The owning tenant/namespace for the request
- **`provider`**: `&'a P` - The provider implementation used to fulfill the request
- **`headers`**: `&'a HeaderMap<String>` - Request headers

### Usage

```rust
async fn handle(self, ctx: Context<'_, P>) -> Result<Reply<MyResponse>> {
    // Access the provider
    let config = ctx.provider.get("KEY");
    
    // Access the owner (tenant identifier)
    let owner = ctx.owner;
    
    // Access headers
    let auth = ctx.headers.get("authorization");
    
    // ...
}
```

### LLM Note

The Context provides access to:
1. **Provider** (`ctx.provider`) - For all external I/O operations
2. **Owner** (`ctx.owner`) - For tenant isolation and scoping
3. **Headers** (`ctx.headers`) - For custom request metadata
"#;

        Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: content.to_string(),
            }),
            range: None,
        }
    }

    /// Create hover content for Result type.
    fn create_result_hover(&self) -> Hover {
        let content = r#"## Result<T>

QWASR uses `qwasr_sdk::Result<T>` which is `std::result::Result<T, qwasr_sdk::Error>`.

### Usage

```rust
use qwasr_sdk::{Result, Error};

// Function returning QWASR Result
async fn process() -> Result<MyResponse> {
    // Use ? operator for error propagation
    let data = fetch_data().await?;
    Ok(MyResponse { data })
}
```

### Error Propagation

Use the `?` operator with `.context()` for descriptive errors:

```rust
let user = get_user(id)
    .await
    .context("fetching user")?;
```

### Creating Errors

Use the error macros:
- `bad_request!("message")` → 400 Bad Request
- `server_error!("message")` → 500 Internal Server Error
- `bad_gateway!("message")` → 502 Bad Gateway
"#;

        Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: content.to_string(),
            }),
            range: None,
        }
    }

    /// Create hover content for Error type.
    fn create_error_hover(&self) -> Hover {
        let content = r#"## qwasr_sdk::Error

The error type used in QWASR handlers. Maps to HTTP status codes.

### Creation

Use the error macros:

```rust
// 400 Bad Request
Err(bad_request!("invalid input: {}", reason))

// 500 Internal Server Error
Err(server_error!("failed to process: {}", err))

// 502 Bad Gateway
Err(bad_gateway!("upstream service error: {}", err))
```

### From Conversion

Standard errors can be converted:

```rust
let data: MyData = serde_json::from_slice(&bytes)?;
// If this fails, converts to 500 Internal Server Error
```

### With Context

Add context to errors for better debugging:

```rust
use anyhow::Context;

let result = operation()
    .await
    .context("while processing request")?;
```

### LLM Note

Always use `qwasr_sdk::Error` in public APIs, not `anyhow::Error`.
The error macros ensure proper HTTP status code mapping.
"#;

        Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: content.to_string(),
            }),
            range: None,
        }
    }

    /// Create hover content for Reply.
    fn create_reply_hover(&self) -> Hover {
        let content = r#"## Reply<B>

Top-level response data structure common to all handlers.

### Fields

- **`status`**: `StatusCode` - HTTP status code
- **`headers`**: `HeaderMap` - Response headers
- **`body`**: `B` - Response body

### Constructors

```rust
// 200 OK
Reply::ok(body)

// 201 Created
Reply::created(body)

// 202 Accepted
Reply::accepted(body)

// Custom status
Reply::ok(body).status(StatusCode::NO_CONTENT)
```

### From Conversion

Response types can be converted to Reply using `.into()`:

```rust
async fn handle(self, ctx: Context<'_, P>) -> Result<Reply<MyResponse>> {
    let response = MyResponse { /* ... */ };
    Ok(response.into())  // Converts to Reply::ok(response)
}
```
"#;

        Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: content.to_string(),
            }),
            range: None,
        }
    }

    /// Create hover content for Message.
    fn create_message_hover(&self) -> Hover {
        let content = r#"## Message

Represents a message to be published via the Publisher provider trait.

### Fields

- **`payload`**: `Vec<u8>` - The message payload
- **`headers`**: `HashMap<String, String>` - Message headers

### Usage

```rust
use qwasr_sdk::{Message, Publisher};

let message = Message::new(&serde_json::to_vec(&data)?);
Publisher::send(provider, "my-topic", &message).await?;
```
"#;

        Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: content.to_string(),
            }),
            range: None,
        }
    }
}
