//! QWASR code patterns and templates.

/// Information about a QWASR error macro.
#[derive(Debug, Clone)]
pub struct ErrorMacro {
    /// Name of the macro.
    pub name: &'static str,

    /// Full path to the macro.
    #[allow(dead_code)]
    pub path: &'static str,

    /// HTTP status code this maps to.
    pub status_code: u16,

    /// When to use this macro.
    pub use_for: &'static str,

    /// Example usage.
    pub example: &'static str,
}

/// Returns all known QWASR error macros.
pub fn error_macros() -> Vec<ErrorMacro> {
    vec![
        ErrorMacro {
            name: "bad_request!",
            path: "qwasr_sdk::bad_request",
            status_code: 400,
            use_for: "Input validation failures, missing required fields, invalid format, parsing failures",
            example: r#"Err(bad_request!("vehicle_id is required"))"#,
        },
        ErrorMacro {
            name: "server_error!",
            path: "qwasr_sdk::server_error",
            status_code: 500,
            use_for: "Internal invariant violations, unexpected states, serialization errors",
            example: r#"Err(server_error!("unexpected state: {}", state))"#,
        },
        ErrorMacro {
            name: "bad_gateway!",
            path: "qwasr_sdk::bad_gateway",
            status_code: 502,
            use_for: "Upstream API failures, external service errors, dependency failures",
            example: r#"Err(bad_gateway!("upstream request failed: {err}"))"#,
        },
    ]
}

/// Code snippet templates for QWASR patterns.
#[derive(Debug, Clone)]
pub struct CodeSnippet {
    /// Snippet identifier.
    pub id: &'static str,

    /// Display label.
    pub label: &'static str,

    /// Description.
    pub description: &'static str,

    /// The code template.
    pub template: &'static str,
}

/// Returns available code snippets for QWASR patterns.
pub fn code_snippets() -> Vec<CodeSnippet> {
    vec![
        CodeSnippet {
            id: "handler_impl",
            label: "Handler Implementation",
            description: "Implement the Handler trait for a request type",
            template: r#"impl<P: ${1:Config}> Handler<P> for ${2:MyRequest} {
    type Error = Error;
    type Input = Vec<u8>;
    type Output = ${3:MyResponse};

    fn from_input(input: Self::Input) -> Result<Self> {
        serde_json::from_slice(&input)
            .context("deserializing ${2:MyRequest}")
            .map_err(Into::into)
    }

    async fn handle(self, ctx: Context<'_, P>) -> Result<Reply<${3:MyResponse}>> {
        ${0:// Implementation}
        Ok(Reply::ok(${3:MyResponse} { /* fields */ }))
    }
}"#,
        },
        CodeSnippet {
            id: "request_struct",
            label: "Request Struct",
            description: "Define a strongly-typed request struct",
            template: r#"#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ${1:MyRequest} {
    ${0:// fields}
}"#,
        },
        CodeSnippet {
            id: "response_struct",
            label: "Response Struct",
            description: "Define a strongly-typed response struct",
            template: r#"#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ${1:MyResponse} {
    ${0:// fields}
}"#,
        },
        CodeSnippet {
            id: "provider_bounds",
            label: "Provider Trait Bounds",
            description: "Add provider trait bounds to a function",
            template: r#"async fn ${1:my_function}<P>(provider: &P, ${2:args}) -> Result<${3:ReturnType}>
where
    P: ${4:Config + HttpRequest},
{
    ${0:// Implementation}
}"#,
        },
        CodeSnippet {
            id: "http_fetch",
            label: "HTTP Fetch",
            description: "Make an HTTP request using HttpRequest provider",
            template: r#"let request = http::Request::builder()
    .uri("${1:https://api.example.com}")
    .method(http::Method::${2:GET})
    .body(http_body_util::Empty::<Bytes>::new())?;

let response = HttpRequest::fetch(provider, request)
    .await
    .context("${3:fetching data}")?;

let body: ${4:ResponseType} = serde_json::from_slice(response.body())
    .context("parsing response")?;"#,
        },
        CodeSnippet {
            id: "config_get",
            label: "Config Get",
            description: "Get a configuration value",
            template: r#"let ${1:value} = Config::get(provider, "${2:KEY}")
    .await
    .context("getting ${2:KEY}")?;"#,
        },
        CodeSnippet {
            id: "publish_message",
            label: "Publish Message",
            description: "Publish a message using Publisher provider",
            template: r#"let message = Message::new(&serde_json::to_vec(&${1:payload})?);
Publisher::send(provider, "${2:topic-name}", &message)
    .await
    .context("publishing to ${2:topic-name}")?;"#,
        },
        CodeSnippet {
            id: "state_cache",
            label: "State Store Cache",
            description: "Cache a value using StateStore provider",
            template: r#"// Try to get from cache
if let Some(cached) = StateStore::get(provider, "${1:cache-key}").await? {
    return serde_json::from_slice(&cached).context("deserializing cached value");
}

// Compute value
let value = ${2:compute_value()};

// Store in cache with TTL
let serialized = serde_json::to_vec(&value)?;
StateStore::set(provider, "${1:cache-key}", &serialized, Some(${3:3600})).await?;

Ok(value)"#,
        },
        CodeSnippet {
            id: "error_domain",
            label: "Domain Error Enum",
            description: "Define a domain-specific error enum with stable codes",
            template: r#"#[derive(Error, Debug)]
pub enum ${1:DomainError} {
    #[error("${2:description}: {0}")]
    ${3:VariantName}(String),
}

impl ${1:DomainError} {
    fn code(&self) -> &'static str {
        match self {
            Self::${3:VariantName}(_) => "${4:error_code}",
        }
    }
}

impl From<${1:DomainError}> for qwasr_sdk::Error {
    fn from(err: ${1:DomainError}) -> Self {
        match &err {
            ${1:DomainError}::${3:VariantName}(_) => Self::BadRequest {
                code: err.code().to_string(),
                description: err.to_string(),
            },
        }
    }
}"#,
        },
    ]
}
