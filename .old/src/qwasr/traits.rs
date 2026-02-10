//! QWASR provider traits definitions.

/// Information about a QWASR provider trait.
#[derive(Debug, Clone)]
pub struct ProviderTrait {
    /// Name of the trait (e.g., "Config", "HttpRequest").
    pub name: &'static str,

    /// Full path to the trait.
    #[allow(dead_code)]
    pub path: &'static str,

    /// Purpose/description of the trait.
    pub description: &'static str,

    /// Associated WASI module.
    pub wasi_module: &'static str,

    /// Methods provided by the trait.
    pub methods: Vec<TraitMethod>,
}

/// Information about a trait method.
#[derive(Debug, Clone)]
pub struct TraitMethod {
    /// Name of the method.
    pub name: &'static str,

    /// Method signature.
    pub signature: &'static str,

    /// Description of what the method does.
    pub description: &'static str,

    /// Example usage.
    pub example: &'static str,
}

/// Returns all known QWASR provider traits.
pub fn provider_traits() -> Vec<ProviderTrait> {
    vec![
        ProviderTrait {
            name: "Config",
            path: "qwasr_sdk::Config",
            description: "Read configuration values from WASI config.",
            wasi_module: "qwasr_wasi_config",
            methods: vec![TraitMethod {
                name: "get",
                signature: "async fn get(&self, key: &str) -> Result<String>",
                description: "Get a configuration value by key.",
                example: r#"let url = Config::get(provider, "API_URL").await?;"#,
            }],
        },
        ProviderTrait {
            name: "HttpRequest",
            path: "qwasr_sdk::HttpRequest",
            description: "Make outbound HTTP requests via WASI HTTP.",
            wasi_module: "qwasr_wasi_http",
            methods: vec![TraitMethod {
                name: "fetch",
                signature:
                    "async fn fetch<T>(&self, request: Request<T>) -> Result<Response<Bytes>>",
                description: "Make an outbound HTTP request.",
                example: r#"let response = HttpRequest::fetch(provider, request).await?;"#,
            }],
        },
        ProviderTrait {
            name: "Publisher",
            path: "qwasr_sdk::Publisher",
            description: "Publish messages to topics via WASI messaging.",
            wasi_module: "qwasr_wasi_messaging",
            methods: vec![TraitMethod {
                name: "send",
                signature: "async fn send(&self, topic: &str, message: &Message) -> Result<()>",
                description: "Publish a message to a topic.",
                example: r#"Publisher::send(provider, "my-topic", &message).await?;"#,
            }],
        },
        ProviderTrait {
            name: "StateStore",
            path: "qwasr_sdk::StateStore",
            description: "Cache/KV operations via WASI keyvalue.",
            wasi_module: "qwasr_wasi_keyvalue",
            methods: vec![
                TraitMethod {
                    name: "get",
                    signature: "async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>",
                    description: "Retrieve a value from the state store.",
                    example: r#"let value = StateStore::get(provider, "key").await?;"#,
                },
                TraitMethod {
                    name: "set",
                    signature: "async fn set(&self, key: &str, value: &[u8], ttl_secs: Option<u64>) -> Result<Option<Vec<u8>>>",
                    description: "Store a value in the state store with optional TTL.",
                    example: r#"StateStore::set(provider, "key", &data, Some(3600)).await?;"#,
                },
                TraitMethod {
                    name: "delete",
                    signature: "async fn delete(&self, key: &str) -> Result<()>",
                    description: "Delete a value from the state store.",
                    example: r#"StateStore::delete(provider, "key").await?;"#,
                },
            ],
        },
        ProviderTrait {
            name: "Identity",
            path: "qwasr_sdk::Identity",
            description: "Get authentication tokens via WASI identity.",
            wasi_module: "qwasr_wasi_identity",
            methods: vec![TraitMethod {
                name: "access_token",
                signature: "async fn access_token(&self, identity: String) -> Result<String>",
                description: "Get an access token for the specified identity.",
                example: r#"let token = Identity::access_token(provider, identity).await?;"#,
            }],
        },
        ProviderTrait {
            name: "TableStore",
            path: "qwasr_sdk::TableStore",
            description: "SQL database operations via WASI SQL ORM.",
            wasi_module: "qwasr_wasi_sql",
            methods: vec![
                TraitMethod {
                    name: "query",
                    signature: "fn query(&self, cnn_name: String, query: String, params: Vec<DataType>) -> FutureResult<Vec<Row>>",
                    description: "Execute a SQL query and return rows.",
                    example: r#"let rows = TableStore::query(provider, "db", "SELECT * FROM users WHERE id = ?", vec![id.into()]).await?;"#,
                },
                TraitMethod {
                    name: "exec",
                    signature: "fn exec(&self, cnn_name: String, query: String, params: Vec<DataType>) -> FutureResult<u32>",
                    description: "Execute a SQL statement and return affected row count.",
                    example: r#"let count = TableStore::exec(provider, "db", "DELETE FROM users WHERE id = ?", vec![id.into()]).await?;"#,
                },
            ],
        },
    ]
}

/// Information about the Handler trait.
#[derive(Debug, Clone)]
pub struct HandlerTraitInfo {
    /// Full trait definition.
    pub definition: &'static str,

    /// Associated types.
    pub associated_types: Vec<(&'static str, &'static str)>,

    /// Required methods.
    pub methods: Vec<(&'static str, &'static str, &'static str)>,

    /// Example implementation.
    pub example: &'static str,
}

/// Returns Handler trait information.
pub fn handler_trait_info() -> HandlerTraitInfo {
    HandlerTraitInfo {
        definition: r#"pub trait Handler<P: Provider>: Sized {
    type Input;
    type Output: Body;
    type Error: Error + Send + Sync;

    fn from_input(input: Self::Input) -> Result<Self, Self::Error>;
    fn handle(self, ctx: Context<P>) -> impl Future<Output = Result<Reply<Self::Output>, Self::Error>> + Send;
}"#,
        associated_types: vec![
            ("Input", "The raw input type (usually Vec<u8>)"),
            ("Output", "The response type (must implement Body)"),
            ("Error", "The error type (usually qwasr_sdk::Error)"),
        ],
        methods: vec![
            (
                "from_input",
                "fn from_input(input: Self::Input) -> Result<Self, Self::Error>",
                "Parse and validate the input into the request type",
            ),
            (
                "handle",
                "async fn handle(self, ctx: Context<P>) -> Result<Reply<Self::Output>, Self::Error>",
                "Process the request and return a response",
            ),
        ],
        example: r#"impl<P: Config + HttpRequest> Handler<P> for MyRequest {
    type Error = Error;
    type Input = Vec<u8>;
    type Output = MyResponse;

    fn from_input(input: Self::Input) -> Result<Self> {
        serde_json::from_slice(&input)
            .context("deserializing MyRequest")
            .map_err(Into::into)
    }

    async fn handle(self, ctx: Context<'_, P>) -> Result<Reply<MyResponse>> {
        let result = process_request(ctx.provider, &self).await?;
        Ok(Reply::ok(result))
    }
}"#,
    }
}
