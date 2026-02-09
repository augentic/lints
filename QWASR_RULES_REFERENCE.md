# QWASR LSP Rules Reference

This document provides a comprehensive reference of all validation rules enforced by the QWASR Language Server Protocol (LSP). The LSP analyzes Rust code for WASM32 handler development and enforces best practices across **15 categories**.

---

## Table of Contents

1. [Handler Rules](#1-handler-rules)
2. [Provider Rules](#2-provider-rules)
3. [Semantic Analysis Rules](#3-semantic-analysis-rules) 
4. [Context Rules](#4-context-rules)
5. [Error Handling Rules](#5-error-handling-rules)
6. [Response Rules](#6-response-rules)
7. [WASM Compatibility Rules](#7-wasm-compatibility-rules)
8. [Statelessness Rules](#8-statelessness-rules)
9. [Performance Rules](#9-performance-rules)
10. [Security Rules](#10-security-rules)
11. [Strong Typing Rules](#11-strong-typing-rules)
12. [Time Rules](#12-time-rules)
13. [Auth Rules](#13-auth-rules)
14. [Caching Rules](#14-caching-rules)
15. [Forbidden Crates](#15-forbidden-crates)
16. [Forbidden Patterns](#16-forbidden-patterns)
17. [Provider Traits Reference](#17-provider-traits-reference)
18. [Error Macros Reference](#18-error-macros-reference)

---

## Severity Levels

| Level | Description |
|-------|-------------|
| **Error** | Code will not work or violates critical constraints |
| **Warning** | Code may have issues or deviates from best practices |
| **Info** | Informational guidance for better code patterns |
| **Hint** | Suggestions for improvement |

---

## 1. Handler Rules

Rules governing the implementation of the `Handler` trait.

| Rule ID | Name | Severity | Description | Fix Template |
|---------|------|----------|-------------|--------------|
| `handler_generic_p` | Handler Generic Parameter | Error | Handler implementations must use a generic parameter `P` for provider type, enabling runtime to inject implementations | `impl<P: TraitBounds> Handler<P> for RequestType` |
| `handler_from_input_result` | from_input Returns Result | Error | The `from_input` method must return `Result<Self>` to properly handle deserialization errors | `fn from_input(input: Self::Input) -> Result<Self>` |
| `handler_serde_deserialize` | Request Derives Deserialize | Error | Request types must derive `Deserialize` for `from_input` parsing | `#[derive(Clone, Debug, Deserialize, Serialize)]` |
| `handler_async_handle` | Handle Method is Async | Error | The `handle` method must be `async` to support asynchronous provider operations | `async fn handle(self, ctx: Context<'_, P>) -> Result<Reply<Self::Output>>` |
| `handler_context_lifetime` | Context Lifetime Parameter | Warning | Context should use the elided lifetime `Context<'_, P>` for clarity | `Context<'_, P>` |
| `handler_output_type` | Handler Output Type Definition | Error | Handler must define `type Output = ResponseType;` to specify the response type | `type Output = ResponseType;` |
| `handler_error_type` | Handler Error Type | Warning | Handler should use `type Error = qwasr_sdk::Error` for proper HTTP status mapping | `type Error = Error;` |
| `handler_input_vec_u8` | Handler Input Type | Info | Handler Input is typically `Vec<u8>` for raw bytes from HTTP body | `type Input = Vec<u8>;` |

### Handler Required Types

| Type Name | Typical Value | Description |
|-----------|---------------|-------------|
| `Error` | `qwasr_sdk::Error` | Error type for handler operations. Must support HTTP status code mapping |
| `Input` | `Vec<u8>` | Raw input type, typically `Vec<u8>` for HTTP body bytes |
| `Output` | `ResponseType` | Response type that will be serialized to JSON |

### Handler Required Methods

| Method | Async | Signature | Description |
|--------|-------|-----------|-------------|
| `from_input` | No | `fn from_input(input: Self::Input) -> Result<Self>` | Parse raw input bytes into the request type |
| `handle` | Yes | `async fn handle(self, ctx: Context<'_, P>) -> Result<Reply<Self::Output>>` | Process the request and return a response |

### Handler Best Practices

| Practice | Description |
|----------|-------------|
| Validate in `from_input` | Add validation after deserialization to fail fast on invalid input |
| Extract business logic | Extract complex logic to separate async functions for testability |
| Use appropriate Reply | Use semantic Reply constructors: `ok` for GET, `created` for POST, `accepted` for async |
| Minimal bounds | Only declare provider traits that are actually used in the handler |

---

## 2. Provider Rules

Rules for using Provider traits correctly.

| Rule ID | Name | Severity | Description | Fix Template |
|---------|------|----------|-------------|--------------|
| `provider_config_get` | Config::get Usage | Info | Use Config trait to retrieve configuration values. Returns `Option<String>` | `let value = ctx.provider.get("KEY").ok_or_else(\|\| bad_request!("missing config"))?;` |
| `provider_config_hardcode` | Avoid Hardcoded Config | Warning | Configuration values should come from the Config provider, not hardcoded strings | `let api_key = ctx.provider.get("API_KEY").ok_or_else(\|\| bad_request!("missing API_KEY"))?;` |
| `provider_http_request_fetch` | HttpRequest::fetch Usage | Info | Use HttpRequest trait for external HTTP calls with proper request building | See code example below |
| `provider_direct_http` | Avoid Direct HTTP | Error | HTTP requests must go through HttpRequest provider, not direct clients like `reqwest`/`hyper` | Use `ctx.provider.fetch()` from HttpRequest trait |
| `provider_publisher_send` | Publisher::send Usage | Info | Use Publisher trait to send events/messages to external systems | `ctx.provider.send("topic", payload).await?;` |
| `provider_statestore_get` | StateStore::get Usage | Info | Use StateStore trait for key-value state access | `let value = ctx.provider.get(key).await?;` |
| `provider_statestore_set` | StateStore::set Usage | Info | Use `StateStore::set` for storing state with optional TTL | `ctx.provider.set(key, value.as_bytes(), Some(ttl)).await?;` |
| `provider_tablestore_query` | TableStore::query Usage | Info | Use TableStore for structured data queries | `ctx.provider.query("SELECT * FROM table WHERE id = $1", &[("$1", id)]).await?;` |
| `provider_tablestore_exec` | TableStore::exec Usage | Info | Use `TableStore::exec` for data mutations | `ctx.provider.exec("INSERT INTO table ...", &params).await?;` |
| `provider_identity_token` | Identity::access_token Usage | Info | Use Identity trait to get OAuth/auth tokens for external services | `let token = ctx.provider.access_token("service-name").await?;` |
| `provider_bounds_minimal` | Minimal Provider Bounds | Warning | Declare only the provider traits that are actually used in the handler | Only include traits that are actually used: `P: Config + HttpRequest` |

### HTTP Fetch Example

```rust
let response = ctx.provider.fetch(Request {
    method: "GET",
    url: &url,
    headers: &[("Authorization", &token)],
    body: None,
}).await?;
```

---

## 3. Semantic Analysis Rules ⭐ NEW

The LSP performs **deep semantic analysis** to understand provider trait bounds and usage patterns. These rules detect mismatches between declared bounds and actual trait usage, with **automatic quick fixes**.

### Handler Provider Bound Analysis

| Rule ID | Name | Severity | Description | Quick Fix |
|---------|------|----------|-------------|-----------|
| `unused_provider_bound` | Unused Provider Trait Bound | Warning | A provider trait is declared in the Handler bounds but never used in the impl | ✅ **Auto-fix:** Remove unused trait from bounds |
| `missing_provider_bound` | Missing Provider Trait Bound | Error | Handler uses a provider trait method but doesn't declare the trait in bounds | ✅ **Auto-fix:** Add missing trait to bounds |

#### Example: Unused Bound Detection

```rust
// ⚠️ WARNING: Publisher is declared but never used
impl<P: Config + HttpRequest + Publisher> Handler<P> for MyRequest {
    async fn handle(self, ctx: Context<'_, P>) -> Result<Reply<Self::Output>> {
        let url = ctx.provider.get("API_URL")?;        // Uses Config
        let response = ctx.provider.fetch(...).await?;  // Uses HttpRequest
        // Publisher is never used!
        Ok(Reply::ok(response))
    }
}

// ✅ FIXED: Remove unused Publisher bound
impl<P: Config + HttpRequest> Handler<P> for MyRequest { ... }
```

#### Example: Missing Bound Detection

```rust
// ❌ ERROR: Uses StateStore but doesn't declare it
impl<P: Config> Handler<P> for CacheRequest {
    async fn handle(self, ctx: Context<'_, P>) -> Result<Reply<Self::Output>> {
        let cached = ctx.provider.get("key").await?;  // Calls StateStore::get!
        Ok(Reply::ok(cached))
    }
}

// ✅ FIXED: Add StateStore to bounds
impl<P: Config + StateStore> Handler<P> for CacheRequest { ... }
```

### Helper Function Provider Bound Analysis

The semantic analyzer also checks async helper functions that take a provider parameter.

| Rule ID | Name | Severity | Description | Quick Fix |
|---------|------|----------|-------------|-----------|
| `unused_fn_provider_bound` | Unused Function Provider Bound | Warning | A helper function declares a provider trait bound that isn't used | ✅ **Auto-fix:** Remove unused trait from function signature |
| `missing_fn_provider_bound` | Missing Function Provider Bound | Error | A helper function uses a provider trait but doesn't declare it | ✅ **Auto-fix:** Add missing trait to function signature |

#### Example: Helper Function Analysis

```rust
// ⚠️ WARNING: TableStore bound is unused in this function
async fn fetch_data<P: HttpRequest + TableStore>(provider: &P) -> Result<Data> {
    let response = provider.fetch(request).await?;  // Only uses HttpRequest
    Ok(response)
}

// ✅ FIXED: Remove unused TableStore
async fn fetch_data<P: HttpRequest>(provider: &P) -> Result<Data> { ... }
```

### StateStore TTL Analysis

| Rule ID | Name | Severity | Description | Quick Fix |
|---------|------|----------|-------------|-----------|
| `statestore_no_ttl` | StateStore::set Without TTL | Warning | `StateStore::set` called with `None` TTL may cause unbounded cache growth | ✅ **Auto-fix:** Add `Some(Duration::from_secs(3600))` |

#### Example: TTL Warning

```rust
// ⚠️ WARNING: No TTL set - cache may grow unbounded
ctx.provider.set("key", value.as_bytes(), None).await?;

// ✅ FIXED: Add TTL for automatic expiration
ctx.provider.set("key", value.as_bytes(), Some(Duration::from_secs(3600))).await?;
```

### Error Context Hints

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| `config_error_handling` | Config::get Error Handling | Hint | `Config::get` returns Result - consider using `?` or `.ok_or_else()` |
| `fetch_error_context` | HttpRequest::fetch Error Context | Hint | Consider adding `.context("...")` for better error messages |

### Automatic Fix Summary

All semantic analysis diagnostics include **exact fix data** that can be applied with a single click:

| Fix Type | What It Does |
|----------|--------------|
| `remove_unused_bound` | Removes the unused trait from Handler impl bounds |
| `add_missing_bound` | Adds the missing trait to Handler impl bounds |
| `remove_unused_fn_bound` | Removes unused trait from function generics |
| `add_missing_fn_bound` | Adds missing trait to function generics |
| `add_ttl` | Replaces `None` TTL with `Some(Duration::from_secs(3600))` |

### How Trait Usage Is Detected

The semantic analyzer recognizes the following patterns for each provider trait:

| Trait | Detection Patterns |
|-------|-------------------|
| **Config** | `provider.get("KEY")`, `Config::get(...)` |
| **HttpRequest** | `provider.fetch(...)`, `HttpRequest::fetch(...)` |
| **Publisher** | `provider.send(...)`, `Publisher::send(...)` |
| **StateStore** | `provider.get(...).await`, `provider.set(...).await`, `provider.delete(...).await`, `StateStore::*` |
| **Identity** | `provider.access_token(...)`, `Identity::access_token(...)` |
| **TableStore** | `provider.query(...)`, `provider.exec(...)`, `TableStore::*` |

---

## 4. Context Rules

Rules for accessing the Context object.

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| `context_owner` | Context Owner Access | Info | `ctx.owner` provides the authenticated user/tenant identifier |
| `context_headers` | Context Headers Access | Info | `ctx.headers` provides access to HTTP request headers |

---

## 5. Error Handling Rules

Comprehensive rules for proper error handling in QWASR handlers.

| Rule ID | Name | Severity | Description | Fix Template |
|---------|------|----------|-------------|--------------|
| `error_bad_request` | bad_request! Macro | Info | Use `bad_request!()` for client errors (400). Takes format string | `bad_request!("validation failed: {}", reason)` |
| `error_server_error` | server_error! Macro | Info | Use `server_error!()` for internal errors (500). Takes format string | `server_error!("internal error: {}", err)` |
| `error_bad_gateway` | bad_gateway! Macro | Info | Use `bad_gateway!()` for upstream service errors (502). Takes format string | `bad_gateway!("upstream error: {}", err)` |
| `error_anyhow_context` | anyhow::Context Usage | Info | Use `.context()` to add context to errors before propagating with `?` | `.context("descriptive error message")` |
| `error_generic_unwrap` | Avoid unwrap/expect | Warning | Avoid `.unwrap()` and `.expect()` as they cause panics. Use `?` operator | `.ok_or_else(\|\| bad_request!("error message"))?` |
| `error_panic_macro` | Avoid panic! Macro | Error | Never use `panic!` in WASM handlers - it aborts the entire component | Return `Err(server_error!("reason"))` instead |
| `error_unreachable` | Avoid unreachable! Macro | Error | Never use `unreachable!` in WASM handlers | Use an explicit error return instead |
| `error_todo` | Avoid todo! Macro | Warning | `todo!` causes panics - replace with proper error handling or implementation | Implement the missing functionality or return an error |
| `error_assert` | No assert! in Handlers | Error | `assert!` causes panics which abort WASM execution | `if !condition { return Err(bad_request!("validation failed")); }` |
| `error_assert_eq` | No assert_eq! in Handlers | Error | `assert_eq!` causes panics which abort WASM execution | `if a != b { return Err(bad_request!("mismatch")); }` |
| `error_debug_assert` | No debug_assert! in Handlers | Warning | `debug_assert!` can cause panics in debug builds | Remove or convert to explicit error check |
| `error_missing_context_serde` | Serde Deserialize Without Context | Warning | `serde_json::from_*` should use `.context()` for meaningful error messages | `serde_json::from_slice(&data).context("deserializing MyType")?` |
| `error_missing_context_parse` | Parse Without Context | Warning | Parsing operations should use `.context()` for meaningful error messages | `.parse().context("parsing field_name")?` |
| `error_dynamic_code` | Error Code Should Be Static | Warning | Error codes should be stable static strings, not dynamically generated with `format!` | `code: "error_code".to_string()` |
| `error_anyhow_in_handler` | Use qwasr_sdk::Error | Warning | Handler Error type should be `qwasr_sdk::Error` for proper HTTP status mapping | `type Error = qwasr_sdk::Error;` |
| `error_impl_from_required` | Domain Error Missing From impl | Info | Domain error enums should implement `From<DomainError> for qwasr_sdk::Error` | `impl From<DomainError> for qwasr_sdk::Error { ... }` |
| `error_map_to_bad_request` | Map Parsing Errors to BadRequest | Info | Parsing/validation errors should map to `bad_request!` (400), not `server_error!` (500) | Use `bad_request!("invalid input: {}", err)` |
| `error_map_to_bad_gateway` | Map Upstream Errors to BadGateway | Info | External service/API errors should map to `bad_gateway!` (502), not `server_error!` (500) | Use `bad_gateway!("upstream failed: {}", err)` |
| `error_result_map_err` | Use map_err for Error Conversion | Info | Use `.map_err(Into::into)` or `.map_err(\|e\| bad_request!(...))` for explicit error conversion | N/A |

---

## 6. Response Rules

Rules for constructing HTTP responses.

| Rule ID | Name | Severity | Description | Fix Template |
|---------|------|----------|-------------|--------------|
| `response_reply_ok` | Reply::ok Usage | Info | Use `Reply::ok(response)` for successful responses (200 OK) | `Reply::ok(ResponseType { /* fields */ })` |
| `response_reply_created` | Reply::created Usage | Info | Use `Reply::created(response)` for resource creation (201 Created) | `Reply::created(ResponseType { id })` |
| `response_reply_accepted` | Reply::accepted Usage | Info | Use `Reply::accepted(response)` for async processing (202 Accepted) | `Reply::accepted(ResponseType { job_id })` |
| `response_into` | Response Into Reply | Info | Response types can use `.into()` to convert to Reply | `Ok(response.into())` |

---

## 7. WASM Compatibility Rules

Critical rules for WASM32 compatibility.

| Rule ID | Name | Severity | Description | Fix Template |
|---------|------|----------|-------------|--------------|
| `wasm_std_fs` | No std::fs | Error | `std::fs` is not available in WASM32. Use provider abstractions | Use StateStore or TableStore provider |
| `wasm_std_net` | No std::net | Error | `std::net` is not available in WASM32. Use HttpRequest provider | Use HttpRequest provider for network access |
| `wasm_std_thread` | No std::thread | Error | `std::thread` is not available in WASM32. Use async/await | Use async/await for concurrency |
| `wasm_std_env` | No std::env | Error | `std::env` is not available in WASM32. Use Config provider | Use Config provider for environment variables |
| `wasm_std_process` | No std::process | Error | `std::process` is not available in WASM32 | N/A |
| `wasm_std_time_instant` | No std::time::Instant | Error | `std::time::Instant` is not available in WASM32 | N/A |
| `wasm_64bit_integer` | Prefer 32-bit Integers | Warning | WASM32 is a 32-bit environment. `i64`/`u64` operations are emulated and slower | Use `i32`/`u32` if the value range allows |
| `wasm_128bit_integer` | Avoid 128-bit Integers | Warning | WASM32 does not natively support 128-bit integers. `i128`/`u128` are heavily emulated and slow | Use smaller integer types |
| `wasm_isize_usize` | Avoid isize/usize for Data | Hint | `isize`/`usize` vary by platform. Use explicit `i32`/`u32` for data that crosses API boundaries | Use `i32`/`u32` for API data, keep `usize` only for indexing |

---

## 8. Statelessness Rules

QWASR handlers must be stateless. These rules enforce that constraint.

| Rule ID | Name | Severity | Description | Fix Template |
|---------|------|----------|-------------|--------------|
| `stateless_static_mut` | No static mut | Error | `static mut` creates global mutable state. QWASR handlers must be stateless | Use StateStore provider for state persistence |
| `stateless_lazy_static` | No lazy_static | Error | `lazy_static` creates global state. Not allowed in QWASR | Pass state through Context or use StateStore |
| `stateless_once_cell` | No OnceCell/OnceLock | Error | `OnceCell`/`OnceLock` create global state. Not allowed in QWASR | Use StateStore provider |
| `stateless_lazy_lock` | No LazyLock | Error | `LazyLock` (std 1.80+) creates global state which is forbidden in QWASR WASM | Use Config provider trait instead |
| `stateless_arc_mutex` | Avoid Arc<Mutex> | Warning | `Arc<Mutex<T>>` suggests shared mutable state. Use StateStore instead | Use StateStore provider for shared state |
| `stateless_mutex` | Avoid Mutex/RwLock | Warning | `Mutex` and `RwLock` create shared mutable state. WASM is single-threaded | Use StateStore provider for shared state |

---

## 9. Performance Rules

Hints and warnings for performance optimization.

| Rule ID | Name | Severity | Description | Fix Template |
|---------|------|----------|-------------|--------------|
| `perf_clone_in_loop` | Avoid Clone in Loop | Hint | Cloning inside loops may be inefficient. Consider borrowing | Use references or move ownership |
| `perf_string_add` | Prefer format! Over String Concatenation | Hint | String concatenation with `+` is inefficient | `format!("{}{}", a, b)` |
| `perf_unbounded_query` | Query Without Limit | Warning | Database queries should have a limit to prevent unbounded result sets | Add `LIMIT` clause or use `.limit()` method |
| `perf_format_in_loop` | Avoid format! in Loops | Hint | `format!` allocates - consider preallocating strings outside loops | Preallocate String and use `push_str` |
| `perf_collect_count` | Use Iterator::count | Hint | Use `.count()` instead of `.collect::<Vec<_>>().len()` to avoid allocation | `.count()` |

---

## 10. Security Rules

Critical security rules.

| Rule ID | Name | Severity | Description | Fix Template |
|---------|------|----------|-------------|--------------|
| `security_hardcoded_secret` | No Hardcoded Secrets | Error | Secrets must come from Config provider, never hardcoded | `let secret = ctx.provider.get("SECRET_KEY")?;` |
| `security_sql_concat` | Avoid SQL String Concatenation | Error | Never concatenate SQL strings - use parameterized queries | `ctx.provider.query("SELECT * FROM t WHERE id = $1", &[("$1", id)])` |

---

## 11. Strong Typing Rules

Rules encouraging type-safe code patterns.

| Rule ID | Name | Severity | Description | Fix Template |
|---------|------|----------|-------------|--------------|
| `type_primitive_string_id` | Use Newtypes for IDs | Warning | Use newtype wrappers for identifiers instead of raw `String`. E.g., `VehicleId(String)` | `pub struct VehicleId(pub String);` |
| `type_string_match` | Use Enums Instead of String Matching | Hint | Replace string literal matching with typed enums for compile-time safety | Define an enum with `#[derive(Deserialize)]` |
| `type_raw_coordinates` | Use Newtypes for Coordinates | Info | Use newtype wrappers for latitude/longitude instead of raw `f64` | `pub struct Latitude(pub f64);` |

---

## 12. Time Rules

Rules for handling time correctly in WASM32.

| Rule ID | Name | Severity | Description | Fix Template |
|---------|------|----------|-------------|--------------|
| `time_system_time_now` | No SystemTime::now() | Error | `SystemTime::now()` is unreliable in WASM32 | `chrono::Utc::now()` |
| `time_instant_duration` | No Instant for Elapsed Time | Error | `Instant::now()` and `elapsed()` are not available in WASM32 | Use chrono timestamps for elapsed time calculations |

---

## 13. Auth Rules

Rules for authentication and authorization.

| Rule ID | Name | Severity | Description | Fix Template |
|---------|------|----------|-------------|--------------|
| `auth_hardcoded_bearer` | No Hardcoded Bearer Tokens | Error | Bearer tokens must come from `Identity::access_token()`, not hardcoded strings | `let token = ctx.provider.access_token("service").await?;` |
| `auth_authorization_without_identity` | Authorization Header Requires Identity Trait | Warning | If using Authorization header, the handler should include Identity trait bound | Add Identity to handler bounds: `P: Config + HttpRequest + Identity` |

---

## 14. Caching Rules

Rules for proper cache usage.

| Rule ID | Name | Severity | Description | Fix Template |
|---------|------|----------|-------------|--------------|
| `cache_missing_ttl` | Cache Set Without TTL | Warning | `StateStore::set` should include a TTL to prevent unbounded cache growth | `ctx.provider.set(key, value, Some(Duration::from_secs(3600))).await?` |
| `cache_key_format` | Cache Key Consistent Format | Info | Cache keys should follow `entity-{id}` pattern for consistency | `format!("entity-{}", id)` |

---

## 15. Forbidden Crates

These crates are **completely forbidden** in QWASR WASM32 code:

| Category | Crates | Reason |
|----------|--------|--------|
| **HTTP Clients** | `reqwest`, `hyper`, `surf`, `ureq` | Use HttpRequest provider trait |
| **Redis/Cache** | `redis` | Use StateStore provider trait |
| **Messaging** | `rdkafka`, `lapin` | Use Publisher provider trait |
| **Async Runtimes** | `tokio`, `async-std`, `smol` | WASI provides the executor |
| **Parallel Processing** | `rayon` | WASM is single-threaded |
| **Concurrency** | `crossbeam`, `parking_lot` | WASM is single-threaded |
| **Global State** | `once_cell`, `lazy_static` | WASM must be stateless |
| **Concurrent Collections** | `dashmap` | Use StateStore provider trait |
| **Database Clients** | `sqlx`, `diesel`, `rusqlite`, `postgres`, `mysql` | Use TableStore provider trait |
| **Filesystem** | `tempfile` | std::fs not available |
| **Network** | `socket2`, `mio` | Use HttpRequest provider trait |

---

## 16. Forbidden Patterns

Anti-patterns that are detected and flagged.

| Pattern ID | Name | Severity | Alternative |
|------------|------|----------|-------------|
| `global_state_static_mut` | Static Mutable State | Error | Use StateStore provider |
| `global_state_once_cell` | OnceCell Global State | Error | Use Config provider |
| `global_state_lazy` | Lazy Static Global State | Error | Use Config provider |
| `std_fs` | Filesystem Access | Error | Use wasi_blobstore provider |
| `std_net` | Network Access | Error | Use HttpRequest provider |
| `std_thread` | Threading | Error | Use async/await |
| `std_process` | Process Spawning | Error | Not applicable in WASM |
| `std_env` | Environment Variables | Error | Use `Config::get()` |
| `std_time_system` | System Time | Warning | Use `chrono::Utc::now()` |
| `thread_sleep` | Thread Sleep | Error | Restructure logic |
| `panic_unwrap` | Unwrap/Expect Usage | Warning | Use `?` operator |
| `println_debug` | Println/Eprintln | Hint | Use tracing macros |

---

## 17. Provider Traits Reference

### Config

**Purpose:** Read configuration values from WASI config.

**WASI Module:** `qwasr_wasi_config`

| Method | Signature | Description |
|--------|-----------|-------------|
| `get` | `async fn get(&self, key: &str) -> Result<String>` | Get a configuration value by key |

**Example:**
```rust
let url = Config::get(provider, "API_URL").await?;
```

---

### HttpRequest

**Purpose:** Make outbound HTTP requests via WASI HTTP.

**WASI Module:** `qwasr_wasi_http`

| Method | Signature | Description |
|--------|-----------|-------------|
| `fetch` | `async fn fetch<T>(&self, request: Request<T>) -> Result<Response<Bytes>>` | Make an outbound HTTP request |

**Example:**
```rust
let response = HttpRequest::fetch(provider, request).await?;
```

---

### Publisher

**Purpose:** Publish messages to topics via WASI messaging.

**WASI Module:** `qwasr_wasi_messaging`

| Method | Signature | Description |
|--------|-----------|-------------|
| `send` | `async fn send(&self, topic: &str, message: &Message) -> Result<()>` | Publish a message to a topic |

**Example:**
```rust
Publisher::send(provider, "my-topic", &message).await?;
```

---

### StateStore

**Purpose:** Cache/KV operations via WASI keyvalue.

**WASI Module:** `qwasr_wasi_keyvalue`

| Method | Signature | Description |
|--------|-----------|-------------|
| `get` | `async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>` | Retrieve a value from the state store |
| `set` | `async fn set(&self, key: &str, value: &[u8], ttl_secs: Option<u64>) -> Result<Option<Vec<u8>>>` | Store a value with optional TTL |
| `delete` | `async fn delete(&self, key: &str) -> Result<()>` | Delete a value from the state store |

**Example:**
```rust
let value = StateStore::get(provider, "key").await?;
StateStore::set(provider, "key", &data, Some(3600)).await?;
```

---

### TableStore

**Purpose:** Structured data storage with SQL-like query capabilities.

| Method | Signature | Description |
|--------|-----------|-------------|
| `query` | `async fn query(&self, sql: &str, params: &[(&str, &str)]) -> Result<Vec<Row>>` | Execute a SELECT query |
| `exec` | `async fn exec(&self, sql: &str, params: &[(&str, &str)]) -> Result<u64>` | Execute INSERT/UPDATE/DELETE |

**Example:**
```rust
let rows = ctx.provider.query(
    "SELECT id, name FROM users WHERE tenant_id = $1",
    &[("$1", &ctx.owner)],
).await?;
```

---

### Identity

**Purpose:** Access identity and authentication tokens for external services.

| Method | Signature | Description |
|--------|-----------|-------------|
| `access_token` | `async fn access_token(&self, service: &str) -> Result<String>` | Get an OAuth access token |

**Example:**
```rust
let token = ctx.provider.access_token("github").await?;
```

---

## 18. Error Macros Reference

| Macro | HTTP Status | Use Case | Example |
|-------|-------------|----------|---------|
| `bad_request!` | 400 | Input validation failures, missing required fields, invalid format, parsing failures | `Err(bad_request!("vehicle_id is required"))` |
| `server_error!` | 500 | Internal invariant violations, unexpected states, serialization errors | `Err(server_error!("unexpected state: {}", state))` |
| `bad_gateway!` | 502 | Upstream API failures, external service errors, dependency failures | `Err(bad_gateway!("upstream request failed: {err}"))` |

---

## Summary Statistics

| Category | Total Rules | Errors | Warnings | Info | Hints |
|----------|-------------|--------|----------|------|-------|
| Handler | 8 | 5 | 2 | 1 | 0 |
| Provider | 11 | 1 | 2 | 8 | 0 |
| **Semantic Analysis** ⭐ | **7** | **2** | **3** | **0** | **2** |
| Context | 2 | 0 | 0 | 2 | 0 |
| Error | 19 | 5 | 8 | 6 | 0 |
| Response | 4 | 0 | 0 | 4 | 0 |
| WASM | 9 | 6 | 2 | 0 | 1 |
| Stateless | 6 | 4 | 2 | 0 | 0 |
| Performance | 5 | 0 | 1 | 0 | 4 |
| Security | 2 | 2 | 0 | 0 | 0 |
| Strong Typing | 3 | 0 | 1 | 1 | 1 |
| Time | 2 | 2 | 0 | 0 | 0 |
| Auth | 2 | 1 | 1 | 0 | 0 |
| Caching | 2 | 0 | 1 | 1 | 0 |
| **Total** | **82+** | **28** | **23** | **23** | **8** |

---

## Quick Reference: Critical Errors to Avoid

1. **No panicking macros:** `panic!`, `unreachable!`, `assert!`, `assert_eq!`
2. **No global state:** `static mut`, `lazy_static!`, `OnceCell`, `LazyLock`
3. **No forbidden std modules:** `std::fs`, `std::net`, `std::thread`, `std::env`, `std::process`
4. **No direct HTTP clients:** Use `ctx.provider.fetch()` instead
5. **No hardcoded secrets:** Use Config provider
6. **No SQL string concatenation:** Use parameterized queries
7. **No `SystemTime::now()` or `Instant::now()`:** Use `chrono::Utc::now()`
8. **No unused provider bounds:** Remove traits you don't use ⭐ NEW
9. **No missing provider bounds:** Add traits for methods you call ⭐ NEW

---

*Generated from QWASR LSP source code analysis.*
