// Test file for QWASR LSP Semantic Analysis
// Open this in your editor to see the new diagnostics
use qwasr_sdk::{Context, Handler, Reply, Result};

// ============================================================
// TEST 1: Unused provider bound (should warn about HttpRequest)
// ============================================================
impl<P: Config + HttpRequest> Handler<P> for UnusedBoundRequest {
    type Input = Vec<u8>;
    type Output = Response;
    type Error = Error;

    fn from_input(input: Self::Input) -> Result<Self> {
        Ok(Self {})
    }

    async fn handle(self, ctx: Context<'_, P>) -> Result<Reply<Self::Output>> {
        // Only uses Config, NOT HttpRequest
        let url = ctx.provider.get("API_URL")?;
        Ok(Reply::ok(Response { url }))
    }
}

// ============================================================
// TEST 2: Missing provider bound (should error about HttpRequest)
// ============================================================
impl<P: Config> Handler<P> for MissingBoundRequest {
    type Input = Vec<u8>;
    type Output = Response;
    type Error = Error;

    fn from_input(input: Self::Input) -> Result<Self> {
        Ok(Self {})
    }

    async fn handle(self, ctx: Context<'_, P>) -> Result<Reply<Self::Output>> {
        let url = ctx.provider.get("API_URL")?;
        // Uses HttpRequest but it's not in the bounds!
        let response = ctx.provider.fetch(request).await?;
        Ok(Reply::ok(Response {}))
    }
}

// ============================================================
// TEST 3: Where clause with unused bound (should warn about Publisher)
// ============================================================
impl<P> Handler<P> for WhereClauseRequest
where
    P: Config + HttpRequest + Publisher,
{
    async fn handle(self, ctx: Context<'_, P>) -> Result<Reply<Self::Output>> {
        let url = ctx.provider.get("URL")?;
        let resp = ctx.provider.fetch(req).await?;
        // Publisher is declared but never used!
        Ok(Reply::ok(Response {}))
    }
}

// ============================================================
// TEST 4: Correct bounds (should have no warnings)
// ============================================================
impl<P: Config + HttpRequest> Handler<P> for CorrectRequest {
    fn handle(self, ctx: Context<'_, P>) -> Result<Reply<Self::Output>> {
        let url = ctx.provider.get("API_URL")?;
        let response = ctx.provider.fetch(request).await?;
        Ok(Reply::ok(Response {}))
    }
}

// ============================================================
// TEST 5: StateStore without TTL (should warn)
// ============================================================
async fn cache_without_ttl<P>(provider: &P) -> Result<()> {
    // Warning: None TTL
    provider
        .set("key", b"value", Some(Duration::from_secs(3600)))
        .await?;
    Ok(())
}

// Stub types (not real - just for testing LSP)
struct UnusedBoundRequest;
struct MissingBoundRequest;
struct WhereClauseRequest;
struct CorrectRequest;
struct Response {
    url: String,
}
struct Error;
