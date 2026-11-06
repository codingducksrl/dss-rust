// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! dss-server: the [`dss`] engine behind HTTP, for applications in other languages (PHP, …) that run it as a
//! sidecar. One engine serves every request: the trusted lists are loaded once and refreshed on a schedule.
//!
//! | Endpoint | Request | Response |
//! |---|---|---|
//! | `POST /validate` | multipart: `document`, `options`?, `detached`* | the library's result JSON |
//! | `POST /extend` | multipart: `document`, `options` | the extended PDF; the result JSON in `Dss-Result` |
//! | `POST /sign/prepare` | multipart: `document`, `options` | the library's result JSON |
//! | `POST /sign/complete` | multipart: `document`, `options`, `signature` | the signed document; `Dss-Result` |
//! | `GET /tl/status` | | the library's trusted-list status JSON |
//! | `POST /tl/refresh` | | 202: an online refresh started |
//! | `GET /version` | | server, library and DSS versions |
//! | `GET /health` | | 200 once the engine is up, 503 while it starts. No token needed |
//! | `GET /openapi.yaml` | | the OpenAPI document of all this (docs/openapi.yaml). No token needed |
//!
//! `options` is the library's `options_json` (README.md, "API"). Errors are the library's
//! `{"ok":false,"error":{"code":"…","message":"…"}}`, with an HTTP status by code. See docs/server.md.

use std::fmt::Write as _;
use std::sync::{Arc, LazyLock, OnceLock};

use axum::Router;
use axum::body::Bytes;
use axum::extract::multipart::{MultipartError, MultipartRejection};
use axum::extract::{DefaultBodyLimit, Multipart, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use serde_json::{Map, Value, json};

use dss::schedule::RefreshScheduler;
use dss::{Engine, Error, ErrorCode, RefreshRecord};

/// Response header carrying the result JSON when the body is a document (`/extend`, `/sign/complete`).
pub const RESULT_HEADER: &str = "dss-result";

/// The API's OpenAPI document as committed (docs/openapi.yaml), its `info.version` the placeholder
/// [`OPENAPI_VERSION_LINE`].
pub const OPENAPI_SOURCE: &str = include_str!("../../../docs/openapi.yaml");

/// `info.version` in [`OPENAPI_SOURCE`]: the committed files' version placeholder.
pub const OPENAPI_VERSION_LINE: &str = "\n  version: 0.0.0-dev\n";

/// The OpenAPI document `/openapi.yaml` serves: [`OPENAPI_SOURCE`] with this server's version.
pub fn openapi() -> &'static str {
    static DOCUMENT: LazyLock<String> = LazyLock::new(|| {
        let version = format!("\n  version: {}\n", env!("CARGO_PKG_VERSION"));
        OPENAPI_SOURCE.replacen(OPENAPI_VERSION_LINE, &version, 1)
    });
    &DOCUMENT
}

/// What every request shares: the engine, once it has started.
pub struct AppState {
    engine: OnceLock<Arc<Engine>>,
    scheduler: OnceLock<RefreshScheduler>,
    token: Option<String>,
}

impl AppState {
    /// With a `token`, every endpoint but `/health` and `/openapi.yaml` needs `Authorization: Bearer <token>`.
    pub fn new(token: Option<String>) -> Arc<Self> {
        Arc::new(AppState {
            engine: OnceLock::new(),
            scheduler: OnceLock::new(),
            token,
        })
    }

    /// Makes the engine available to requests: `/health` turns ready. `scheduler` refreshes its trusted lists;
    /// without one, `/tl/refresh` still refreshes on demand.
    pub fn set_engine(&self, engine: Arc<Engine>, scheduler: Option<RefreshScheduler>) {
        if let Some(s) = scheduler {
            let _ = self.scheduler.set(s);
        }
        let _ = self.engine.set(engine);
    }

    /// Stops the refresh schedule and releases the engine. Blocking: dropping the last reference to the engine
    /// waits for queued work and a running online refresh, then tears down the isolate.
    pub fn shutdown(self) {
        if let Some(s) = self.scheduler.into_inner() {
            s.stop();
        }
        drop(self.engine.into_inner());
    }

    fn engine(&self) -> Result<Arc<Engine>, ApiError> {
        self.engine.get().cloned().ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "NOT_INITIALIZED",
                "the engine is starting",
            )
        })
    }
}

/// The HTTP API. `max_request_bytes` caps a whole request (document, detached contents, signature).
pub fn router(state: Arc<AppState>, max_request_bytes: usize) -> Router {
    let api = Router::new()
        .route("/validate", post(validate))
        .route("/extend", post(extend))
        .route("/sign/prepare", post(sign_prepare))
        .route("/sign/complete", post(sign_complete))
        .route("/tl/status", get(tl_status))
        .route("/tl/refresh", post(tl_refresh))
        .route("/version", get(version))
        .route_layer(middleware::from_fn_with_state(Arc::clone(&state), authorize));
    Router::new()
        .route("/health", get(health))
        .route("/openapi.yaml", get(openapi_yaml))
        .merge(api)
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(max_request_bytes))
        .with_state(state)
}

/// One line for the log about an online refresh.
pub fn describe_refresh(result: &dss::Result<RefreshRecord>) -> String {
    match result {
        Ok(r) if r.completed => format!(
            "online trusted-list refresh completed in {} ms, {} trusted certificates",
            r.duration_ms, r.trusted_certificates
        ),
        Ok(r) => format!(
            "online trusted-list refresh failed after {} ms: {}",
            r.duration_ms,
            r.error.as_deref().unwrap_or("no reason given")
        ),
        Err(e) => format!("online trusted-list refresh failed: {e}"),
    }
}

async fn validate(
    State(state): State<Arc<AppState>>,
    multipart: Result<Multipart, MultipartRejection>,
) -> Result<Response, ApiError> {
    let engine = state.engine()?;
    let parts = Parts::read(multipart?, &["document", "options", "detached"]).await?;
    let document = required(parts.document, "document")?;
    let mut options = parts.options.unwrap_or_default();
    default_filename(&mut options, parts.filename);
    add_detached(&mut options, parts.detached)?;
    let options = Value::Object(options).to_string();
    let json = run(engine, move |e| e.validate_json(&document, &options)).await?;
    Ok(json_response(StatusCode::OK, json))
}

async fn extend(
    State(state): State<Arc<AppState>>,
    multipart: Result<Multipart, MultipartRejection>,
) -> Result<Response, ApiError> {
    let engine = state.engine()?;
    let parts = Parts::read(multipart?, &["document", "options"]).await?;
    let document = required(parts.document, "document")?;
    let mut options = required(parts.options, "options")?;
    default_filename(&mut options, parts.filename);
    let options = Value::Object(options).to_string();
    let (json, pdf) = run(engine, move |e| e.extend_json(&document, &options)).await?;
    document_response(&parse_result(&json)?, pdf, "application/pdf")
}

/// Signing passes the options on untouched, filename included: `complete` must get exactly what `prepare` got,
/// or the digest differs.
async fn sign_prepare(
    State(state): State<Arc<AppState>>,
    multipart: Result<Multipart, MultipartRejection>,
) -> Result<Response, ApiError> {
    let engine = state.engine()?;
    let parts = Parts::read(multipart?, &["document", "options"]).await?;
    let document = required(parts.document, "document")?;
    let options = Value::Object(required(parts.options, "options")?).to_string();
    let json = run(engine, move |e| e.prepare_signature_json(&document, &options)).await?;
    Ok(json_response(StatusCode::OK, json))
}

async fn sign_complete(
    State(state): State<Arc<AppState>>,
    multipart: Result<Multipart, MultipartRejection>,
) -> Result<Response, ApiError> {
    let engine = state.engine()?;
    let parts = Parts::read(multipart?, &["document", "options", "signature"]).await?;
    let document = required(parts.document, "document")?;
    let options = Value::Object(required(parts.options, "options")?).to_string();
    let signature = required(parts.signature, "signature")?;
    let (json, signed) = run(engine, move |e| {
        e.complete_signature_json(&document, &options, &signature)
    })
    .await?;
    let result = parse_result(&json)?;
    let content_type = match (result["format"].as_str(), result["packaging"].as_str()) {
        (Some("PAdES"), _) => "application/pdf",
        (Some("CAdES"), Some("DETACHED")) => "application/pkcs7-signature",
        (Some("CAdES"), _) => "application/pkcs7-mime",
        _ => "application/octet-stream",
    };
    document_response(&result, signed, content_type)
}

async fn tl_status(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let engine = state.engine()?;
    let json = run(engine, |e| e.trusted_list_status_json()).await?;
    Ok(json_response(StatusCode::OK, json))
}

/// Starts an online refresh and answers at once; `/tl/status` shows its progress and outcome.
async fn tl_refresh(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let engine = state.engine()?;
    let running = run(Arc::clone(&engine), |e| e.trusted_list_status())
        .await?
        .refresh_in_progress;
    let started = !running
        && match state.scheduler.get() {
            Some(scheduler) => scheduler.refresh_now(),
            None => {
                tokio::task::spawn_blocking(move || {
                    eprintln!("dss-server: {}", describe_refresh(&engine.refresh_trusted_lists()));
                });
                true
            }
        };
    if !started {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "REFRESH_IN_PROGRESS",
            "an online refresh is already running",
        ));
    }
    Ok(json_response(StatusCode::ACCEPTED, json!({"ok": true}).to_string()))
}

async fn version(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let engine = state.engine()?;
    let v = run(engine, |e| e.version()).await?;
    let body = json!({
        "ok": true,
        "server": env!("CARGO_PKG_VERSION"),
        "library": v.library,
        "dss": v.dss,
        "runtime": v.runtime,
    });
    Ok(json_response(StatusCode::OK, body.to_string()))
}

async fn health(State(state): State<Arc<AppState>>) -> Response {
    let Ok(engine) = state.engine() else {
        let body = json!({"ok": false, "status": "starting"});
        return json_response(StatusCode::SERVICE_UNAVAILABLE, body.to_string());
    };
    match run(engine, |e| e.trusted_list_status()).await {
        Ok(s) => {
            let body = json!({
                "ok": true,
                "status": "ready",
                "trusted_lists_loaded": s.loaded,
                "refresh_in_progress": s.refresh_in_progress,
            });
            json_response(StatusCode::OK, body.to_string())
        }
        Err(e) => e.into_response(),
    }
}

async fn openapi_yaml() -> Response {
    ([(header::CONTENT_TYPE, "application/yaml")], openapi()).into_response()
}

async fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "NOT_FOUND", "no such endpoint")
}

async fn authorize(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    if let Some(token) = &state.token {
        let given = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if !given.is_some_and(|g| same(g.as_bytes(), token.as_bytes())) {
            return ApiError::new(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "missing or wrong bearer token",
            )
            .into_response();
        }
    }
    next.run(request).await
}

/// Constant-time comparison: the response time does not tell how much of the token matched.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Runs a blocking engine call off the async threads. The engine's own workers do the work; this thread waits.
async fn run<T: Send + 'static>(
    engine: Arc<Engine>,
    call: impl FnOnce(&Engine) -> dss::Result<T> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(move || call(&engine))
        .await
        .map_err(|e| ApiError::internal(format!("engine call failed: {e}")))?
        .map_err(ApiError::from)
}

/// The multipart parts of a request. Each endpoint names the ones it takes; any other part is an error.
#[derive(Default)]
struct Parts {
    document: Option<Bytes>,
    /// The `document` part's filename, if the client sent one.
    filename: Option<String>,
    options: Option<Map<String, Value>>,
    detached: Vec<(String, Bytes)>,
    signature: Option<Bytes>,
}

impl Parts {
    async fn read(mut multipart: Multipart, accepted: &[&str]) -> Result<Parts, ApiError> {
        let mut parts = Parts::default();
        while let Some(field) = multipart.next_field().await? {
            let name = field.name().unwrap_or_default().to_owned();
            if !accepted.contains(&name.as_str()) {
                return Err(ApiError::invalid(format!(
                    "unexpected part '{name}': this endpoint takes {}",
                    accepted.join(", ")
                )));
            }
            let filename = field.file_name().map(str::to_owned);
            let bytes = field.bytes().await?;
            match name.as_str() {
                "document" => {
                    set_once(&mut parts.document, bytes, &name)?;
                    parts.filename = filename;
                }
                "options" => set_once(&mut parts.options, parse_options(&bytes)?, &name)?,
                "signature" => set_once(&mut parts.signature, bytes, &name)?,
                _ => {
                    let name = filename.unwrap_or_else(|| format!("detached-{}", parts.detached.len() + 1));
                    parts.detached.push((name, bytes));
                }
            }
        }
        Ok(parts)
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<(), ApiError> {
    if slot.replace(value).is_some() {
        return Err(ApiError::invalid(format!("more than one '{name}' part")));
    }
    Ok(())
}

fn required<T>(part: Option<T>, name: &str) -> Result<T, ApiError> {
    part.ok_or_else(|| ApiError::invalid(format!("missing part '{name}'")))
}

fn parse_options(bytes: &[u8]) -> Result<Map<String, Value>, ApiError> {
    match serde_json::from_slice(bytes) {
        Ok(Value::Object(options)) => Ok(options),
        Ok(_) => Err(ApiError::invalid("the 'options' part must be a JSON object")),
        Err(e) => Err(ApiError::invalid(format!("the 'options' part is not JSON: {e}"))),
    }
}

/// The name shown in reports and DSS's messages: the uploaded file's, unless the options give one.
fn default_filename(options: &mut Map<String, Value>, filename: Option<String>) {
    if let Some(name) = filename
        && !options.contains_key("filename")
    {
        options.insert("filename".into(), name.into());
    }
}

/// Detached contents arrive as `detached` parts and go to the library as base64. A `path` in the options would
/// make the server read its own files, so it is refused.
fn add_detached(options: &mut Map<String, Value>, detached: Vec<(String, Bytes)>) -> Result<(), ApiError> {
    if let Some(entries) = options.get("detached_contents")
        && entries
            .as_array()
            .is_some_and(|a| a.iter().any(|e| e.get("path").is_some()))
    {
        return Err(ApiError::invalid(
            "detached_contents[].path is not accepted over HTTP: send the file as a 'detached' part, or as base64",
        ));
    }
    if detached.is_empty() {
        return Ok(());
    }
    let Value::Array(entries) = options
        .entry("detached_contents")
        .or_insert_with(|| Value::Array(vec![]))
    else {
        return Err(ApiError::invalid("detached_contents must be an array"));
    };
    for (name, bytes) in detached {
        let base64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        entries.push(json!({"name": name, "base64": base64}));
    }
    Ok(())
}

fn parse_result(json: &str) -> Result<Value, ApiError> {
    serde_json::from_str(json).map_err(|e| ApiError::internal(format!("unexpected JSON from libdssnative: {e}")))
}

/// A document as the body, its result JSON in [`RESULT_HEADER`].
fn document_response(result: &Value, document: Vec<u8>, content_type: &'static str) -> Result<Response, ApiError> {
    // Compact JSON has no line breaks; header values must also be ASCII, so anything else is escaped as \uXXXX
    // (it can only occur inside strings).
    let mut ascii = String::new();
    for c in result.to_string().chars() {
        if c.is_ascii() {
            ascii.push(c);
        } else {
            for unit in c.encode_utf16(&mut [0; 2]) {
                let _ = write!(ascii, "\\u{unit:04x}");
            }
        }
    }
    let value = HeaderValue::from_str(&ascii).map_err(|e| ApiError::internal(format!("result header: {e}")))?;
    Ok((
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (header::HeaderName::from_static(RESULT_HEADER), value),
        ],
        document,
    )
        .into_response())
}

fn json_response(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// An error result: the library's code and message, or one of the server's own codes (`UNAUTHORIZED`,
/// `NOT_FOUND`, `REQUEST_TOO_LARGE`), with the HTTP status for it.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: String,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &str, message: impl Into<String>) -> Self {
        ApiError {
            status,
            code: code.into(),
            message: message.into(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", message)
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", message)
    }

    fn from_body(status: StatusCode, message: String) -> Self {
        if status == StatusCode::PAYLOAD_TOO_LARGE {
            Self::new(status, "REQUEST_TOO_LARGE", message)
        } else {
            Self::new(status, "INVALID_ARGUMENT", message)
        }
    }
}

/// The HTTP status for a library error code.
fn status_of(code: ErrorCode) -> StatusCode {
    match code {
        ErrorCode::InvalidArgument => StatusCode::BAD_REQUEST,
        ErrorCode::UnsupportedDocument
        | ErrorCode::ValidationFailed
        | ErrorCode::ExtensionFailed
        | ErrorCode::SigningFailed => StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::NotInitialized | ErrorCode::TrustedListsNotLoaded => StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::RefreshInProgress => StatusCode::CONFLICT,
        ErrorCode::TlRefreshFailed => StatusCode::BAD_GATEWAY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        match e {
            Error::Api { code, message } => {
                let name = match serde_json::to_value(code) {
                    Ok(Value::String(name)) => name,
                    _ => format!("{code:?}"),
                };
                ApiError::new(status_of(code), &name, message)
            }
            Error::Nul => ApiError::invalid(e.to_string()),
            Error::Closed => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "NOT_INITIALIZED", e.to_string()),
            e => ApiError::internal(e.to_string()),
        }
    }
}

impl From<MultipartRejection> for ApiError {
    fn from(r: MultipartRejection) -> Self {
        ApiError::from_body(r.status(), r.body_text())
    }
}

impl From<MultipartError> for ApiError {
    fn from(e: MultipartError) -> Self {
        ApiError::from_body(e.status(), e.body_text())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            eprintln!("dss-server: {} {}: {}", self.status.as_u16(), self.code, self.message);
        }
        let body = json!({"ok": false, "error": {"code": self.code, "message": self.message}});
        json_response(self.status, body.to_string())
    }
}
