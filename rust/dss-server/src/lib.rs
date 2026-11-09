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
//! | `POST /tl/refresh` | | 202: an online refresh starts |
//! | `GET /version` | | server, library and DSS versions |
//! | `GET /health` | | 200 once the engine can serve, 503 while it starts or waits for trusted lists. No token |
//! | `GET /openapi.yaml` | | the OpenAPI document of all this (docs/openapi.yaml). No token needed |
//!
//! `options` is the library's `options_json` (README.md, "API"). Errors are the library's
//! `{"ok":false,"error":{"code":"…","message":"…"}}`, with an HTTP status by code. See docs/server.md.
//!
//! Admission control: at most [`Settings::max_in_flight`] document requests are read and processed at the same
//! time (the rest get 503 `SERVER_BUSY` at once), and a request may take at most
//! [`Settings::request_timeout`] (504 `TIMEOUT`). Both bound the memory the server holds and the time a client
//! waits, which neither the engine's heap cap nor the request size cap do on their own. Every engine call is
//! bound to a [`CancelToken`] that is cancelled when the request is abandoned (its deadline passed, or its
//! client went away before the answer), so a call still queued for a worker is skipped instead of run for
//! nobody; a call already running completes, as the library cannot interrupt it.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use axum::Router;
use axum::body::Bytes;
use axum::extract::multipart::{MultipartError, MultipartRejection};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Extension, Multipart, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::{Map, Value, json};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use dss::schedule::{RefreshRequest, RefreshScheduler};
use dss::{CancelToken, DetachedBytes, Engine, Error, ErrorCode, RefreshRecord};

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

/// How the server admits and guards requests. [`Default`]: no token, 32 requests in flight, no deadline, ready
/// as soon as the engine is up.
#[derive(Debug, Clone)]
pub struct Settings {
    /// With a token, every endpoint but `/health` and `/openapi.yaml` needs `Authorization: Bearer <token>`.
    /// Without one, requests carrying an `Origin` header (sent by browsers) are refused with 403.
    pub token: Option<String>,
    /// Document requests (`/validate`, `/extend`, `/sign/*`) being read or processed at the same time. The next
    /// one is answered 503 `SERVER_BUSY` with `Retry-After` at once, before its body is read. Each request in
    /// flight holds up to twice its size on the Rust side besides the engine's own copy, so this times the
    /// request size cap is the memory bound.
    pub max_in_flight: usize,
    /// How long a request may take, body upload and engine call included; over it, 504 `TIMEOUT`. An engine
    /// call already running finishes in the background (the library cannot cancel it) and keeps its admission
    /// slot until then; one still queued for a worker is skipped (its [`CancelToken`] is cancelled), as it is
    /// when the client disconnects before the answer.
    pub request_timeout: Option<Duration>,
    /// Whether `/health` stays 503 (`waiting_for_trusted_lists`) until the trusted lists are loaded: true when
    /// the engine requires them for validation (the library's `require_trusted_lists`, its default), so that an
    /// orchestrator does not route traffic to an instance that answers `TRUSTED_LISTS_NOT_LOADED`.
    pub trusted_lists_required: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            token: None,
            max_in_flight: 32,
            request_timeout: None,
            trusted_lists_required: false,
        }
    }
}

/// What every request shares: the engine, once it has started, and the admission state.
pub struct AppState {
    engine: OnceLock<Arc<Engine>>,
    scheduler: OnceLock<RefreshScheduler>,
    settings: Settings,
    /// One permit per document request in flight.
    permits: Arc<Semaphore>,
    /// A refresh started by `/tl/refresh` without a scheduler is running (the engine's own flag lags behind
    /// the 202 by a few thread hand-offs, this one does not).
    direct_refresh: AtomicBool,
}

impl AppState {
    /// [`Settings::default`] with this `token`.
    pub fn new(token: Option<String>) -> Arc<Self> {
        Self::with(Settings {
            token,
            ..Settings::default()
        })
    }

    /// A state with these settings.
    pub fn with(settings: Settings) -> Arc<Self> {
        let permits = Arc::new(Semaphore::new(settings.max_in_flight.max(1)));
        Arc::new(AppState {
            engine: OnceLock::new(),
            scheduler: OnceLock::new(),
            settings,
            permits,
            direct_refresh: AtomicBool::new(false),
        })
    }

    /// The settings this state was created with.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Makes the engine available to requests: `/health` turns ready. `scheduler` refreshes its trusted lists;
    /// without one, `/tl/refresh` still refreshes on demand.
    pub fn set_engine(&self, engine: Arc<Engine>, scheduler: Option<RefreshScheduler>) {
        if let Some(s) = scheduler {
            let _ = self.scheduler.set(s);
        }
        let _ = self.engine.set(engine);
    }

    /// Asks the refresh schedule for an online refresh as soon as possible; [`RefreshRequest::Stopped`] when
    /// there is no scheduler.
    pub fn request_refresh(&self) -> RefreshRequest {
        self.scheduler
            .get()
            .map_or(RefreshRequest::Stopped, RefreshScheduler::request_refresh)
    }

    /// Ends the refresh schedule, waiting for a refresh it has in flight (its outcome is still published), then
    /// releases the engine, which waits for queued work before it tears down the isolate.
    pub async fn shutdown(self) {
        if let Some(scheduler) = self.scheduler.into_inner() {
            let mut outcomes = scheduler.subscribe();
            // Dropping the handle (not stopping it) lets the schedule end after the refresh in flight.
            drop(scheduler);
            while outcomes.changed().await.is_ok() {}
        }
        if let Some(engine) = self.engine.into_inner() {
            let _ = tokio::task::spawn_blocking(move || drop(engine)).await;
        }
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

    /// A slot for a document request, or 503 at once.
    fn admit(&self) -> Result<OwnedSemaphorePermit, ApiError> {
        Arc::clone(&self.permits).try_acquire_owned().map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVER_BUSY",
                format!(
                    "{} requests are already in flight (the server's --max-in-flight): retry shortly",
                    self.settings.max_in_flight
                ),
            )
            .with_header(header::RETRY_AFTER, "1")
        })
    }

    fn in_flight(&self) -> usize {
        self.settings
            .max_in_flight
            .max(1)
            .saturating_sub(self.permits.available_permits())
    }

    /// When a request starting now must be done.
    fn deadline(&self) -> Option<Instant> {
        self.settings.request_timeout.map(|t| Instant::now() + t)
    }
}

/// The HTTP API. `max_request_bytes` caps a whole request (document, detached contents, signature).
pub fn router(state: Arc<AppState>, max_request_bytes: usize) -> Router {
    // The guarded endpoints get their 405 fallback before the token and deadline layers, so that a wrong-method
    // request on one of them is answered by the token check first (401, not 405) like every other request to
    // them; `route_layer` would leave that fallback outside the layers.
    let api = Router::new()
        .route("/validate", post(validate))
        .route("/extend", post(extend))
        .route("/sign/prepare", post(sign_prepare))
        .route("/sign/complete", post(sign_complete))
        .route("/tl/status", get(tl_status))
        .route("/tl/refresh", post(tl_refresh))
        .route("/version", get(version))
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn_with_state(Arc::clone(&state), authorize))
        .layer(middleware::from_fn_with_state(Arc::clone(&state), with_deadline));
    Router::new()
        .route("/health", get(health))
        .route("/openapi.yaml", get(openapi_yaml))
        .merge(api)
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(DefaultBodyLimit::max(max_request_bytes))
        .with_state(state)
}

/// An RFC 3339 / ISO 8601 instant (`2026-01-31T12:00:00Z`, `2026-01-31T12:00:00.123+01:00`, as the library's
/// JSON dates them) as a [`SystemTime`]; `None` for anything else.
pub fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    let text = text.trim();
    let (date, rest) = text.split_once(['T', 't', ' '])?;
    let mut date = date.splitn(3, '-');
    let year: i64 = date.next()?.parse().ok()?;
    let month: u32 = date.next()?.parse().ok()?;
    let day: u32 = date.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let offset_at = rest.find(['Z', 'z', '+', '-'])?;
    let (time, offset) = rest.split_at(offset_at);
    let (time, fraction) = time.split_once('.').unwrap_or((time, "0"));
    let mut time = time.splitn(3, ':');
    let hour: i64 = time.next()?.parse().ok()?;
    let minute: i64 = time.next()?.parse().ok()?;
    let second: i64 = time.next()?.parse().ok()?;
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let nanos: u32 = if fraction.is_empty() || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    } else {
        let digits: String = fraction.chars().chain(std::iter::repeat('0')).take(9).collect();
        digits.parse().ok()?
    };
    let offset_secs: i64 = match offset {
        "Z" | "z" => 0,
        _ => {
            let (hours, minutes) = offset[1..].split_once(':')?;
            let magnitude = hours.parse::<i64>().ok()? * 3600 + minutes.parse::<i64>().ok()? * 60;
            if offset.starts_with('-') { -magnitude } else { magnitude }
        }
    };
    // Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's days_from_civil).
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * i64::from(m) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second - offset_secs;
    let since_epoch = Duration::new(u64::try_from(secs).ok()?, nanos);
    SystemTime::UNIX_EPOCH.checked_add(since_epoch)
}

/// One line for the log about an online refresh.
pub fn describe_refresh(result: &dss::Result<RefreshRecord>) -> String {
    match result {
        Ok(r) if r.completed => format!(
            "online trusted-list refresh completed in {} ms, {} trusted certificates",
            r.duration_ms, r.trusted_certificates
        ),
        Ok(r) => format!(
            "online trusted-list refresh published nothing after {} ms, the lists loaded before are kept: {}",
            r.duration_ms,
            r.error.as_deref().unwrap_or("no reason given")
        ),
        Err(e) => format!("online trusted-list refresh failed: {e}"),
    }
}

/// Whether an online refresh left the engine without new lists: an error, nothing published, or no trusted
/// certificate at all. A refresh refused because another one was running is not a failure of the lists.
pub fn refresh_failed(result: &dss::Result<RefreshRecord>) -> bool {
    match result {
        Ok(r) => !r.completed || r.trusted_certificates == 0,
        Err(e) => e.code() != Some(ErrorCode::RefreshInProgress),
    }
}

async fn validate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    multipart: Result<Multipart, MultipartRejection>,
) -> Result<Response, ApiError> {
    let engine = state.engine()?;
    let permit = state.admit()?;
    let deadline = state.deadline();
    let parts = Parts::read(multipart_of(&headers, multipart)?, &["document", "options", "detached"]).await?;
    let document = required(parts.document, "document")?;
    let mut options = parts.options.unwrap_or_default();
    default_filename(&mut options, parts.filename);
    refuse_detached_paths(&options)?;
    let options = Value::Object(options).to_string();
    let detached = parts.detached;
    let json = run(engine, Some(permit), deadline, move |e, token| {
        // The `detached` parts go to the library as binary buffers (`dss_validate_with_contents`), borrowed
        // from the multipart body: no base64, no copy into the options.
        let contents: Vec<DetachedBytes<'_>> = detached
            .iter()
            .map(|(name, bytes)| DetachedBytes::named(name, bytes))
            .collect();
        e.cancellable(token)
            .validate_with_contents_json(&document, &options, &contents)
    })
    .await?;
    Ok(json_response(StatusCode::OK, json))
}

async fn extend(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    multipart: Result<Multipart, MultipartRejection>,
) -> Result<Response, ApiError> {
    let engine = state.engine()?;
    let permit = state.admit()?;
    let deadline = state.deadline();
    let parts = Parts::read(multipart_of(&headers, multipart)?, &["document", "options"]).await?;
    let document = required(parts.document, "document")?;
    let mut options = required(parts.options, "options")?;
    default_filename(&mut options, parts.filename);
    let options = Value::Object(options).to_string();
    let (json, pdf) = run(engine, Some(permit), deadline, move |e, token| {
        e.cancellable(token).extend_json(&document, &options)
    })
    .await?;
    document_response(&parse_result(&json)?, pdf, "application/pdf")
}

/// Signing passes the options on untouched, filename included: `complete` must get exactly what `prepare` got,
/// or the digest differs.
async fn sign_prepare(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    multipart: Result<Multipart, MultipartRejection>,
) -> Result<Response, ApiError> {
    let engine = state.engine()?;
    let permit = state.admit()?;
    let deadline = state.deadline();
    let parts = Parts::read(multipart_of(&headers, multipart)?, &["document", "options"]).await?;
    let document = required(parts.document, "document")?;
    let options = Value::Object(required(parts.options, "options")?).to_string();
    let json = run(engine, Some(permit), deadline, move |e, token| {
        e.cancellable(token).prepare_signature_json(&document, &options)
    })
    .await?;
    Ok(json_response(StatusCode::OK, json))
}

async fn sign_complete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    multipart: Result<Multipart, MultipartRejection>,
) -> Result<Response, ApiError> {
    let engine = state.engine()?;
    let permit = state.admit()?;
    let deadline = state.deadline();
    let parts = Parts::read(
        multipart_of(&headers, multipart)?,
        &["document", "options", "signature"],
    )
    .await?;
    let document = required(parts.document, "document")?;
    let options = Value::Object(required(parts.options, "options")?).to_string();
    let signature = required(parts.signature, "signature")?;
    let (json, signed) = run(engine, Some(permit), deadline, move |e, token| {
        e.cancellable(token)
            .complete_signature_json(&document, &options, &signature)
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
    let json = run(engine, None, None, |e, _| e.trusted_list_status_json()).await?;
    Ok(json_response(StatusCode::OK, json))
}

/// Starts an online refresh and answers at once; `/tl/status` shows its progress and outcome. The caller is
/// logged: the token that validates also refreshes, and each refresh downloads every list again.
async fn tl_refresh(
    State(state): State<Arc<AppState>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Result<Response, ApiError> {
    let engine = state.engine()?;
    let peer = peer.map_or_else(|| "a client".to_owned(), |Extension(ConnectInfo(p))| p.to_string());
    let already = || {
        ApiError::new(
            StatusCode::CONFLICT,
            "REFRESH_IN_PROGRESS",
            "an online refresh is already running or requested",
        )
    };
    if state.scheduler.get().is_some() {
        match state.request_refresh() {
            RefreshRequest::Started => {}
            RefreshRequest::AlreadyPending => return Err(already()),
            _ => {
                return Err(ApiError::internal(
                    "the refresh schedule has stopped: restart the server (POST /tl/refresh cannot run a refresh)",
                ));
            }
        }
    } else {
        if state.direct_refresh.swap(true, Ordering::AcqRel) {
            return Err(already());
        }
        // Only the engine is held while the refresh runs, not the state: a shutdown meanwhile can take the
        // state apart (the engine is released when this call returns).
        let state = Arc::downgrade(&state);
        tokio::task::spawn_blocking(move || {
            let result = engine.refresh_trusted_lists();
            if let Some(state) = state.upgrade() {
                state.direct_refresh.store(false, Ordering::Release);
            }
            eprintln!("dss-server: {}", describe_refresh(&result));
        });
    }
    eprintln!("dss-server: online trusted-list refresh requested by {peer}");
    Ok(json_response(StatusCode::ACCEPTED, json!({"ok": true}).to_string()))
}

async fn version(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let engine = state.engine()?;
    let v = run(engine, None, None, |e, _| e.version()).await?;
    let body = json!({
        "ok": true,
        "server": env!("CARGO_PKG_VERSION"),
        "library": v.library,
        "dss": v.dss,
        "runtime": v.runtime,
        "api_version": v.api_version,
    });
    Ok(json_response(StatusCode::OK, body.to_string()))
}

/// 200 when the engine can serve: it is up, and the trusted lists are loaded when it requires them. 503 with
/// `status` `starting` or `waiting_for_trusted_lists` otherwise, so that `--health-check` and orchestrators do
/// not route traffic to an instance that answers `TRUSTED_LISTS_NOT_LOADED`.
async fn health(State(state): State<Arc<AppState>>) -> Response {
    let Ok(engine) = state.engine() else {
        let body = json!({"ok": false, "status": "starting"});
        return json_response(StatusCode::SERVICE_UNAVAILABLE, body.to_string());
    };
    match run(engine, None, None, |e, _| e.trusted_list_status()).await {
        Ok(s) => {
            let ready = s.loaded || !state.settings.trusted_lists_required;
            let mut body = json!({
                "ok": ready,
                "status": if ready { "ready" } else { "waiting_for_trusted_lists" },
                "trusted_lists_loaded": s.loaded,
                "refresh_in_progress": s.refresh_in_progress,
                "last_online_refresh": s.last_online_refresh,
                "in_flight": state.in_flight(),
                "max_in_flight": state.settings.max_in_flight,
            });
            if !ready {
                body["ok"] = Value::Bool(false);
            }
            let status = if ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            json_response(status, body.to_string())
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

async fn method_not_allowed() -> ApiError {
    ApiError::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "METHOD_NOT_ALLOWED",
        "this endpoint does not take this method (the Allow header lists the ones it takes)",
    )
}

async fn authorize(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    match &state.settings.token {
        Some(token) => {
            let sent = request
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok());
            let given = sent.and_then(bearer_token);
            if !given.is_some_and(|g| same(g.as_bytes(), token.as_bytes())) {
                // RFC 9110: a 401 names the scheme it expects; RFC 6750: `invalid_token` when one was sent.
                let challenge = if sent.is_some() {
                    "Bearer error=\"invalid_token\""
                } else {
                    "Bearer"
                };
                return ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    "UNAUTHORIZED",
                    "missing or wrong bearer token",
                )
                .with_header(header::WWW_AUTHENTICATE, challenge)
                .into_response();
            }
        }
        // Browsers send Origin with every cross-site POST, and a form or fetch from any web page can reach a
        // sidecar on localhost. Without a token to stop them, those requests are refused.
        None if request.headers().contains_key(header::ORIGIN) => {
            return ApiError::new(
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                "requests from web pages (with an Origin header) are not accepted; run the server with a token \
                 (--token-file) if a page must call it",
            )
            .into_response();
        }
        None => {}
    }
    next.run(request).await
}

/// The token of an `Authorization` header value: the scheme is case-insensitive and followed by one or more
/// spaces (RFC 7235).
fn bearer_token(value: &str) -> Option<&str> {
    let (scheme, rest) = value.trim().split_once([' ', '\t'])?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim();
    (!token.is_empty()).then_some(token)
}

/// Constant-time comparison: the response time does not tell how much of the token matched.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Bounds a request to [`Settings::request_timeout`]: body upload and engine call together.
async fn with_deadline(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    match state.settings.request_timeout {
        None => next.run(request).await,
        Some(timeout) => match tokio::time::timeout(timeout, next.run(request)).await {
            Ok(response) => response,
            Err(_) => ApiError::timeout(timeout).into_response(),
        },
    }
}

/// Runs a blocking engine call off the async threads. The engine's own workers do the work; this thread waits.
/// The admission `permit` is released when the call returns, even if the request was abandoned (client gone or
/// deadline passed) meanwhile; a call whose `deadline` has already passed is not made.
///
/// `call` gets a [`CancelToken`] for the engine ([`Engine::cancellable`]) that is cancelled as soon as this
/// future is dropped without an answer: the deadline layer drops it when [`Settings::request_timeout`] fires,
/// and the connection drops it when the client goes away before the response. A call still queued in the
/// engine is then skipped by the worker that takes it (and one not yet submitted is not submitted at all);
/// one already running finishes, as the library cannot interrupt it.
async fn run<T: Send + 'static>(
    engine: Arc<Engine>,
    permit: Option<OwnedSemaphorePermit>,
    deadline: Option<Instant>,
    call: impl FnOnce(&Engine, &CancelToken) -> dss::Result<T> + Send + 'static,
) -> Result<T, ApiError> {
    let token = CancelToken::new();
    // Dropped with this future: after the answer (harmless, the token is only read while the call is queued)
    // or when the request is abandoned (then it cancels).
    let _abandoned = CancelOnDrop(token.clone());
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        if token.is_cancelled() || deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(ApiError::new(
                StatusCode::GATEWAY_TIMEOUT,
                "TIMEOUT",
                "the request waited past the server's --request-timeout before the engine could take it",
            ));
        }
        call(&engine, &token).map_err(ApiError::from)
    })
    .await
    .map_err(|e| ApiError::internal(format!("engine call failed: {e}")))?
}

/// Cancels its token when dropped: the request's engine call, if still queued, is skipped.
struct CancelOnDrop(CancelToken);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// The `Multipart` extractor, or 400 saying what the request should have been.
fn multipart_of(headers: &HeaderMap, multipart: Result<Multipart, MultipartRejection>) -> Result<Multipart, ApiError> {
    multipart.map_err(|rejection| {
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::trim);
        match content_type {
            Some(ct) if ct.to_ascii_lowercase().starts_with("multipart/form-data") => {
                ApiError::from_body(rejection.status(), rejection.body_text())
            }
            Some(ct) => ApiError::invalid(format!(
                "the request must be multipart/form-data (its Content-Type is {ct})"
            )),
            None => ApiError::invalid("the request must be multipart/form-data (it has no Content-Type)"),
        }
    })
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

/// A `path` in `detached_contents` would make the server read its own files for a client, so it is refused.
/// (Detached contents arrive as `detached` parts, passed to the library as binary buffers, or as `base64`
/// entries, which the library decodes.)
fn refuse_detached_paths(options: &Map<String, Value>) -> Result<(), ApiError> {
    if let Some(entries) = options.get("detached_contents")
        && entries
            .as_array()
            .is_some_and(|a| a.iter().any(|e| e.get("path").is_some()))
    {
        return Err(ApiError::invalid(
            "detached_contents[].path is not accepted over HTTP: send the file as a 'detached' part, or as base64",
        ));
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
            (HeaderName::from_static(RESULT_HEADER), value),
        ],
        document,
    )
        .into_response())
}

fn json_response(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// An error result: the library's code and message, or one of the server's own codes (`UNAUTHORIZED`,
/// `FORBIDDEN`, `NOT_FOUND`, `METHOD_NOT_ALLOWED`, `REQUEST_TOO_LARGE`, `SERVER_BUSY`, `TIMEOUT`), with the
/// HTTP status for it.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: String,
    message: String,
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl ApiError {
    fn new(status: StatusCode, code: &str, message: impl Into<String>) -> Self {
        ApiError {
            status,
            code: code.into(),
            message: message.into(),
            headers: vec![],
        }
    }

    fn with_header(mut self, name: HeaderName, value: &'static str) -> Self {
        self.headers.push((name, HeaderValue::from_static(value)));
        self
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", message)
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", message)
    }

    fn timeout(timeout: Duration) -> Self {
        Self::new(
            StatusCode::GATEWAY_TIMEOUT,
            "TIMEOUT",
            format!(
                "the request took longer than the server's --request-timeout ({} s)",
                timeout.as_secs()
            ),
        )
    }

    /// An error reading the multipart body: 413 keeps its status; anything else is the client's request (a
    /// malformed body, a stream that broke off), never a server error.
    fn from_body(status: StatusCode, message: String) -> Self {
        if status == StatusCode::PAYLOAD_TOO_LARGE {
            Self::new(status, "REQUEST_TOO_LARGE", message)
        } else if status.is_client_error() {
            Self::invalid(message)
        } else {
            Self::invalid(format!("the request body could not be read: {message}"))
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
        ErrorCode::TlRefreshFailed | ErrorCode::TsaFailed => StatusCode::BAD_GATEWAY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        match e {
            Error::Api { code, message } => ApiError::new(status_of(code), code.as_str(), message),
            Error::Nul | Error::Argument(_) => ApiError::invalid(e.to_string()),
            Error::Closed => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "NOT_INITIALIZED", e.to_string()),
            // Only ever produced for a request nobody waits for any more (see `run`): never sent, not a 5xx.
            Error::Cancelled => ApiError::new(
                StatusCode::GATEWAY_TIMEOUT,
                "TIMEOUT",
                "the request was abandoned before the engine could take it",
            ),
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
        let mut response = json_response(self.status, body.to_string());
        for (name, value) in self.headers {
            response.headers_mut().insert(name, value);
        }
        response
    }
}
