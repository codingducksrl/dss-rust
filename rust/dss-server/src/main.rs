// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! dss-server: the HTTP sidecar (see lib.rs and docs/server.md).
//!
//!   dss-server [--listen 127.0.0.1:8484] [--token-file <file>] [--refresh-hours 6] [engine options as dss-cli]
//!   dss-server --health-check     exit status 0 if the server at --listen answers /health with 200
//!
//! Every option also reads an environment variable (`dss-server --help`), for containers; an empty variable is
//! the same as an unset one. The server listens at once and answers 503 until the engine is up and, unless
//! --allow-without-trusted-lists, until its trusted lists are loaded; if the engine cannot start, it exits with
//! status 2. SIGTERM or Ctrl-C stops it after the requests in progress (bounded by --request-timeout); a second
//! signal stops it at once.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use axum::Router;
use axum::extract::ConnectInfo;
use clap::builder::BoolishValueParser;
use clap::{ArgAction, Parser, ValueEnum};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::{Semaphore, watch};
use tower::ServiceExt as _;

use dss::schedule::RefreshScheduler;
use dss::{Config, Engine, EngineBuilder, Http, Revocation, Tsa};
use dss_server::{AppState, Settings, describe_refresh, parse_rfc3339, refresh_failed, router};

/// A client that has not sent a whole request line and headers within this time (also idle on a keep-alive
/// connection) is disconnected.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// The shortest token accepted from --token-file, in bytes: anything less is guessable from the network.
const MIN_TOKEN_BYTES: usize = 16;
/// The first retry after a failed online refresh; each further failure doubles it, up to --refresh-hours.
const FIRST_RETRY: Duration = Duration::from_secs(60);

/// The engine options a full `--config` replaces: giving one of them (or its environment variable) together with
/// `--config` is a usage error instead of being silently dropped.
const CONFIG_REPLACES: [&str; 14] = [
    "oj_keystore",
    "oj_url",
    "lotl_url",
    "tl_snapshot",
    "countries",
    "offline_revocation",
    "trusted_certificates",
    "allow_without_trusted_lists",
    "tsa_url",
    "tsa_user",
    "tsa_password_file",
    "allow_private_addresses",
    "tl_threads",
    "log_level",
];

#[derive(Parser)]
#[command(
    name = "dss-server",
    version,
    about = "EU DSS over HTTP: validate CAdES/PAdES signatures, extend PAdES signatures, sign with an external \
             signer. One engine for every request; the trusted lists are refreshed on a schedule"
)]
struct Args {
    /// Address and port to listen on. Use 0.0.0.0:<port> in a container.
    #[arg(long, env = "DSS_LISTEN", default_value = "127.0.0.1:8484")]
    listen: SocketAddr,
    /// File holding a bearer token (at least 16 bytes, e.g. `openssl rand -base64 32`) that every endpoint but
    /// /health and /openapi.yaml then requires.
    #[arg(long, env = "DSS_TOKEN_FILE")]
    token_file: Option<PathBuf>,
    /// Hours between online trusted-list refreshes; 0 refreshes only when POST /tl/refresh asks. The first
    /// refresh starts at once when nothing is cached or the cache is older than this, else when it gets that
    /// old; a failed refresh is retried after 1, 2, 4, … minutes.
    #[arg(long, env = "DSS_REFRESH_HOURS", default_value_t = 6, value_parser = clap::value_parser!(u64).range(0..=1_000_000))]
    refresh_hours: u64,
    /// Largest request accepted, in MiB (document, detached contents and signature together).
    #[arg(long, env = "DSS_MAX_REQUEST_MB", default_value_t = 100, value_parser = clap::value_parser!(u64).range(1..=1_048_576))]
    max_request_mb: u64,
    /// Document requests (/validate, /extend, /sign/*) read and processed at the same time; the next one is
    /// answered 503 SERVER_BUSY at once. With --max-request-mb, the bound on the server's own memory
    /// [default: twice --workers].
    #[arg(long, env = "DSS_MAX_IN_FLIGHT", value_parser = clap::value_parser!(u64).range(1..=256))]
    max_in_flight: Option<u64>,
    /// Seconds a request may take, upload and engine call included, before 504 TIMEOUT; 0: no limit. An engine
    /// call still queued when the deadline fires (or the client disconnects) is skipped; a running one finishes.
    #[arg(long, env = "DSS_REQUEST_TIMEOUT", default_value_t = 300, value_parser = clap::value_parser!(u64).range(0..=86_400))]
    request_timeout: u64,
    /// Open connections accepted at the same time; further clients wait in the listen queue.
    #[arg(long, env = "DSS_MAX_CONNECTIONS", default_value_t = 1024, value_parser = clap::value_parser!(u64).range(1..=65_536))]
    max_connections: u64,
    /// Engine threads: requests the engine runs at the same time [default: number of CPUs].
    #[arg(long, env = "DSS_WORKERS", value_parser = clap::value_parser!(u64).range(1..=1024))]
    workers: Option<u64>,

    /// Trusted-list cache directory (created if missing) [default: dss-native in the user cache directory:
    /// $XDG_CACHE_HOME or ~/.cache, ~/Library/Caches on macOS]. Never the current directory.
    #[arg(long, env = "DSS_CACHE_DIR")]
    cache_dir: Option<PathBuf>,
    /// Full config_json file. Excludes the trusted-list, trust, TSA and log options below (as flags or through
    /// their environment variables); --cache-dir, --workers and --max-heap still apply.
    #[arg(long, env = "DSS_CONFIG", conflicts_with_all = CONFIG_REPLACES)]
    config: Option<PathBuf>,
    /// OJ keystore with the LOTL signing certificates [default: oj-keystore.p12 next to the executable, else
    /// ../share/dss-native/oj-keystore.p12 relative to it; a development build also knows the repository's
    /// trust/oj-keystore.p12]. Never looked up in the current directory.
    #[arg(long, env = "DSS_OJ_KEYSTORE")]
    oj_keystore: Option<PathBuf>,
    /// URL of the Official Journal publication of the LOTL signing certificates (for a mirror or a test).
    #[arg(long, env = "DSS_OJ_URL")]
    oj_url: Option<String>,
    /// URL of the LOTL (for a mirror or a test).
    #[arg(long, env = "DSS_LOTL_URL")]
    lotl_url: Option<String>,
    /// Start from this trusted-list snapshot (dss-cli `tl snapshot`) instead of the cache: no list is parsed or
    /// validated. It must have been written with the same trusted-list options.
    #[arg(long, env = "DSS_TL_SNAPSHOT")]
    tl_snapshot: Option<PathBuf>,
    /// Load only these national trusted lists (repeatable, or comma-separated in the variable, e.g. IT).
    /// Signatures anchored in another member state's list then validate INDETERMINATE.
    #[arg(long = "country", env = "DSS_COUNTRIES", value_delimiter = ',')]
    countries: Vec<String>,
    /// Use only revocation data embedded in the signatures (no CRL/OCSP/AIA requests).
    #[arg(long, env = "DSS_OFFLINE_REVOCATION", value_parser = BoolishValueParser::new(), action = ArgAction::Set,
          num_args = 0..=1, default_missing_value = "true", default_value_t = false)]
    offline_revocation: bool,
    /// Extra trusted certificate, PEM or DER (repeatable, or comma-separated in the variable).
    #[arg(long = "trust", env = "DSS_TRUST", value_delimiter = ',')]
    trusted_certificates: Vec<PathBuf>,
    /// Validate even if no trusted list is loaded; /health is then ready as soon as the engine is up.
    #[arg(long, env = "DSS_ALLOW_WITHOUT_TRUSTED_LISTS", value_parser = BoolishValueParser::new(), action = ArgAction::Set,
          num_args = 0..=1, default_missing_value = "true", default_value_t = false)]
    allow_without_trusted_lists: bool,
    /// RFC 3161 timestamping service, for extension and signing at T and LTA.
    #[arg(long, env = "DSS_TSA_URL")]
    tsa_url: Option<String>,
    /// HTTP Basic user for the TSA (needs --tsa-url); the password comes from --tsa-password-file or the
    /// DSS_TSA_PASSWORD environment variable.
    #[arg(long, env = "DSS_TSA_USER", requires = "tsa_url")]
    tsa_user: Option<String>,
    /// File holding the TSA password (trailing whitespace ignored): like the token, it stays out of `ps`,
    /// `docker inspect` and the environment.
    #[arg(long, env = "DSS_TSA_PASSWORD_FILE", requires = "tsa_user")]
    tsa_password_file: Option<PathBuf>,
    /// Let the engine fetch from loopback, private, link-local and similar addresses (literal or resolved).
    /// By default a TSA, LOTL/TL mirror, CRL or OCSP responder there is refused: "outbound request to <url>
    /// refused by policy". Needed for a TSA or mirror on the Compose network or on this host.
    #[arg(long, env = "DSS_ALLOW_PRIVATE_ADDRESSES", value_parser = BoolishValueParser::new(), action = ArgAction::Set,
          num_args = 0..=1, default_missing_value = "true", default_value_t = false)]
    allow_private_addresses: bool,
    /// Threads that download and validate the trusted lists, 1 to 64 [default: CPUs, at most 16].
    #[arg(long, env = "DSS_TL_THREADS", value_parser = clap::value_parser!(u32).range(1..=64))]
    tl_threads: Option<u32>,
    /// Maximum heap of the engine, e.g. 512m, 2g (digits and a unit k, m, g or t) [default: grows with
    /// physical memory].
    #[arg(long, env = "DSS_MAX_HEAP")]
    max_heap: Option<String>,
    /// Library log level (stderr).
    #[arg(long, env = "DSS_LOG_LEVEL", value_enum, default_value_t = LogLevel::Warn)]
    log_level: LogLevel,

    /// Ask the server at --listen for /health instead of starting one: exit status 0 if it is ready, 1 if not.
    /// For container health checks, which then need no HTTP client in the image.
    #[arg(long)]
    health_check: bool,
}

/// The library's log levels (slf4j-simple's names).
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn name(self) -> &'static str {
        match self {
            LogLevel::Off => "off",
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
}

fn main() -> ExitCode {
    drop_empty_dss_variables();
    let args = Args::parse();
    if args.health_check {
        return if healthy(args.listen) {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("dss-server: cannot start the runtime: {e}");
            return ExitCode::from(2);
        }
    };
    match runtime.block_on(serve(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dss-server: {e}");
            ExitCode::from(2)
        }
    }
}

/// An empty `DSS_*` variable (a Compose `${VAR:-}` or a blank `.env` line) means unset, not an empty value:
/// clap would otherwise take it as a given, empty option and fail, with a message about a flag nobody typed.
fn drop_empty_dss_variables() {
    let empty: Vec<String> = std::env::vars_os()
        .filter(|(name, value)| name.to_str().is_some_and(|n| n.starts_with("DSS_")) && value.is_empty())
        .filter_map(|(name, _)| name.into_string().ok())
        .collect();
    for name in empty {
        // SAFETY: called first thing in main, before any other thread of this process exists.
        unsafe { std::env::remove_var(name) };
    }
}

async fn serve(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let token = read_token(args.token_file.as_deref())?;
    let cache_dir = cache_dir(&args)?;
    let builder = engine_builder(&args, &cache_dir)?;
    let trusted_lists_required = trusted_lists_required(&args)?;
    // Registered before anything runs: a failure is a start-up error, not a server that silently stops as if
    // a signal had arrived when the stop channel's sender goes away.
    let signals = (
        signal(SignalKind::terminate()).map_err(|e| format!("cannot install the SIGTERM handler: {e}"))?,
        signal(SignalKind::interrupt()).map_err(|e| format!("cannot install the SIGINT handler: {e}"))?,
    );
    let refresh_every = match args.refresh_hours {
        0 => None,
        hours => Some(Duration::from_secs(
            hours.checked_mul(3600).ok_or("--refresh-hours is too large")?,
        )),
    };
    let max_request_bytes = args
        .max_request_mb
        .checked_mul(1024 * 1024)
        .and_then(|b| usize::try_from(b).ok())
        .ok_or("--max-request-mb is too large for this platform")?;
    let workers = workers(&args);
    let settings = Settings {
        token,
        max_in_flight: args
            .max_in_flight
            .map_or(workers.saturating_mul(2).min(256), |n| n as usize),
        request_timeout: (args.request_timeout > 0).then(|| Duration::from_secs(args.request_timeout)),
        trusted_lists_required,
    };

    let state = AppState::with(settings);
    let app = router(Arc::clone(&state), max_request_bytes);
    let listener = TcpListener::bind(args.listen)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", args.listen))?;
    eprintln!("dss-server: listening on {}", listener.local_addr()?);

    start_engine(Arc::clone(&state), builder, cache_dir, refresh_every);

    let (stopping_tx, stopping_rx) = watch::channel(false);
    let open = Arc::new(AtomicUsize::new(0));
    watch_signals(signals, stopping_tx, Arc::clone(&open));
    serve_connections(listener, app, args.max_connections as usize, stopping_rx, open).await;
    eprintln!("dss-server: stopping");
    // The engine is released once nothing holds the state any more. The engine's start-up task holds it until the
    // engine is up, and a refresh started by /tl/refresh without a schedule holds the engine itself: in both
    // cases exiting is enough (dropping the runtime waits for the blocking call, which releases the engine).
    match Arc::into_inner(state) {
        Some(state) => state.shutdown().await,
        None => eprintln!(
            "dss-server: the state is still in use (the engine is starting, or a refresh is running): not \
             waiting for it"
        ),
    }
    Ok(())
}

/// `--cache-dir` / `DSS_CACHE_DIR`, else `dss-native` in the user's cache directory. Never the current
/// directory: a directory someone else prepared must not decide which trusted lists are loaded.
fn cache_dir(a: &Args) -> Result<PathBuf, String> {
    match &a.cache_dir {
        Some(dir) => Ok(dir.clone()),
        None => default_cache_dir()
            .ok_or_else(|| "no cache directory: HOME is not set, pass --cache-dir or set DSS_CACHE_DIR".to_string()),
    }
}

fn default_cache_dir() -> Option<PathBuf> {
    let home = || std::env::var_os("HOME").map(PathBuf::from).filter(|h| h.is_absolute());
    let base = if cfg!(target_os = "macos") {
        home()?.join("Library/Caches")
    } else {
        // XDG Base Directory: a relative XDG_CACHE_HOME is invalid and ignored.
        match std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from) {
            Some(dir) if dir.is_absolute() => dir,
            _ => home()?.join(".cache"),
        }
    };
    Some(base.join("dss-native"))
}

fn absolute(p: &Path) -> PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

/// The bearer token from its file: trimmed, non-empty and long enough to be unguessable.
fn read_token(path: Option<&Path>) -> Result<Option<String>, String> {
    let Some(path) = path else {
        return Ok(None);
    };
    let token = std::fs::read_to_string(path)
        .map_err(|e| format!("token file {}: {e}", path.display()))?
        .trim()
        .to_owned();
    if token.is_empty() {
        return Err(format!("token file {}: the token file is empty", path.display()));
    }
    if token.len() < MIN_TOKEN_BYTES {
        return Err(format!(
            "token file {}: the token is {} bytes long, at least {MIN_TOKEN_BYTES} are needed (e.g. openssl rand \
             -base64 32)",
            path.display(),
            token.len()
        ));
    }
    Ok(Some(token))
}

fn workers(a: &Args) -> usize {
    a.workers.map_or_else(
        || std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        |n| n as usize,
    )
}

/// Whether validation needs loaded trusted lists (the library's `require_trusted_lists`, default true), which
/// `/health` then waits for.
fn trusted_lists_required(a: &Args) -> Result<bool, String> {
    match &a.config {
        None => Ok(!a.allow_without_trusted_lists),
        Some(path) => {
            let text = std::fs::read_to_string(path).map_err(|e| format!("config file {}: {e}", path.display()))?;
            // A malformed file is reported by the engine (INVALID_CONFIG) when it starts.
            let config: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
            Ok(config["require_trusted_lists"].as_bool().unwrap_or(true))
        }
    }
}

/// Builds the engine off the async threads, then publishes it to the requests and starts the refresh schedule.
fn start_engine(state: Arc<AppState>, builder: EngineBuilder, cache_dir: PathBuf, refresh_every: Option<Duration>) {
    tokio::spawn(async move {
        let started = Instant::now();
        let built = tokio::task::spawn_blocking(move || {
            builder.build().map(|engine| {
                let loaded = engine.init_info().trusted_lists_loaded;
                let age = loaded.then(|| trusted_list_age(&engine, &cache_dir)).flatten();
                (Arc::new(engine), loaded, age)
            })
        })
        .await;
        let (engine, loaded, age) = match built {
            Ok(Ok(e)) => e,
            Ok(Err(e)) => fail(&format!("the engine did not start: {e}")),
            Err(e) => fail(&format!("the engine did not start: {e}")),
        };
        eprintln!(
            "dss-server: engine ready in {} ms, trusted lists {}",
            started.elapsed().as_millis(),
            match (loaded, age) {
                (false, _) => "not cached yet".to_owned(),
                (true, None) => "loaded (age unknown)".to_owned(),
                (true, Some(age)) => format!("loaded, downloaded {} ago", describe(age)),
            }
        );
        let scheduler = refresh_every.map(|every| {
            // Lists older than the period are refreshed at once; younger ones when they reach that age, so that
            // restarts more frequent than the period do not keep them from ever being refreshed.
            let due_in = age.filter(|_| loaded).map(|age| every.saturating_sub(age));
            let refresh_on_start = due_in.is_none_or(|d| d.is_zero());
            let scheduler = match RefreshScheduler::try_spawn(Arc::clone(&engine), every, refresh_on_start) {
                Ok(s) => s,
                Err(e) => fail(&format!("cannot schedule the trusted-list refresh: {e}")),
            };
            if let Some(due_in) = due_in.filter(|d| !d.is_zero()) {
                eprintln!("dss-server: first online trusted-list refresh in {}", describe(due_in));
                let state = Arc::downgrade(&state);
                tokio::spawn(async move {
                    tokio::time::sleep(due_in).await;
                    if let Some(state) = state.upgrade() {
                        state.request_refresh();
                    }
                });
            }
            log_and_retry_refreshes(&scheduler, Arc::downgrade(&state), every);
            scheduler
        });
        if scheduler.is_none() && !loaded {
            eprintln!("dss-server: no trusted lists yet and no refresh scheduled: POST /tl/refresh loads them");
        }
        state.set_engine(engine, scheduler);
    });
}

/// Logs every outcome of the schedule; after a failed refresh, asks for another one after 1, 2, 4, … minutes
/// (at most `every`), instead of waiting a whole period with no lists or stale ones.
fn log_and_retry_refreshes(scheduler: &RefreshScheduler, state: std::sync::Weak<AppState>, every: Duration) {
    let mut outcomes = scheduler.subscribe();
    tokio::spawn(async move {
        let mut failures: u32 = 0;
        while outcomes.changed().await.is_ok() {
            let Some(outcome) = outcomes.borrow_and_update().clone() else {
                continue;
            };
            eprintln!("dss-server: {}", describe_refresh(&outcome.result));
            if !refresh_failed(&outcome.result) {
                failures = 0;
                continue;
            }
            failures += 1;
            let retry_in = FIRST_RETRY
                .checked_mul(1u32 << failures.saturating_sub(1).min(20))
                .map_or(every, |d| d.min(every));
            eprintln!(
                "dss-server: retrying the online trusted-list refresh in {}",
                describe(retry_in)
            );
            let state = state.clone();
            tokio::spawn(async move {
                tokio::time::sleep(retry_in).await;
                if let Some(state) = state.upgrade() {
                    state.request_refresh();
                }
            });
        }
    });
}

/// How long ago the loaded trusted lists were downloaded: the newest file of the cache, or, from a snapshot,
/// when its lists were published (`snapshot_published_at`; the snapshot file's mtime only when the status does
/// not say, since a copy or an image build dates the file, not the lists). None when nothing tells.
fn trusted_list_age(engine: &Engine, cache_dir: &Path) -> Option<Duration> {
    let downloaded = if engine.init_info().initial_load.mode == "snapshot" {
        let status = engine.trusted_list_status().ok()?;
        match status.snapshot_published_at.as_deref().and_then(parse_rfc3339) {
            Some(published) => published,
            None => {
                let path = status.tl_snapshot?.path?;
                std::fs::metadata(path).ok()?.modified().ok()?
            }
        }
    } else {
        std::fs::read_dir(cache_dir.join("tl"))
            .ok()?
            .flatten()
            .filter(|entry| !entry.file_name().to_string_lossy().starts_with('.'))
            .filter_map(|entry| entry.metadata().ok())
            .filter(|m| m.is_file())
            .filter_map(|m| m.modified().ok())
            .max()?
    };
    // A file dated in the future (clock skew) counts as just downloaded.
    Some(SystemTime::now().duration_since(downloaded).unwrap_or_default())
}

fn describe(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 7200 {
        format!("{} h", secs / 3600)
    } else if secs >= 120 {
        format!("{} min", secs / 60)
    } else {
        format!("{secs} s")
    }
}

/// Accepts connections and serves each with HTTP/1.1 until the stop signal, then finishes the requests in
/// progress: idle connections are closed at once, the rest when their response is written (a stalled upload
/// ends with --request-timeout, a stalled request line with the header timeout).
async fn serve_connections(
    listener: TcpListener,
    app: Router,
    max_connections: usize,
    mut stopping: watch::Receiver<bool>,
    open: Arc<AtomicUsize>,
) {
    let slots = Arc::new(Semaphore::new(max_connections));
    let (close_tx, close_rx) = watch::channel(());
    loop {
        // Only a stop that was sent counts: a sender gone without one (which cannot happen, the signal task
        // runs for the life of the process) is not a stop.
        let slot = tokio::select! {
            slot = Arc::clone(&slots).acquire_owned() => slot.expect("connection semaphore is never closed"),
            Ok(_) = stopping.wait_for(|s| *s) => break,
        };
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(c) => c,
                Err(e) => {
                    // Out of file descriptors or a transient network error: back off instead of spinning.
                    eprintln!("dss-server: accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            Ok(_) = stopping.wait_for(|s| *s) => break,
        };
        let service = app
            .clone()
            .map_request(move |mut request: axum::http::Request<hyper::body::Incoming>| {
                request.extensions_mut().insert(ConnectInfo(peer));
                request
            });
        let mut stopping = stopping.clone();
        let close_rx = close_rx.clone();
        let open = Arc::clone(&open);
        open.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            let mut builder = http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT);
            {
                let connection = builder.serve_connection(TokioIo::new(stream), TowerToHyperService::new(service));
                let mut connection = pin!(connection);
                let mut told = false;
                loop {
                    tokio::select! {
                        _ = connection.as_mut() => break,
                        stop = stopping.wait_for(|s| *s), if !told => {
                            told = true;
                            if stop.is_ok() {
                                connection.as_mut().graceful_shutdown();
                            }
                        }
                    }
                }
            }
            // The connection (and the router clone it served, which holds the state) is gone before the accept
            // loop can see this connection as closed.
            open.fetch_sub(1, Ordering::Relaxed);
            drop(close_rx);
            drop(slot);
        });
    }
    drop(listener);
    drop(close_rx);
    close_tx.closed().await;
}

/// The first SIGTERM or SIGINT starts the graceful stop; a second one ends the process at once, dropping what is
/// still open (tokio keeps its handlers installed for the life of the process, so without this a second signal
/// would be swallowed and only SIGKILL could end a server waiting on a stalled client). The task never ends, so
/// the stop channel's sender lives for the life of the process.
fn watch_signals((mut term, mut int): (Signal, Signal), stopping: watch::Sender<bool>, open: Arc<AtomicUsize>) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = term.recv() => {}
                _ = int.recv() => {}
            }
            if *stopping.borrow() {
                eprintln!(
                    "dss-server: stopping now, {} connection(s) dropped",
                    open.load(Ordering::Relaxed)
                );
                std::process::exit(0);
            }
            eprintln!(
                "dss-server: stop requested, finishing the requests in progress ({} connection(s) open)",
                open.load(Ordering::Relaxed)
            );
            let _ = stopping.send(true);
        }
    });
}

fn healthy(mut addr: SocketAddr) -> bool {
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() {
            Ipv4Addr::LOCALHOST.into()
        } else {
            Ipv6Addr::LOCALHOST.into()
        });
    }
    let timeout = Duration::from_secs(3);
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, timeout) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let mut response = String::new();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .and_then(|()| stream.read_to_string(&mut response))
        .is_ok_and(|_| response.starts_with("HTTP/1.1 200"))
}

fn fail(message: &str) -> ! {
    eprintln!("dss-server: {message}");
    std::process::exit(2)
}

/// As dss-cli builds its engine. The trust inputs it resolved (keystore, cache directory, or the config file
/// that names them) are logged, so that a start-up against the wrong ones can be told from the log.
fn engine_builder(a: &Args, cache_dir: &Path) -> Result<EngineBuilder, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(cache_dir).map_err(|e| format!("cache directory {}: {e}", cache_dir.display()))?;
    let mut builder = match &a.config {
        Some(path) => {
            eprintln!(
                "dss-server: engine configuration from {}, cache directory {}",
                absolute(path).display(),
                absolute(cache_dir).display()
            );
            EngineBuilder::with_config_json(
                cache_dir,
                std::fs::read_to_string(path).map_err(|e| format!("config file {}: {e}", path.display()))?,
            )
        }
        None => {
            let keystore = oj_keystore(a)?;
            eprintln!(
                "dss-server: OJ keystore {}, cache directory {}",
                absolute(&keystore).display(),
                absolute(cache_dir).display()
            );
            let mut config = Config::new(keystore);
            config.oj_url = a.oj_url.clone();
            config.lotl_url = a.lotl_url.clone();
            config.tl_snapshot = a.tl_snapshot.clone();
            config.countries = a.countries.clone();
            config.extra_trusted_certificates = a.trusted_certificates.clone();
            if a.offline_revocation {
                config.revocation = Some(Revocation::Offline);
            }
            if a.allow_without_trusted_lists {
                config.require_trusted_lists = Some(false);
            }
            if let Some(url) = &a.tsa_url {
                let password = match (&a.tsa_user, &a.tsa_password_file) {
                    (None, _) => None,
                    (Some(_), Some(path)) => Some(
                        std::fs::read_to_string(path)
                            .map_err(|e| format!("TSA password file {}: {e}", path.display()))?
                            .trim_end()
                            .to_owned(),
                    ),
                    (Some(_), None) => Some(std::env::var("DSS_TSA_PASSWORD").map_err(|_| {
                        "--tsa-user needs the password: --tsa-password-file or the DSS_TSA_PASSWORD environment \
                         variable"
                    })?),
                };
                config.tsa = Some(Tsa {
                    username: a.tsa_user.clone(),
                    password,
                    ..Tsa::new(url.clone())
                });
            }
            if a.allow_private_addresses {
                config.http = Some(Http {
                    block_private_addresses: Some(false),
                    ..Http::default()
                });
            }
            config.tl_threads = a.tl_threads;
            config.log_level = Some(a.log_level.name().to_owned());
            Engine::builder(cache_dir, &config)
        }
    };
    builder = builder.workers(workers(a));
    if let Some(heap) = &a.max_heap {
        builder = builder.max_heap(heap);
    }
    Ok(builder)
}

/// The OJ keystore is the root of trust of the trusted lists, so it is looked up only where the installation put
/// it (as dss-cli): next to the executable, the package layout (`bin/../share/dss-native/`), and for a
/// development build (built without DSS_RELEASE_RPATH_ONLY=1) the repository's `trust/oj-keystore.p12`, by the
/// absolute path build.rs found. Never the current directory.
fn oj_keystore(a: &Args) -> Result<PathBuf, String> {
    if let Some(p) = &a.oj_keystore {
        return Ok(p.clone());
    }
    let mut candidates = vec![];
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        candidates.push(dir.join("oj-keystore.p12"));
        candidates.push(dir.join("../share/dss-native/oj-keystore.p12"));
    }
    if let Some(dev) = option_env!("DSS_SERVER_DEV_OJ_KEYSTORE") {
        candidates.push(PathBuf::from(dev));
    }
    candidates.into_iter().find(|p| p.is_file()).ok_or_else(|| {
        "OJ keystore not found next to the executable or in ../share/dss-native/ relative to it: pass \
         --oj-keystore or set DSS_OJ_KEYSTORE"
            .to_string()
    })
}
