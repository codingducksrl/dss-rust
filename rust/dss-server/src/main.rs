// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! dss-server: the HTTP sidecar (see lib.rs and docs/server.md).
//!
//!   dss-server [--listen 127.0.0.1:8484] [--token-file <file>] [--refresh-hours 6] [engine options as dss-cli]
//!   dss-server --health-check     exit status 0 if the server at --listen answers /health with 200
//!
//! Every option also reads an environment variable (`dss-server --help`), for containers. The server listens at
//! once and answers 503 until the engine has loaded its trusted lists; if the engine cannot start, it exits with
//! status 2. SIGTERM or Ctrl-C stops it after the requests in progress.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};

use dss::schedule::RefreshScheduler;
use dss::{Config, Engine, EngineBuilder, Revocation, Tsa};
use dss_server::{AppState, describe_refresh, router};

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
    /// File holding a bearer token that every endpoint but /health and /openapi.yaml then requires.
    #[arg(long, env = "DSS_TOKEN_FILE")]
    token_file: Option<PathBuf>,
    /// Hours between online trusted-list refreshes; 0 refreshes only when POST /tl/refresh asks. With an empty
    /// cache the first refresh starts at once.
    #[arg(long, env = "DSS_REFRESH_HOURS", default_value_t = 6)]
    refresh_hours: u64,
    /// Largest request accepted, in MiB (document, detached contents and signature together).
    #[arg(long, env = "DSS_MAX_REQUEST_MB", default_value_t = 100)]
    max_request_mb: usize,
    /// Engine threads: requests the engine runs at the same time [default: number of CPUs].
    #[arg(long, env = "DSS_WORKERS")]
    workers: Option<usize>,

    /// Trusted-list cache directory (created if missing).
    #[arg(long, env = "DSS_CACHE_DIR", default_value = "dss-cache")]
    cache_dir: PathBuf,
    /// Full config_json file; replaces every option below except --max-heap.
    #[arg(long, env = "DSS_CONFIG")]
    config: Option<PathBuf>,
    /// OJ keystore with the LOTL signing certificates [default: oj-keystore.p12 next to the executable,
    /// else ../share/dss-native/oj-keystore.p12, else trust/oj-keystore.p12].
    #[arg(long, env = "DSS_OJ_KEYSTORE")]
    oj_keystore: Option<PathBuf>,
    /// Load only these national trusted lists (repeatable, or comma-separated in the variable, e.g. IT).
    #[arg(long = "country", env = "DSS_COUNTRIES", value_delimiter = ',')]
    countries: Vec<String>,
    /// Use only revocation data embedded in the signatures (no CRL/OCSP/AIA requests).
    #[arg(long, env = "DSS_OFFLINE_REVOCATION")]
    offline_revocation: bool,
    /// Extra trusted certificate, PEM or DER (repeatable, or comma-separated in the variable).
    #[arg(long = "trust", env = "DSS_TRUST", value_delimiter = ',')]
    trusted_certificates: Vec<PathBuf>,
    /// Validate even if no trusted list is loaded.
    #[arg(long, env = "DSS_ALLOW_WITHOUT_TRUSTED_LISTS")]
    allow_without_trusted_lists: bool,
    /// RFC 3161 timestamping service, for extension and signing at T and LTA.
    #[arg(long, env = "DSS_TSA_URL")]
    tsa_url: Option<String>,
    /// HTTP Basic user for the TSA; the password comes from the DSS_TSA_PASSWORD environment variable.
    #[arg(long, env = "DSS_TSA_USER")]
    tsa_user: Option<String>,
    /// Maximum heap of the engine, e.g. 512m, 2g [default: grows with physical memory].
    #[arg(long, env = "DSS_MAX_HEAP")]
    max_heap: Option<String>,
    /// Library log level (stderr): error, warn, info, debug.
    #[arg(long, env = "DSS_LOG_LEVEL", default_value = "warn")]
    log_level: String,

    /// Ask the server at --listen for /health instead of starting one: exit status 0 if it is ready, 1 if not.
    /// For container health checks, which then need no HTTP client in the image.
    #[arg(long)]
    health_check: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    if args.health_check {
        return if healthy(args.listen) {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }
    match serve(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dss-server: {e}");
            ExitCode::from(2)
        }
    }
}

async fn serve(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let token = match &args.token_file {
        Some(path) => Some(
            std::fs::read_to_string(path)
                .map_err(|e| format!("token file {}: {e}", path.display()))?
                .trim()
                .to_owned(),
        )
        .filter(|t| !t.is_empty()),
        None => None,
    };
    if args.token_file.is_some() && token.is_none() {
        return Err("the token file is empty".into());
    }
    let builder = engine_builder(&args)?;
    let refresh_every = (args.refresh_hours > 0).then(|| Duration::from_secs(args.refresh_hours * 3600));

    let state = AppState::new(token);
    let app = router(Arc::clone(&state), args.max_request_mb * 1024 * 1024);
    let listener = TcpListener::bind(args.listen).await?;
    eprintln!("dss-server: listening on {}", listener.local_addr()?);

    // Requests get 503 until the engine is up: loading the full EU trusted lists takes seconds.
    let starting = Arc::clone(&state);
    tokio::spawn(async move {
        let started = Instant::now();
        let engine = match tokio::task::spawn_blocking(move || builder.build()).await {
            Ok(Ok(engine)) => Arc::new(engine),
            Ok(Err(e)) => fail(&format!("the engine did not start: {e}")),
            Err(e) => fail(&format!("the engine did not start: {e}")),
        };
        let loaded = engine.init_info().trusted_lists_loaded;
        eprintln!(
            "dss-server: engine ready in {} ms, trusted lists {}",
            started.elapsed().as_millis(),
            if loaded {
                "loaded from the cache"
            } else {
                "not cached yet"
            }
        );
        let scheduler = refresh_every.map(|every| {
            let scheduler = RefreshScheduler::spawn(Arc::clone(&engine), every, !loaded);
            let mut outcomes = scheduler.subscribe();
            tokio::spawn(async move {
                while outcomes.changed().await.is_ok() {
                    if let Some(outcome) = &*outcomes.borrow_and_update() {
                        eprintln!("dss-server: {}", describe_refresh(&outcome.result));
                    }
                }
            });
            scheduler
        });
        if scheduler.is_none() && !loaded {
            eprintln!("dss-server: no trusted lists yet and no refresh scheduled: POST /tl/refresh loads them");
        }
        starting.set_engine(engine, scheduler);
    });

    axum::serve(listener, app).with_graceful_shutdown(stop_signal()).await?;
    eprintln!("dss-server: stopping");
    // The engine is released once no request holds the state any more; if it is still starting, exiting is enough.
    if let Some(state) = Arc::into_inner(state) {
        tokio::task::spawn_blocking(move || state.shutdown()).await?;
    }
    Ok(())
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

async fn stop_signal() {
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

/// As dss-cli builds its engine.
fn engine_builder(a: &Args) -> Result<EngineBuilder, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(&a.cache_dir)?;
    let mut builder = match &a.config {
        Some(path) => EngineBuilder::with_config_json(&a.cache_dir, std::fs::read_to_string(path)?),
        None => {
            let mut config = Config::new(oj_keystore(a)?);
            config.countries = a.countries.clone();
            config.extra_trusted_certificates = a.trusted_certificates.clone();
            if a.offline_revocation {
                config.revocation = Some(Revocation::Offline);
            }
            if a.allow_without_trusted_lists {
                config.require_trusted_lists = Some(false);
            }
            if let Some(url) = &a.tsa_url {
                let password = std::env::var("DSS_TSA_PASSWORD").ok();
                if a.tsa_user.is_some() && password.is_none() {
                    return Err("--tsa-user needs the DSS_TSA_PASSWORD environment variable".into());
                }
                config.tsa = Some(Tsa {
                    url: url.clone(),
                    username: a.tsa_user.clone(),
                    password: a.tsa_user.as_ref().and(password),
                });
            }
            config.log_level = Some(a.log_level.clone());
            Engine::builder(&a.cache_dir, &config)
        }
    };
    let workers = a
        .workers
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));
    builder = builder.workers(workers);
    if let Some(heap) = &a.max_heap {
        builder = builder.max_heap(heap);
    }
    Ok(builder)
}

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
    candidates.push(PathBuf::from("trust/oj-keystore.p12"));
    candidates
        .into_iter()
        .find(|p| p.is_file())
        .ok_or_else(|| "OJ keystore not found: pass --oj-keystore or set DSS_OJ_KEYSTORE".to_string())
}
