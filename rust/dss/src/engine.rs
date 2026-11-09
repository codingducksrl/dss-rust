// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::{CStr, CString, c_char};
use std::fmt;
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};

use serde::Deserialize;
use serde::de::DeserializeOwned;

use dss_sys as sys;

use crate::config::{Config, DetachedBytes, ExtendOptions, Options, SignOptions};
use crate::error::{Error, ErrorCode, Result};
use crate::types::{
    Extended, InitInfo, PreparedSignature, RefreshRecord, Reports, Signed, TlSnapshot, TlSnapshotInfo,
    TrustedListStatus, Version,
};

/// The version of the C/JSON contract this crate speaks. A library that reports another
/// [`Version::api_version`] is refused by [`EngineBuilder::build`] (a library that reports none is accepted).
pub const API_VERSION: u32 = 1;

/// Builds an [`Engine`]: one GraalVM isolate, the library initialised from `cache_dir`, and its threads.
///
/// The setters never fail; an argument they cannot accept (a configuration with a non-UTF-8 path, a heap size
/// without a unit, an isolate option that is not one) is reported by [`build`](Self::build) as
/// [`Error::Argument`].
#[derive(Clone)]
pub struct EngineBuilder {
    cache_dir: PathBuf,
    config_json: String,
    workers: usize,
    isolate_args: Vec<String>,
    /// The first argument that was refused; `build` fails with it.
    error: Option<Error>,
}

impl fmt::Debug for EngineBuilder {
    /// `config_json` may hold passwords, so only its size is shown.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineBuilder")
            .field("cache_dir", &self.cache_dir)
            .field("config_json", &format_args!("<{} bytes>", self.config_json.len()))
            .field("workers", &self.workers)
            .field("isolate_args", &self.isolate_args)
            .field("error", &self.error)
            .finish()
    }
}

impl EngineBuilder {
    /// A builder for an engine caching its trusted lists under `cache_dir` and configured by `config`.
    pub fn new(cache_dir: impl Into<PathBuf>, config: &Config) -> Self {
        let mut builder = Self::with_config_json(cache_dir, String::new());
        match serde_json::to_string(config) {
            Ok(json) => builder.config_json = json,
            Err(e) => builder.refuse(format!("config: {e}")),
        }
        builder
    }

    /// Uses a `config_json` document as-is (see README.md, "config_json").
    pub fn with_config_json(cache_dir: impl Into<PathBuf>, config_json: impl Into<String>) -> Self {
        EngineBuilder {
            cache_dir: cache_dir.into(),
            config_json: config_json.into(),
            workers: 1,
            isolate_args: vec![],
            error: None,
        }
    }

    /// Number of threads that run validations, extensions and signatures concurrently (default 1).
    pub fn workers(mut self, n: usize) -> Self {
        self.workers = n.max(1);
        self
    }

    /// Maximum Java heap of the isolate, e.g. `"512m"`, `"2g"` (`-Xmx`): digits and a unit (`k`, `m`, `g` or
    /// `t`, either case). Default: Native Image's, which grows with physical memory. A size without a unit would
    /// be bytes (`"512"` is a 512-byte heap, which fails every call), so it is refused by [`build`](Self::build).
    pub fn max_heap(mut self, size: &str) -> Self {
        // Split on a char boundary: a multi-byte last character ("512é") must be refused, not panic.
        let digits = size.strip_suffix(['k', 'K', 'm', 'M', 'g', 'G', 't', 'T']);
        let well_formed = digits.is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()));
        if well_formed {
            self.isolate_args.push(format!("-Xmx{size}"));
        } else {
            self.refuse(format!(
                "max_heap: expected digits and a unit (k, m, g, t), e.g. \"512m\", got {size:?}"
            ));
        }
        self
    }

    /// Any other isolate runtime option, e.g. `-XX:MissingRegistrationReportingMode=Warn`. Options start with
    /// `-X`, `-XX:` or `-D` and hold no whitespace; anything else (which the isolate would silently ignore) is
    /// refused by [`build`](Self::build). An option the isolate itself rejects fails `build` with
    /// [`Error::Isolate`].
    pub fn isolate_arg(mut self, arg: impl Into<String>) -> Self {
        let arg = arg.into();
        let well_formed =
            (arg.starts_with("-X") || arg.starts_with("-D")) && arg.len() > 2 && !arg.chars().any(char::is_whitespace);
        if well_formed {
            self.isolate_args.push(arg);
        } else {
            self.refuse(format!(
                "isolate option {arg:?} is not one: options start with -X, -XX: or -D and hold no whitespace"
            ));
        }
        self
    }

    fn refuse(&mut self, why: String) {
        if self.error.is_none() {
            self.error = Some(Error::Argument(why));
        }
    }

    /// Creates the isolate and loads the trusted lists from the cache (no network). Blocking.
    ///
    /// Fails with [`Error::Argument`] for an argument a setter refused, [`Error::Thread`] when the engine's
    /// threads cannot be spawned, [`Error::Isolate`] when the isolate cannot be created, [`Error::Protocol`] when
    /// the library speaks another [`API_VERSION`], and with the library's own error
    /// ([`ErrorCode::InvalidConfig`], [`ErrorCode::TlSnapshotRejected`]) when it refuses the configuration.
    pub fn build(self) -> Result<Engine> {
        Engine::start(self)
    }
}

/// The DSS validation engine, backed by one isolate of the native library.
///
/// Thread-safe: share it (e.g. in an `Arc`) and call [`validate`](Self::validate), [`extend`](Self::extend) and
/// the signing calls from any number of threads. They run on the engine's worker threads, online refreshes on a
/// separate thread, so validating keeps working during a refresh. Status calls never wait for either.
///
/// Dropping the engine waits for queued work and for a running online refresh, then tears down the isolate.
pub struct Engine {
    control: Sender<Control>,
    jobs: Option<Sender<Job>>,
    refresh: Option<Sender<RefreshJob>>,
    refreshing: AtomicBool,
    threads: Vec<JoinHandle<()>>,
    control_thread: Option<JoinHandle<()>>,
    init: Option<InitInfo>,
}

impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine")
            .field("threads", &self.threads.len())
            .field("init", &self.init)
            .finish()
    }
}

enum Control {
    Status(SyncSender<Result<String>>),
    Version(SyncSender<Result<String>>),
    /// `dss_tl_export_snapshot`: its result JSON and the file.
    ExportTlSnapshot(SyncSender<Result<(String, Vec<u8>)>>),
    /// Stop the library's background threads and tear down the isolate; sent once every other thread detached.
    TearDown,
}

/// Lets a caller abandon document calls it no longer needs (its client went away, its deadline passed): see
/// [`Engine::cancellable`]. Clones share the flag; once [`cancel`](Self::cancel) was called it stays set.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// A token that is not cancelled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancels: every queued call bound to this token is skipped when a worker takes it, and fails with
    /// [`Error::Cancelled`]. A call that is already running completes (the library cannot be interrupted) and
    /// returns its result.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Whether [`cancel`](Self::cancel) was called.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// The document calls of an [`Engine`] bound to a [`CancelToken`], from [`Engine::cancellable`]. Each call waits
/// for a worker like the engine's own; a worker that takes a call whose token is cancelled by then skips it and
/// the call fails with [`Error::Cancelled`] at once. Cancelling has no effect on a call a worker already runs.
#[derive(Debug, Clone, Copy)]
pub struct Cancellable<'a> {
    engine: &'a Engine,
    token: Option<&'a CancelToken>,
}

/// Work for the worker threads: what to do, and the token of the caller that may abandon it.
struct Job {
    work: Work,
    cancel: Option<CancelToken>,
}

enum Work {
    Validate {
        document: Vec<u8>,
        options: CString,
        /// Binary detached contents (`dss_validate_with_contents`); `dss_validate` when empty.
        contents: Vec<OwnedContent>,
        reply: SyncSender<Result<String>>,
    },
    Extend {
        document: Vec<u8>,
        options: CString,
        reply: SyncSender<Result<(String, Vec<u8>)>>,
    },
    SignPrepare {
        document: Vec<u8>,
        options: CString,
        reply: SyncSender<Result<String>>,
    },
    SignComplete {
        document: Vec<u8>,
        options: CString,
        signature: Vec<u8>,
        reply: SyncSender<Result<(String, Vec<u8>)>>,
    },
}

impl Work {
    /// Answers the caller of a skipped job.
    fn reply_cancelled(self) {
        match self {
            Work::Validate { reply, .. } | Work::SignPrepare { reply, .. } => {
                let _ = reply.send(Err(Error::Cancelled));
            }
            Work::Extend { reply, .. } | Work::SignComplete { reply, .. } => {
                let _ = reply.send(Err(Error::Cancelled));
            }
        }
    }
}

struct RefreshJob {
    reply: SyncSender<Result<String>>,
}

/// A [`DetachedBytes`] copied for the worker thread.
struct OwnedContent {
    name: Option<CString>,
    content: Vec<u8>,
}

impl OwnedContent {
    /// Fails ([`Error::Nul`]) for a name with an embedded NUL, which no C string can carry.
    fn new(content: &DetachedBytes<'_>) -> Result<Self> {
        let name = match content.name {
            Some(name) => Some(CString::new(name).map_err(|_| Error::Nul)?),
            None => None,
        };
        Ok(OwnedContent {
            name,
            content: content.content.to_vec(),
        })
    }
}

/// `DetachedBytes` as the owned contents of a job.
fn owned_contents(contents: &[DetachedBytes<'_>]) -> Result<Vec<OwnedContent>> {
    contents.iter().map(OwnedContent::new).collect()
}

/// Typed options as the JSON the library takes. Fails ([`Error::Argument`]) only for a path that is not UTF-8.
fn options_json<T: serde::Serialize>(what: &str, options: &T) -> Result<String> {
    serde_json::to_string(options).map_err(|e| Error::Argument(format!("{what}: {e}")))
}

impl Engine {
    /// A builder for an engine caching its trusted lists under `cache_dir` and configured by `config`
    /// (the same as [`EngineBuilder::new`]).
    pub fn builder(cache_dir: impl Into<PathBuf>, config: &Config) -> EngineBuilder {
        EngineBuilder::new(cache_dir, config)
    }

    /// What `dss_init` reported: whether trusted lists were loaded from the cache, and how long it took.
    pub fn init_info(&self) -> &InitInfo {
        self.init.as_ref().expect("set before the engine is handed out")
    }

    /// The document calls ([`validate`](Self::validate), [`extend`](Self::extend), the signing calls) bound to
    /// `token`: a call still queued when the token is cancelled is skipped and fails with [`Error::Cancelled`]
    /// instead of occupying a worker for a caller that is gone. The view is `Copy` and borrows both.
    ///
    /// ```no_run
    /// # fn demo(engine: &dss::Engine, pdf: &[u8]) -> dss::Result<()> {
    /// let token = dss::CancelToken::new();
    /// let abandon = token.clone(); // e.g. handed to a request-timeout or disconnect handler
    /// let reports = engine.cancellable(&token).validate(pdf, &dss::Options::default());
    /// # let _ = abandon; let _ = reports;
    /// # Ok(()) }
    /// ```
    pub fn cancellable<'a>(&'a self, token: &'a CancelToken) -> Cancellable<'a> {
        Cancellable {
            engine: self,
            token: Some(token),
        }
    }

    fn uncancellable(&self) -> Cancellable<'_> {
        Cancellable {
            engine: self,
            token: None,
        }
    }

    /// Validates a PDF or CMS/CAdES document (also base64/PEM-wrapped and nested `.p7m.p7m`).
    ///
    /// The signed content of a detached signature comes from [`Options::detached_contents`]:
    /// [`DetachedContent::Bytes`](crate::DetachedContent::Bytes) entries are passed to the library as binary
    /// buffers (no base64), before any [`File`](crate::DetachedContent::File) entry.
    pub fn validate(&self, document: &[u8], options: &Options) -> Result<Reports> {
        self.uncancellable().validate(document, options)
    }

    /// As [`validate`](Self::validate), with the signed content of a detached signature as bytes the caller holds:
    /// `contents` are added to [`Options::detached_contents`] first (binary, no base64), then the options' own
    /// `Bytes` entries, then its `File` entries. The buffers are only read during the call.
    ///
    /// An empty content, more than 1024 contents and a name the library cannot read are
    /// [`ErrorCode::InvalidArgument`]; a name with an embedded NUL is [`Error::Nul`].
    pub fn validate_with_contents(
        &self,
        document: &[u8],
        options: &Options,
        contents: &[DetachedBytes<'_>],
    ) -> Result<Reports> {
        self.uncancellable().validate_with_contents(document, options, contents)
    }

    /// As [`validate`](Self::validate), with options and result as the library's raw JSON.
    pub fn validate_json(&self, document: &[u8], options_json: &str) -> Result<String> {
        self.uncancellable().validate_json(document, options_json)
    }

    /// As [`validate_with_contents`](Self::validate_with_contents), with options and result as the library's raw
    /// JSON (`dss_validate_with_contents`): `contents` are added to the JSON's `detached_contents` before any
    /// entry it carries.
    pub fn validate_with_contents_json(
        &self,
        document: &[u8],
        options_json: &str,
        contents: &[DetachedBytes<'_>],
    ) -> Result<String> {
        self.uncancellable()
            .validate_with_contents_json(document, options_json, contents)
    }

    /// Extends the signatures of a PDF to PAdES-BASELINE-T, -LT or -LTA: for LT, the certificates and
    /// revocation data they need (fetched online unless [`Config::revocation`] is offline); for T and LTA, also
    /// a document timestamp from [`Config::tsa`] (a B-level signature going to LT needs that timestamp first, so
    /// it needs the TSA too). Signatures already above the target level are left as they are. Validate the
    /// result to see the new level.
    ///
    /// DSS checks the signatures first. It refuses with [`ErrorCode::ExtensionFailed`] when one does not
    /// validate, a certificate is revoked or expired, revocation data is missing (and cannot be fetched), every
    /// signature is already above the target level, or a timestamp is needed and no TSA is configured; a TSA that
    /// fails is [`ErrorCode::TsaFailed`].
    pub fn extend(&self, document: &[u8], options: &ExtendOptions) -> Result<Extended> {
        self.uncancellable().extend(document, options)
    }

    /// As [`extend`](Self::extend), with options and result as the library's raw JSON, plus the extended PDF.
    pub fn extend_json(&self, document: &[u8], options_json: &str) -> Result<(String, Vec<u8>)> {
        self.uncancellable().extend_json(document, options_json)
    }

    /// Signing with a key held elsewhere, step 1: the digest the external signer must sign, for `document` and
    /// `options`. Needs no network and no trusted lists. Before any external signature is spent, it refuses
    /// ([`ErrorCode::SigningFailed`]) a signing certificate that is expired or not yet valid at the signing time,
    /// or not meant for signing documents (a CA certificate, key usage, extended key usage), when it is given;
    /// for PAdES at LT/LTA (and T in mode [`Cms`](crate::SigningMode::Cms)) a PDF whose existing signatures DSS
    /// would refuse to extend; and, in mode [`SignatureValue`](crate::SigningMode::SignatureValue), a
    /// `pades.content_size` the CMS cannot fit ([`ErrorCode::InvalidArgument`]).
    ///
    /// Send [`PreparedSignature::digest`] to the signer: with [`SigningMode::Cms`](crate::SigningMode::Cms) it
    /// returns a detached CMS for it, with [`SigningMode::SignatureValue`](crate::SigningMode::SignatureValue) a bare
    /// signature value. Nothing is kept between the two steps: they may run in different processes.
    pub fn prepare_signature(&self, document: &[u8], options: &SignOptions) -> Result<PreparedSignature> {
        self.uncancellable().prepare_signature(document, options)
    }

    /// As [`prepare_signature`](Self::prepare_signature), with options and result as the library's raw JSON.
    pub fn prepare_signature_json(&self, document: &[u8], options_json: &str) -> Result<String> {
        self.uncancellable().prepare_signature_json(document, options_json)
    }

    /// Step 2: the signed document, from the same `document` and `options` as
    /// [`prepare_signature`](Self::prepare_signature) (with [`SignOptions::signing_time`] set to the one it
    /// returned) and what the external signer returned (`signature`: DER, BER or base64).
    ///
    /// The external result is checked first: it must sign this document's digest with the signer's certificate,
    /// and a CMS must be a detached baseline one (for PAdES without signing-time, with at most one signature
    /// timestamp as unsigned attribute). Then DSS builds the document and adds the level asked for: T, LT and LTA
    /// need [`Config::tsa`](crate::Config::tsa) unless an external CMS already carries a signature timestamp (the
    /// B signature gets its timestamp first); LT and LTA fetch revocation data like [`extend`](Self::extend).
    /// Failures are [`ErrorCode::SigningFailed`] (a failing TSA [`ErrorCode::TsaFailed`]).
    pub fn complete_signature(&self, document: &[u8], options: &SignOptions, signature: &[u8]) -> Result<Signed> {
        self.uncancellable().complete_signature(document, options, signature)
    }

    /// As [`complete_signature`](Self::complete_signature), with options and result as the library's raw JSON,
    /// plus the signed document.
    pub fn complete_signature_json(
        &self,
        document: &[u8],
        options_json: &str,
        signature: &[u8],
    ) -> Result<(String, Vec<u8>)> {
        self.uncancellable()
            .complete_signature_json(document, options_json, signature)
    }

    fn submit(&self, job: Job) -> Result<()> {
        let jobs = self.jobs.as_ref().ok_or(Error::Closed)?;
        jobs.send(job).map_err(|_| Error::Closed)
    }

    /// Downloads and validates the LOTL and national trusted lists. Blocking; validations keep running.
    ///
    /// Fails with [`ErrorCode::RefreshInProgress`] if a refresh is already running, and with
    /// [`ErrorCode::TlRefreshFailed`] when the refresh published nothing (the lists loaded before are kept; see
    /// [`RefreshRecord::completed`]). A returned record always has `completed == true`; per-list problems are in
    /// [`trusted_list_status`](Self::trusted_list_status).
    pub fn refresh_trusted_lists(&self) -> Result<RefreshRecord> {
        if self.refreshing.swap(true, Ordering::AcqRel) {
            return Err(Error::Api {
                code: ErrorCode::RefreshInProgress,
                message: "an online refresh of this engine is already running".into(),
            });
        }
        struct Reset<'a>(&'a AtomicBool);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _reset = Reset(&self.refreshing);

        let (reply, result) = mpsc::sync_channel(1);
        self.refresh
            .as_ref()
            .ok_or(Error::Closed)?
            .send(RefreshJob { reply })
            .map_err(|_| Error::Closed)?;
        let json = result.recv().map_err(|_| Error::Closed)??;
        #[derive(Deserialize)]
        struct Envelope {
            refresh: RefreshRecord,
        }
        decode::<Envelope>(&json).map(|e| e.refresh)
    }

    /// Trusted-list freshness and per-list state. Never waits for a running refresh.
    pub fn trusted_list_status(&self) -> Result<TrustedListStatus> {
        decode(&self.control_call(Control::Status)?)
    }

    /// As [`trusted_list_status`](Self::trusted_list_status), as the library's raw JSON.
    pub fn trusted_list_status_json(&self) -> Result<String> {
        let json = self.control_call(Control::Status)?;
        check_ok(&json)?;
        Ok(json)
    }

    /// The loaded trusted lists as a trusted-list snapshot file. An engine whose
    /// [`Config::tl_snapshot`](crate::Config::tl_snapshot) names it starts from it in a fraction of the time it
    /// takes to load the cache: no list is parsed or validated. It must have the same trusted-list settings
    /// (LOTL, OJ keystore, countries, `tl_sync`, ...) and the same DSS version.
    ///
    /// The file is not signed: the library only checks that it is intact. Whether a snapshot can be trusted is for
    /// the application that stores and hands it over to decide. Fails with [`ErrorCode::TrustedListsNotLoaded`]
    /// when no list is loaded. Runs on the thread that answers [`trusted_list_status`](Self::trusted_list_status).
    pub fn export_tl_snapshot(&self) -> Result<TlSnapshot> {
        let (reply, result) = mpsc::sync_channel(1);
        self.control
            .send(Control::ExportTlSnapshot(reply))
            .map_err(|_| Error::Closed)?;
        let (json, bytes) = result.recv().map_err(|_| Error::Closed)??;
        let info: TlSnapshotInfo = decode(&json)?;
        Ok(TlSnapshot { info, bytes })
    }

    /// Library, DSS and runtime versions.
    pub fn version(&self) -> Result<Version> {
        decode(&self.control_call(Control::Version)?)
    }

    fn control_call(&self, make: fn(SyncSender<Result<String>>) -> Control) -> Result<String> {
        let (reply, result) = mpsc::sync_channel(1);
        self.control.send(make(reply)).map_err(|_| Error::Closed)?;
        result.recv().map_err(|_| Error::Closed)?
    }

    fn start(b: EngineBuilder) -> Result<Engine> {
        if let Some(e) = b.error {
            return Err(e);
        }
        let cache_dir = b
            .cache_dir
            .to_str()
            .ok_or_else(|| Error::Argument(format!("cache_dir {:?} is not valid UTF-8", b.cache_dir)))?;
        let cache_dir = CString::new(cache_dir).map_err(|_| Error::Nul)?;
        let config = CString::new(b.config_json).map_err(|_| Error::Nul)?;
        let mut args = vec![CString::new("dss-native").unwrap()];
        for a in &b.isolate_args {
            args.push(CString::new(a.as_str()).map_err(|_| Error::Nul)?);
        }

        let (control_tx, control_rx) = mpsc::channel::<Control>();
        let (started_tx, started_rx) = mpsc::sync_channel::<Result<(Isolate, String)>>(1);
        let control_thread = thread::Builder::new()
            .name("dss-control".into())
            .spawn(move || control_main(args, cache_dir, config, started_tx, control_rx))
            .map_err(|e| Error::Thread(format!("dss-control: {e}")))?;

        let (isolate, init_json) = match started_rx.recv() {
            Ok(Ok(started)) => started,
            Ok(Err(e)) => {
                let _ = control_thread.join();
                return Err(e);
            }
            Err(_) => {
                let _ = control_thread.join();
                return Err(Error::Closed);
            }
        };

        let mut engine = Engine {
            control: control_tx,
            jobs: None,
            refresh: None,
            refreshing: AtomicBool::new(false),
            threads: vec![],
            control_thread: Some(control_thread),
            init: None,
        };
        // From here on, Drop tears everything down if something fails.
        engine.init = Some(decode(&init_json)?);
        let version: Version = engine.version()?;
        if let Some(api) = version.api_version
            && api != API_VERSION
        {
            return Err(Error::Protocol(format!(
                "libdssnative {} speaks API version {api}, this crate version {API_VERSION}",
                version.library
            )));
        }

        let (job_tx, job_rx) = mpsc::channel::<Job>();
        let job_rx = Arc::new(Mutex::new(job_rx));
        let (attached_tx, attached_rx) = mpsc::channel::<Result<()>>();
        engine.jobs = Some(job_tx);
        for i in 0..b.workers {
            let rx = Arc::clone(&job_rx);
            let attached = attached_tx.clone();
            let name = format!("dss-validate-{i}");
            engine.threads.push(
                thread::Builder::new()
                    .name(name.clone())
                    .spawn(move || worker_main(isolate, rx, attached))
                    .map_err(|e| Error::Thread(format!("{name}: {e}")))?,
            );
        }

        let (refresh_tx, refresh_rx) = mpsc::channel::<RefreshJob>();
        let attached = attached_tx.clone();
        engine.threads.push(
            thread::Builder::new()
                .name("dss-refresh".into())
                .spawn(move || refresh_main(isolate, refresh_rx, attached))
                .map_err(|e| Error::Thread(format!("dss-refresh: {e}")))?,
        );
        engine.refresh = Some(refresh_tx);
        drop(attached_tx);

        for _ in 0..=b.workers {
            attached_rx.recv().map_err(|_| Error::Closed)??;
        }
        Ok(engine)
    }
}

impl Cancellable<'_> {
    /// As [`Engine::validate`], cancellable.
    pub fn validate(&self, document: &[u8], options: &Options) -> Result<Reports> {
        self.validate_with_contents(document, options, &[])
    }

    /// As [`Engine::validate_with_contents`], cancellable.
    pub fn validate_with_contents(
        &self,
        document: &[u8],
        options: &Options,
        contents: &[DetachedBytes<'_>],
    ) -> Result<Reports> {
        let (json, bytes) = options.split();
        let mut all = owned_contents(contents)?;
        all.extend(owned_contents(&bytes)?);
        decode(&self.validate_raw(document, &options_json("options", &json)?, all)?)
    }

    /// As [`Engine::validate_json`], cancellable.
    pub fn validate_json(&self, document: &[u8], options_json: &str) -> Result<String> {
        self.validate_with_contents_json(document, options_json, &[])
    }

    /// As [`Engine::validate_with_contents_json`], cancellable.
    pub fn validate_with_contents_json(
        &self,
        document: &[u8],
        options_json: &str,
        contents: &[DetachedBytes<'_>],
    ) -> Result<String> {
        let json = self.validate_raw(document, options_json, owned_contents(contents)?)?;
        check_ok(&json)?;
        Ok(json)
    }

    fn validate_raw(&self, document: &[u8], options_json: &str, contents: Vec<OwnedContent>) -> Result<String> {
        let options = CString::new(options_json).map_err(|_| Error::Nul)?;
        let (reply, result) = mpsc::sync_channel(1);
        self.submit(Work::Validate {
            document: document.to_vec(),
            options,
            contents,
            reply,
        })?;
        result.recv().map_err(|_| Error::Closed)?
    }

    /// As [`Engine::extend`], cancellable.
    pub fn extend(&self, document: &[u8], options: &ExtendOptions) -> Result<Extended> {
        let (json, pdf) = self.extend_raw(document, &options_json("options", options)?)?;
        let mut extended: Extended = decode(&json)?;
        extended.document = pdf;
        Ok(extended)
    }

    /// As [`Engine::extend_json`], cancellable.
    pub fn extend_json(&self, document: &[u8], options_json: &str) -> Result<(String, Vec<u8>)> {
        let (json, pdf) = self.extend_raw(document, options_json)?;
        check_ok(&json)?;
        Ok((json, pdf))
    }

    fn extend_raw(&self, document: &[u8], options_json: &str) -> Result<(String, Vec<u8>)> {
        let options = CString::new(options_json).map_err(|_| Error::Nul)?;
        let (reply, result) = mpsc::sync_channel(1);
        self.submit(Work::Extend {
            document: document.to_vec(),
            options,
            reply,
        })?;
        result.recv().map_err(|_| Error::Closed)?
    }

    /// As [`Engine::prepare_signature`], cancellable.
    pub fn prepare_signature(&self, document: &[u8], options: &SignOptions) -> Result<PreparedSignature> {
        decode(&self.prepare_signature_raw(document, &options_json("options", options)?)?)
    }

    /// As [`Engine::prepare_signature_json`], cancellable.
    pub fn prepare_signature_json(&self, document: &[u8], options_json: &str) -> Result<String> {
        let json = self.prepare_signature_raw(document, options_json)?;
        check_ok(&json)?;
        Ok(json)
    }

    fn prepare_signature_raw(&self, document: &[u8], options_json: &str) -> Result<String> {
        let options = CString::new(options_json).map_err(|_| Error::Nul)?;
        let (reply, result) = mpsc::sync_channel(1);
        self.submit(Work::SignPrepare {
            document: document.to_vec(),
            options,
            reply,
        })?;
        result.recv().map_err(|_| Error::Closed)?
    }

    /// As [`Engine::complete_signature`], cancellable.
    pub fn complete_signature(&self, document: &[u8], options: &SignOptions, signature: &[u8]) -> Result<Signed> {
        let (json, signed) = self.complete_signature_raw(document, &options_json("options", options)?, signature)?;
        let mut result: Signed = decode(&json)?;
        result.document = signed;
        Ok(result)
    }

    /// As [`Engine::complete_signature_json`], cancellable.
    pub fn complete_signature_json(
        &self,
        document: &[u8],
        options_json: &str,
        signature: &[u8],
    ) -> Result<(String, Vec<u8>)> {
        let (json, signed) = self.complete_signature_raw(document, options_json, signature)?;
        check_ok(&json)?;
        Ok((json, signed))
    }

    fn complete_signature_raw(
        &self,
        document: &[u8],
        options_json: &str,
        signature: &[u8],
    ) -> Result<(String, Vec<u8>)> {
        let options = CString::new(options_json).map_err(|_| Error::Nul)?;
        let (reply, result) = mpsc::sync_channel(1);
        self.submit(Work::SignComplete {
            document: document.to_vec(),
            options,
            signature: signature.to_vec(),
            reply,
        })?;
        result.recv().map_err(|_| Error::Closed)?
    }

    fn submit(&self, work: Work) -> Result<()> {
        self.engine.submit(Job {
            work,
            cancel: self.token.cloned(),
        })
    }
}

/// Library, DSS and runtime versions without an engine (the same as [`Engine::version`]): a GraalVM isolate is
/// created for the call and torn down again, which takes milliseconds and loads nothing.
pub fn library_version() -> Result<Version> {
    ensure_first_isolate_created()?;
    // SAFETY: the attached thread's handle; dss_version needs no dss_init.
    decode(&with_default_isolate(|me| {
        me.call(|t| unsafe { sys::dss_version(t) })
    })??)
}

impl Drop for Engine {
    fn drop(&mut self) {
        // Closing the queues lets workers finish what they have and detach; the refresh thread finishes a
        // running refresh first. Only then may the isolate be torn down.
        self.jobs.take();
        self.refresh.take();
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        let _ = self.control.send(Control::TearDown);
        if let Some(t) = self.control_thread.take() {
            let _ = t.join();
        }
    }
}

// ---------------------------------------------------------------------------------------------- threads

#[derive(Clone, Copy)]
struct Isolate(*mut sys::graal_isolate_t);

// SAFETY: the isolate pointer is an opaque handle: any thread may attach to it.
unsafe impl Send for Isolate {}

/// This OS thread's attachment to the isolate. Not `Send`: it is only valid on the thread that attached.
///
/// Dropping it detaches the thread, also when a worker unwinds: GraalVM's tear-down waits without a deadline for
/// every attached thread, so a thread that exited while attached would hang `Engine::drop` forever.
struct Attached(*mut sys::graal_isolatethread_t);

impl Attached {
    fn attach(isolate: Isolate) -> Result<Attached> {
        let mut thread = ptr::null_mut();
        // SAFETY: a valid isolate handle and an out-pointer for the thread handle, as graal_isolate.h asks.
        let rc = unsafe { sys::graal_attach_thread(isolate.0, &mut thread) };
        if rc != 0 {
            Err(Error::Isolate(rc))
        } else {
            Ok(Attached(thread))
        }
    }

    /// Calls a `dss_*` entry point and takes ownership of the string it returns.
    fn call(&self, entry: impl FnOnce(*mut sys::graal_isolatethread_t) -> *mut c_char) -> Result<String> {
        let p = entry(self.0);
        if p.is_null() {
            return Err(Error::NoResult);
        }
        // SAFETY: the library returns a NUL-terminated string that we own until dss_free.
        let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        // SAFETY: p came from this isolate thread's call and is released exactly once.
        unsafe { sys::dss_free(self.0, p) };
        Ok(s)
    }

    /// Calls `dss_validate`, or `dss_validate_with_contents` when there are binary detached contents, and takes
    /// ownership of the result string.
    fn validate(&self, document: &[u8], options: &CStr, contents: &[OwnedContent]) -> Result<String> {
        if contents.is_empty() {
            // SAFETY: this thread's handle, and buffers that outlive the call.
            return self.call(|t| unsafe {
                sys::dss_validate(t, document.as_ptr() as *const c_char, document.len(), options.as_ptr())
            });
        }
        // Three parallel arrays, as the C API takes them; a NULL name is an unnamed content. bindgen renders the
        // header's `const char**` as `*mut *const c_char`, hence `as_mut_ptr`: the library only reads them.
        let mut names: Vec<*const c_char> = contents
            .iter()
            .map(|c| c.name.as_ref().map_or(ptr::null(), |n| n.as_ptr()))
            .collect();
        let mut pointers: Vec<*const c_char> = contents.iter().map(|c| c.content.as_ptr() as *const c_char).collect();
        let lens: Vec<usize> = contents.iter().map(|c| c.content.len()).collect();
        // SAFETY: this thread's handle; the document, options, the three arrays of `contents.len()` entries and
        // every buffer they point to outlive the call, which only reads them.
        self.call(|t| unsafe {
            sys::dss_validate_with_contents(
                t,
                document.as_ptr() as *const c_char,
                document.len(),
                contents.len(),
                names.as_mut_ptr(),
                pointers.as_mut_ptr(),
                lens.as_ptr(),
                options.as_ptr(),
            )
        })
    }

    /// Calls `dss_extend` and takes ownership of its result string and of the document it hands back.
    fn extend(&self, document: &[u8], options: &CStr) -> Result<(String, Vec<u8>)> {
        // SAFETY: the pointers and lengths describe live buffers for the duration of the call.
        self.call_with_document(|t, out, out_len| unsafe {
            sys::dss_extend(
                t,
                document.as_ptr() as *const c_char,
                document.len(),
                options.as_ptr(),
                out,
                out_len,
            )
        })
    }

    /// Calls `dss_sign_complete`, taking ownership as [`extend`](Self::extend) does.
    fn sign_complete(&self, document: &[u8], options: &CStr, signature: &[u8]) -> Result<(String, Vec<u8>)> {
        // SAFETY: the pointers and lengths describe live buffers for the duration of the call.
        self.call_with_document(|t, out, out_len| unsafe {
            sys::dss_sign_complete(
                t,
                document.as_ptr() as *const c_char,
                document.len(),
                options.as_ptr(),
                signature.as_ptr() as *const c_char,
                signature.len(),
                out,
                out_len,
            )
        })
    }

    /// Calls an entry point that returns a JSON string and hands back a document through out-parameters.
    fn call_with_document(
        &self,
        entry: impl FnOnce(*mut sys::graal_isolatethread_t, *mut *mut c_char, *mut usize) -> *mut c_char,
    ) -> Result<(String, Vec<u8>)> {
        let mut out: *mut c_char = ptr::null_mut();
        let mut out_len: usize = 0;
        let json = self.call(|t| entry(t, &mut out, &mut out_len));
        let document = if out.is_null() {
            Vec::new()
        } else {
            // SAFETY: the library malloc'd out_len bytes at out; we own them until dss_free.
            let document = unsafe { std::slice::from_raw_parts(out as *const u8, out_len) }.to_vec();
            // SAFETY: released exactly once, on the thread that received it.
            unsafe { sys::dss_free(self.0, out) };
            document
        };
        Ok((json?, document))
    }

    /// Gives up the attachment without detaching: for the thread that tears the isolate down, which takes the
    /// attached thread handle and leaves nothing to detach from.
    fn into_raw(self) -> *mut sys::graal_isolatethread_t {
        let thread = self.0;
        std::mem::forget(self);
        thread
    }
}

impl Drop for Attached {
    fn drop(&mut self) {
        // SAFETY: this thread attached with this handle and has not detached; the isolate is still up because
        // tear-down waits for every attached thread.
        let rc = unsafe { sys::graal_detach_thread(self.0) };
        if rc != 0 {
            eprintln!("dss: graal_detach_thread returned {rc}");
        }
    }
}

/// GraalVM CE 25.4: if the first isolate creation in a process fails (e.g. on an invalid `-Xmx`), every later
/// `graal_create_isolate` in that process hangs. Later failures are harmless. So before the first engine, create
/// and tear down one isolate without options; a bad option can then only fail its own engine.
fn ensure_first_isolate_created() -> Result<()> {
    static FIRST: OnceLock<Result<()>> = OnceLock::new();
    FIRST.get_or_init(|| with_default_isolate(|_| ())).clone()
}

/// Creates an isolate without options on this thread, runs `f` attached to it, and tears it down.
fn with_default_isolate<T>(f: impl FnOnce(&Attached) -> T) -> Result<T> {
    let mut isolate = ptr::null_mut();
    let mut thread = ptr::null_mut();
    // SAFETY: null parameters ask for the default isolate; the out-pointers are valid for the call
    // (graal_isolate.h).
    let rc = unsafe { sys::graal_create_isolate(ptr::null_mut(), &mut isolate, &mut thread) };
    if rc != 0 {
        return Err(Error::Isolate(rc));
    }
    let me = Attached(thread);
    let out = f(&me);
    // SAFETY: the isolate created above, torn down from its only attached thread; the handle is not used after.
    let rc = unsafe { sys::graal_tear_down_isolate(me.into_raw()) };
    if rc != 0 {
        eprintln!("dss: graal_tear_down_isolate returned {rc}");
    }
    Ok(out)
}

fn control_main(
    args: Vec<CString>,
    cache_dir: CString,
    config: CString,
    started: SyncSender<Result<(Isolate, String)>>,
    requests: Receiver<Control>,
) {
    if let Err(e) = ensure_first_isolate_created() {
        let _ = started.send(Err(e));
        return;
    }
    let mut argv: Vec<*mut c_char> = args.iter().map(|a| a.as_ptr() as *mut c_char).collect();
    // SAFETY: zeroing then setting `version` is how the struct is meant to be initialised (graal_isolate.h).
    let mut params: sys::graal_create_isolate_params_t = unsafe { std::mem::zeroed() };
    params.version = sys::__graal_create_isolate_params_version as i32;
    params.argc = argv.len() as i32;
    params.argv = argv.as_mut_ptr();
    let mut isolate = ptr::null_mut();
    let mut thread = ptr::null_mut();
    // SAFETY: params, argv and the CStrings behind it outlive the call; isolate and thread are out-pointers.
    let rc = unsafe { sys::graal_create_isolate(&mut params, &mut isolate, &mut thread) };
    if rc != 0 {
        let _ = started.send(Err(Error::Isolate(rc)));
        return;
    }
    let me = Attached(thread);

    // SAFETY: dss_init takes this thread's handle and two NUL-terminated strings that outlive the call.
    let init = me.call(|t| unsafe { sys::dss_init(t, cache_dir.as_ptr(), config.as_ptr()) });
    let failed = !matches!(init.as_deref().map(check_ok), Ok(Ok(())));
    let _ = started.send(init.map(|json| (Isolate(isolate), json)));
    if !failed {
        for request in requests.iter() {
            match request {
                Control::Status(reply) => {
                    // SAFETY: this thread's handle.
                    let _ = reply.send(me.call(|t| unsafe { sys::dss_tl_status(t) }));
                }
                Control::Version(reply) => {
                    // SAFETY: this thread's handle.
                    let _ = reply.send(me.call(|t| unsafe { sys::dss_version(t) }));
                }
                Control::ExportTlSnapshot(reply) => {
                    // SAFETY: this thread's handle and out-pointers for the document.
                    let _ =
                        reply.send(me.call_with_document(|t, out, out_len| unsafe {
                            sys::dss_tl_export_snapshot(t, out, out_len)
                        }));
                }
                Control::TearDown => break,
            }
        }
    }
    // SAFETY: this thread's handle; every other thread has detached (Engine::drop joined them first).
    match me
        .call(|t| unsafe { sys::dss_shutdown(t) })
        .and_then(|json| check_ok(&json))
    {
        Ok(()) => {}
        // Shutting down an engine whose init failed: nothing to stop.
        Err(Error::Api {
            code: ErrorCode::NotInitialized,
            ..
        }) => {}
        Err(e) => eprintln!("dss: dss_shutdown failed: {e}"),
    }
    // SAFETY: tear-down takes the attached thread's handle and ends the isolate; the handle is not used after it.
    let rc = unsafe { sys::graal_tear_down_isolate(me.into_raw()) };
    if rc != 0 {
        eprintln!("dss: graal_tear_down_isolate returned {rc}");
    }
}

fn worker_main(isolate: Isolate, jobs: Arc<Mutex<Receiver<Job>>>, attached: Sender<Result<()>>) {
    let me = match Attached::attach(isolate) {
        Ok(me) => me,
        Err(e) => {
            let _ = attached.send(Err(e));
            return;
        }
    };
    let _ = attached.send(Ok(()));
    loop {
        // Only one idle worker waits in recv(); the lock is released before the job runs.
        let job = match jobs.lock() {
            Ok(rx) => rx.recv(),
            Err(_) => break,
        };
        let Ok(Job { work, cancel }) = job else { break };
        // A caller that gave up (deadline passed, client gone) gets its answer without the isolate's time.
        if cancel.is_some_and(|c| c.is_cancelled()) {
            work.reply_cancelled();
            continue;
        }
        match work {
            Work::Validate {
                document,
                options,
                contents,
                reply,
            } => {
                let _ = reply.send(me.validate(&document, &options, &contents));
            }
            Work::Extend {
                document,
                options,
                reply,
            } => {
                let _ = reply.send(me.extend(&document, &options));
            }
            Work::SignPrepare {
                document,
                options,
                reply,
            } => {
                // SAFETY: this thread's handle, and buffers that outlive the call.
                let result = me.call(|t| unsafe {
                    sys::dss_sign_prepare(t, document.as_ptr() as *const c_char, document.len(), options.as_ptr())
                });
                let _ = reply.send(result);
            }
            Work::SignComplete {
                document,
                options,
                signature,
                reply,
            } => {
                let _ = reply.send(me.sign_complete(&document, &options, &signature));
            }
        }
    }
    // `me` detaches on drop, also if a job above panicked.
}

fn refresh_main(isolate: Isolate, jobs: Receiver<RefreshJob>, attached: Sender<Result<()>>) {
    let me = match Attached::attach(isolate) {
        Ok(me) => me,
        Err(e) => {
            let _ = attached.send(Err(e));
            return;
        }
    };
    let _ = attached.send(Ok(()));
    for job in jobs.iter() {
        // SAFETY: this thread's handle.
        let _ = job.reply.send(me.call(|t| unsafe { sys::dss_tl_refresh_online(t) }));
    }
}

// ---------------------------------------------------------------------------------------------- JSON

#[derive(Deserialize)]
struct ApiError {
    code: String,
    message: String,
}

/// `Err` for `{"ok":false,"error":{...}}`, `Ok` for `{"ok":true,...}`.
fn check_ok(json: &str) -> Result<()> {
    #[derive(Deserialize)]
    struct Head {
        ok: bool,
        error: Option<ApiError>,
    }
    let head: Head = serde_json::from_str(json).map_err(|e| Error::Protocol(e.to_string()))?;
    match (head.ok, head.error) {
        (true, _) => Ok(()),
        (false, Some(e)) if e.code.is_empty() => Err(Error::Protocol("empty error code".into())),
        (false, Some(e)) => {
            let code = ErrorCode::from_wire(&e.code);
            // Past the bound on distinct unknown names the code is UNKNOWN: the name goes into the message.
            let message = if code.as_str() != e.code {
                format!("{}: {}", e.code, e.message)
            } else {
                e.message
            };
            Err(Error::Api { code, message })
        }
        (false, None) => Err(Error::Protocol("ok:false without error".into())),
    }
}

/// A result JSON as `T`: the library's error for an error result, else the fields decoded straight into `T`.
fn decode<T: DeserializeOwned>(json: &str) -> Result<T> {
    check_ok(json)?;
    serde_json::from_str(json).map_err(|e| Error::Protocol(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_ok_reads_the_envelope() {
        assert!(check_ok(r#"{"ok":true,"library":"x"}"#).is_ok());
        let err = check_ok(r#"{"ok":false,"error":{"code":"INVALID_ARGUMENT","message":"bad"}}"#).unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::InvalidArgument));
        assert_eq!(err.to_string(), "INVALID_ARGUMENT: bad");
        let err = check_ok(r#"{"ok":false,"error":{"code":"NEVER_SEEN","message":"new"}}"#).unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::Unknown("NEVER_SEEN")));
        assert!(matches!(
            check_ok(r#"{"ok":false,"error":{"code":"","message":"m"}}"#),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(check_ok(r#"{"ok":false}"#), Err(Error::Protocol(_))));
        assert!(matches!(check_ok("not json"), Err(Error::Protocol(_))));
        assert!(matches!(check_ok(r#"{"library":"x"}"#), Err(Error::Protocol(_))));
    }

    #[test]
    fn decode_reports_malformed_results_as_protocol_errors() {
        let v: Version = decode(r#"{"ok":true,"library":"1","dss":"6.5.1","runtime":"r","api_version":1}"#).unwrap();
        assert_eq!(v.api_version, Some(1));
        let err = decode::<Version>(r#"{"ok":true,"library":"1"}"#).unwrap_err();
        assert!(
            matches!(err, Error::Protocol(ref m) if m.contains("missing field")),
            "{err}"
        );
        let err = decode::<Version>(r#"{"ok":false,"error":{"code":"INTERNAL_ERROR","message":"m"}}"#).unwrap_err();
        assert_eq!(
            err.code(),
            Some(ErrorCode::InternalError),
            "the error wins over the shape"
        );
    }

    #[test]
    #[cfg(unix)]
    fn builder_refuses_bad_arguments_before_touching_the_library() {
        fn refused(b: EngineBuilder) -> String {
            match b.build() {
                Err(Error::Argument(why)) => why,
                other => panic!("expected Error::Argument, got {other:?}"),
            }
        }
        let config = Config::new("oj.p12");
        // "512é", "é" and "5€" end in a multi-byte character: refused, not a char-boundary panic.
        for bad in [
            "512", "", "m", "512 m", "-512m", "512mb", "0x10m", "512é", "é", "5€", "２m",
        ] {
            let why = refused(EngineBuilder::new("cache", &config).max_heap(bad));
            assert!(why.contains("max_heap") && why.contains(bad), "{why}");
        }
        for bad in ["foo", "--foo", "-xmx512m", "-Xmx 64m", "-X", "-D", ""] {
            let why = refused(EngineBuilder::new("cache", &config).isolate_arg(bad));
            assert!(why.contains("isolate option") && why.contains(bad), "{why}");
        }
        // The first refusal is kept.
        let why = refused(EngineBuilder::new("cache", &config).max_heap("1").isolate_arg("x"));
        assert!(why.contains("max_heap"), "{why}");

        let mut config = Config::new("oj.p12");
        config.extra_trusted_certificates = vec![non_utf8_path()];
        let why = refused(EngineBuilder::new("cache", &config));
        assert!(why.starts_with("config:") && why.contains("UTF-8"), "{why}");
        let why = refused(EngineBuilder::new(non_utf8_path(), &Config::new("oj.p12")));
        assert!(why.contains("cache_dir") && why.contains("UTF-8"), "{why}");

        let b = EngineBuilder::new("cache", &Config::new("oj.p12"))
            .max_heap("512m")
            .max_heap("2G")
            .isolate_arg("-Dfoo=bar");
        assert!(b.error.is_none());
        assert_eq!(b.isolate_args, vec!["-Xmx512m", "-Xmx2G", "-Dfoo=bar"]);
    }

    #[test]
    fn a_cancelled_token_is_shared_by_its_clones() {
        let token = CancelToken::new();
        let other = token.clone();
        assert!(!token.is_cancelled() && !other.is_cancelled());
        other.cancel();
        assert!(token.is_cancelled() && other.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled(), "stays set");
        assert!(!CancelToken::default().is_cancelled());
    }

    /// A worker that takes a cancelled job answers it without running it: the reply arrives as Cancelled.
    #[test]
    fn cancelled_work_is_answered_without_running() {
        let (reply, result) = mpsc::sync_channel(1);
        Work::Validate {
            document: vec![],
            options: CString::new("{}").unwrap(),
            contents: vec![],
            reply,
        }
        .reply_cancelled();
        assert!(matches!(result.recv().unwrap(), Err(Error::Cancelled)));
        let (reply, result) = mpsc::sync_channel(1);
        Work::Extend {
            document: vec![],
            options: CString::new("{}").unwrap(),
            reply,
        }
        .reply_cancelled();
        assert!(matches!(result.recv().unwrap(), Err(Error::Cancelled)));
    }

    #[test]
    #[cfg(unix)]
    fn typed_options_with_a_non_utf8_path_are_refused() {
        let options = Options {
            detached_contents: vec![crate::DetachedContent::file(non_utf8_path())],
            ..Default::default()
        };
        let err = options_json("options", &options).unwrap_err();
        assert!(matches!(err, Error::Argument(ref m) if m.contains("UTF-8")), "{err}");
    }

    /// A content name with an embedded NUL cannot cross the C API: refused before any job is queued.
    #[test]
    fn content_names_with_a_nul_are_refused() {
        let Err(err) = owned_contents(&[DetachedBytes::named("a\0b", b"x")]) else {
            panic!("a NUL in the name must be refused")
        };
        assert!(matches!(err, Error::Nul), "{err}");
        let owned = owned_contents(&[DetachedBytes::unnamed(b"xy"), DetachedBytes::named("n", b"")]).unwrap();
        assert!(owned[0].name.is_none() && owned[0].content == b"xy");
        assert_eq!(owned[1].name.as_deref(), Some(c"n"));
        assert!(owned[1].content.is_empty(), "left to the library to refuse");
    }

    #[test]
    fn builder_debug_hides_the_configuration() {
        let mut config = Config::new("oj.p12");
        config.oj_keystore.password = Some("OJ_SECRET".into());
        let debug = format!("{:?}", EngineBuilder::new("cache", &config).workers(2));
        assert!(!debug.contains("OJ_SECRET"), "{debug}");
        assert!(
            debug.contains("config_json: <") && debug.contains("workers: 2"),
            "{debug}"
        );
    }

    #[cfg(unix)]
    fn non_utf8_path() -> PathBuf {
        use std::os::unix::ffi::OsStrExt;
        PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/\xff\xfe.pdf"))
    }
}
