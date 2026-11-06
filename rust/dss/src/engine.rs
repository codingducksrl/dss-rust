// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::{CStr, CString, c_char};
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use dss_sys as sys;

use crate::config::{Config, ExtendOptions, Options, SignOptions};
use crate::error::{Error, ErrorCode, Result};
use crate::types::{
    Extended, InitInfo, PreparedSignature, RefreshRecord, Reports, Signed, TlSnapshot, TlSnapshotInfo,
    TrustedListStatus, Version,
};

/// Builds an [`Engine`]: one GraalVM isolate, the library initialised from `cache_dir`, and its threads.
#[derive(Debug, Clone)]
pub struct EngineBuilder {
    cache_dir: PathBuf,
    config_json: String,
    workers: usize,
    isolate_args: Vec<String>,
}

impl EngineBuilder {
    pub fn new(cache_dir: impl Into<PathBuf>, config: &Config) -> Self {
        let json = serde_json::to_string(config).expect("Config always serializes");
        Self::with_config_json(cache_dir, json)
    }

    /// Uses a `config_json` document as-is (see README.md, "config_json").
    pub fn with_config_json(cache_dir: impl Into<PathBuf>, config_json: impl Into<String>) -> Self {
        EngineBuilder {
            cache_dir: cache_dir.into(),
            config_json: config_json.into(),
            workers: 1,
            isolate_args: vec![],
        }
    }

    /// Number of threads that run validations, extensions and signatures concurrently (default 1).
    pub fn workers(mut self, n: usize) -> Self {
        self.workers = n.max(1);
        self
    }

    /// Maximum Java heap of the isolate, e.g. `"512m"`, `"2g"` (`-Xmx`). Default: Native Image's, which grows
    /// with physical memory.
    pub fn max_heap(mut self, size: &str) -> Self {
        self.isolate_args.push(format!("-Xmx{size}"));
        self
    }

    /// Any other isolate runtime option, e.g. `-XX:MissingRegistrationReportingMode=Warn`.
    pub fn isolate_arg(mut self, arg: impl Into<String>) -> Self {
        self.isolate_args.push(arg.into());
        self
    }

    /// Creates the isolate and loads the trusted lists from the cache (no network). Blocking.
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
    init: InitInfo,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

/// Work for the worker threads.
enum Job {
    Validate {
        document: Vec<u8>,
        options: CString,
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

struct RefreshJob {
    reply: SyncSender<Result<String>>,
}

impl Engine {
    pub fn builder(cache_dir: impl Into<PathBuf>, config: &Config) -> EngineBuilder {
        EngineBuilder::new(cache_dir, config)
    }

    /// What `dss_init` reported: whether trusted lists were loaded from the cache, and how long it took.
    pub fn init_info(&self) -> &InitInfo {
        &self.init
    }

    /// Validates a PDF or CMS/CAdES document (also base64/PEM-wrapped and nested `.p7m.p7m`).
    pub fn validate(&self, document: &[u8], options: &Options) -> Result<Reports> {
        decode(&self.validate_json(document, &serde_json::to_string(options).expect("Options serialize"))?)
    }

    /// As [`validate`](Self::validate), with options and result as the library's raw JSON.
    pub fn validate_json(&self, document: &[u8], options_json: &str) -> Result<String> {
        let options = CString::new(options_json).map_err(|_| Error::Nul)?;
        let (reply, result) = mpsc::sync_channel(1);
        self.submit(Job::Validate {
            document: document.to_vec(),
            options,
            reply,
        })?;
        let json = result.recv().map_err(|_| Error::Closed)??;
        check_ok(&json)?;
        Ok(json)
    }

    /// Extends every signature of a PDF to PAdES-BASELINE-T, -LT or -LTA: for LT, the certificates and
    /// revocation data they need (fetched online unless [`Config::revocation`] is offline); for T and LTA, also
    /// a document timestamp from [`Config::tsa`]. Validate the result to see the new level.
    ///
    /// DSS checks the signatures first. It refuses with [`ErrorCode::ExtensionFailed`] when one does not
    /// validate, a certificate is revoked or expired, revocation data is missing, a signature is already at a
    /// higher level, or a timestamp is needed and no TSA is configured.
    pub fn extend(&self, document: &[u8], options: &ExtendOptions) -> Result<Extended> {
        let (json, pdf) = self.extend_json(
            document,
            &serde_json::to_string(options).expect("ExtendOptions serialize"),
        )?;
        let mut extended: Extended = decode(&json)?;
        extended.document = pdf;
        Ok(extended)
    }

    /// As [`extend`](Self::extend), with options and result as the library's raw JSON, plus the extended PDF.
    pub fn extend_json(&self, document: &[u8], options_json: &str) -> Result<(String, Vec<u8>)> {
        let options = CString::new(options_json).map_err(|_| Error::Nul)?;
        let (reply, result) = mpsc::sync_channel(1);
        self.submit(Job::Extend {
            document: document.to_vec(),
            options,
            reply,
        })?;
        let (json, pdf) = result.recv().map_err(|_| Error::Closed)??;
        check_ok(&json)?;
        Ok((json, pdf))
    }

    /// Signing with a key held elsewhere, step 1: the digest the external signer must sign, for `document` and
    /// `options`. Needs no network and no trusted lists. Refuses ([`ErrorCode::SigningFailed`]) a signing
    /// certificate that is expired or not yet valid at the signing time, before any external signature is spent.
    ///
    /// Send [`PreparedSignature::digest`] to the signer: with [`SigningMode::Cms`](crate::SigningMode::Cms) it
    /// returns a detached CMS for it, with [`SigningMode::SignatureValue`](crate::SigningMode::SignatureValue) a bare
    /// signature value. Nothing is kept between the two steps: they may run in different processes.
    pub fn prepare_signature(&self, document: &[u8], options: &SignOptions) -> Result<PreparedSignature> {
        decode(&self.prepare_signature_json(
            document,
            &serde_json::to_string(options).expect("SignOptions serialize"),
        )?)
    }

    /// As [`prepare_signature`](Self::prepare_signature), with options and result as the library's raw JSON.
    pub fn prepare_signature_json(&self, document: &[u8], options_json: &str) -> Result<String> {
        let options = CString::new(options_json).map_err(|_| Error::Nul)?;
        let (reply, result) = mpsc::sync_channel(1);
        self.submit(Job::SignPrepare {
            document: document.to_vec(),
            options,
            reply,
        })?;
        let json = result.recv().map_err(|_| Error::Closed)??;
        check_ok(&json)?;
        Ok(json)
    }

    /// Step 2: the signed document, from the same `document` and `options` as
    /// [`prepare_signature`](Self::prepare_signature) (with [`SignOptions::signing_time`] set to the one it
    /// returned) and what the external signer returned (`signature`: DER, BER or base64).
    ///
    /// The external result is checked first: it must sign this document's digest, and a CMS must be a detached
    /// baseline one (for PAdES without signing-time). Then DSS builds the document and adds the level asked for:
    /// T and LTA need [`Config::tsa`](crate::Config::tsa), LT and LTA fetch revocation data like
    /// [`extend`](Self::extend). Failures are [`ErrorCode::SigningFailed`].
    pub fn complete_signature(&self, document: &[u8], options: &SignOptions, signature: &[u8]) -> Result<Signed> {
        let (json, signed) = self.complete_signature_json(
            document,
            &serde_json::to_string(options).expect("SignOptions serialize"),
            signature,
        )?;
        let mut result: Signed = decode(&json)?;
        result.document = signed;
        Ok(result)
    }

    /// As [`complete_signature`](Self::complete_signature), with options and result as the library's raw JSON,
    /// plus the signed document.
    pub fn complete_signature_json(
        &self,
        document: &[u8],
        options_json: &str,
        signature: &[u8],
    ) -> Result<(String, Vec<u8>)> {
        let options = CString::new(options_json).map_err(|_| Error::Nul)?;
        let (reply, result) = mpsc::sync_channel(1);
        self.submit(Job::SignComplete {
            document: document.to_vec(),
            options,
            signature: signature.to_vec(),
            reply,
        })?;
        let (json, signed) = result.recv().map_err(|_| Error::Closed)??;
        check_ok(&json)?;
        Ok((json, signed))
    }

    fn submit(&self, job: Job) -> Result<()> {
        let jobs = self.jobs.as_ref().ok_or(Error::Closed)?;
        jobs.send(job).map_err(|_| Error::Closed)
    }

    /// Downloads and validates the LOTL and national trusted lists. Blocking; validations keep running.
    ///
    /// Fails with [`ErrorCode::RefreshInProgress`] if a refresh is already running.
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
        let cache_dir = CString::new(b.cache_dir.to_string_lossy().as_bytes()).map_err(|_| Error::Nul)?;
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
            .expect("cannot spawn dss-control thread");

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
            init: InitInfo {
                trusted_lists_loaded: false,
                initial_load: RefreshRecord {
                    mode: String::new(),
                    started_at: String::new(),
                    finished_at: String::new(),
                    duration_ms: 0,
                    completed: false,
                    error: None,
                    trusted_certificates: 0,
                },
            },
        };
        // From here on, Drop tears everything down if something fails.
        engine.init = decode(&init_json)?;

        let (job_tx, job_rx) = mpsc::channel::<Job>();
        let job_rx = Arc::new(Mutex::new(job_rx));
        let (attached_tx, attached_rx) = mpsc::channel::<Result<()>>();
        for i in 0..b.workers {
            let rx = Arc::clone(&job_rx);
            let attached = attached_tx.clone();
            engine.threads.push(
                thread::Builder::new()
                    .name(format!("dss-validate-{i}"))
                    .spawn(move || worker_main(isolate, rx, attached))
                    .expect("cannot spawn validation thread"),
            );
        }
        engine.jobs = Some(job_tx);

        let (refresh_tx, refresh_rx) = mpsc::channel::<RefreshJob>();
        let attached = attached_tx.clone();
        engine.threads.push(
            thread::Builder::new()
                .name("dss-refresh".into())
                .spawn(move || refresh_main(isolate, refresh_rx, attached))
                .expect("cannot spawn refresh thread"),
        );
        engine.refresh = Some(refresh_tx);
        drop(attached_tx);

        for _ in 0..=b.workers {
            attached_rx.recv().map_err(|_| Error::Closed)??;
        }
        Ok(engine)
    }
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

// The isolate pointer is an opaque handle: any thread may attach to it.
unsafe impl Send for Isolate {}

/// This OS thread's attachment to the isolate. Not `Send`: it is only valid on the thread that attached.
struct Attached(*mut sys::graal_isolatethread_t);

impl Attached {
    fn attach(isolate: Isolate) -> Result<Attached> {
        let mut thread = ptr::null_mut();
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
        unsafe { sys::dss_free(self.0, p) };
        Ok(s)
    }

    /// Calls `dss_extend` and takes ownership of its result string and of the document it hands back.
    fn extend(&self, document: &[u8], options: &CStr) -> Result<(String, Vec<u8>)> {
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
            unsafe { sys::dss_free(self.0, out) };
            document
        };
        Ok((json?, document))
    }

    fn detach(self) {
        unsafe { sys::graal_detach_thread(self.0) };
    }
}

/// GraalVM CE 25.4: if the first isolate creation in a process fails (e.g. on an invalid `-Xmx`), every later
/// `graal_create_isolate` in that process hangs. Later failures are harmless. So before the first engine, create
/// and tear down one isolate without options; a bad option can then only fail its own engine.
fn ensure_first_isolate_created() -> Result<()> {
    static FIRST: OnceLock<i32> = OnceLock::new();
    let rc = *FIRST.get_or_init(|| unsafe {
        let mut isolate = ptr::null_mut();
        let mut thread = ptr::null_mut();
        let rc = sys::graal_create_isolate(ptr::null_mut(), &mut isolate, &mut thread);
        if rc == 0 {
            sys::graal_tear_down_isolate(thread);
        }
        rc
    });
    if rc == 0 { Ok(()) } else { Err(Error::Isolate(rc)) }
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
    let rc = unsafe { sys::graal_create_isolate(&mut params, &mut isolate, &mut thread) };
    if rc != 0 {
        let _ = started.send(Err(Error::Isolate(rc)));
        return;
    }
    let me = Attached(thread);

    let init = me.call(|t| unsafe { sys::dss_init(t, cache_dir.as_ptr(), config.as_ptr()) });
    let failed = !matches!(init.as_deref().map(check_ok), Ok(Ok(())));
    let _ = started.send(init.map(|json| (Isolate(isolate), json)));
    if !failed {
        for request in requests.iter() {
            match request {
                Control::Status(reply) => {
                    let _ = reply.send(me.call(|t| unsafe { sys::dss_tl_status(t) }));
                }
                Control::Version(reply) => {
                    let _ = reply.send(me.call(|t| unsafe { sys::dss_version(t) }));
                }
                Control::ExportTlSnapshot(reply) => {
                    let _ =
                        reply.send(me.call_with_document(|t, out, out_len| unsafe {
                            sys::dss_tl_export_snapshot(t, out, out_len)
                        }));
                }
                Control::TearDown => break,
            }
        }
    }
    let _ = me.call(|t| unsafe { sys::dss_shutdown(t) });
    unsafe { sys::graal_tear_down_isolate(me.0) };
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
        let Ok(job) = job else { break };
        match job {
            Job::Validate {
                document,
                options,
                reply,
            } => {
                let result = me.call(|t| unsafe {
                    sys::dss_validate(t, document.as_ptr() as *const c_char, document.len(), options.as_ptr())
                });
                let _ = reply.send(result);
            }
            Job::Extend {
                document,
                options,
                reply,
            } => {
                let _ = reply.send(me.extend(&document, &options));
            }
            Job::SignPrepare {
                document,
                options,
                reply,
            } => {
                let result = me.call(|t| unsafe {
                    sys::dss_sign_prepare(t, document.as_ptr() as *const c_char, document.len(), options.as_ptr())
                });
                let _ = reply.send(result);
            }
            Job::SignComplete {
                document,
                options,
                signature,
                reply,
            } => {
                let _ = reply.send(me.sign_complete(&document, &options, &signature));
            }
        }
    }
    me.detach();
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
        let _ = job.reply.send(me.call(|t| unsafe { sys::dss_tl_refresh_online(t) }));
    }
    me.detach();
}

// ---------------------------------------------------------------------------------------------- JSON

#[derive(Deserialize)]
struct ApiError {
    code: ErrorCode,
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
        (false, Some(e)) => Err(Error::Api {
            code: e.code,
            message: e.message,
        }),
        (false, None) => Err(Error::Protocol("ok:false without error".into())),
    }
}

fn decode<T: DeserializeOwned>(json: &str) -> Result<T> {
    check_ok(json)?;
    let value: Value = serde_json::from_str(json).map_err(|e| Error::Protocol(e.to_string()))?;
    serde_json::from_value(value).map_err(|e| Error::Protocol(e.to_string()))
}
